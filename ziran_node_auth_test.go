package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const baselineNodeAuthenticationWindow = 5 * time.Minute

func baselineRandomHex(bytes int) string {
	data := make([]byte, bytes)
	if _, err := rand.Read(data); err != nil {
		panic(err)
	}
	return hex.EncodeToString(data)
}

func baselineSignNodeRequest(nodeID string, privateKey ed25519.PrivateKey, req *http.Request, body []byte) {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := baselineRandomHex(16)
	message := []byte(baselineNodeMessage("daochi-node-request-v1", nodeID, timestamp, nonce,
		req.Method, req.URL.EscapedPath(), body))
	signature := ed25519.Sign(privateKey, message)

	req.Header.Set("X-Daochi-Node-ID", nodeID)
	req.Header.Set("X-Daochi-Node-Time", timestamp)
	req.Header.Set("X-Daochi-Node-Nonce", nonce)
	req.Header.Set("X-Daochi-Node-Signature",
		base64.RawURLEncoding.EncodeToString(signature))
}

func baselineVerifyNodeRequest(database *sql.DB, ctx context.Context, req *http.Request, body []byte) error {
	nodeID := strings.TrimSpace(req.Header.Get("X-Daochi-Node-ID"))
	timestampText := strings.TrimSpace(req.Header.Get("X-Daochi-Node-Time"))
	nonce := strings.TrimSpace(req.Header.Get("X-Daochi-Node-Nonce"))
	if !baselineValidNodeID(nodeID) || nonce == "" || len(nonce) > 128 {
		return errors.New("invalid node authentication")
	}
	timestamp, err := strconv.ParseInt(timestampText, 10, 64)
	if err != nil {
		return errors.New("invalid node authentication time")
	}
	now := time.Now().Unix()
	windowSeconds := int64(baselineNodeAuthenticationWindow / time.Second)
	if timestamp < now-windowSeconds || timestamp > now+windowSeconds {
		return errors.New("expired node authentication")
	}
	publicKey, found, err := baselinePeerPublicKey(database, ctx, nodeID)
	if err != nil {
		return err
	}
	if !found {
		return errors.New("node is not paired")
	}
	signature, err := base64.RawURLEncoding.DecodeString(
		req.Header.Get("X-Daochi-Node-Signature"))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("invalid node signature")
	}
	message := []byte(baselineNodeMessage("daochi-node-request-v1", nodeID, timestampText, nonce,
		req.Method, req.URL.EscapedPath(), body))
	if !ed25519.Verify(publicKey, message, signature) {
		return errors.New("invalid node signature")
	}
	return baselineConsumeNodeNonce(database, ctx, nodeID, nonce, timestamp+windowSeconds)
}

func baselineValidNodeID(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, byte := range []byte(value) {
		if byte < '0' || byte > '9' {
			if byte < 'a' || byte > 'f' {
				return false
			}
		}
	}
	return true
}

func baselineNodeMessage(context, nodeID, timestamp, nonce, method, path string, body []byte) string {
	digest := sha256.Sum256(body)
	return strings.Join([]string{context, nodeID, timestamp, nonce, strings.ToUpper(method),
		path, hex.EncodeToString(digest[:]), ""}, "\n")
}

func baselinePeerPublicKey(database *sql.DB, ctx context.Context, nodeID string) (ed25519.PublicKey, bool, error) {
	var publicKey []byte
	err := database.QueryRowContext(ctx, `
SELECT public_key FROM trusted_node_peers
WHERE node_id=?1 AND revoked_at=''`, nodeID).Scan(&publicKey)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, false, errors.New("stored peer key is invalid")
	}
	return ed25519.PublicKey(publicKey), true, nil
}

func nodeAuthFixture(t *testing.T, nodeID string, publicKey []byte) *sql.DB {
	t.Helper()
	database := nodeNonceFixture(t)
	if _, err := database.Exec(`
CREATE TABLE trusted_node_peers (
node_id TEXT PRIMARY KEY, public_key BLOB NOT NULL, revoked_at TEXT NOT NULL DEFAULT '')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("INSERT INTO trusted_node_peers(node_id,public_key) VALUES(?1,?2)", nodeID, publicKey); err != nil {
		t.Fatal(err)
	}
	return database
}

func signedNodeFixture(nodeID string, key ed25519.PrivateKey, method, path, timestamp, nonce string, body []byte) *http.Request {
	request, err := http.NewRequest(method, "https://peer.example"+path, bytes.NewReader(body))
	if err != nil {
		panic(err)
	}
	message := baselineNodeMessage("daochi-node-request-v1", nodeID, timestamp, nonce,
		request.Method, request.URL.EscapedPath(), body)
	request.Header.Set("X-Daochi-Node-ID", nodeID)
	request.Header.Set("X-Daochi-Node-Time", timestamp)
	request.Header.Set("X-Daochi-Node-Nonce", nonce)
	request.Header.Set("X-Daochi-Node-Signature", base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(message))))
	return request
}

func TestZiranNodeSigningPreservesExactMessages(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	publicKey := key.Public().(ed25519.PublicKey)
	digest := sha256.Sum256(publicKey)
	nodeID := hex.EncodeToString(digest[:])
	for _, item := range []struct {
		method string
		path   string
		body   []byte
	}{
		{http.MethodPost, "/api/v1/node/mesh/export", nil},
		{"patch", "/a%2Fb?ignored=1", []byte{0, 255, 195, 169}},
		{http.MethodGet, "/日本語?x=1", []byte("body")},
		{http.MethodPost, "/a%252Fb", []byte("\x00binary\xff")},
	} {
		request, err := http.NewRequest(item.method, "https://peer.example"+item.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Unrelated", "preserved")
		before := time.Now().Unix()
		NodeAuth_Sign(nodeID, key, request, item.body)
		after := time.Now().Unix()
		timestamp := request.Header.Get("X-Daochi-Node-Time")
		parsed, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil || parsed < before || parsed > after {
			t.Fatalf("signing timestamp = %q", timestamp)
		}
		nonce := request.Header.Get("X-Daochi-Node-Nonce")
		decoded, err := hex.DecodeString(nonce)
		if err != nil || len(decoded) != 16 || nonce != strings.ToLower(nonce) {
			t.Fatalf("signing nonce = %q", nonce)
		}
		message := baselineNodeMessage("daochi-node-request-v1", nodeID, timestamp, nonce,
			request.Method, request.URL.EscapedPath(), item.body)
		want := base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(message)))
		if got := request.Header.Get("X-Daochi-Node-Signature"); got != want {
			t.Fatalf("signature for %s %s = %q, want %q", item.method, item.path, got, want)
		}
		if request.Header.Get("X-Daochi-Node-ID") != nodeID || request.Header.Get("Unrelated") != "preserved" || len(request.Header) != 5 {
			t.Fatalf("signing headers = %#v", request.Header)
		}
	}
}

func TestZiranNodeAuthenticationAgainstBaseline(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	publicKey := key.Public().(ed25519.PublicKey)
	digest := sha256.Sum256(publicKey)
	nodeID := hex.EncodeToString(digest[:])
	body := []byte{0, 255, 195, 169}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	cases := []struct {
		name   string
		modify func(*http.Request, *sql.DB)
		want   string
	}{
		{"valid", func(*http.Request, *sql.DB) {}, ""},
		{"upper node", func(r *http.Request, _ *sql.DB) {
			r.Header.Set("X-Daochi-Node-ID", strings.ToUpper(nodeID))
		}, "invalid node authentication"},
		{"missing nonce", func(r *http.Request, _ *sql.DB) {
			r.Header.Del("X-Daochi-Node-Nonce")
		}, "invalid node authentication"},
		{"long nonce", func(r *http.Request, _ *sql.DB) {
			r.Header.Set("X-Daochi-Node-Nonce", strings.Repeat("é", 65))
		}, "invalid node authentication"},
		{"malformed time", func(r *http.Request, _ *sql.DB) {
			r.Header.Set("X-Daochi-Node-Time", "9223372036854775808")
		}, "invalid node authentication time"},
		{"old time", func(r *http.Request, _ *sql.DB) {
			r.Header.Set("X-Daochi-Node-Time", "0")
		}, "expired node authentication"},
		{"future time", func(r *http.Request, _ *sql.DB) {
			r.Header.Set("X-Daochi-Node-Time", "9223372036854775807")
		}, "expired node authentication"},
		{"body mismatch", func(r *http.Request, _ *sql.DB) {
			r.Header.Set("X-Daochi-Node-Signature", strings.Repeat("A", 86))
		}, "invalid node signature"},
		{"bad base64", func(r *http.Request, _ *sql.DB) {
			r.Header.Set("X-Daochi-Node-Signature", "!")
		}, "invalid node signature"},
		{"padded signature", func(r *http.Request, _ *sql.DB) {
			r.Header.Set("X-Daochi-Node-Signature", r.Header.Get("X-Daochi-Node-Signature")+"==")
		}, "invalid node signature"},
		{"short signature", func(r *http.Request, _ *sql.DB) {
			r.Header.Set("X-Daochi-Node-Signature", "AQ")
		}, "invalid node signature"},
		{"method mismatch", func(r *http.Request, _ *sql.DB) {
			r.Method = http.MethodGet
		}, "invalid node signature"},
		{"path mismatch", func(r *http.Request, _ *sql.DB) {
			r.URL.Path = "/different"
		}, "invalid node signature"},
		{"whitespace", func(r *http.Request, _ *sql.DB) {
			for _, name := range []string{"X-Daochi-Node-ID", "X-Daochi-Node-Time", "X-Daochi-Node-Nonce"} {
				r.Header.Set(name, "\u2003"+r.Header.Get(name)+"\t")
			}
		}, ""},
		{"base64 line breaks", func(r *http.Request, _ *sql.DB) {
			r.Header.Set("X-Daochi-Node-Signature", "\r\n"+r.Header.Get("X-Daochi-Node-Signature")+"\n")
		}, ""},
		{"revoked", func(_ *http.Request, db *sql.DB) {
			if _, err := db.Exec("UPDATE trusted_node_peers SET revoked_at='revoked'"); err != nil {
				t.Fatal(err)
			}
		}, "node is not paired"},
		{"missing peer", func(_ *http.Request, db *sql.DB) {
			if _, err := db.Exec("DELETE FROM trusted_node_peers"); err != nil {
				t.Fatal(err)
			}
		}, "node is not paired"},
		{"corrupt key", func(_ *http.Request, db *sql.DB) {
			if _, err := db.Exec("UPDATE trusted_node_peers SET public_key=x'01'"); err != nil {
				t.Fatal(err)
			}
		}, "stored peer key is invalid"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			actual, expected := nodeAuthFixture(t, nodeID, publicKey), nodeAuthFixture(t, nodeID, publicKey)
			request := signedNodeFixture(nodeID, key, http.MethodPost, "/a%2Fb", timestamp, "nonce", body)
			baselineRequest := request.Clone(context.Background())
			item.modify(request, actual)
			item.modify(baselineRequest, expected)
			got := NodeAuth_Verify(actual, context.Background(), request, body)
			want := baselineVerifyNodeRequest(expected, context.Background(), baselineRequest, body)
			if (got == nil) != (want == nil) || got != nil && got.Error() != want.Error() ||
				got == nil && item.want != "" || got != nil && got.Error() != item.want {
				t.Fatalf("verification = %v, baseline = %v, expected = %q", got, want, item.want)
			}
			if got, want := nodeNonceSnapshot(t, actual), nodeNonceSnapshot(t, expected); !reflect.DeepEqual(got, want) {
				t.Fatalf("verification nonce state = %#v, want %#v", got, want)
			}
		})
	}
}

func TestZiranNodeAuthenticationPreservesDatabaseErrorsAndOrder(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	publicKey := key.Public().(ed25519.PublicKey)
	digest := sha256.Sum256(publicKey)
	nodeID := hex.EncodeToString(digest[:])
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	t.Run("cancellation", func(t *testing.T) {
		database := nodeAuthFixture(t, nodeID, publicKey)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		request := signedNodeFixture(nodeID, key, http.MethodPost, "/sync", timestamp, "nonce", nil)
		request.Header.Set("X-Daochi-Node-Signature", "!")
		got := NodeAuth_Verify(database, ctx, request, nil)
		want := baselineVerifyNodeRequest(database, ctx, request, nil)
		if !errors.Is(got, context.Canceled) || got != want {
			t.Fatalf("canceled peer lookup = %v, baseline = %v", got, want)
		}
		if got := PeerTrust_PublicKey(database, ctx, nodeID); !errors.Is(got.Error, context.Canceled) || got.Found || got.Value != nil {
			t.Fatalf("canceled public key lookup = %#v", got)
		}
		request.Header.Del("X-Daochi-Node-ID")
		if got := NodeAuth_Verify(database, ctx, request, nil); got == nil || got.Error() != "invalid node authentication" {
			t.Fatalf("header validation must precede canceled lookup: %v", got)
		}
	})

	t.Run("closed database", func(t *testing.T) {
		database := nodeAuthFixture(t, nodeID, publicKey)
		if err := database.Close(); err != nil {
			t.Fatal(err)
		}
		request := signedNodeFixture(nodeID, key, http.MethodPost, "/sync", timestamp, "nonce", nil)
		request.Header.Set("X-Daochi-Node-Signature", "!")
		got := NodeAuth_Verify(database, context.Background(), request, nil)
		want := baselineVerifyNodeRequest(database, context.Background(), request, nil)
		if got == nil || want == nil || got.Error() != want.Error() || got.Error() == "invalid node signature" {
			t.Fatalf("database error must precede signature validation: %v, baseline = %v", got, want)
		}
	})

	t.Run("failed nonce storage", func(t *testing.T) {
		actual, expected := nodeAuthFixture(t, nodeID, publicKey), nodeAuthFixture(t, nodeID, publicKey)
		for _, database := range []*sql.DB{actual, expected} {
			if _, err := database.Exec("DROP TABLE node_request_nonces"); err != nil {
				t.Fatal(err)
			}
		}
		request := signedNodeFixture(nodeID, key, http.MethodPost, "/sync", timestamp, "nonce", nil)
		got := NodeAuth_Verify(actual, context.Background(), request, nil)
		want := baselineVerifyNodeRequest(expected, context.Background(), request, nil)
		if got == nil || want == nil || got.Error() != want.Error() {
			t.Fatalf("nonce storage error = %v, baseline = %v", got, want)
		}
	})
}

func TestZiranNodeAuthenticationConcurrentReplay(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	publicKey := key.Public().(ed25519.PublicKey)
	digest := sha256.Sum256(publicKey)
	nodeID := hex.EncodeToString(digest[:])
	database := nodeAuthFixture(t, nodeID, publicKey)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	request := signedNodeFixture(nodeID, key, http.MethodPost, "/sync", timestamp, "shared", nil)
	const consumers = 20
	results := make(chan error, consumers)
	var workers sync.WaitGroup
	for index := 0; index < consumers; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			results <- NodeAuth_Verify(database, context.Background(), request, nil)
		}()
	}
	workers.Wait()
	close(results)
	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
		} else if err.Error() != "node request replayed" {
			t.Fatalf("unexpected authentication error: %v", err)
		}
	}
	if accepted != 1 {
		t.Fatalf("concurrent signed request accepted %d times, want one", accepted)
	}
	rows := nodeNonceSnapshot(t, database)
	if len(rows) != 2 || rows[0].nodeID != nodeID || rows[0].nonce != "shared" {
		t.Fatalf("persisted replay state = %#v", rows)
	}
}
