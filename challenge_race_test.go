package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// nonceVerifier accepts a signature only over the challenge it was made for.
type nonceVerifier struct {
	mu     sync.Mutex
	nonces map[string]string
}

func (v *nonceVerifier) sign(signature, nonceHex string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.nonces[signature] = nonceHex
}

func (v *nonceVerifier) Verify(publicKey, message, signature []byte) bool {
	v.mu.Lock()
	nonce := v.nonces[hex.EncodeToString(signature)]
	v.mu.Unlock()
	return nonce != "" && len(publicKey) == mlDSA44PublicKeySize &&
		bytes.Contains(message, []byte("\n"+nonce+"\n"))
}

func raceServer(t *testing.T) (http.Handler, *nonceVerifier) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "race.db")
	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	verifier := &nonceVerifier{nonces: map[string]string{}}
	server := NewServer(Config{
		Addr:         "127.0.0.1:0",
		BaseURL:      "http://127.0.0.1:0",
		DBPath:       dbPath,
		ChallengeTTL: time.Minute,
		TokenTTL:     time.Hour,
		TokenSecret:  bytes.Repeat([]byte{0x77}, 32),
		MaxBodyBytes: 1 << 20,
	}, store, verifier)
	return server.Routes(), verifier
}

func raceLogin(handler http.Handler, userID, publicKeyHex, signature string) *httptest.ResponseRecorder {
	body := []byte(`{"user_id_hash":"` + userID + `","client_id":"race-client","public_key":"` + publicKeyHex + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sync/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Daochi-User", userID)
	req.Header.Set("X-Daochi-Signature", signature)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	return res
}

func raceChallenge(t *testing.T, handler http.Handler, userID string) string {
	t.Helper()
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/api/v1/sync/challenge?user_id="+userID, nil))
	if res.Code != http.StatusOK {
		t.Fatalf("challenge status = %d body=%s", res.Code, res.Body.String())
	}
	var payload ChallengeResponse
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	return payload.Nonce
}

// Two sign-ins of one account overlap: the second challenge must not make
// the first login fail, and neither challenge can sign in twice.
func TestOverlappingLoginsKeepTheirOwnChallenges(t *testing.T) {
	handler, verifier := raceServer(t)
	publicKey := bytes.Repeat([]byte{0x42}, mlDSA44PublicKeySize)
	sum := sha256.Sum256(publicKey)
	identity := struct{ UserID string }{hex.EncodeToString(sum[:])}
	publicKeyHex := hex.EncodeToString(publicKey)
	first := hex.EncodeToString(bytes.Repeat([]byte{0x01}, mlDSA44SignatureSize))
	second := hex.EncodeToString(bytes.Repeat([]byte{0x02}, mlDSA44SignatureSize))

	verifier.sign(first, raceChallenge(t, handler, identity.UserID))
	verifier.sign(second, raceChallenge(t, handler, identity.UserID))

	if res := raceLogin(handler, identity.UserID, publicKeyHex, first); res.Code != http.StatusOK {
		t.Fatalf("first login status = %d body=%s", res.Code, res.Body.String())
	}
	if res := raceLogin(handler, identity.UserID, publicKeyHex, second); res.Code != http.StatusOK {
		t.Fatalf("second login status = %d body=%s", res.Code, res.Body.String())
	}
	if res := raceLogin(handler, identity.UserID, publicKeyHex, first); res.Code != http.StatusBadRequest {
		t.Fatalf("replayed login status = %d body=%s", res.Code, res.Body.String())
	}

	forged := hex.EncodeToString(bytes.Repeat([]byte{0x03}, mlDSA44SignatureSize))
	verifier.sign(second, raceChallenge(t, handler, identity.UserID))
	if res := raceLogin(handler, identity.UserID, publicKeyHex, forged); res.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned login status = %d body=%s", res.Code, res.Body.String())
	}
	if res := raceLogin(handler, identity.UserID, publicKeyHex, second); res.Code != http.StatusOK {
		t.Fatalf("a rejected signature must not use up the account's challenge: %d %s", res.Code, res.Body.String())
	}
}

func TestChallengeStoreBoundsExpiresAndTakesOnce(t *testing.T) {
	store := NewChallengeStore(time.Minute)
	issued := make([][]byte, 0, maxOutstandingChallenges+2)
	for i := 0; i < maxOutstandingChallenges+2; i++ {
		nonce, err := store.Issue("alice")
		if err != nil {
			t.Fatal(err)
		}
		issued = append(issued, nonce)
	}
	outstanding := store.Outstanding("alice")
	if len(outstanding) != maxOutstandingChallenges {
		t.Fatalf("outstanding = %d", len(outstanding))
	}
	if !bytes.Equal(outstanding[0], issued[len(issued)-1]) {
		t.Fatal("newest challenge must come first")
	}
	if store.Take("alice", issued[0]) {
		t.Fatal("the oldest challenge beyond the bound must be gone")
	}
	if !store.Take("alice", issued[5]) || store.Take("alice", issued[5]) {
		t.Fatal("a challenge must be taken exactly once")
	}
	if peek, ok := store.PeekBase64("alice"); !ok || peek == "" {
		t.Fatal("peek must show the newest challenge")
	}
	if store.Take("bob", issued[6]) {
		t.Fatal("another account cannot take the challenge")
	}

	expired := NewChallengeStore(-time.Second)
	nonce, err := expired.Issue("alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(expired.Outstanding("alice")) != 0 || expired.Take("alice", nonce) {
		t.Fatal("expired challenges must not sign in")
	}
}
