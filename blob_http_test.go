package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func blobRequest(t *testing.T, server *Server, user string, key ed25519.PrivateKey, method, path string, body []byte, nonce string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	token := issueTestBearer(t, server, user, time.Now().Add(time.Hour))
	request.Header.Set("Authorization", "Bearer "+token)
	tx := SignedTxEnvelope{ProtocolVersion: 6, TxID: nonce, Nonce: nonce, AccountID: user,
		AppID: "target", DeviceKeyID: "device-key", Method: method, Path: request.URL.Path,
		BodySHA256: Signing_SHA256Hex(body), ExpiresAt: time.Now().Add(time.Minute).Unix(),
		Signature: hex.EncodeToString(bytes.Repeat([]byte{0x33}, mlDSA44SignatureSize))}
	signDeviceTransaction(&tx, key)
	encoded, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Daochi-Tx", string(encoded))
	return request
}

func TestPrivateBlobsPreserveBinaryBytesAndRejectUnauthorizedReplayCorruption(t *testing.T) {
	server, user, key := registryHTTPFixture(t)
	server.Verifier = testVerifier(&transactionVerifier{accept: true})
	server.Cfg.DBPath = filepath.Join(t.TempDir(), "node.sqlite")
	data := []byte("\x00\xffprivate encrypted photo bytes\x00")
	path := "/api/v1/blobs/target/" + Signing_SHA256Hex(data)
	put := blobRequest(t, server, user, key, "PUT", path, data, "put-original")
	recorder := httptest.NewRecorder()
	Server_HandleBlobHttpRoute(server, recorder, put)
	if recorder.Code != 204 {
		t.Fatalf("put: %d %s", recorder.Code, recorder.Body)
	}
	recorder = httptest.NewRecorder()
	Server_HandleBlobHttpRoute(server, recorder, blobRequest(t, server, user, key, "GET", path, nil, "read-original"))
	if recorder.Code != 200 || !bytes.Equal(recorder.Body.Bytes(), data) {
		t.Fatalf("get: %d %q", recorder.Code, recorder.Body)
	}
	if recorder.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatal("blob can be publicly cached")
	}
	recorder = httptest.NewRecorder()
	Server_HandleBlobHttpRoute(server, recorder, put.Clone(t.Context()))
	if recorder.Code != 409 && recorder.Code != 413 {
		t.Fatalf("replay accepted: %d", recorder.Code)
	}
	for _, mode := range []string{"no token", "no signature", "bad hash", "expired", "traversal", "other user"} {
		t.Run(mode, func(t *testing.T) {
			request := blobRequest(t, server, user, key, "PUT", path, data, "reject-"+strings.ReplaceAll(mode, " ", "-"))
			switch mode {
			case "no token":
				request.Header.Del("Authorization")
			case "no signature":
				request.Header.Del("X-Daochi-Tx")
			case "bad hash":
				request.URL.Path = "/api/v1/blobs/target/" + strings.Repeat("0", 64)
			case "expired":
				var tx SignedTxEnvelope
				if err := json.Unmarshal([]byte(request.Header.Get("X-Daochi-Tx")), &tx); err != nil {
					t.Fatal(err)
				}
				tx.ExpiresAt = 1
				signDeviceTransaction(&tx, key)
				value, _ := json.Marshal(tx)
				request.Header.Set("X-Daochi-Tx", string(value))
			case "traversal":
				request.URL.Path = "/api/v1/blobs/target/../../secret"
			case "other user":
				request.Header.Set("Authorization", "Bearer "+Token_IssueAuthToken(server.Cfg.TokenSecret, strings.Repeat("b", 64), time.Now().Add(time.Hour).Unix()).Value)
			}
			r := httptest.NewRecorder()
			Server_HandleBlobHttpRoute(server, r, request)
			if r.Code >= 200 && r.Code < 300 {
				t.Fatalf("unsafe request accepted: %d", r.Code)
			}
		})
	}
}

// Blobs count toward the account storage limit, and deleting the account
// removes its blob files as well as its rows.
func TestBlobsCountTowardStorageAndLeaveWithTheAccount(t *testing.T) {
	server, user, key := registryHTTPFixture(t)
	server.Verifier = testVerifier(&transactionVerifier{accept: true})
	server.Cfg.DBPath = filepath.Join(t.TempDir(), "node.sqlite")
	before := AccountStorage_Used(server.Store.Database, t.Context(), user)
	if before.Error != nil {
		t.Fatal(before.Error)
	}
	server.Cfg.AccountStorageLimitBytes = before.Value + 64
	small := bytes.Repeat([]byte{0x01}, 40)
	large := bytes.Repeat([]byte{0x02}, 40)
	put := func(data []byte, nonce string) int {
		t.Helper()
		recorder := httptest.NewRecorder()
		path := "/api/v1/blobs/target/" + Signing_SHA256Hex(data)
		Server_HandleBlobHttpRoute(server, recorder, blobRequest(t, server, user, key, "PUT", path, data, nonce))
		return recorder.Code
	}
	if code := put(small, "put-small"); code != http.StatusNoContent {
		t.Fatalf("blob under the limit = %d", code)
	}
	used := AccountStorage_Used(server.Store.Database, t.Context(), user)
	if used.Error != nil || used.Value != before.Value+int64(len(small)) {
		t.Fatalf("blob bytes not counted: %#v", used)
	}
	if code := put(small, "put-small-again"); code != http.StatusNoContent {
		t.Fatalf("storing the same blob again = %d", code)
	}
	if code := put(large, "put-large"); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("blob past the limit = %d", code)
	}

	folder := AccountStorage_BlobAccountFolder(server.Cfg.DBPath, user)
	if _, err := os.Stat(folder); err != nil {
		t.Fatalf("blob folder missing before deletion: %v", err)
	}
	if err := AccountState_Delete(server.Store.Database, t.Context(), user); err != nil {
		t.Fatal(err)
	}
	if err := AccountStorage_RemoveBlobs(server.Cfg.DBPath, user); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(folder); !os.IsNotExist(err) {
		t.Fatalf("blob folder survived account deletion: %v", err)
	}
	if err := AccountStorage_RemoveBlobs(server.Cfg.DBPath, "../../etc"); err == nil {
		t.Fatal("blob removal accepted a path outside the account folders")
	}
}
