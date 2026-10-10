package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func blobRequest(t *testing.T, server *Server, user string, key ed25519.PrivateKey, method, path string, body []byte, nonce string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	token := Token_IssueAuthToken(server.Cfg.TokenSecret, user, time.Now().Add(time.Hour).Unix()).Value
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
				json.Unmarshal([]byte(request.Header.Get("X-Daochi-Tx")), &tx)
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
