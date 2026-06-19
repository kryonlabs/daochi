package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type recordingVerifier struct {
	message []byte
}

func (v *recordingVerifier) Verify(publicKey, message, signature []byte) bool {
	v.message = append(v.message[:0], message...)
	return len(publicKey) == mlDSA44PublicKeySize && len(signature) == mlDSA44SignatureSize
}

func testServer(t *testing.T) (*Server, *Store, *recordingVerifier) {
	t.Helper()
	store, err := OpenStore(filepath.Join(t.TempDir(), "lyra-test.db"))
	if err != nil {
		t.Fatal(err)
	}
	verifier := &recordingVerifier{}
	server := NewServer(Config{
		Addr:         "127.0.0.1:0",
		BaseURL:      "http://127.0.0.1:0",
		DBPath:       "test.db",
		ChallengeTTL: time.Minute,
		MaxBodyBytes: 1 << 20,
	}, store, verifier)
	t.Cleanup(func() { _ = store.Close() })
	return server, store, verifier
}

func TestDocsEndpoints(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()

	root := httptest.NewRecorder()
	handler.ServeHTTP(root, httptest.NewRequest(http.MethodGet, "/", nil))
	if root.Code != http.StatusOK {
		t.Fatalf("root status = %d", root.Code)
	}
	if !strings.Contains(root.Body.String(), "Lyra Sync API") {
		t.Fatalf("root docs missing title: %s", root.Body.String())
	}

	spec := httptest.NewRecorder()
	handler.ServeHTTP(spec, httptest.NewRequest(http.MethodGet, "/openapi.json", nil))
	if spec.Code != http.StatusOK {
		t.Fatalf("openapi status = %d", spec.Code)
	}
	var decoded map[string]any
	if err := json.Unmarshal(spec.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["openapi"] != "3.1.0" {
		t.Fatalf("unexpected openapi version: %#v", decoded["openapi"])
	}
}

func TestHeaderSignedSyncAndDelete(t *testing.T) {
	server, store, verifier := testServer(t)
	handler := server.Routes()
	publicKey := bytes.Repeat([]byte{0x42}, mlDSA44PublicKeySize)
	userHash := sha256.Sum256(publicKey)
	userID := hex.EncodeToString(userHash[:])
	signature := hex.EncodeToString(bytes.Repeat([]byte{0x33}, mlDSA44SignatureSize))

	nonce := issueChallenge(t, handler, userID)
	body := []byte(`{"user_id_hash":"` + userID + `","public_key":"` + hex.EncodeToString(publicKey) + `","preferences":[{"key":"theme","value":"dark","updated_at":"2026-06-19T00:00:00Z"}],"habits":[{"id":"habit-1","name":"Meditate","color_r":1,"color_g":2,"color_b":3,"sync_mode":1,"sync_activity":2,"sort_order":0,"deleted_at":0,"updated_at":"2026-06-19T00:00:00Z"}],"habit_days":[{"habit_id":"habit-1","local_date":20260619,"completed":true,"updated_at":"2026-06-19T00:00:00Z"}],"sessions":[{"id":"session-1","started_at":"2026-06-19T00:00:00Z","local_date":20260619,"topic":"0","activity":1,"source":"test","rounds_hash":"abc","deleted_at":0,"updated_at":"2026-06-19T00:00:00Z","rounds":[{"round_index":0,"breaths":0,"hold_seconds":60}]}]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sync", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Inbe-User", userID)
	req.Header.Set("X-Inbe-Signature", signature)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("sync status = %d body=%s", res.Code, res.Body.String())
	}
	wantMessage := string(canonicalMessage(mustDecodeHex(t, nonce), http.MethodPost, "/api/v1/sync", body))
	if string(verifier.message) != wantMessage {
		t.Fatalf("signed message mismatch\n got: %q\nwant: %q", string(verifier.message), wantMessage)
	}
	assertCount(t, store, "server_users", 1)
	assertCount(t, store, "server_preferences", 1)
	assertCount(t, store, "server_habits", 1)
	assertCount(t, store, "server_habit_days", 1)
	assertCount(t, store, "server_sessions", 1)
	assertCount(t, store, "server_session_rounds", 1)

	nonce = issueChallenge(t, handler, userID)
	deleteBody := []byte(`{"user_id_hash":"` + userID + `"}`)
	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/v1/account", bytes.NewReader(deleteBody))
	deleteReq.Header.Set("Content-Type", "application/json")
	deleteReq.Header.Set("X-Inbe-User", userID)
	deleteReq.Header.Set("X-Inbe-Signature", signature)
	deleteRes := httptest.NewRecorder()
	handler.ServeHTTP(deleteRes, deleteReq)
	if deleteRes.Code != http.StatusOK {
		t.Fatalf("delete status = %d body=%s", deleteRes.Code, deleteRes.Body.String())
	}
	wantMessage = string(canonicalMessage(mustDecodeHex(t, nonce), http.MethodDelete, "/api/v1/account", deleteBody))
	if string(verifier.message) != wantMessage {
		t.Fatalf("delete signed message mismatch\n got: %q\nwant: %q", string(verifier.message), wantMessage)
	}
	assertCount(t, store, "server_users", 0)
	assertCount(t, store, "server_preferences", 0)
	assertCount(t, store, "server_habits", 0)
	assertCount(t, store, "server_habit_days", 0)
	assertCount(t, store, "server_sessions", 0)
	assertCount(t, store, "server_session_rounds", 0)
}

func issueChallenge(t *testing.T, handler http.Handler, userID string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sync/challenge?user_id="+userID, nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("challenge status = %d body=%s", res.Code, res.Body.String())
	}
	var payload ChallengeResponse
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Nonce) != 64 {
		t.Fatalf("nonce length = %d", len(payload.Nonce))
	}
	return payload.Nonce
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func assertCount(t *testing.T, store *Store, table string, want int) {
	t.Helper()
	var got int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("%s count = %d, want %d", table, got, want)
	}
}
