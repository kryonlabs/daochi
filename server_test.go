package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
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
	dbPath := filepath.Join(t.TempDir(), "ksync-test.db")
	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	verifier := &recordingVerifier{}
	server := NewServer(Config{
		Addr:         "127.0.0.1:0",
		BaseURL:      "http://127.0.0.1:0",
		DBPath:       dbPath,
		ChallengeTTL: time.Minute,
		TokenTTL:     time.Hour,
		TokenSecret:  bytes.Repeat([]byte{0x99}, 32),
		MaxBodyBytes: 1 << 20,
	}, store, verifier)
	t.Cleanup(func() { _ = store.Close() })
	return server, store, verifier
}

type testIdentity struct {
	PublicKey []byte
	UserID    string
	Signature string
	Token     string
}

func newTestIdentity(t *testing.T, target any, seed byte) testIdentity {
	return newTestIdentityAt(t, target, "", seed)
}

func newTestIdentityAt(t *testing.T, target any, baseURL string, seed byte) testIdentity {
	t.Helper()
	publicKey := bytes.Repeat([]byte{seed}, mlDSA44PublicKeySize)
	userHash := sha256.Sum256(publicKey)
	userID := hex.EncodeToString(userHash[:])
	signature := hex.EncodeToString(bytes.Repeat([]byte{seed + 0x11}, mlDSA44SignatureSize))
	token, _ := loginWithKey(t, target, baseURL, userID, hex.EncodeToString(publicKey), signature)
	return testIdentity{PublicKey: publicKey, UserID: userID, Signature: signature, Token: token}
}

func TestDocsEndpoints(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()

	root := httptest.NewRecorder()
	handler.ServeHTTP(root, httptest.NewRequest(http.MethodGet, "/", nil))
	if root.Code != http.StatusOK {
		t.Fatalf("root status = %d", root.Code)
	}
	if !strings.Contains(root.Body.String(), "Ksync Sync API") {
		t.Fatalf("root docs missing title: %s", root.Body.String())
	}
	for _, want := range []string{"Users", "Storage", "/"} {
		if !strings.Contains(root.Body.String(), want) {
			t.Fatalf("root docs missing %q: %s", want, root.Body.String())
		}
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

	token, loginNonce := loginWithKey(t, handler, "", userID, hex.EncodeToString(publicKey), signature)
	body := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-1","habits":[{"id":"habit-1","name":"Meditate","color_r":1,"color_g":2,"color_b":3,"sync_mode":1,"sync_activity":2,"counter_enabled":1,"sort_order":0,"deleted_at":0,"updated_at":"2026-06-19T00:00:00Z"}],"habit_days":[{"habit_id":"habit-1","local_date":20260619,"completed":true,"count":4,"updated_at":"2026-06-19T00:00:00Z"}],"sessions":[{"id":"session-1","started_at":"2026-06-19T00:00:00Z","local_date":20260619,"topic":"0","activity":1,"source":"test","rounds_hash":"abc","deleted_at":0,"updated_at":"2026-06-19T00:00:00Z","rounds":[{"round_index":0,"breaths":0,"hold_seconds":60}]}]}`)
	res := syncWithBody(t, handler, "", userID, token, body)
	if res.Code != http.StatusOK {
		t.Fatalf("sync status = %d body=%s", res.Code, res.Body.String())
	}
	var syncResponse SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &syncResponse); err != nil {
		t.Fatal(err)
	}
	if syncResponse.Status != "ok" || syncResponse.ServerVersion == 0 ||
		len(syncResponse.Changes.Habits) != 1 || len(syncResponse.Changes.HabitDays) != 1 ||
		len(syncResponse.Changes.Sessions) != 1 {
		t.Fatalf("unexpected sync changes: %#v", syncResponse)
	}
	if syncResponse.Changes.HabitDays[0].Count != 4 {
		t.Fatalf("habit day count = %d, want 4", syncResponse.Changes.HabitDays[0].Count)
	}
	if syncResponse.Changes.Habits[0].CounterEnabled != 1 {
		t.Fatalf("habit counter_enabled = %d, want 1", syncResponse.Changes.Habits[0].CounterEnabled)
	}
	loginBody := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-1","public_key":"` + hex.EncodeToString(publicKey) + `"}`)
	wantMessage := string(canonicalMessage(mustDecodeHex(t, loginNonce), http.MethodPost, "/api/v1/sync/login", loginBody))
	if string(verifier.message) != wantMessage {
		t.Fatalf("signed message mismatch\n got: %q\nwant: %q", string(verifier.message), wantMessage)
	}
	assertCount(t, store, "server_users", 1)
	assertCount(t, store, "server_habits", 1)
	assertCount(t, store, "server_habit_days", 1)
	assertCount(t, store, "server_sessions", 1)
	assertCount(t, store, "server_session_rounds", 1)

	nonce := issueChallenge(t, handler, "", userID)
	deleteBody := []byte(`{"user_id_hash":"` + userID + `"}`)
	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/v1/account", bytes.NewReader(deleteBody))
	deleteReq.Header.Set("Content-Type", "application/json")
	deleteReq.Header.Set("X-Ksync-User", userID)
	deleteReq.Header.Set("X-Ksync-Signature", signature)
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
	assertCount(t, store, "server_habits", 0)
	assertCount(t, store, "server_habit_days", 0)
	assertCount(t, store, "server_sessions", 0)
	assertCount(t, store, "server_session_rounds", 0)
}

func TestLegacyInbeSignedLoginDeleteAndBearerHeaders(t *testing.T) {
	server, store, verifier := testServer(t)
	handler := server.Routes()
	publicKey := bytes.Repeat([]byte{0x45}, mlDSA44PublicKeySize)
	userHash := sha256.Sum256(publicKey)
	userID := hex.EncodeToString(userHash[:])
	signature := hex.EncodeToString(bytes.Repeat([]byte{0x55}, mlDSA44SignatureSize))

	loginNonce := issueChallenge(t, handler, "", userID)
	loginBody := []byte(`{"user_id_hash":"` + userID + `","client_id":"legacy-inbe-client","public_key":"` + hex.EncodeToString(publicKey) + `"}`)
	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/sync/login", bytes.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginReq.Header.Set("X-Inbe-User", userID)
	loginReq.Header.Set("X-Inbe-Signature", signature)
	loginRes := httptest.NewRecorder()
	handler.ServeHTTP(loginRes, loginReq)
	if loginRes.Code != http.StatusOK {
		t.Fatalf("legacy login status = %d body=%s", loginRes.Code, loginRes.Body.String())
	}
	wantMessage := string(canonicalMessageWithContext("inbe-sync-v1", mustDecodeHex(t, loginNonce), http.MethodPost, "/api/v1/sync/login", loginBody))
	if string(verifier.message) != wantMessage {
		t.Fatalf("legacy login signed message mismatch\n got: %q\nwant: %q", string(verifier.message), wantMessage)
	}
	var login LoginResponse
	if err := json.Unmarshal(loginRes.Body.Bytes(), &login); err != nil {
		t.Fatal(err)
	}
	if login.AuthToken == "" {
		t.Fatal("missing legacy auth token")
	}

	syncBody := []byte(`{"user_id_hash":"` + userID + `","client_id":"legacy-inbe-client","since_server_version":0}`)
	syncReq := httptest.NewRequest(http.MethodPost, "/api/v1/sync", bytes.NewReader(syncBody))
	syncReq.Header.Set("Content-Type", "application/json")
	syncReq.Header.Set("X-Inbe-User", userID)
	syncReq.Header.Set("Authorization", "Bearer "+login.AuthToken)
	syncRes := httptest.NewRecorder()
	handler.ServeHTTP(syncRes, syncReq)
	if syncRes.Code != http.StatusOK {
		t.Fatalf("legacy sync status = %d body=%s", syncRes.Code, syncRes.Body.String())
	}

	deleteNonce := issueChallenge(t, handler, "", userID)
	deleteBody := []byte(`{"user_id_hash":"` + userID + `"}`)
	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/v1/account", bytes.NewReader(deleteBody))
	deleteReq.Header.Set("Content-Type", "application/json")
	deleteReq.Header.Set("X-Inbe-User", userID)
	deleteReq.Header.Set("X-Inbe-Signature", signature)
	deleteRes := httptest.NewRecorder()
	handler.ServeHTTP(deleteRes, deleteReq)
	if deleteRes.Code != http.StatusOK {
		t.Fatalf("legacy delete status = %d body=%s", deleteRes.Code, deleteRes.Body.String())
	}
	wantMessage = string(canonicalMessageWithContext("inbe-sync-v1", mustDecodeHex(t, deleteNonce), http.MethodDelete, "/api/v1/account", deleteBody))
	if string(verifier.message) != wantMessage {
		t.Fatalf("legacy delete signed message mismatch\n got: %q\nwant: %q", string(verifier.message), wantMessage)
	}
	assertCount(t, store, "server_users", 0)
}

func TestSyncReturnsRemoteChangesSinceVersion(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	publicKey := bytes.Repeat([]byte{0x42}, mlDSA44PublicKeySize)
	userHash := sha256.Sum256(publicKey)
	userID := hex.EncodeToString(userHash[:])
	signature := hex.EncodeToString(bytes.Repeat([]byte{0x33}, mlDSA44SignatureSize))

	token, _ := loginWithKey(t, handler, "", userID, hex.EncodeToString(publicKey), signature)
	body := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-1","habits":[{"id":"habit-1","name":"Meditate","color_r":1,"color_g":2,"color_b":3,"sync_mode":1,"sync_activity":2,"counter_enabled":1,"sort_order":0,"deleted_at":0,"updated_at":"2026-06-19T00:00:00Z"}],"habit_days":[{"habit_id":"habit-1","local_date":20260619,"completed":true,"count":4,"updated_at":"2026-06-19T00:00:00Z"}]}`)
	res := syncWithBody(t, handler, "", userID, token, body)
	var first SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if first.ServerVersion == 0 || len(first.Changes.Habits) != 1 || len(first.Changes.HabitDays) != 1 {
		t.Fatalf("first changes = %#v", first)
	}
	if first.Changes.HabitDays[0].Count != 4 {
		t.Fatalf("first habit day count = %d, want 4", first.Changes.HabitDays[0].Count)
	}
	if first.Changes.Habits[0].CounterEnabled != 1 {
		t.Fatalf("first habit counter_enabled = %d, want 1", first.Changes.Habits[0].CounterEnabled)
	}

	emptyBody := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-1","since_server_version":` + strconv.FormatInt(first.ServerVersion, 10) + `}`)
	res = syncWithBody(t, handler, "", userID, token, emptyBody)
	var payload SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Changes.Habits) != 0 || len(payload.Changes.HabitDays) != 0 {
		t.Fatalf("expected no changes after latest version: %#v", payload.Changes)
	}

	updateBody := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-1","since_server_version":` + strconv.FormatInt(first.ServerVersion, 10) + `,"habit_days":[{"habit_id":"habit-1","local_date":20260619,"completed":true,"count":7,"updated_at":"2026-06-19T00:01:00Z"}]}`)
	res = syncWithBody(t, handler, "", userID, token, updateBody)
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Changes.Habits) != 0 || len(payload.Changes.HabitDays) != 1 ||
		!payload.Changes.HabitDays[0].Completed ||
		payload.Changes.HabitDays[0].Count != 7 {
		t.Fatalf("expected only changed habit day: %#v", payload.Changes)
	}
}

func TestHashMismatchRequiresFullSnapshotAfterApplyingUpload(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	publicKey := bytes.Repeat([]byte{0x49}, mlDSA44PublicKeySize)
	userHash := sha256.Sum256(publicKey)
	userID := hex.EncodeToString(userHash[:])
	signature := hex.EncodeToString(bytes.Repeat([]byte{0x5a}, mlDSA44SignatureSize))
	habit1ID := "00000000-0000-4000-8000-000000000001"
	habit2ID := "00000000-0000-4000-8000-000000000002"

	token, _ := loginWithKey(t, handler, "", userID, hex.EncodeToString(publicKey), signature)
	body := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-1","habits":[{"id":"` + habit1ID + `","name":"Remote","color_r":1,"color_g":2,"color_b":3,"sync_mode":1,"sync_activity":2,"counter_enabled":1,"sort_order":0,"deleted_at":0,"updated_at":"2026-06-19T00:00:00Z"}]}`)
	res := syncWithBody(t, handler, "", userID, token, body)
	var first SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if first.ServerStateHash == "" || !first.ChangesComplete || first.FullSnapshotRequired {
		t.Fatalf("first response = %#v", first)
	}

	staleHash := strings.Repeat("0", 64)
	staleBody := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-2","since_server_version":` + strconv.FormatInt(first.ServerVersion, 10) + `,"last_server_state_hash":"` + staleHash + `","habits":[{"id":"` + habit2ID + `","name":"Local stale upload","color_r":9,"color_g":9,"color_b":9,"sync_mode":1,"sync_activity":2,"counter_enabled":0,"sort_order":1,"deleted_at":0,"updated_at":"2026-06-20T00:00:00Z"}]}`)
	res = syncWithBody(t, handler, "", userID, token, staleBody)
	var mismatch SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &mismatch); err != nil {
		t.Fatal(err)
	}
	if !mismatch.FullSnapshotRequired || mismatch.ChangesComplete || mismatch.Applied.Habits != 1 {
		t.Fatalf("mismatch response = %#v", mismatch)
	}
	if len(mismatch.Changes.Habits) != 2 {
		t.Fatalf("mismatch snapshot = %#v", mismatch.Changes.Habits)
	}

	fullBody := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-3","since_server_version":0}`)
	res = syncWithBody(t, handler, "", userID, token, fullBody)
	var full SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &full); err != nil {
		t.Fatal(err)
	}
	if len(full.Changes.Habits) != 2 {
		t.Fatalf("stale upload was not applied: %#v", full.Changes.Habits)
	}

	replaceBody := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-2","since_server_version":0,"full_sync_requested":true,"habits":[{"id":"` + habit2ID + `","name":"Local replacement","color_r":9,"color_g":9,"color_b":9,"sync_mode":1,"sync_activity":2,"counter_enabled":0,"sort_order":1,"deleted_at":0,"updated_at":"2026-06-20T00:00:00Z"}]}`)
	res = syncWithBody(t, handler, "", userID, token, replaceBody)
	var replaced SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &replaced); err != nil {
		t.Fatal(err)
	}
	if replaced.FullSnapshotRequired || !replaced.ChangesComplete || replaced.Applied.Habits != 1 {
		t.Fatalf("replace response = %#v", replaced)
	}
	fullBody = []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-3","since_server_version":0}`)
	res = syncWithBody(t, handler, "", userID, token, fullBody)
	if err := json.Unmarshal(res.Body.Bytes(), &full); err != nil {
		t.Fatal(err)
	}
	if len(full.Changes.Habits) != 1 || full.Changes.Habits[0].ID != habit2ID {
		t.Fatalf("remote was not replaced: %#v", full.Changes.Habits)
	}
}

func TestSyncV2AppliesOpsIdempotentlyAndReturnsRemoteOps(t *testing.T) {
	server, store, _ := testServer(t)
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x61)

	opPayload := `{"id":"habit-v2","name":"Yoga","color_r":1,"color_g":2,"color_b":3,"sync_mode":1,"sync_activity":4,"counter_enabled":0,"sort_order":0,"deleted_at":0,"updated_at":"2026-06-24T10:00:00Z"}`
	body := []byte(`{"protocol_version":2,"user_id_hash":"` + identity.UserID + `","client_id":"client-a","client_clock":0,"ops":[{"op_id":"client-a:1","client_id":"client-a","seq":1,"entity_type":"habit","entity_id":"habit-v2","op_type":"upsert","payload":` + opPayload + `,"created_at":"2026-06-24T10:00:00Z"}]}`)
	res := syncWithBody(t, handler, "", identity.UserID, identity.Token, body)
	if res.Code != http.StatusOK {
		t.Fatalf("v2 sync status = %d body=%s", res.Code, res.Body.String())
	}
	var first SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if first.ProtocolVersion != 2 || first.ServerClock == 0 || len(first.AcceptedOps) != 1 || first.AcceptedOps[0] != "client-a:1" {
		t.Fatalf("first v2 response = %#v", first)
	}
	assertCount(t, store, "server_habits", 1)
	assertCount(t, store, "server_sync_ops", 1)

	res = syncWithBody(t, handler, "", identity.UserID, identity.Token, body)
	if res.Code != http.StatusOK {
		t.Fatalf("duplicate v2 sync status = %d body=%s", res.Code, res.Body.String())
	}
	var duplicate SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &duplicate); err != nil {
		t.Fatal(err)
	}
	if len(duplicate.AcceptedOps) != 1 || duplicate.AcceptedOps[0] != "client-a:1" {
		t.Fatalf("duplicate accepted ops = %#v", duplicate.AcceptedOps)
	}
	assertCount(t, store, "server_habits", 1)
	assertCount(t, store, "server_sync_ops", 1)

	readBody := []byte(`{"protocol_version":2,"user_id_hash":"` + identity.UserID + `","client_id":"client-b","client_clock":0}`)
	res = syncWithBody(t, handler, "", identity.UserID, identity.Token, readBody)
	if res.Code != http.StatusOK {
		t.Fatalf("v2 read status = %d body=%s", res.Code, res.Body.String())
	}
	var read SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &read); err != nil {
		t.Fatal(err)
	}
	if len(read.Ops) != 1 || read.Ops[0].OpID != "client-a:1" || read.Ops[0].EntityType != "habit" {
		t.Fatalf("remote ops = %#v", read.Ops)
	}
	if len(read.Changes.Habits) != 1 || !isCanonicalHabitID(read.Changes.Habits[0].ID) {
		t.Fatalf("materialized changes = %#v", read.Changes.Habits)
	}
}

func TestAccountExportReturnsOnlyAuthenticatedAccountData(t *testing.T) {
	server, store, _ := testServer(t)
	handler := server.Routes()
	alice := newTestIdentity(t, handler, 0x65)
	bob := newTestIdentity(t, handler, 0x66)

	aliceBody := []byte(`{"protocol_version":2,"user_id_hash":"` + alice.UserID + `","client_id":"client-a","client_clock":0,"habits":[{"id":"alice-habit","name":"Alice Habit","color_r":1,"color_g":2,"color_b":3,"sync_mode":1,"sync_activity":4,"counter_enabled":0,"sort_order":0,"deleted_at":0,"updated_at":"2026-06-24T10:00:00Z"}],"ops":[{"op_id":"client-a:1","client_id":"client-a","seq":1,"entity_type":"artifact","entity_id":"odd-one","op_type":"upsert","payload":{"kind":"weird"},"created_at":"2026-06-24T10:00:00Z"}]}`)
	if res := syncWithBody(t, handler, "", alice.UserID, alice.Token, aliceBody); res.Code != http.StatusOK {
		t.Fatalf("alice sync status = %d body=%s", res.Code, res.Body.String())
	}
	if _, err := store.db.Exec(`INSERT INTO server_social_snapshots(user_id_hash,kind,json,updated_at,server_version) VALUES(?1,'friends.list','{"friends":[]}','2026-06-24T10:00:00Z',99)`, alice.UserID); err != nil {
		t.Fatal(err)
	}
	bobBody := []byte(`{"user_id_hash":"` + bob.UserID + `","client_id":"client-b","habits":[{"id":"bob-habit","name":"Bob Habit","color_r":1,"color_g":2,"color_b":3,"sync_mode":1,"sync_activity":4,"counter_enabled":0,"sort_order":0,"deleted_at":0,"updated_at":"2026-06-24T10:00:00Z"}]}`)
	if res := syncWithBody(t, handler, "", bob.UserID, bob.Token, bobBody); res.Code != http.StatusOK {
		t.Fatalf("bob sync status = %d body=%s", res.Code, res.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/account/export", nil)
	req.Header.Set("Authorization", "Bearer "+alice.Token)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("export status = %d body=%s", res.Code, res.Body.String())
	}
	var payload AccountExportResponse
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.UserIDHash != alice.UserID {
		t.Fatalf("export user = %s, want %s", payload.UserIDHash, alice.UserID)
	}
	if len(payload.Tables["habits"]) != 1 {
		t.Fatalf("export habits = %#v", payload.Tables["habits"])
	}
	id, _ := payload.Tables["habits"][0]["id"].(string)
	if !isCanonicalHabitID(id) {
		t.Fatalf("export habits = %#v", payload.Tables["habits"])
	}
	if len(payload.Tables["social_snapshots"]) != 1 {
		t.Fatalf("export social cache = %#v", payload.Tables["social_snapshots"])
	}
	if len(payload.Tables["sync_ops"]) != 1 || payload.Tables["sync_ops"][0]["entity_type"] != "artifact" {
		t.Fatalf("export sync ops = %#v", payload.Tables["sync_ops"])
	}
	for _, row := range payload.Tables["habits"] {
		if row["id"] == "bob-habit" {
			t.Fatalf("export leaked bob data: %#v", payload.Tables["habits"])
		}
	}

	unauth := httptest.NewRecorder()
	handler.ServeHTTP(unauth, httptest.NewRequest(http.MethodGet, "/api/v1/account/export", nil))
	if unauth.Code != http.StatusUnauthorized {
		t.Fatalf("unauth export status = %d body=%s", unauth.Code, unauth.Body.String())
	}
}

func TestHabitDayZeroCountIncompleteIsSyncedState(t *testing.T) {
	server, store, _ := testServer(t)
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x64)

	createBody := []byte(`{"user_id_hash":"` + identity.UserID + `","client_id":"client-a","habits":[{"id":"push-ups","name":"Push Ups","color_r":1,"color_g":2,"color_b":3,"sync_mode":0,"sync_activity":0,"counter_enabled":0,"sort_order":0,"deleted_at":0,"updated_at":"2026-06-28T10:00:00Z"}],"habit_days":[{"habit_id":"push-ups","local_date":20260628,"completed":true,"count":1,"updated_at":"2026-06-28T10:00:00Z"}]}`)
	res := syncWithBody(t, handler, "", identity.UserID, identity.Token, createBody)
	if res.Code != http.StatusOK {
		t.Fatalf("create status = %d body=%s", res.Code, res.Body.String())
	}

	zeroBody := []byte(`{"user_id_hash":"` + identity.UserID + `","client_id":"client-b","since_server_version":0,"habit_days":[{"habit_id":"push-ups","local_date":20260628,"completed":false,"count":0,"updated_at":"2026-06-28T11:00:00Z"}]}`)
	res = syncWithBody(t, handler, "", identity.UserID, identity.Token, zeroBody)
	if res.Code != http.StatusOK {
		t.Fatalf("zero status = %d body=%s", res.Code, res.Body.String())
	}
	assertCount(t, store, "server_habit_days", 1)

	readBody := []byte(`{"user_id_hash":"` + identity.UserID + `","client_id":"client-c","since_server_version":0}`)
	res = syncWithBody(t, handler, "", identity.UserID, identity.Token, readBody)
	if res.Code != http.StatusOK {
		t.Fatalf("read status = %d body=%s", res.Code, res.Body.String())
	}
	var read SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &read); err != nil {
		t.Fatal(err)
	}
	if len(read.Changes.HabitDays) != 1 || read.Changes.HabitDays[0].Completed || read.Changes.HabitDays[0].Count != 0 {
		t.Fatalf("zero count habit day not preserved: %#v", read.Changes.HabitDays)
	}
}

func TestSyncV2DeleteHabitKeepsSessions(t *testing.T) {
	server, store, _ := testServer(t)
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x62)

	body := []byte(`{"protocol_version":2,"user_id_hash":"` + identity.UserID + `","client_id":"client-a","client_clock":0,"ops":[` +
		`{"op_id":"client-a:1","client_id":"client-a","seq":1,"entity_type":"habit","entity_id":"yoga","op_type":"upsert","payload":{"id":"yoga","name":"Yoga","color_r":1,"color_g":2,"color_b":3,"sync_mode":1,"sync_activity":4,"counter_enabled":0,"sort_order":0,"deleted_at":0,"updated_at":"2026-06-24T10:00:00Z"},"created_at":"2026-06-24T10:00:00Z"},` +
		`{"op_id":"client-a:2","client_id":"client-a","seq":2,"entity_type":"session","entity_id":"sun-1","op_type":"upsert","payload":{"id":"sun-1","started_at":"2026-06-24T10:05:00Z","local_date":20260624,"topic":"0","activity":2,"source":"sun","rounds_hash":"1","deleted_at":0,"updated_at":"2026-06-24T10:05:00Z","rounds":[{"round_index":0,"breaths":0,"hold_seconds":1}]},"created_at":"2026-06-24T10:05:00Z"},` +
		`{"op_id":"client-a:3","client_id":"client-a","seq":3,"entity_type":"habit","entity_id":"yoga","op_type":"delete","payload":{"id":"yoga","name":"Yoga","color_r":1,"color_g":2,"color_b":3,"sync_mode":1,"sync_activity":4,"counter_enabled":0,"sort_order":0,"deleted_at":1782300600,"updated_at":"2026-06-24T10:10:00Z"},"created_at":"2026-06-24T10:10:00Z"}` +
		`]}`)
	res := syncWithBody(t, handler, "", identity.UserID, identity.Token, body)
	if res.Code != http.StatusOK {
		t.Fatalf("v2 delete sync status = %d body=%s", res.Code, res.Body.String())
	}
	var response SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.AcceptedOps) != 3 {
		t.Fatalf("accepted delete ops = %#v", response.AcceptedOps)
	}
	assertCount(t, store, "server_sync_ops", 3)
	assertCount(t, store, "server_sessions", 1)
	assertCount(t, store, "server_session_rounds", 1)
	assertCount(t, store, "server_habits", 0)
}

func TestSyncV2CompactsAcknowledgedOpsAndFallsBackToSnapshot(t *testing.T) {
	server, store, _ := testServer(t)
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x63)

	writeBody := []byte(`{"protocol_version":2,"user_id_hash":"` + identity.UserID + `","client_id":"client-a","client_clock":0,"ops":[{"op_id":"client-a:1","client_id":"client-a","seq":1,"entity_type":"habit","entity_id":"habit-v2","op_type":"upsert","payload":{"id":"habit-v2","name":"Yoga","color_r":1,"color_g":2,"color_b":3,"sync_mode":1,"sync_activity":4,"counter_enabled":0,"sort_order":0,"deleted_at":0,"updated_at":"2026-06-24T10:00:00Z"},"created_at":"2026-06-24T10:00:00Z"}]}`)
	res := syncWithBody(t, handler, "", identity.UserID, identity.Token, writeBody)
	if res.Code != http.StatusOK {
		t.Fatalf("v2 write status = %d body=%s", res.Code, res.Body.String())
	}
	var written SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &written); err != nil {
		t.Fatal(err)
	}
	assertCount(t, store, "server_sync_ops", 1)

	readBody := []byte(`{"protocol_version":2,"user_id_hash":"` + identity.UserID + `","client_id":"client-b","client_clock":0}`)
	res = syncWithBody(t, handler, "", identity.UserID, identity.Token, readBody)
	if res.Code != http.StatusOK {
		t.Fatalf("v2 read status = %d body=%s", res.Code, res.Body.String())
	}
	var read SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &read); err != nil {
		t.Fatal(err)
	}
	if read.FullSnapshotRequired || len(read.Ops) != 1 || read.ServerClock == 0 {
		t.Fatalf("expected op replay before compaction: %#v", read)
	}
	assertCount(t, store, "server_sync_ops", 1)

	ackBody := []byte(`{"protocol_version":2,"user_id_hash":"` + identity.UserID + `","client_id":"client-b","client_clock":` + strconv.FormatInt(read.ServerClock, 10) + `}`)
	res = syncWithBody(t, handler, "", identity.UserID, identity.Token, ackBody)
	if res.Code != http.StatusOK {
		t.Fatalf("v2 ack status = %d body=%s", res.Code, res.Body.String())
	}
	assertCount(t, store, "server_sync_ops", 0)

	staleBody := []byte(`{"protocol_version":2,"user_id_hash":"` + identity.UserID + `","client_id":"client-c","client_clock":0,"ops":[{"op_id":"client-c:1","client_id":"client-c","seq":1,"entity_type":"habit","entity_id":"stale-local","op_type":"upsert","payload":{"id":"stale-local","name":"Stale local","color_r":9,"color_g":9,"color_b":9,"sync_mode":0,"sync_activity":0,"counter_enabled":0,"sort_order":1,"deleted_at":0,"updated_at":"2026-06-24T10:30:00Z"},"created_at":"2026-06-24T10:30:00Z"}]}`)
	res = syncWithBody(t, handler, "", identity.UserID, identity.Token, staleBody)
	if res.Code != http.StatusOK {
		t.Fatalf("v2 stale status = %d body=%s", res.Code, res.Body.String())
	}
	var stale SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &stale); err != nil {
		t.Fatal(err)
	}
	if !stale.FullSnapshotRequired || stale.ChangesComplete || len(stale.Ops) != 0 || stale.Applied.Habits != 1 {
		t.Fatalf("expected full snapshot fallback after accepting compacted-client ops: %#v", stale)
	}
	if len(stale.AcceptedOps) != 1 || stale.AcceptedOps[0] != "client-c:1" {
		t.Fatalf("stale accepted ops = %#v", stale.AcceptedOps)
	}
	if len(stale.Changes.Habits) != 2 || !isCanonicalHabitID(stale.Changes.Habits[0].ID) || !isCanonicalHabitID(stale.Changes.Habits[1].ID) {
		t.Fatalf("stale fallback snapshot = %#v", stale.Changes.Habits)
	}
	assertCount(t, store, "server_habits", 2)
	assertCount(t, store, "server_sync_ops", 1)
}

func TestProtocolV3CleanDataHidesDeletedAndOrphanHabits(t *testing.T) {
	server, store, _ := testServer(t)
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x73)

	body := []byte(`{"user_id_hash":"` + identity.UserID + `","client_id":"client-v2","habits":[{"id":"habit-8","name":"Old Habit","color_r":1,"color_g":2,"color_b":3,"sync_mode":1,"sync_activity":2,"counter_enabled":0,"sort_order":0,"deleted_at":0,"updated_at":"2026-06-24T10:00:00Z"}],"habit_days":[{"habit_id":"habit-8","local_date":20260624,"completed":true,"count":1,"updated_at":"2026-06-24T10:00:00Z"}]}`)
	if res := syncWithBody(t, handler, "", identity.UserID, identity.Token, body); res.Code != http.StatusOK {
		t.Fatalf("initial sync status=%d body=%s", res.Code, res.Body.String())
	}
	deleteBody := []byte(`{"user_id_hash":"` + identity.UserID + `","client_id":"client-v2","habits":[{"id":"habit-8","name":"Old Habit","color_r":1,"color_g":2,"color_b":3,"sync_mode":1,"sync_activity":2,"counter_enabled":0,"sort_order":0,"deleted_at":1782300600,"updated_at":"2026-06-24T10:10:00Z"}]}`)
	if res := syncWithBody(t, handler, "", identity.UserID, identity.Token, deleteBody); res.Code != http.StatusOK {
		t.Fatalf("delete sync status=%d body=%s", res.Code, res.Body.String())
	}
	if _, err := store.db.Exec(`INSERT INTO server_habit_days(user_id_hash,habit_id,local_date,completed,count,updated_at,server_version) VALUES(?1,'habit-8',20260625,0,0,'2026-06-25T00:00:00Z',999)`, identity.UserID); err != nil {
		t.Fatal(err)
	}

	readBody := []byte(`{"protocol_version":3,"user_id_hash":"` + identity.UserID + `","client_id":"client-v3","client_clock":0,"since_server_version":0}`)
	res := syncWithBody(t, handler, "", identity.UserID, identity.Token, readBody)
	if res.Code != http.StatusOK {
		t.Fatalf("v3 sync status=%d body=%s", res.Code, res.Body.String())
	}
	var decoded SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Data == nil {
		t.Fatalf("v3 response missing clean data: %s", res.Body.String())
	}
	if len(decoded.Data.Habits) != 0 || len(decoded.Data.HabitDays) != 0 {
		t.Fatalf("deleted/orphan habit leaked into v3 data: %#v %#v", decoded.Data.Habits, decoded.Data.HabitDays)
	}
	var orphanCount int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM server_habit_days WHERE user_id_hash=?1 AND habit_id='habit-8'`, identity.UserID).Scan(&orphanCount); err != nil {
		t.Fatal(err)
	}
	if orphanCount != 0 {
		t.Fatalf("orphan habit days were not cleaned: %d", orphanCount)
	}
}

func TestProtocolV3MaterializesLegacyOrphanHabitDays(t *testing.T) {
	server, store, _ := testServer(t)
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x75)

	if _, err := store.db.Exec(`INSERT INTO server_habit_days(user_id_hash,habit_id,local_date,completed,count,updated_at,server_version) VALUES(?1,'habit-8',20260625,1,2,'2026-06-25T00:00:00Z',9)`, identity.UserID); err != nil {
		t.Fatal(err)
	}

	readBody := []byte(`{"protocol_version":3,"user_id_hash":"` + identity.UserID + `","client_id":"client-v3","client_clock":0,"since_server_version":0}`)
	res := syncWithBody(t, handler, "", identity.UserID, identity.Token, readBody)
	if res.Code != http.StatusOK {
		t.Fatalf("v3 sync status=%d body=%s", res.Code, res.Body.String())
	}
	var decoded SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Data == nil || len(decoded.Data.Habits) != 1 {
		t.Fatalf("unexpected clean habits: %#v body=%s", decoded.Data, res.Body.String())
	}
	if !isCanonicalHabitID(decoded.Data.Habits[0].ID) || decoded.Data.Habits[0].Name != "Habit 8" {
		t.Fatalf("legacy habit was not materialized with a readable name: %#v", decoded.Data.Habits[0])
	}
	if len(decoded.Data.HabitDays) != 1 || decoded.Data.HabitDays[0].HabitID != decoded.Data.Habits[0].ID || decoded.Data.HabitDays[0].HabitName != "Habit 8" || decoded.Data.HabitDays[0].Count != 2 {
		t.Fatalf("legacy habit day was not attached to materialized habit: %#v", decoded.Data.HabitDays)
	}
	var habitRows int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM server_habits WHERE user_id_hash=?1 AND id=?2 AND name='Habit 8'`, identity.UserID, decoded.Data.Habits[0].ID).Scan(&habitRows); err != nil {
		t.Fatal(err)
	}
	if habitRows != 1 {
		t.Fatalf("materialized habit row missing: %d", habitRows)
	}
}

func TestProtocolV3AutoMigratesSunSalutationHabitIDAndKeepsLegacyClient(t *testing.T) {
	server, store, _ := testServer(t)
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x74)

	legacyBody := []byte(`{"protocol_version":2,"user_id_hash":"` + identity.UserID + `","client_id":"old-inbe","habits":[{"id":"yoga","name":"Yoga","color_r":1,"color_g":2,"color_b":3,"sync_mode":1,"sync_activity":4,"counter_enabled":0,"sort_order":0,"deleted_at":0,"updated_at":"2026-06-24T10:00:00Z"}],"habit_days":[{"habit_id":"yoga","local_date":20260624,"completed":true,"count":3,"updated_at":"2026-06-24T10:00:00Z"}]}`)
	if res := syncWithBody(t, handler, "", identity.UserID, identity.Token, legacyBody); res.Code != http.StatusOK {
		t.Fatalf("legacy sync status=%d body=%s", res.Code, res.Body.String())
	}
	readBody := []byte(`{"protocol_version":3,"user_id_hash":"` + identity.UserID + `","client_id":"new-inbe","client_clock":0,"since_server_version":0}`)
	res := syncWithBody(t, handler, "", identity.UserID, identity.Token, readBody)
	if res.Code != http.StatusOK {
		t.Fatalf("v3 sync status=%d body=%s", res.Code, res.Body.String())
	}
	var decoded SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Data == nil || len(decoded.Data.Habits) != 1 {
		t.Fatalf("unexpected clean habits: %#v body=%s", decoded.Data, res.Body.String())
	}
	if !isCanonicalHabitID(decoded.Data.Habits[0].ID) {
		t.Fatalf("habit was not canonicalized: %#v", decoded.Data.Habits[0])
	}
	if len(decoded.Data.HabitDays) != 1 || decoded.Data.HabitDays[0].HabitID != decoded.Data.Habits[0].ID || decoded.Data.HabitDays[0].HabitName != "Yoga" {
		t.Fatalf("habit day was not canonicalized with name: %#v", decoded.Data.HabitDays)
	}
	if len(decoded.LegacyClients) == 0 {
		t.Fatalf("legacy client diagnostics missing: clients=%#v", decoded.LegacyClients)
	}
	if decoded.UpgradeNotice != "" {
		t.Fatalf("dual-mode compatibility should not warn: %q", decoded.UpgradeNotice)
	}
	var oldRows int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM server_habits WHERE user_id_hash=?1 AND id='yoga'`, identity.UserID).Scan(&oldRows); err != nil {
		t.Fatal(err)
	}
	if oldRows != 0 {
		t.Fatalf("legacy yoga row still exists: %d", oldRows)
	}
}

func TestAccountAliasRegistersAndSyncs(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	publicKey := bytes.Repeat([]byte{0x4a}, mlDSA44PublicKeySize)
	userHash := sha256.Sum256(publicKey)
	userID := hex.EncodeToString(userHash[:])
	signature := hex.EncodeToString(bytes.Repeat([]byte{0x6a}, mlDSA44SignatureSize))

	token, _ := loginWithKey(t, handler, "", userID, hex.EncodeToString(publicKey), signature)
	aliasBody := []byte(`{"user_id_hash":"` + userID + `","alias":"@waozi"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/account/alias", bytes.NewReader(aliasBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Ksync-User", userID)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("alias status = %d body=%s", res.Code, res.Body.String())
	}
	var aliasRes AliasResponse
	if err := json.Unmarshal(res.Body.Bytes(), &aliasRes); err != nil {
		t.Fatal(err)
	}
	if aliasRes.Alias != "waozi" {
		t.Fatalf("alias = %q", aliasRes.Alias)
	}
	{
		nonce := issueChallenge(t, handler, "", userID)
		loginBody := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-1","public_key":"` + hex.EncodeToString(publicKey) + `"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sync/login", bytes.NewReader(loginBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Ksync-User", userID)
		req.Header.Set("X-Ksync-Signature", signature)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("login alias status = %d body=%s nonce=%s", res.Code, res.Body.String(), nonce)
		}
		var loginRes LoginResponse
		if err := json.Unmarshal(res.Body.Bytes(), &loginRes); err != nil {
			t.Fatal(err)
		}
		if loginRes.AccountAlias != "waozi" {
			t.Fatalf("login alias = %q", loginRes.AccountAlias)
		}
	}

	body := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-1","since_server_version":0}`)
	syncRes := syncWithBody(t, handler, "", userID, token, body)
	var payload SyncResponse
	if err := json.Unmarshal(syncRes.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.AccountAlias != "waozi" {
		t.Fatalf("sync alias = %q", payload.AccountAlias)
	}

	aliasBody = []byte(`{"user_id_hash":"` + userID + `","alias":"@new_waozi"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/account/alias", bytes.NewReader(aliasBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Ksync-User", userID)
	req.Header.Set("Authorization", "Bearer "+token)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("alias change status = %d body=%s", res.Code, res.Body.String())
	}
	if err := json.Unmarshal(res.Body.Bytes(), &aliasRes); err != nil {
		t.Fatal(err)
	}
	if aliasRes.Alias != "new_waozi" {
		t.Fatalf("changed alias = %q", aliasRes.Alias)
	}
	syncRes = syncWithBody(t, handler, "", userID, token, body)
	if err := json.Unmarshal(syncRes.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.AccountAlias != "new_waozi" {
		t.Fatalf("sync changed alias = %q", payload.AccountAlias)
	}

	otherKey := bytes.Repeat([]byte{0x4b}, mlDSA44PublicKeySize)
	otherHash := sha256.Sum256(otherKey)
	otherID := hex.EncodeToString(otherHash[:])
	otherToken, _ := loginWithKey(t, handler, "", otherID, hex.EncodeToString(otherKey), signature)
	aliasBody = []byte(`{"user_id_hash":"` + otherID + `","alias":"waozi"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/account/alias", bytes.NewReader(aliasBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Ksync-User", otherID)
	req.Header.Set("Authorization", "Bearer "+otherToken)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("old alias reuse status = %d body=%s", res.Code, res.Body.String())
	}
	aliasBody = []byte(`{"user_id_hash":"` + otherID + `","alias":"new_waozi"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/account/alias", bytes.NewReader(aliasBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Ksync-User", otherID)
	req.Header.Set("Authorization", "Bearer "+otherToken)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusConflict {
		t.Fatalf("alias conflict status = %d body=%s", res.Code, res.Body.String())
	}
}

func TestAccountProfileIconRegistersAndSyncs(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	publicKey := bytes.Repeat([]byte{0x5c}, mlDSA44PublicKeySize)
	userHash := sha256.Sum256(publicKey)
	userID := hex.EncodeToString(userHash[:])
	signature := hex.EncodeToString(bytes.Repeat([]byte{0x7c}, mlDSA44SignatureSize))

	token, _ := loginWithKey(t, handler, "", userID, hex.EncodeToString(publicKey), signature)
	iconBody := []byte(`{"user_id_hash":"` + userID + `","profile_icon":` + strconv.Itoa(ProfileIconLotus) + `}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/account/profile-icon", bytes.NewReader(iconBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Ksync-User", userID)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("profile icon status = %d body=%s", res.Code, res.Body.String())
	}
	var iconRes ProfileIconResponse
	if err := json.Unmarshal(res.Body.Bytes(), &iconRes); err != nil {
		t.Fatal(err)
	}
	if iconRes.ProfileIcon != ProfileIconLotus {
		t.Fatalf("profile icon = %d", iconRes.ProfileIcon)
	}

	{
		nonce := issueChallenge(t, handler, "", userID)
		loginBody := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-1","public_key":"` + hex.EncodeToString(publicKey) + `"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sync/login", bytes.NewReader(loginBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Ksync-User", userID)
		req.Header.Set("X-Ksync-Signature", signature)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("login profile icon status = %d body=%s nonce=%s", res.Code, res.Body.String(), nonce)
		}
		var loginRes LoginResponse
		if err := json.Unmarshal(res.Body.Bytes(), &loginRes); err != nil {
			t.Fatal(err)
		}
		if loginRes.ProfileIcon != ProfileIconLotus {
			t.Fatalf("login profile icon = %d", loginRes.ProfileIcon)
		}
	}

	body := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-1","since_server_version":0}`)
	syncRes := syncWithBody(t, handler, "", userID, token, body)
	var payload SyncResponse
	if err := json.Unmarshal(syncRes.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.ProfileIcon != ProfileIconLotus {
		t.Fatalf("sync profile icon = %d", payload.ProfileIcon)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/account/profile-icon", bytes.NewReader([]byte(`{"user_id_hash":"`+userID+`","profile_icon":99}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Ksync-User", userID)
	req.Header.Set("Authorization", "Bearer "+token)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("invalid profile icon status = %d body=%s", res.Code, res.Body.String())
	}
}

func TestFriendRequestsByAliasAndPublicID(t *testing.T) {
	server, store, _ := testServer(t)
	handler := server.Routes()
	alice := newTestIdentity(t, handler, 0x21)
	bob := newTestIdentity(t, handler, 0x22)
	carol := newTestIdentity(t, handler, 0x23)

	setAlias(t, handler, alice, "alice")
	setAlias(t, handler, bob, "bobby")

	res := friendJSONRequest(t, handler, http.MethodPost, "/api/v1/friends/requests", alice, []byte(`{"target":"@bobby"}`))
	if res.Code != http.StatusCreated {
		t.Fatalf("create by alias status = %d body=%s", res.Code, res.Body.String())
	}
	var created FriendRequestResponse
	if err := json.Unmarshal(res.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Request.RequesterUserID != alice.UserID || created.Request.TargetUserID != bob.UserID || created.Request.TargetAlias != "bobby" {
		t.Fatalf("unexpected created request: %#v", created.Request)
	}

	res = friendJSONRequest(t, handler, http.MethodGet, "/api/v1/friends/requests", bob, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("bob requests status = %d body=%s", res.Code, res.Body.String())
	}
	var pending FriendRequestsResponse
	if err := json.Unmarshal(res.Body.Bytes(), &pending); err != nil {
		t.Fatal(err)
	}
	if len(pending.Incoming) != 1 || pending.Incoming[0].RequesterAlias != "alice" || len(pending.Outgoing) != 0 {
		t.Fatalf("unexpected bob pending: %#v", pending)
	}

	res = friendJSONRequest(t, handler, http.MethodPost, "/api/v1/friends/requests/"+created.Request.ID+"/accept", alice, []byte(`{}`))
	if res.Code != http.StatusForbidden {
		t.Fatalf("requester accept status = %d body=%s", res.Code, res.Body.String())
	}
	res = friendJSONRequest(t, handler, http.MethodPost, "/api/v1/friends/requests/"+created.Request.ID+"/accept", bob, []byte(`{}`))
	if res.Code != http.StatusOK {
		t.Fatalf("target accept status = %d body=%s", res.Code, res.Body.String())
	}

	res = friendJSONRequest(t, handler, http.MethodGet, "/api/v1/friends", alice, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("alice friends status = %d body=%s", res.Code, res.Body.String())
	}
	var friends FriendsResponse
	if err := json.Unmarshal(res.Body.Bytes(), &friends); err != nil {
		t.Fatal(err)
	}
	if len(friends.Friends) != 1 || friends.Friends[0].UserIDHash != bob.UserID || friends.Friends[0].Alias != "bobby" {
		t.Fatalf("unexpected alice friends: %#v", friends)
	}

	res = friendJSONRequest(t, handler, http.MethodPost, "/api/v1/friends/requests", alice, []byte(`{"target":"`+bob.UserID+`"}`))
	if res.Code != http.StatusConflict {
		t.Fatalf("already friends status = %d body=%s", res.Code, res.Body.String())
	}
	res = friendJSONRequest(t, handler, http.MethodPost, "/api/v1/friends/requests", carol, []byte(`{"target":"`+alice.UserID+`"}`))
	if res.Code != http.StatusCreated {
		t.Fatalf("create by public id status = %d body=%s", res.Code, res.Body.String())
	}
	var outgoing FriendRequestResponse
	if err := json.Unmarshal(res.Body.Bytes(), &outgoing); err != nil {
		t.Fatal(err)
	}
	res = friendJSONRequest(t, handler, http.MethodPost, "/api/v1/friends/requests/"+outgoing.Request.ID+"/decline", carol, []byte(`{}`))
	if res.Code != http.StatusOK {
		t.Fatalf("requester cancel outgoing status = %d body=%s", res.Code, res.Body.String())
	}
	res = friendJSONRequest(t, handler, http.MethodGet, "/api/v1/friends/requests", alice, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("alice requests after cancel status = %d body=%s", res.Code, res.Body.String())
	}
	if err := json.Unmarshal(res.Body.Bytes(), &pending); err != nil {
		t.Fatal(err)
	}
	if len(pending.Incoming) != 0 || len(pending.Outgoing) != 0 {
		t.Fatalf("canceled outgoing request still visible: %#v", pending)
	}
	res = friendJSONRequest(t, handler, http.MethodPost, "/api/v1/friends/requests", alice, []byte(`{"target":"`+alice.UserID+`"}`))
	if res.Code != http.StatusConflict {
		t.Fatalf("self friend status = %d body=%s", res.Code, res.Body.String())
	}
	res = friendJSONRequest(t, handler, http.MethodPost, "/api/v1/friends/requests", alice, []byte(`{"target":"@missing_alias"}`))
	if res.Code != http.StatusNotFound {
		t.Fatalf("missing target status = %d body=%s", res.Code, res.Body.String())
	}

	assertCount(t, store, "server_friend_requests", 2)
	assertCount(t, store, "server_friendships", 1)
}

func TestFriendRequestsRejectMismatchedHeaderUser(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	alice := newTestIdentity(t, handler, 0x31)
	bob := newTestIdentity(t, handler, 0x32)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/friends/requests",
		bytes.NewReader([]byte(`{"target":"`+bob.UserID+`"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+alice.Token)
	req.Header.Set("X-Ksync-User", bob.UserID)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("mismatched friend user status = %d body=%s", res.Code, res.Body.String())
	}
}

func TestFriendDeclineAndStatsVisibility(t *testing.T) {
	server, store, _ := testServer(t)
	handler := server.Routes()
	alice := newTestIdentity(t, handler, 0x24)
	bob := newTestIdentity(t, handler, 0x25)
	carol := newTestIdentity(t, handler, 0x26)

	req := createFriendRequest(t, handler, alice, bob.UserID)
	res := friendJSONRequest(t, handler, http.MethodPost, "/api/v1/friends/requests/"+req.ID+"/decline", bob, []byte(`{}`))
	if res.Code != http.StatusOK {
		t.Fatalf("decline status = %d body=%s", res.Code, res.Body.String())
	}
	res = friendJSONRequest(t, handler, http.MethodPost, "/api/v1/friends/requests/"+req.ID+"/accept", bob, []byte(`{}`))
	if res.Code != http.StatusConflict {
		t.Fatalf("accept declined status = %d body=%s", res.Code, res.Body.String())
	}

	req = createFriendRequest(t, handler, alice, bob.UserID)
	res = friendJSONRequest(t, handler, http.MethodPost, "/api/v1/friends/requests/"+req.ID+"/accept", bob, []byte(`{}`))
	if res.Code != http.StatusOK {
		t.Fatalf("accept resent status = %d body=%s", res.Code, res.Body.String())
	}

	syncWithBody(t, handler, "", alice.UserID, alice.Token, []byte(`{"user_id_hash":"`+alice.UserID+`","client_id":"alice-stats","habits":[{"id":"whm","name":"WHM","color_r":1,"color_g":2,"color_b":3,"sync_mode":1,"sync_activity":1,"counter_enabled":0,"sort_order":0,"deleted_at":0,"updated_at":"2026-06-26T00:00:00Z"}],"habit_days":[{"habit_id":"whm","local_date":`+time.Now().UTC().Format("20060102")+`,"completed":true,"count":1,"updated_at":"2026-06-28T00:00:00Z"}],"sessions":[{"id":"alice-hold","started_at":"2026-06-28T00:00:00Z","local_date":`+time.Now().UTC().Format("20060102")+`,"topic":"0","activity":0,"source":"test","rounds_hash":"alice","deleted_at":0,"updated_at":"2026-06-28T00:00:00Z","rounds":[{"round_index":0,"breaths":0,"hold_seconds":82},{"round_index":1,"breaths":0,"hold_seconds":83}]}]}`))
	syncWithBody(t, handler, "", bob.UserID, bob.Token, []byte(`{"user_id_hash":"`+bob.UserID+`","client_id":"bob-stats","habits":[{"id":"whm","name":"WHM","color_r":1,"color_g":2,"color_b":3,"sync_mode":1,"sync_activity":1,"counter_enabled":0,"sort_order":0,"deleted_at":0,"updated_at":"2026-06-26T00:00:00Z"}],"habit_days":[{"habit_id":"whm","local_date":`+time.Now().UTC().Format("20060102")+`,"completed":true,"count":1,"updated_at":"2026-06-28T00:00:00Z"}]}`))
	syncWithBody(t, handler, "", carol.UserID, carol.Token, []byte(`{"user_id_hash":"`+carol.UserID+`","client_id":"carol-stats","habits":[{"id":"whm","name":"WHM","color_r":1,"color_g":2,"color_b":3,"sync_mode":1,"sync_activity":1,"counter_enabled":0,"sort_order":0,"deleted_at":0,"updated_at":"2026-06-26T00:00:00Z"}],"habit_days":[{"habit_id":"whm","local_date":`+time.Now().UTC().Format("20060102")+`,"completed":true,"count":1,"updated_at":"2026-06-28T00:00:00Z"}]}`))
	yesterdayDay := time.Now().UTC().AddDate(0, 0, -1)
	yesterdayDate := yesterdayDay.Year()*10000 + int(yesterdayDay.Month())*100 + yesterdayDay.Day()
	if _, err := store.db.Exec(`
	INSERT INTO server_leaderboard_stats(user_id_hash,app,practice,metric,source_version,value,label,local_date,updated_at)
	SELECT ?1,'inbe','whm','avg_hold',server_version,0,'0',0,'stale'
	FROM server_sync_state WHERE user_id_hash=?1`, alice.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`
	INSERT INTO server_leaderboard_stats(user_id_hash,app,practice,metric,source_version,calc_version,value,label,local_date,updated_at)
	SELECT ?1,'inbe','whm','streak',server_version,?2,9,'9',?3,'stale'
	FROM server_sync_state WHERE user_id_hash=?1`,
		alice.UserID, leaderboardStatsCalcVersion, yesterdayDate); err != nil {
		t.Fatal(err)
	}

	res = friendJSONRequest(t, handler, http.MethodGet, "/api/v1/friends/stats?app=inbe&practice=whm&metric=streak", bob, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("bob stats status = %d body=%s", res.Code, res.Body.String())
	}
	var stats FriendStatsResponse
	if err := json.Unmarshal(res.Body.Bytes(), &stats); err != nil {
		t.Fatal(err)
	}
	if len(stats.Rows) != 2 || stats.Rows[0].UserIDHash != alice.UserID || stats.Rows[0].Value != 1 ||
		stats.Rows[1].UserIDHash != bob.UserID || stats.Rows[1].Value != 0 {
		t.Fatalf("unexpected friend stats: %#v", stats.Rows)
	}
	for _, row := range stats.Rows {
		if row.UserIDHash == carol.UserID {
			t.Fatalf("non-friend carol leaked into stats: %#v", stats.Rows)
		}
	}

	res = friendJSONRequest(t, handler, http.MethodGet, "/api/v1/friends/stats?app=inbe&practice=whm&metric=avg_hold", bob, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("avg hold stats status = %d body=%s", res.Code, res.Body.String())
	}
	if err := json.Unmarshal(res.Body.Bytes(), &stats); err != nil {
		t.Fatal(err)
	}
	if len(stats.Rows) != 2 || stats.Rows[0].UserIDHash != alice.UserID || stats.Rows[0].Value != 82.5 ||
		stats.Rows[1].UserIDHash != bob.UserID || stats.Rows[1].Value != 0 {
		t.Fatalf("unexpected avg hold stats: %#v", stats.Rows)
	}

	twoDaysAgo := time.Now().UTC().AddDate(0, 0, -2).Format(time.RFC3339)
	threeDaysAgo := time.Now().UTC().AddDate(0, 0, -3).Format(time.RFC3339)
	syncWithBody(t, handler, "", bob.UserID, bob.Token, []byte(`{"user_id_hash":"`+bob.UserID+`","client_id":"bob-past-meditation-stats","meditation_logs":[{"id":"bob-past-meditation-1","session_id":"bob-past-meditation-session-1","duration_seconds":600,"completed_at":"`+twoDaysAgo+`"},{"id":"bob-past-meditation-2","session_id":"bob-past-meditation-session-2","duration_seconds":600,"completed_at":"`+threeDaysAgo+`"}]}`))

	res = friendJSONRequest(t, handler, http.MethodGet, "/api/v1/friends/stats?app=inbe&practice=meditation&metric=streak", bob, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("meditation streak before meditation status = %d body=%s", res.Code, res.Body.String())
	}
	if err := json.Unmarshal(res.Body.Bytes(), &stats); err != nil {
		t.Fatal(err)
	}
	if len(stats.Rows) != 2 || stats.Rows[0].Value != 0 || stats.Rows[1].Value != 0 {
		t.Fatalf("whm or habit-only data leaked into meditation streak: %#v", stats.Rows)
	}

	yesterday := time.Now().UTC().AddDate(0, 0, -1).Format(time.RFC3339)
	syncWithBody(t, handler, "", alice.UserID, alice.Token, []byte(`{"user_id_hash":"`+alice.UserID+`","client_id":"alice-meditation-stats","sessions":[{"id":"alice-meditation-1","started_at":"2026-06-28T00:00:00Z","local_date":`+time.Now().UTC().Format("20060102")+`,"topic":"0","activity":1,"source":"test","rounds_hash":"meditation-1","deleted_at":0,"updated_at":"2026-06-28T00:00:00Z","rounds":[{"round_index":0,"breaths":0,"hold_seconds":600}]}],"meditation_logs":[{"id":"alice-meditation-log-1","session_id":"alice-meditation-log-session","duration_seconds":1200,"completed_at":"`+yesterday+`"}]}`))
	res = friendJSONRequest(t, handler, http.MethodGet, "/api/v1/friends/stats?app=inbe&practice=meditation&metric=streak", bob, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("meditation streak status = %d body=%s", res.Code, res.Body.String())
	}
	if err := json.Unmarshal(res.Body.Bytes(), &stats); err != nil {
		t.Fatal(err)
	}
	if len(stats.Rows) != 2 || stats.Rows[0].UserIDHash != alice.UserID || stats.Rows[0].Value != 2 ||
		stats.Rows[1].UserIDHash != bob.UserID || stats.Rows[1].Value != 0 {
		t.Fatalf("unexpected meditation streak stats: %#v", stats.Rows)
	}

	res = friendJSONRequest(t, handler, http.MethodGet, "/api/v1/friends/stats?app=inbe&practice=meditation&metric=avg_time", bob, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("avg time stats status = %d body=%s", res.Code, res.Body.String())
	}
	if err := json.Unmarshal(res.Body.Bytes(), &stats); err != nil {
		t.Fatal(err)
	}
	if len(stats.Rows) != 2 || stats.Rows[0].UserIDHash != alice.UserID || stats.Rows[0].Value != 900 ||
		stats.Rows[0].Label != "0:15" || stats.Rows[1].UserIDHash != bob.UserID || stats.Rows[1].Value != 600 ||
		stats.Rows[1].Label != "0:10" {
		t.Fatalf("unexpected avg time stats: %#v", stats.Rows)
	}

	syncWithBody(t, handler, "", alice.UserID, alice.Token, []byte(`{"user_id_hash":"`+alice.UserID+`","client_id":"alice-meditation-stats","sessions":[{"id":"alice-meditation-2","started_at":"2026-06-28T00:30:00Z","local_date":`+time.Now().UTC().Format("20060102")+`,"topic":"0","activity":1,"source":"test","rounds_hash":"meditation-2","deleted_at":0,"updated_at":"2026-06-28T00:30:00Z","rounds":[{"round_index":0,"breaths":0,"hold_seconds":1800}]}]}`))
	res = friendJSONRequest(t, handler, http.MethodGet, "/api/v1/friends/stats?app=inbe&practice=meditation&metric=avg_time", bob, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("recomputed avg time stats status = %d body=%s", res.Code, res.Body.String())
	}
	if err := json.Unmarshal(res.Body.Bytes(), &stats); err != nil {
		t.Fatal(err)
	}
	if len(stats.Rows) != 2 || stats.Rows[0].UserIDHash != alice.UserID || stats.Rows[0].Value != 1200 ||
		stats.Rows[0].Label != "0:20" {
		t.Fatalf("avg time cache was not refreshed after source data changed: %#v", stats.Rows)
	}

	res = friendJSONRequest(t, handler, http.MethodGet, "/api/v1/friends/stats?app=inbe&practice=sun_salutation&metric=avg_hold", bob, nil)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("sun avg hold should be rejected, status = %d body=%s", res.Code, res.Body.String())
	}

	res = friendJSONRequest(t, handler, http.MethodDelete, "/api/v1/friends/"+alice.UserID, bob, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("remove status = %d body=%s", res.Code, res.Body.String())
	}
	res = friendJSONRequest(t, handler, http.MethodGet, "/api/v1/friends/stats?app=inbe&practice=whm&metric=streak", bob, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("post-remove stats status = %d body=%s", res.Code, res.Body.String())
	}
	if err := json.Unmarshal(res.Body.Bytes(), &stats); err != nil {
		t.Fatal(err)
	}
	if len(stats.Rows) != 1 || stats.Rows[0].UserIDHash != bob.UserID {
		t.Fatalf("removed friend still visible: %#v", stats.Rows)
	}
	req = createFriendRequest(t, handler, alice, bob.UserID)
	if req.Status != "pending" || req.RequesterUserID != alice.UserID || req.TargetUserID != bob.UserID {
		t.Fatalf("new friend request after unfriend mismatch: %#v", req)
	}
}

func TestSocialCacheIsServerOwnedAndSynced(t *testing.T) {
	server, store, _ := testServer(t)
	handler := server.Routes()
	alice := newTestIdentity(t, handler, 0x27)
	bob := newTestIdentity(t, handler, 0x28)

	req := createFriendRequest(t, handler, alice, bob.UserID)
	res := friendJSONRequest(t, handler, http.MethodPost, "/api/v1/friends/requests/"+req.ID+"/accept", bob, []byte(`{}`))
	if res.Code != http.StatusOK {
		t.Fatalf("accept status = %d body=%s", res.Code, res.Body.String())
	}

	upload := []byte(`{"protocol_version":2,"user_id_hash":"` + alice.UserID + `","client_id":"test-client-social","social_cache":[{"kind":"friends.list","json":{"friends":[{"user_id_hash":"hacked"}]},"updated_at":"2026-06-28T00:00:00Z"}]}`)
	raw := httptest.NewRequest(http.MethodPost, "/api/v1/sync", bytes.NewReader(upload))
	raw.Header.Set("Content-Type", "application/json")
	raw.Header.Set("X-Ksync-User", alice.UserID)
	raw.Header.Set("Authorization", "Bearer "+alice.Token)
	rejected := httptest.NewRecorder()
	handler.ServeHTTP(rejected, raw)
	if rejected.Code == http.StatusOK {
		t.Fatalf("client social cache upload accepted: %s", rejected.Body.String())
	}
	assertCount(t, store, "server_social_snapshots", 0)

	res = friendJSONRequest(t, handler, http.MethodGet, "/api/v1/friends", alice, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("friends status = %d body=%s", res.Code, res.Body.String())
	}
	assertCount(t, store, "server_social_snapshots", 1)

	syncBody := []byte(`{"protocol_version":2,"user_id_hash":"` + alice.UserID + `","client_id":"test-client-social","since_server_version":0}`)
	res = syncWithBody(t, handler, "", alice.UserID, alice.Token, syncBody)
	var synced SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &synced); err != nil {
		t.Fatal(err)
	}
	if len(synced.Changes.SocialCache) != 1 ||
		synced.Changes.SocialCache[0].Kind != "friends.list" ||
		!bytes.Contains(synced.Changes.SocialCache[0].JSON, []byte(bob.UserID)) ||
		bytes.Contains(synced.Changes.SocialCache[0].JSON, []byte("hacked")) {
		t.Fatalf("unexpected synced social cache: %#v", synced.Changes.SocialCache)
	}
}

func TestCrossAccountSyncIsolation(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	alice := newTestIdentity(t, handler, 0x51)
	bob := newTestIdentity(t, handler, 0x52)

	aliceBody := []byte(`{"user_id_hash":"` + alice.UserID + `","client_id":"alice-client","habits":[{"id":"shared-id","name":"Alice habit","color_r":1,"color_g":2,"color_b":3,"sync_mode":1,"sync_activity":2,"counter_enabled":0,"sort_order":0,"deleted_at":0,"updated_at":"2026-06-19T00:00:00Z"}],"habit_days":[{"habit_id":"shared-id","local_date":20260619,"completed":true,"count":1,"updated_at":"2026-06-19T00:00:00Z"}],"sessions":[{"id":"shared-session","started_at":"2026-06-19T00:00:00Z","local_date":20260619,"topic":"0","activity":1,"source":"test","rounds_hash":"a","deleted_at":0,"updated_at":"2026-06-19T00:00:00Z","rounds":[{"round_index":0,"breaths":10,"hold_seconds":20}]}],"meditation_logs":[{"id":"shared-log","session_id":"alice-session","duration_seconds":60,"completed_at":"2026-06-19T00:00:00Z"}]}`)
	syncWithBody(t, handler, "", alice.UserID, alice.Token, aliceBody)

	bobBody := []byte(`{"user_id_hash":"` + bob.UserID + `","client_id":"bob-client","since_server_version":0}`)
	res := syncWithBody(t, handler, "", bob.UserID, bob.Token, bobBody)
	var bobSync SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &bobSync); err != nil {
		t.Fatal(err)
	}
	if len(bobSync.Changes.Habits) != 0 || len(bobSync.Changes.HabitDays) != 0 ||
		len(bobSync.Changes.Sessions) != 0 || len(bobSync.Changes.MeditationLogs) != 0 {
		t.Fatalf("bob received alice data: %#v", bobSync.Changes)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sync", bytes.NewReader(aliceBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Ksync-User", alice.UserID)
	req.Header.Set("Authorization", "Bearer "+bob.Token)
	mismatch := httptest.NewRecorder()
	handler.ServeHTTP(mismatch, req)
	if mismatch.Code != http.StatusUnauthorized {
		t.Fatalf("bob token for alice sync status = %d body=%s", mismatch.Code, mismatch.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/sync", bytes.NewReader(bobBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Ksync-User", bob.UserID)
	req.Header.Set("Authorization", "Bearer "+alice.Token)
	mismatch = httptest.NewRecorder()
	handler.ServeHTTP(mismatch, req)
	if mismatch.Code != http.StatusUnauthorized {
		t.Fatalf("alice token for bob sync status = %d body=%s", mismatch.Code, mismatch.Body.String())
	}
}

func TestMeditationLogsAreScopedPerUser(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	alice := newTestIdentity(t, handler, 0x61)
	bob := newTestIdentity(t, handler, 0x62)

	aliceBody := []byte(`{"user_id_hash":"` + alice.UserID + `","client_id":"alice-client","meditation_logs":[{"id":"same-log","session_id":"alice-session","duration_seconds":60,"completed_at":"2026-06-19T00:00:00Z"}]}`)
	bobBody := []byte(`{"user_id_hash":"` + bob.UserID + `","client_id":"bob-client","meditation_logs":[{"id":"same-log","session_id":"bob-session","duration_seconds":120,"completed_at":"2026-06-20T00:00:00Z"}]}`)
	res := syncWithBody(t, handler, "", alice.UserID, alice.Token, aliceBody)
	var aliceWrite SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &aliceWrite); err != nil {
		t.Fatal(err)
	}
	if aliceWrite.Applied.MeditationLogs != 1 {
		t.Fatalf("alice applied meditation logs = %d", aliceWrite.Applied.MeditationLogs)
	}
	res = syncWithBody(t, handler, "", bob.UserID, bob.Token, bobBody)
	var bobWrite SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &bobWrite); err != nil {
		t.Fatal(err)
	}
	if bobWrite.Applied.MeditationLogs != 1 {
		t.Fatalf("bob applied meditation logs = %d", bobWrite.Applied.MeditationLogs)
	}

	res = syncWithBody(t, handler, "", alice.UserID, alice.Token, []byte(`{"user_id_hash":"`+alice.UserID+`","client_id":"alice-reader","since_server_version":0}`))
	var aliceRead SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &aliceRead); err != nil {
		t.Fatal(err)
	}
	res = syncWithBody(t, handler, "", bob.UserID, bob.Token, []byte(`{"user_id_hash":"`+bob.UserID+`","client_id":"bob-reader","since_server_version":0}`))
	var bobRead SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &bobRead); err != nil {
		t.Fatal(err)
	}
	if len(aliceRead.Changes.MeditationLogs) != 1 || aliceRead.Changes.MeditationLogs[0].DurationSeconds != 60 {
		t.Fatalf("alice meditation logs = %#v", aliceRead.Changes.MeditationLogs)
	}
	if len(bobRead.Changes.MeditationLogs) != 1 || bobRead.Changes.MeditationLogs[0].DurationSeconds != 120 {
		t.Fatalf("bob meditation logs = %#v", bobRead.Changes.MeditationLogs)
	}
}

func TestMigrateMeditationLogsToPerUserPrimaryKey(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "old-ksync.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
CREATE TABLE server_users (
	user_id_hash TEXT PRIMARY KEY,
	public_key BLOB NOT NULL,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE server_meditation_logs (
	id TEXT PRIMARY KEY,
	user_id_hash TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	session_id TEXT NOT NULL,
	duration_seconds INTEGER NOT NULL DEFAULT 0,
	completed_at TEXT NOT NULL,
	server_version INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);`)
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	rows, err := store.db.Query(`PRAGMA table_info(server_meditation_logs)`)
	if err != nil {
		t.Fatal(err)
	}
	userIDPK := 0
	idPK := 0
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var defaultValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if name == "user_id_hash" {
			userIDPK = pk
		}
		if name == "id" {
			idPK = pk
		}
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if userIDPK != 1 || idPK != 2 {
		t.Fatalf("meditation log primary key user_id_hash=%d id=%d", userIDPK, idPK)
	}
}

func TestAliasRejectsCrossAccountAndMissingAccount(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	alice := newTestIdentity(t, handler, 0x71)
	bob := newTestIdentity(t, handler, 0x72)

	aliasBody := []byte(`{"user_id_hash":"` + alice.UserID + `","alias":"alice_alias"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/account/alias", bytes.NewReader(aliasBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Ksync-User", alice.UserID)
	req.Header.Set("Authorization", "Bearer "+bob.Token)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("bob token for alice alias status = %d body=%s", res.Code, res.Body.String())
	}

	missingUser := strings.Repeat("a", 64)
	missingToken, err := issueAuthToken(server.cfg.TokenSecret, missingUser, server.cfg.TokenTTL)
	if err != nil {
		t.Fatal(err)
	}
	aliasBody = []byte(`{"user_id_hash":"` + missingUser + `","alias":"missing_alias"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/account/alias", bytes.NewReader(aliasBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Ksync-User", missingUser)
	req.Header.Set("Authorization", "Bearer "+missingToken)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusNotFound {
		t.Fatalf("missing account alias status = %d body=%s", res.Code, res.Body.String())
	}
}

func TestSyncReturnsRecoveredHabitForOrphanHabitDays(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	publicKey := bytes.Repeat([]byte{0x42}, mlDSA44PublicKeySize)
	userHash := sha256.Sum256(publicKey)
	userID := hex.EncodeToString(userHash[:])
	signature := hex.EncodeToString(bytes.Repeat([]byte{0x33}, mlDSA44SignatureSize))
	habitID := "00000000-0000-4000-8000-000000000002"

	token, _ := loginWithKey(t, handler, "", userID, hex.EncodeToString(publicKey), signature)
	body := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-1","habit_days":[{"habit_id":"` + habitID + `","local_date":20260619,"completed":true,"count":1,"updated_at":"2026-06-19T00:00:00Z"}]}`)
	res := syncWithBody(t, handler, "", userID, token, body)
	var payload SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Changes.Habits) != 1 || payload.Changes.Habits[0].ID != habitID ||
		payload.Changes.Habits[0].Name != "Recovered "+habitID {
		t.Fatalf("recovered habits = %#v", payload.Changes.Habits)
	}
	if len(payload.Changes.HabitDays) != 1 || payload.Changes.HabitDays[0].HabitID != habitID {
		t.Fatalf("habit day changes = %#v", payload.Changes.HabitDays)
	}

	emptyBody := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-1","since_server_version":` + strconv.FormatInt(payload.ServerVersion, 10) + `}`)
	res = syncWithBody(t, handler, "", userID, token, emptyBody)
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Changes.Habits) != 0 || len(payload.Changes.HabitDays) != 0 {
		t.Fatalf("expected no repeated recovered changes: %#v", payload.Changes)
	}
}

func TestSyncAppliesLaterZeroHabitDay(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	publicKey := bytes.Repeat([]byte{0x44}, mlDSA44PublicKeySize)
	userHash := sha256.Sum256(publicKey)
	userID := hex.EncodeToString(userHash[:])
	signature := hex.EncodeToString(bytes.Repeat([]byte{0x55}, mlDSA44SignatureSize))

	token, _ := loginWithKey(t, handler, "", userID, hex.EncodeToString(publicKey), signature)
	body := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-1","habit_days":[{"habit_id":"habit-2","local_date":20260619,"completed":true,"count":1,"updated_at":"2026-06-19T00:00:00Z"}]}`)
	res := syncWithBody(t, handler, "", userID, token, body)
	var payload SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	zeroBody := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-2","since_server_version":` + strconv.FormatInt(payload.ServerVersion, 10) + `,"habit_days":[{"habit_id":"habit-2","local_date":20260619,"completed":false,"count":0,"updated_at":"2026-06-20T00:00:00Z"}]}`)
	res = syncWithBody(t, handler, "", userID, token, zeroBody)
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	fullBody := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-3","since_server_version":0}`)
	res = syncWithBody(t, handler, "", userID, token, fullBody)
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Changes.HabitDays) != 1 || payload.Changes.HabitDays[0].Completed || payload.Changes.HabitDays[0].Count != 0 {
		t.Fatalf("habit day zero state was not snapshotted: %#v", payload.Changes.HabitDays)
	}
}

func TestSyncAppliesEqualTimestampZeroHabitDay(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	publicKey := bytes.Repeat([]byte{0x45}, mlDSA44PublicKeySize)
	userHash := sha256.Sum256(publicKey)
	userID := hex.EncodeToString(userHash[:])
	signature := hex.EncodeToString(bytes.Repeat([]byte{0x56}, mlDSA44SignatureSize))

	token, _ := loginWithKey(t, handler, "", userID, hex.EncodeToString(publicKey), signature)
	body := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-1","habit_days":[{"habit_id":"habit-2","local_date":20260619,"completed":true,"count":1,"updated_at":"2026-06-19T00:00:00Z"}]}`)
	res := syncWithBody(t, handler, "", userID, token, body)
	var payload SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	zeroBody := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-2","since_server_version":` + strconv.FormatInt(payload.ServerVersion, 10) + `,"habit_days":[{"habit_id":"habit-2","local_date":20260619,"completed":false,"count":0,"updated_at":"2026-06-19T00:00:00Z"}]}`)
	res = syncWithBody(t, handler, "", userID, token, zeroBody)
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	fullBody := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-3","since_server_version":0}`)
	res = syncWithBody(t, handler, "", userID, token, fullBody)
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Changes.HabitDays) != 1 || payload.Changes.HabitDays[0].Completed || payload.Changes.HabitDays[0].Count != 0 {
		t.Fatalf("equal timestamp zero state was not snapshotted: %#v", payload.Changes.HabitDays)
	}
}

func TestNormalDeletesRemoveServerData(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	publicKey := bytes.Repeat([]byte{0x47}, mlDSA44PublicKeySize)
	userHash := sha256.Sum256(publicKey)
	userID := hex.EncodeToString(userHash[:])
	signature := hex.EncodeToString(bytes.Repeat([]byte{0x58}, mlDSA44SignatureSize))

	token, _ := loginWithKey(t, handler, "", userID, hex.EncodeToString(publicKey), signature)
	body := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-1","habits":[{"id":"habit-1","name":"Meditate","color_r":1,"color_g":2,"color_b":3,"sync_mode":1,"sync_activity":2,"counter_enabled":1,"sort_order":0,"deleted_at":0,"updated_at":"2026-06-19T00:00:00Z"}],"habit_days":[{"habit_id":"habit-1","local_date":20260619,"completed":true,"count":4,"updated_at":"2026-06-19T00:00:00Z"}],"sessions":[{"id":"session-1","started_at":"2026-06-19T00:00:00Z","local_date":20260619,"topic":"0","activity":1,"source":"test","rounds_hash":"abc","deleted_at":0,"updated_at":"2026-06-19T00:00:00Z","rounds":[{"round_index":0,"breaths":0,"hold_seconds":60}]}]}`)
	res := syncWithBody(t, handler, "", userID, token, body)
	var payload SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}

	deletes := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-2","since_server_version":` + strconv.FormatInt(payload.ServerVersion, 10) + `,"habits":[{"id":"habit-1","name":"Meditate","color_r":1,"color_g":2,"color_b":3,"sync_mode":1,"sync_activity":2,"counter_enabled":1,"sort_order":0,"deleted_at":1782098659,"updated_at":"2026-06-20T00:00:00Z"}],"habit_days":[{"habit_id":"habit-1","local_date":20260619,"completed":false,"count":0,"updated_at":"2026-06-20T00:00:00Z"}],"sessions":[{"id":"session-1","started_at":"2026-06-19T00:00:00Z","local_date":20260619,"topic":"0","activity":1,"source":"test","rounds_hash":"abc","deleted_at":1782098659,"updated_at":"2026-06-20T00:00:00Z"}]}`)
	res = syncWithBody(t, handler, "", userID, token, deletes)
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Applied.Habits == 0 || payload.Applied.Sessions == 0 {
		t.Fatalf("delete commands were not applied: %#v", payload.Applied)
	}

	fullBody := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-3","since_server_version":0}`)
	res = syncWithBody(t, handler, "", userID, token, fullBody)
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Changes.Habits) != 0 || len(payload.Changes.HabitDays) != 0 || len(payload.Changes.Sessions) != 0 {
		t.Fatalf("deleted data was still snapshotted: %#v", payload.Changes)
	}
}

func TestBootstrapDoesNotApplyLocalTombstones(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	publicKey := bytes.Repeat([]byte{0x46}, mlDSA44PublicKeySize)
	userHash := sha256.Sum256(publicKey)
	userID := hex.EncodeToString(userHash[:])
	signature := hex.EncodeToString(bytes.Repeat([]byte{0x57}, mlDSA44SignatureSize))

	token, _ := loginWithKey(t, handler, "", userID, hex.EncodeToString(publicKey), signature)
	body := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-1","habits":[{"id":"habit-1","name":"Meditate","color_r":1,"color_g":2,"color_b":3,"sync_mode":1,"sync_activity":2,"counter_enabled":1,"sort_order":0,"deleted_at":0,"updated_at":"2026-06-19T00:00:00Z"}],"habit_days":[{"habit_id":"habit-1","local_date":20260619,"completed":true,"count":4,"updated_at":"2026-06-19T00:00:00Z"}],"sessions":[{"id":"session-1","started_at":"2026-06-19T00:00:00Z","local_date":20260619,"topic":"0","activity":1,"source":"test","rounds_hash":"abc","deleted_at":0,"updated_at":"2026-06-19T00:00:00Z","rounds":[{"round_index":0,"breaths":0,"hold_seconds":60}]}]}`)
	res := syncWithBody(t, handler, "", userID, token, body)
	var payload SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}

	bootstrapDeletes := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-2","since_server_version":0,"bootstrap":true,"habits":[{"id":"habit-1","name":"Meditate","color_r":1,"color_g":2,"color_b":3,"sync_mode":1,"sync_activity":2,"counter_enabled":1,"sort_order":0,"deleted_at":1782098659,"updated_at":"2026-06-20T00:00:00Z"}],"habit_days":[{"habit_id":"habit-1","local_date":20260619,"completed":false,"count":0,"updated_at":"2026-06-20T00:00:00Z"}],"sessions":[{"id":"session-1","started_at":"2026-06-19T00:00:00Z","local_date":20260619,"topic":"0","activity":1,"source":"test","rounds_hash":"abc","deleted_at":1782098659,"updated_at":"2026-06-20T00:00:00Z"}]}`)
	res = syncWithBody(t, handler, "", userID, token, bootstrapDeletes)
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}

	fullBody := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-3","since_server_version":0}`)
	res = syncWithBody(t, handler, "", userID, token, fullBody)
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Changes.Habits) != 1 || payload.Changes.Habits[0].DeletedAt != 0 {
		t.Fatalf("bootstrap tombstone erased habit: %#v", payload.Changes.Habits)
	}
	if len(payload.Changes.HabitDays) != 1 || !payload.Changes.HabitDays[0].Completed || payload.Changes.HabitDays[0].Count != 4 {
		t.Fatalf("bootstrap clear erased habit day: %#v", payload.Changes.HabitDays)
	}
	if len(payload.Changes.Sessions) != 1 || payload.Changes.Sessions[0].DeletedAt != 0 || len(payload.Changes.Sessions[0].Rounds) != 1 {
		t.Fatalf("bootstrap tombstone erased session: %#v", payload.Changes.Sessions)
	}
}

func TestBearerSyncCanRegisterUserWithPublicKey(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	publicKey := bytes.Repeat([]byte{0x48}, mlDSA44PublicKeySize)
	userHash := sha256.Sum256(publicKey)
	userID := hex.EncodeToString(userHash[:])
	token, err := issueAuthToken(server.cfg.TokenSecret, userID, server.cfg.TokenTTL)
	if err != nil {
		t.Fatal(err)
	}

	body := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-1","public_key":"` + hex.EncodeToString(publicKey) + `","since_server_version":0,"bootstrap":true,"habits":[{"id":"habit-1","name":"Meditate","color_r":1,"color_g":2,"color_b":3,"sync_mode":1,"sync_activity":2,"counter_enabled":1,"sort_order":0,"deleted_at":0,"updated_at":"2026-06-19T00:00:00Z"}]}`)
	res := syncWithBody(t, handler, "", userID, token, body)
	if res.Code != http.StatusOK {
		t.Fatalf("sync status = %d body=%s", res.Code, res.Body.String())
	}
	var payload SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Applied.Habits != 1 || len(payload.Changes.Habits) != 1 {
		t.Fatalf("registered sync response = %#v", payload)
	}
	if _, found, err := server.store.PublicKey(t.Context(), userID); err != nil || !found {
		t.Fatalf("registered public key found=%v err=%v", found, err)
	}
}

func TestSyncWebSocketReceivesChangeEvents(t *testing.T) {
	server, _, _ := testServer(t)
	ts := httptest.NewServer(server.Routes())
	t.Cleanup(ts.Close)

	publicKey := bytes.Repeat([]byte{0x42}, mlDSA44PublicKeySize)
	userHash := sha256.Sum256(publicKey)
	userID := hex.EncodeToString(userHash[:])
	signature := hex.EncodeToString(bytes.Repeat([]byte{0x33}, mlDSA44SignatureSize))

	token, _ := loginWithKey(t, ts.Client(), ts.URL, userID, hex.EncodeToString(publicKey), signature)
	reader, conn := openSyncWebSocket(t, ts.URL, token)
	t.Cleanup(func() { _ = conn.Close() })

	ready := readTestWebSocketEvent(t, reader)
	if ready.Type != "sync_ready" || ready.UserIDHash != userID {
		t.Fatalf("ready event = %#v", ready)
	}

	body := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-1","habits":[{"id":"habit-1","name":"Meditate","color_r":1,"color_g":2,"color_b":3,"sync_mode":1,"sync_activity":2,"sort_order":0,"deleted_at":0,"updated_at":"2026-06-19T00:00:00Z"}]}`)
	res := syncWithBody(t, ts.Client(), ts.URL, userID, token, body)
	var syncResponse SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &syncResponse); err != nil {
		t.Fatal(err)
	}
	changed := readTestWebSocketEvent(t, reader)
	if changed.Type != "sync_changed" || changed.UserIDHash != userID ||
		changed.ServerVersion != syncResponse.ServerVersion {
		t.Fatalf("changed event = %#v, sync response version = %d", changed, syncResponse.ServerVersion)
	}
}

func TestSyncWebSocketIsScopedToTokenUser(t *testing.T) {
	server, _, _ := testServer(t)
	ts := httptest.NewServer(server.Routes())
	t.Cleanup(ts.Close)

	alice := newTestIdentityAt(t, ts.Client(), ts.URL, 0x81)
	bob := newTestIdentityAt(t, ts.Client(), ts.URL, 0x82)
	reader, conn := openSyncWebSocket(t, ts.URL, alice.Token)
	t.Cleanup(func() { _ = conn.Close() })

	ready := readTestWebSocketEvent(t, reader)
	if ready.Type != "sync_ready" || ready.UserIDHash != alice.UserID {
		t.Fatalf("ready event = %#v", ready)
	}
	server.syncHub.mu.Lock()
	aliceSubs := len(server.syncHub.subs[alice.UserID])
	bobSubs := len(server.syncHub.subs[bob.UserID])
	server.syncHub.mu.Unlock()
	if aliceSubs != 1 || bobSubs != 0 {
		t.Fatalf("unexpected websocket subscriptions alice=%d bob=%d", aliceSubs, bobSubs)
	}

	bobBody := []byte(`{"user_id_hash":"` + bob.UserID + `","client_id":"bob-client","habits":[{"id":"bob-habit","name":"Bob habit","color_r":1,"color_g":2,"color_b":3,"sync_mode":1,"sync_activity":2,"sort_order":0,"deleted_at":0,"updated_at":"2026-06-19T00:00:00Z"}]}`)
	syncWithBody(t, ts.Client(), ts.URL, bob.UserID, bob.Token, bobBody)
	server.syncHub.mu.Lock()
	aliceSubs = len(server.syncHub.subs[alice.UserID])
	bobSubs = len(server.syncHub.subs[bob.UserID])
	server.syncHub.mu.Unlock()
	if aliceSubs != 1 || bobSubs != 0 {
		t.Fatalf("bob sync changed websocket subscriptions alice=%d bob=%d", aliceSubs, bobSubs)
	}

	aliceBody := []byte(`{"user_id_hash":"` + alice.UserID + `","client_id":"alice-client","habits":[{"id":"alice-habit","name":"Alice habit","color_r":1,"color_g":2,"color_b":3,"sync_mode":1,"sync_activity":2,"sort_order":0,"deleted_at":0,"updated_at":"2026-06-19T00:00:00Z"}]}`)
	res := syncWithBody(t, ts.Client(), ts.URL, alice.UserID, alice.Token, aliceBody)
	var syncResponse SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &syncResponse); err != nil {
		t.Fatal(err)
	}
	changed := readTestWebSocketEvent(t, reader)
	if changed.Type != "sync_changed" || changed.UserIDHash != alice.UserID ||
		changed.ServerVersion != syncResponse.ServerVersion {
		t.Fatalf("alice changed event = %#v, sync response version = %d", changed, syncResponse.ServerVersion)
	}
}

func TestSyncWebSocketRejectsQueryToken(t *testing.T) {
	server, _, _ := testServer(t)
	ts := httptest.NewServer(server.Routes())
	t.Cleanup(ts.Close)

	identity := newTestIdentityAt(t, ts.Client(), ts.URL, 0x83)
	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = conn.Write([]byte("GET /api/v1/sync/ws?token=" + identity.Token + " HTTP/1.1\r\n" +
		"Host: " + u.Host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "401") {
		t.Fatalf("websocket query-token status = %q", strings.TrimSpace(status))
	}
}

func TestSyncWebSocketAcceptsBearerSubprotocol(t *testing.T) {
	server, _, _ := testServer(t)
	ts := httptest.NewServer(server.Routes())
	t.Cleanup(ts.Close)

	identity := newTestIdentityAt(t, ts.Client(), ts.URL, 0x84)
	reader, conn := openSyncWebSocketWithProtocol(t, ts.URL, identity.Token)
	t.Cleanup(func() { _ = conn.Close() })

	ready := readTestWebSocketEvent(t, reader)
	if ready.Type != "sync_ready" || ready.UserIDHash != identity.UserID {
		t.Fatalf("ready event = %#v", ready)
	}
}

func TestSyncWebSocketAcceptsLegacyInbeBearerSubprotocol(t *testing.T) {
	server, _, _ := testServer(t)
	ts := httptest.NewServer(server.Routes())
	t.Cleanup(ts.Close)

	identity := newTestIdentityAt(t, ts.Client(), ts.URL, 0x85)
	reader, conn := openLegacyInbeSyncWebSocketWithProtocol(t, ts.URL, identity.Token)
	t.Cleanup(func() { _ = conn.Close() })

	ready := readTestWebSocketEvent(t, reader)
	if ready.Type != "sync_ready" || ready.UserIDHash != identity.UserID {
		t.Fatalf("ready event = %#v", ready)
	}
}

func TestParseExportedSyncKey(t *testing.T) {
	privateKey := bytes.Repeat([]byte{0x64}, mlDSA44PrivateKeySize)
	publicID := strings.Repeat("a", 64)
	for _, header := range []string{
		"ksync-account-key-v1",
		"lyra-account-key-v1",
		"account-key-v1",
		"inbe-sync-key-v1",
	} {
		keyText := header + "\nalgorithm=ML-DSA-44\npublic_id=" + publicID + "\nprivate_key=" + hex.EncodeToString(privateKey) + "\n"
		parsed, err := parseExportedSyncKey(keyText)
		if err != nil {
			t.Fatalf("%s parse: %v", header, err)
		}
		if parsed.PublicID != publicID {
			t.Fatalf("%s public id = %q", header, parsed.PublicID)
		}
		if !bytes.Equal(parsed.PrivateKey, privateKey) {
			t.Fatalf("%s parsed private key mismatch", header)
		}
	}
}

func TestDeleteWithKeyCORSPreflight(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/account/delete-with-key", nil)
	req.Header.Set("Origin", "https://inbe.waozi.xyz")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d", res.Code)
	}
	if got := res.Header().Get("Access-Control-Allow-Origin"); got != "https://inbe.waozi.xyz" {
		t.Fatalf("allow-origin = %q", got)
	}
}

func TestLocalhostCORSPreflight(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	for _, origin := range []string{
		"http://localhost:8080",
		"http://127.0.0.1:8080",
		"http://0.0.0.0:8080",
	} {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/sync/challenge", nil)
		req.Header.Set("Origin", origin)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusNoContent {
			t.Fatalf("%s preflight status = %d", origin, res.Code)
		}
		if got := res.Header().Get("Access-Control-Allow-Origin"); got != origin {
			t.Fatalf("%s allow-origin = %q", origin, got)
		}
	}
}

func TestChromeExtensionCORSPreflight(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	origin := "chrome-extension://lballhghblaenelehneigekpofgcaifa"
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/sync/challenge", nil)
	req.Header.Set("Origin", origin)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d", res.Code)
	}
	if got := res.Header().Get("Access-Control-Allow-Origin"); got != origin {
		t.Fatalf("allow-origin = %q", got)
	}
}

func TestUnknownOriginDoesNotGetCORS(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	for _, origin := range []string{
		"https://evil.example",
		"chrome-extension://bad",
		"chrome-extension://lballhghblaenelehneigekpofgcaifq",
	} {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/sync/challenge", nil)
		req.Header.Set("Origin", origin)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusNoContent {
			t.Fatalf("%s preflight status = %d", origin, res.Code)
		}
		if got := res.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Fatalf("%s allow-origin = %q", origin, got)
		}
	}
}

func TestDeleteWithExportedKeyDeletesAccount(t *testing.T) {
	publicKey, privateKey, err := generateMLDSA44Keypair()
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(filepath.Join(t.TempDir(), "ksync-delete-key-test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	verifier, err := NewVerifier()
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(Config{
		Addr:         "127.0.0.1:0",
		BaseURL:      "http://127.0.0.1:0",
		DBPath:       "test.db",
		ChallengeTTL: time.Minute,
		MaxBodyBytes: 1 << 20,
	}, store, verifier)
	handler := server.Routes()
	userHash := sha256.Sum256(publicKey)
	userID := hex.EncodeToString(userHash[:])
	_, err = store.ApplySync(t.Context(), SyncRequest{
		UserIDHash: userID,
		Habits: []Habit{{
			ID:        "delete-key-probe",
			Name:      "Delete key probe",
			UpdatedAt: "2026-06-19T00:00:00Z",
		}},
	}, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyText := "account-key-v1\nalgorithm=ML-DSA-44\npublic_id=" + userID + "\nprivate_key=" + hex.EncodeToString(privateKey) + "\n"
	body, err := json.Marshal(DeleteWithKeyRequest{UserIDHash: userID, ExportedKey: keyText})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/account/delete-with-key", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("delete-with-key status = %d body=%s", res.Code, res.Body.String())
	}
	assertCount(t, store, "server_users", 0)
}

func TestUkuProcessesVisibilityAndMutationAuth(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x72)
	other := newTestIdentity(t, handler, 0x73)

	publicBody := []byte(`{"user_id_hash":"` + identity.UserID + `","id":"public-process","type":"consent","title":"Where should we meet?","description":"Choose a place","visibility":"public","proposal_minutes":60,"voting_minutes":60,"negative_weight":3}`)
	res := ukuJSONRequest(t, handler, http.MethodPost, "/api/v1/processes", identity.UserID, identity.Token, publicBody)
	if res.Code != http.StatusCreated {
		t.Fatalf("create public status = %d body=%s", res.Code, res.Body.String())
	}
	var process UkuProcess
	if err := json.Unmarshal(res.Body.Bytes(), &process); err != nil {
		t.Fatal(err)
	}
	if process.ID != "public-process" || process.OwnerUserIDHash != identity.UserID || len(process.Proposals) != 2 {
		t.Fatalf("unexpected process: %#v", process)
	}

	privateBody := []byte(`{"user_id_hash":"` + identity.UserID + `","id":"secret-process","type":"consent","title":"Private vote","visibility":"unlisted","proposal_minutes":60,"voting_minutes":60,"negative_weight":3}`)
	res = ukuJSONRequest(t, handler, http.MethodPost, "/api/v1/processes", identity.UserID, identity.Token, privateBody)
	if res.Code != http.StatusCreated {
		t.Fatalf("create unlisted status = %d body=%s", res.Code, res.Body.String())
	}

	list := httptest.NewRecorder()
	handler.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/api/v1/processes", nil))
	if list.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s", list.Code, list.Body.String())
	}
	if !strings.Contains(list.Body.String(), "public-process") || strings.Contains(list.Body.String(), "secret-process") {
		t.Fatalf("public list leaked or missed process: %s", list.Body.String())
	}

	direct := httptest.NewRecorder()
	handler.ServeHTTP(direct, httptest.NewRequest(http.MethodGet, "/api/v1/processes/secret-process", nil))
	if direct.Code != http.StatusOK || !strings.Contains(direct.Body.String(), "Private vote") {
		t.Fatalf("direct unlisted status = %d body=%s", direct.Code, direct.Body.String())
	}

	unauth := ukuJSONRequest(t, handler, http.MethodPost, "/api/v1/processes/public-process/proposals", identity.UserID, "", []byte(`{"user_id_hash":"`+identity.UserID+`","id":"prop-1","title":"Cafe"}`))
	if unauth.Code != http.StatusUnauthorized {
		t.Fatalf("unauth proposal status = %d body=%s", unauth.Code, unauth.Body.String())
	}

	res = ukuJSONRequest(t, handler, http.MethodPost, "/api/v1/processes/public-process/proposals", identity.UserID, identity.Token, []byte(`{"user_id_hash":"`+identity.UserID+`","id":"prop-1","title":"Cafe","description":"Near transit"}`))
	if res.Code != http.StatusOK {
		t.Fatalf("proposal status = %d body=%s", res.Code, res.Body.String())
	}
	res = ukuJSONRequest(t, handler, http.MethodPost, "/api/v1/processes/public-process/votes", identity.UserID, identity.Token, []byte(`{"user_id_hash":"`+identity.UserID+`","display_name":"wao","scores":{"prop-1":3,"status-quo":-1},"reason":"Cafe is close and status quo is harder for transit."}`))
	if res.Code != http.StatusOK {
		t.Fatalf("vote status = %d body=%s", res.Code, res.Body.String())
	}
	if err := json.Unmarshal(res.Body.Bytes(), &process); err != nil {
		t.Fatal(err)
	}
	if len(process.Votes) != 1 || process.Votes[0].Scores["prop-1"] != 3 || process.Votes[0].Reason == "" {
		t.Fatalf("unexpected votes: %#v", process.Votes)
	}

	res = ukuJSONRequest(t, handler, http.MethodDelete, "/api/v1/processes/public-process/proposals/prop-1", other.UserID, other.Token, nil)
	if res.Code != http.StatusForbidden {
		t.Fatalf("other proposal delete status = %d body=%s", res.Code, res.Body.String())
	}
	res = ukuJSONRequest(t, handler, http.MethodDelete, "/api/v1/processes/public-process/proposals/prop-1", identity.UserID, identity.Token, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("proposal delete status = %d body=%s", res.Code, res.Body.String())
	}
	if err := json.Unmarshal(res.Body.Bytes(), &process); err != nil {
		t.Fatal(err)
	}
	for _, proposal := range process.Proposals {
		if proposal.ID == "prop-1" {
			t.Fatalf("deleted proposal still returned: %#v", process.Proposals)
		}
	}

	res = ukuJSONRequest(t, handler, http.MethodDelete, "/api/v1/processes/public-process", other.UserID, other.Token, nil)
	if res.Code != http.StatusForbidden {
		t.Fatalf("other process delete status = %d body=%s", res.Code, res.Body.String())
	}
	res = ukuJSONRequest(t, handler, http.MethodDelete, "/api/v1/processes/public-process", identity.UserID, identity.Token, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("process delete status = %d body=%s", res.Code, res.Body.String())
	}
	deleted := httptest.NewRecorder()
	handler.ServeHTTP(deleted, httptest.NewRequest(http.MethodGet, "/api/v1/processes/public-process", nil))
	if deleted.Code != http.StatusNotFound {
		t.Fatalf("deleted process get status = %d body=%s", deleted.Code, deleted.Body.String())
	}
}

func TestUkuDataCascadesOnAccountDelete(t *testing.T) {
	server, store, _ := testServer(t)
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x31)

	body := []byte(`{"user_id_hash":"` + identity.UserID + `","id":"delete-me","type":"consent","title":"Delete?","visibility":"public","proposal_minutes":60,"voting_minutes":60,"negative_weight":3}`)
	res := ukuJSONRequest(t, handler, http.MethodPost, "/api/v1/processes", identity.UserID, identity.Token, body)
	if res.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", res.Code, res.Body.String())
	}
	res = ukuJSONRequest(t, handler, http.MethodPost, "/api/v1/processes/delete-me/votes", identity.UserID, identity.Token, []byte(`{"user_id_hash":"`+identity.UserID+`","scores":{"status-quo":1},"reason":"Keep it simple."}`))
	if res.Code != http.StatusOK {
		t.Fatalf("vote status = %d body=%s", res.Code, res.Body.String())
	}
	assertCount(t, store, "uku_processes", 1)
	assertCount(t, store, "uku_proposals", 2)
	assertCount(t, store, "uku_votes", 1)

	issueChallenge(t, handler, "", identity.UserID)
	deleteBody := []byte(`{"user_id_hash":"` + identity.UserID + `"}`)
	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/v1/account", bytes.NewReader(deleteBody))
	deleteReq.Header.Set("Content-Type", "application/json")
	deleteReq.Header.Set("X-Ksync-User", identity.UserID)
	deleteReq.Header.Set("X-Ksync-Signature", identity.Signature)
	deleteRes := httptest.NewRecorder()
	handler.ServeHTTP(deleteRes, deleteReq)
	if deleteRes.Code != http.StatusOK {
		t.Fatalf("delete status = %d body=%s", deleteRes.Code, deleteRes.Body.String())
	}
	assertCount(t, store, "server_users", 0)
	assertCount(t, store, "uku_processes", 0)
	assertCount(t, store, "uku_proposals", 0)
	assertCount(t, store, "uku_votes", 0)
}

func TestUkuProcessMetadataVoteReasonAndExport(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x42)

	body := []byte(`{"user_id_hash":"` + identity.UserID + `","id":"consent-process","type":"consent","title":"Adopt the policy?","visibility":"public","proposal_minutes":60,"voting_minutes":60,"negative_weight":5,"quorum_percent":60}`)
	res := ukuJSONRequest(t, handler, http.MethodPost, "/api/v1/processes", identity.UserID, identity.Token, body)
	if res.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", res.Code, res.Body.String())
	}
	var process UkuProcess
	if err := json.Unmarshal(res.Body.Bytes(), &process); err != nil {
		t.Fatal(err)
	}
	if process.Type != "consent" || process.Title != "Adopt the policy?" || process.QuorumPercent != 60 || !process.RequireReason {
		t.Fatalf("unexpected process metadata: %#v", process)
	}

	res = ukuJSONRequest(t, handler, http.MethodPost, "/api/v1/processes/consent-process/votes", identity.UserID, identity.Token, []byte(`{"user_id_hash":"`+identity.UserID+`","scores":{"status-quo":1}}`))
	if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "vote reason required") {
		t.Fatalf("missing reason status = %d body=%s", res.Code, res.Body.String())
	}

	res = ukuJSONRequest(t, handler, http.MethodPost, "/api/v1/processes/consent-process/votes", identity.UserID, identity.Token, []byte(`{"user_id_hash":"`+identity.UserID+`","display_name":"wao","scores":{"status-quo":1},"reason":"This is acceptable."}`))
	if res.Code != http.StatusOK {
		t.Fatalf("vote status = %d body=%s", res.Code, res.Body.String())
	}
	if err := json.Unmarshal(res.Body.Bytes(), &process); err != nil {
		t.Fatal(err)
	}
	if len(process.Votes) != 1 || process.Votes[0].Reason != "This is acceptable." {
		t.Fatalf("unexpected vote reason: %#v", process.Votes)
	}

	update := []byte(`{"user_id_hash":"` + identity.UserID + `","quorum_percent":0,"outcome":"accepted","review_at":"2026-08-01"}`)
	res = ukuJSONRequest(t, handler, http.MethodPatch, "/api/v1/processes/consent-process", identity.UserID, identity.Token, update)
	if res.Code != http.StatusOK {
		t.Fatalf("update status = %d body=%s", res.Code, res.Body.String())
	}
	if err := json.Unmarshal(res.Body.Bytes(), &process); err != nil {
		t.Fatal(err)
	}
	if process.QuorumPercent != 0 || process.Outcome != "accepted" || process.ReviewAt != "2026-08-01" {
		t.Fatalf("unexpected update: %#v", process)
	}

	export := httptest.NewRecorder()
	handler.ServeHTTP(export, httptest.NewRequest(http.MethodGet, "/api/v1/processes/consent-process/export", nil))
	if export.Code != http.StatusOK {
		t.Fatalf("export status = %d body=%s", export.Code, export.Body.String())
	}
	var packet struct {
		PacketType string     `json:"packet_type"`
		Process    UkuProcess `json:"process"`
	}
	if err := json.Unmarshal(export.Body.Bytes(), &packet); err != nil {
		t.Fatal(err)
	}
	if packet.PacketType != "uku-process-packet-v1" || len(packet.Process.Audit) < 3 {
		t.Fatalf("unexpected export packet: %#v", packet)
	}
}

func TestUkuOptionProcessTypes(t *testing.T) {
	server, store, _ := testServer(t)
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x52)

	pollBody := []byte(`{"user_id_hash":"` + identity.UserID + `","id":"poll-process","type":"poll","title":"Pick a place","visibility":"public","voting_minutes":60,"options":[{"id":"cafe","label":"Cafe"},{"id":"park","label":"Park"}]}`)
	res := ukuJSONRequest(t, handler, http.MethodPost, "/api/v1/processes", identity.UserID, identity.Token, pollBody)
	if res.Code != http.StatusCreated {
		t.Fatalf("create poll status = %d body=%s", res.Code, res.Body.String())
	}
	var process UkuProcess
	if err := json.Unmarshal(res.Body.Bytes(), &process); err != nil {
		t.Fatal(err)
	}
	if process.Type != "poll" || len(process.Options) != 2 || len(process.Proposals) != 0 || process.ProposalMinutes != 0 || process.NegativeWeight != 0 {
		t.Fatalf("unexpected poll process: %#v", process)
	}

	res = ukuJSONRequest(t, handler, http.MethodPost, "/api/v1/processes/poll-process/proposals", identity.UserID, identity.Token, []byte(`{"user_id_hash":"`+identity.UserID+`","id":"prop-1","title":"Cafe"}`))
	if res.Code != http.StatusBadRequest {
		t.Fatalf("poll proposal status = %d body=%s", res.Code, res.Body.String())
	}
	res = ukuJSONRequest(t, handler, http.MethodPost, "/api/v1/processes/poll-process/votes", identity.UserID, identity.Token, []byte(`{"user_id_hash":"`+identity.UserID+`","scores":{"cafe":1,"park":0}}`))
	if res.Code != http.StatusOK {
		t.Fatalf("poll vote status = %d body=%s", res.Code, res.Body.String())
	}
	res = ukuJSONRequest(t, handler, http.MethodPost, "/api/v1/processes/poll-process/votes", identity.UserID, identity.Token, []byte(`{"user_id_hash":"`+identity.UserID+`","scores":{"prop-1":1}}`))
	if res.Code != http.StatusBadRequest {
		t.Fatalf("invalid poll vote status = %d body=%s", res.Code, res.Body.String())
	}

	rankedBody := []byte(`{"user_id_hash":"` + identity.UserID + `","id":"ranked-process","type":"ranked_choice","title":"Rank a place","visibility":"public","voting_minutes":60,"options":[{"id":"cafe","label":"Cafe"},{"id":"park","label":"Park"},{"id":"hall","label":"Hall"}]}`)
	res = ukuJSONRequest(t, handler, http.MethodPost, "/api/v1/processes", identity.UserID, identity.Token, rankedBody)
	if res.Code != http.StatusCreated {
		t.Fatalf("create ranked status = %d body=%s", res.Code, res.Body.String())
	}
	res = ukuJSONRequest(t, handler, http.MethodPost, "/api/v1/processes/ranked-process/votes", identity.UserID, identity.Token, []byte(`{"user_id_hash":"`+identity.UserID+`","scores":{"cafe":1,"park":1}}`))
	if res.Code != http.StatusBadRequest {
		t.Fatalf("duplicate rank status = %d body=%s", res.Code, res.Body.String())
	}
	res = ukuJSONRequest(t, handler, http.MethodPost, "/api/v1/processes/ranked-process/votes", identity.UserID, identity.Token, []byte(`{"user_id_hash":"`+identity.UserID+`","scores":{"cafe":1,"park":2,"hall":0}}`))
	if res.Code != http.StatusOK {
		t.Fatalf("ranked vote status = %d body=%s", res.Code, res.Body.String())
	}

	collectionBody := []byte(`{"user_id_hash":"` + identity.UserID + `","id":"collection-process","type":"collection","title":"Collect ideas","visibility":"public","proposal_minutes":60}`)
	res = ukuJSONRequest(t, handler, http.MethodPost, "/api/v1/processes", identity.UserID, identity.Token, collectionBody)
	if res.Code != http.StatusCreated {
		t.Fatalf("create collection status = %d body=%s", res.Code, res.Body.String())
	}
	res = ukuJSONRequest(t, handler, http.MethodPost, "/api/v1/processes/collection-process/votes", identity.UserID, identity.Token, []byte(`{"user_id_hash":"`+identity.UserID+`","scores":{"anything":1}}`))
	if res.Code != http.StatusBadRequest {
		t.Fatalf("collection vote status = %d body=%s", res.Code, res.Body.String())
	}
	assertCount(t, store, "uku_options", 5)
}

func issueChallenge(t *testing.T, target any, baseURL, userID string) string {
	t.Helper()
	req := newTestRequest(t, http.MethodGet, baseURL, "/api/v1/sync/challenge?user_id="+userID, nil)
	res := serveTestRequest(t, target, req)
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

func loginWithKey(t *testing.T, target any, baseURL, userID, publicKeyHex, signature string) (string, string) {
	t.Helper()
	nonce := issueChallenge(t, target, baseURL, userID)
	body := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-1","public_key":"` + publicKeyHex + `"}`)
	req := newTestRequest(t, http.MethodPost, baseURL, "/api/v1/sync/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Ksync-User", userID)
	req.Header.Set("X-Ksync-Signature", signature)
	res := serveTestRequest(t, target, req)
	if res.Code != http.StatusOK {
		t.Fatalf("login status = %d body=%s", res.Code, res.Body.String())
	}
	var payload LoginResponse
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.AuthToken == "" {
		t.Fatal("missing auth token")
	}
	return payload.AuthToken, nonce
}

func syncWithBody(t *testing.T, target any, baseURL, userID, token string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := newTestRequest(t, http.MethodPost, baseURL, "/api/v1/sync", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Ksync-User", userID)
	req.Header.Set("Authorization", "Bearer "+token)
	res := serveTestRequest(t, target, req)
	if res.Code != http.StatusOK {
		t.Fatalf("sync status = %d body=%s", res.Code, res.Body.String())
	}
	return res
}

func ukuJSONRequest(t *testing.T, target any, method, path, userID, token string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if userID != "" {
		req.Header.Set("X-Ksync-User", userID)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res := httptest.NewRecorder()
	target.(http.Handler).ServeHTTP(res, req)
	return res
}

func friendJSONRequest(t *testing.T, target any, method, path string, identity testIdentity, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+identity.Token)
	req.Header.Set("X-Ksync-User", identity.UserID)
	res := httptest.NewRecorder()
	target.(http.Handler).ServeHTTP(res, req)
	return res
}

func setAlias(t *testing.T, target any, identity testIdentity, alias string) {
	t.Helper()
	body := []byte(`{"user_id_hash":"` + identity.UserID + `","alias":"` + alias + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/account/alias", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Ksync-User", identity.UserID)
	req.Header.Set("Authorization", "Bearer "+identity.Token)
	res := httptest.NewRecorder()
	target.(http.Handler).ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("set alias status = %d body=%s", res.Code, res.Body.String())
	}
}

func createFriendRequest(t *testing.T, target any, requester testIdentity, targetRef string) FriendRequest {
	t.Helper()
	res := friendJSONRequest(t, target, http.MethodPost, "/api/v1/friends/requests", requester, []byte(`{"target":"`+targetRef+`"}`))
	if res.Code != http.StatusCreated {
		t.Fatalf("create friend request status = %d body=%s", res.Code, res.Body.String())
	}
	var payload FriendRequestResponse
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	return payload.Request
}

func putStats(t *testing.T, target any, identity testIdentity, body string) {
	t.Helper()
	res := friendJSONRequest(t, target, http.MethodPut, "/api/v1/profile/stats", identity, []byte(body))
	if res.Code != http.StatusOK {
		t.Fatalf("put stats status = %d body=%s", res.Code, res.Body.String())
	}
}

func newTestRequest(t *testing.T, method, baseURL, path string, body io.Reader) *http.Request {
	t.Helper()
	if baseURL == "" {
		return httptest.NewRequest(method, path, body)
	}
	req, err := http.NewRequest(method, baseURL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func serveTestRequest(t *testing.T, target any, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	res := httptest.NewRecorder()
	switch v := target.(type) {
	case http.Handler:
		v.ServeHTTP(res, req)
	case *http.Client:
		httpRes, err := v.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer httpRes.Body.Close()
		res.Code = httpRes.StatusCode
		res.HeaderMap = httpRes.Header
		if _, err := io.Copy(res.Body, httpRes.Body); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unsupported test target %T", target)
	}
	return res
}

func openSyncWebSocket(t *testing.T, baseURL, token string) (*bufio.Reader, net.Conn) {
	t.Helper()
	return openSyncWebSocketRaw(t, baseURL, "Authorization: Bearer "+token+"\r\n")
}

func openSyncWebSocketWithProtocol(t *testing.T, baseURL, token string) (*bufio.Reader, net.Conn) {
	t.Helper()
	return openSyncWebSocketRaw(t, baseURL, "Sec-WebSocket-Protocol: ksync-sync-v1, bearer."+token+"\r\n")
}

func openLegacyInbeSyncWebSocketWithProtocol(t *testing.T, baseURL, token string) (*bufio.Reader, net.Conn) {
	t.Helper()
	return openSyncWebSocketRaw(t, baseURL, "Sec-WebSocket-Protocol: inbe-sync-v1, bearer."+token+"\r\n")
}

func openSyncWebSocketRaw(t *testing.T, baseURL, extraHeaders string) (*bufio.Reader, net.Conn) {
	t.Helper()
	parsed, err := url.Parse(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	_, err = conn.Write([]byte("GET /api/v1/sync/ws HTTP/1.1\r\n" +
		"Host: " + parsed.Host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		extraHeaders + "\r\n"))
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	status, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if !strings.Contains(status, " 101 ") {
		conn.Close()
		t.Fatalf("websocket status = %q", strings.TrimSpace(status))
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			conn.Close()
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	return reader, conn
}

func readTestWebSocketEvent(t *testing.T, reader *bufio.Reader) syncEvent {
	t.Helper()
	_, payload, err := readWebSocketFrame(reader)
	if err != nil {
		t.Fatal(err)
	}
	var event syncEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		t.Fatal(err)
	}
	return event
}

func TestSyncRejectsSignedRequestWithoutBearer(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	publicKey := bytes.Repeat([]byte{0x42}, mlDSA44PublicKeySize)
	userHash := sha256.Sum256(publicKey)
	userID := hex.EncodeToString(userHash[:])

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sync", strings.NewReader(`{"user_id_hash":"`+userID+`","client_id":"test-client-1"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Ksync-User", userID)
	req.Header.Set("X-Ksync-Signature", hex.EncodeToString(bytes.Repeat([]byte{0x33}, mlDSA44SignatureSize)))
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("signed sync status = %d body=%s", res.Code, res.Body.String())
	}
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
