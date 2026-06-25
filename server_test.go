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
	dbPath := filepath.Join(t.TempDir(), "lyra-test.db")
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
	if !strings.Contains(root.Body.String(), "Lyra Sync API") {
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
	assertCount(t, store, "server_habits", 0)
	assertCount(t, store, "server_habit_days", 0)
	assertCount(t, store, "server_sessions", 0)
	assertCount(t, store, "server_session_rounds", 0)
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

func TestHashMismatchRequiresFullSnapshotWithoutApplyingUpload(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	publicKey := bytes.Repeat([]byte{0x49}, mlDSA44PublicKeySize)
	userHash := sha256.Sum256(publicKey)
	userID := hex.EncodeToString(userHash[:])
	signature := hex.EncodeToString(bytes.Repeat([]byte{0x5a}, mlDSA44SignatureSize))

	token, _ := loginWithKey(t, handler, "", userID, hex.EncodeToString(publicKey), signature)
	body := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-1","habits":[{"id":"habit-1","name":"Remote","color_r":1,"color_g":2,"color_b":3,"sync_mode":1,"sync_activity":2,"counter_enabled":1,"sort_order":0,"deleted_at":0,"updated_at":"2026-06-19T00:00:00Z"}]}`)
	res := syncWithBody(t, handler, "", userID, token, body)
	var first SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if first.ServerStateHash == "" || !first.ChangesComplete || first.FullSnapshotRequired {
		t.Fatalf("first response = %#v", first)
	}

	staleHash := strings.Repeat("0", 64)
	staleBody := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-2","since_server_version":` + strconv.FormatInt(first.ServerVersion, 10) + `,"last_server_state_hash":"` + staleHash + `","habits":[{"id":"habit-2","name":"Local stale upload","color_r":9,"color_g":9,"color_b":9,"sync_mode":1,"sync_activity":2,"counter_enabled":0,"sort_order":1,"deleted_at":0,"updated_at":"2026-06-20T00:00:00Z"}]}`)
	res = syncWithBody(t, handler, "", userID, token, staleBody)
	var mismatch SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &mismatch); err != nil {
		t.Fatal(err)
	}
	if !mismatch.FullSnapshotRequired || mismatch.ChangesComplete || mismatch.Applied.Habits != 0 {
		t.Fatalf("mismatch response = %#v", mismatch)
	}
	if len(mismatch.Changes.Habits) != 1 || mismatch.Changes.Habits[0].ID != "habit-1" {
		t.Fatalf("mismatch snapshot = %#v", mismatch.Changes.Habits)
	}

	fullBody := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-3","since_server_version":0}`)
	res = syncWithBody(t, handler, "", userID, token, fullBody)
	var full SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &full); err != nil {
		t.Fatal(err)
	}
	if len(full.Changes.Habits) != 1 || full.Changes.Habits[0].ID != "habit-1" {
		t.Fatalf("stale upload was applied: %#v", full.Changes.Habits)
	}

	replaceBody := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-2","since_server_version":0,"full_sync_requested":true,"habits":[{"id":"habit-2","name":"Local replacement","color_r":9,"color_g":9,"color_b":9,"sync_mode":1,"sync_activity":2,"counter_enabled":0,"sort_order":1,"deleted_at":0,"updated_at":"2026-06-20T00:00:00Z"}]}`)
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
	if len(full.Changes.Habits) != 1 || full.Changes.Habits[0].ID != "habit-2" {
		t.Fatalf("remote was not replaced: %#v", full.Changes.Habits)
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
	req.Header.Set("X-Inbe-User", userID)
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
	req.Header.Set("X-Inbe-User", userID)
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
	req.Header.Set("X-Inbe-User", otherID)
	req.Header.Set("Authorization", "Bearer "+otherToken)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("old alias reuse status = %d body=%s", res.Code, res.Body.String())
	}
	aliasBody = []byte(`{"user_id_hash":"` + otherID + `","alias":"new_waozi"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/account/alias", bytes.NewReader(aliasBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Inbe-User", otherID)
	req.Header.Set("Authorization", "Bearer "+otherToken)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusConflict {
		t.Fatalf("alias conflict status = %d body=%s", res.Code, res.Body.String())
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
	req.Header.Set("X-Inbe-User", alice.UserID)
	req.Header.Set("Authorization", "Bearer "+bob.Token)
	mismatch := httptest.NewRecorder()
	handler.ServeHTTP(mismatch, req)
	if mismatch.Code != http.StatusUnauthorized {
		t.Fatalf("bob token for alice sync status = %d body=%s", mismatch.Code, mismatch.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/sync", bytes.NewReader(bobBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Inbe-User", bob.UserID)
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
	dbPath := filepath.Join(t.TempDir(), "old-lyra.db")
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
	req.Header.Set("X-Inbe-User", alice.UserID)
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
	req.Header.Set("X-Inbe-User", missingUser)
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

	token, _ := loginWithKey(t, handler, "", userID, hex.EncodeToString(publicKey), signature)
	body := []byte(`{"user_id_hash":"` + userID + `","client_id":"test-client-1","habit_days":[{"habit_id":"habit-2","local_date":20260619,"completed":true,"count":1,"updated_at":"2026-06-19T00:00:00Z"}]}`)
	res := syncWithBody(t, handler, "", userID, token, body)
	var payload SyncResponse
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Changes.Habits) != 1 || payload.Changes.Habits[0].ID != "habit-2" ||
		payload.Changes.Habits[0].Name != "Recovered habit-2" {
		t.Fatalf("recovered habits = %#v", payload.Changes.Habits)
	}
	if len(payload.Changes.HabitDays) != 1 || payload.Changes.HabitDays[0].HabitID != "habit-2" {
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
	if len(payload.Changes.HabitDays) != 0 {
		t.Fatalf("habit day clear was still snapshotted: %#v", payload.Changes.HabitDays)
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
	if len(payload.Changes.HabitDays) != 0 {
		t.Fatalf("equal timestamp habit day clear was still snapshotted: %#v", payload.Changes.HabitDays)
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

func TestParseExportedSyncKey(t *testing.T) {
	privateKey := bytes.Repeat([]byte{0x64}, mlDSA44PrivateKeySize)
	publicID := strings.Repeat("a", 64)
	keyText := "inbe-sync-key-v1\nalgorithm=ML-DSA-44\npublic_id=" + publicID + "\nprivate_key=" + hex.EncodeToString(privateKey) + "\n"
	parsed, err := parseExportedSyncKey(keyText)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.PublicID != publicID {
		t.Fatalf("public id = %q", parsed.PublicID)
	}
	if !bytes.Equal(parsed.PrivateKey, privateKey) {
		t.Fatal("parsed private key mismatch")
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
	store, err := OpenStore(filepath.Join(t.TempDir(), "lyra-delete-key-test.db"))
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
	keyText := "inbe-sync-key-v1\nalgorithm=ML-DSA-44\npublic_id=" + userID + "\nprivate_key=" + hex.EncodeToString(privateKey) + "\n"
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
	req.Header.Set("X-Inbe-User", userID)
	req.Header.Set("X-Inbe-Signature", signature)
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
	req.Header.Set("X-Inbe-User", userID)
	req.Header.Set("Authorization", "Bearer "+token)
	res := serveTestRequest(t, target, req)
	if res.Code != http.StatusOK {
		t.Fatalf("sync status = %d body=%s", res.Code, res.Body.String())
	}
	return res
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
		"Authorization: Bearer " + token + "\r\n\r\n"))
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
	req.Header.Set("X-Inbe-User", userID)
	req.Header.Set("X-Inbe-Signature", hex.EncodeToString(bytes.Repeat([]byte{0x33}, mlDSA44SignatureSize)))
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
