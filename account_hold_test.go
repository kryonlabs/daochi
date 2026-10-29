package main

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

type holdAccount struct {
	userID    string
	publicKey string
	signature string
}

func newHoldAccount(seed byte) holdAccount {
	publicKey := bytes.Repeat([]byte{seed}, mlDSA44PublicKeySize)
	userHash := sha256.Sum256(publicKey)
	return holdAccount{
		userID:    hex.EncodeToString(userHash[:]),
		publicKey: hex.EncodeToString(publicKey),
		signature: hex.EncodeToString(bytes.Repeat([]byte{seed + 0x11}, mlDSA44SignatureSize)),
	}
}

func (account holdAccount) login(t *testing.T, handler http.Handler, restore bool) (LoginResponse, int) {
	t.Helper()
	issueChallenge(t, handler, "", account.userID)
	body := `{"user_id_hash":"` + account.userID + `","client_id":"test-client-1","public_key":"` + account.publicKey + `"`
	if restore {
		body += `,"restore":true`
	}
	body += `}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/sync/login", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Ksync-User", account.userID)
	request.Header.Set("X-Ksync-Signature", account.signature)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var payload LoginResponse
	if response.Code == http.StatusOK {
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
	}
	return payload, response.Code
}

func (account holdAccount) delete(t *testing.T, handler http.Handler) {
	t.Helper()
	issueChallenge(t, handler, "", account.userID)
	body := `{"user_id_hash":"` + account.userID + `","public_key":"` + account.publicKey + `"}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/account/delete", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Ksync-User", account.userID)
	request.Header.Set("X-Ksync-Signature", account.signature)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("delete status = %d body=%s", response.Code, response.Body.String())
	}
}

func holdCount(t *testing.T, database *sql.DB, query string, arguments ...any) int {
	t.Helper()
	var count int
	if err := database.QueryRow(query, arguments...).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// Gives the account rows in a charged record, a grandchild table, a blob
// with its file, a friendship and an alias.
func seedHeldAccount(t *testing.T, server *Server, store *Store, account holdAccount, friend holdAccount) {
	t.Helper()
	statements := []struct {
		query     string
		arguments []any
	}{
		{"UPDATE server_users SET alias='keeper' WHERE user_id_hash=?1", []any{account.userID}},
		{"INSERT INTO server_encrypted_records(user_id_hash,collection,id,key_id,nonce,ciphertext,updated_at) VALUES(?1,'private.inbe.v1.cells','cell.diary.1','main','nonce',?2,'2026-10-01T00:00:00Z')", []any{account.userID, strings.Repeat("x", 300)}},
		{"INSERT INTO server_sessions(user_id_hash,id,started_at,updated_at) VALUES(?1,'session-1','2026-10-01T00:00:00Z','2026-10-01T00:00:00Z')", []any{account.userID}},
		{"INSERT INTO server_session_rounds(user_id_hash,session_id,round_index,breaths) VALUES(?1,'session-1',0,30)", []any{account.userID}},
		{"INSERT INTO server_blobs(user_id_hash,app_id,hash,size) VALUES(?1,'inbe',?2,5)", []any{account.userID, strings.Repeat("a", 64)}},
	}
	for _, statement := range statements {
		if _, err := store.Database.Exec(statement.query, statement.arguments...); err != nil {
			t.Fatal(statement.query, err)
		}
	}
	low, high := account.userID, friend.userID
	if high < low {
		low, high = high, low
	}
	if _, err := store.Database.Exec("INSERT INTO server_friendships(user_id_a,user_id_b) VALUES(?1,?2)", low, high); err != nil {
		t.Fatal(err)
	}
	folder := filepath.Join(AccountStorage_BlobAccountFolder(server.Cfg.DBPath, account.userID), "inbe")
	if err := os.MkdirAll(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, strings.Repeat("a", 64)), []byte("bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Every table a deletion of server_users reaches through ON DELETE CASCADE,
// found here independently of the server's own query.
func cascadeTables(t *testing.T, database *sql.DB) []string {
	t.Helper()
	rows, err := database.Query("SELECT name FROM sqlite_master WHERE type='table'")
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	parents := map[string][]string{}
	for _, table := range tables {
		keys, err := database.Query("SELECT \"table\",on_delete FROM pragma_foreign_key_list(?1)", table)
		if err != nil {
			t.Fatal(err)
		}
		for keys.Next() {
			var parent, onDelete string
			if err := keys.Scan(&parent, &onDelete); err != nil {
				t.Fatal(err)
			}
			if onDelete == "CASCADE" {
				parents[table] = append(parents[table], parent)
			}
		}
		if err := keys.Close(); err != nil {
			t.Fatal(err)
		}
	}
	reached := map[string]bool{"server_users": true}
	for changed := true; changed; {
		changed = false
		for table, owners := range parents {
			if reached[table] {
				continue
			}
			for _, owner := range owners {
				if reached[owner] {
					reached[table] = true
					changed = true
					break
				}
			}
		}
	}
	delete(reached, "server_storage_usage")
	var result []string
	for table := range reached {
		result = append(result, table)
	}
	sort.Strings(result)
	return result
}

func heldTables(t *testing.T, path string) []string {
	t.Helper()
	held, err := sql.Open("sqlite3", path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer ignoreCleanupError(held.Close)
	rows, err := held.Query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
	if err != nil {
		t.Fatal(err)
	}
	defer ignoreCleanupError(rows.Close)
	var result []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		result = append(result, name)
	}
	return result
}

func TestAccountDeletionHoldsEveryCascadedTableAndRestoresOnRequest(t *testing.T) {
	server, store, _ := testServer(t)
	handler := server.Routes()
	account := newHoldAccount(0x51)
	friend := newHoldAccount(0x52)
	account.login(t, handler, false)
	friend.login(t, handler, false)
	seedHeldAccount(t, server, store, account, friend)
	usedBefore := AccountStorage_Used(store.Database, t.Context(), account.userID)
	if usedBefore.Error != nil || usedBefore.Value == 0 {
		t.Fatalf("seeded account uses no storage: %#v", usedBefore)
	}

	before := time.Now().Unix()
	account.delete(t, handler)
	// Nothing of the account stays in the live tables or counts as used.
	for _, table := range []string{"server_users", "server_encrypted_records", "server_sessions", "server_session_rounds", "server_blobs", "server_storage_usage"} {
		owner := "user_id_hash"
		if holdCount(t, store.Database, "SELECT COUNT(*) FROM "+table+" WHERE "+owner+"=?1", account.userID) != 0 {
			t.Fatalf("%s kept the deleted account's rows", table)
		}
	}
	if holdCount(t, store.Database, "SELECT COUNT(*) FROM server_friendships") != 0 {
		t.Fatal("the friendship stayed visible")
	}
	var heldAt, purgeAfter int64
	if err := store.Database.QueryRow("SELECT held_at,purge_after FROM server_account_holds WHERE user_id_hash=?1", account.userID).Scan(&heldAt, &purgeAfter); err != nil {
		t.Fatal(err)
	}
	if heldAt < before || purgeAfter != heldAt+30*86400 {
		t.Fatalf("hold %d until %d, want 30 days from deletion", heldAt, purgeAfter)
	}
	file := server.Cfg.DBPath + ".held/" + account.userID + ".db"
	if got, want := heldTables(t, file), cascadeTables(t, store.Database); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("held tables %v, want every cascaded table %v", got, want)
	}
	if _, err := os.Stat(filepath.Join(server.Cfg.DBPath+".held", account.userID+".blobs", "inbe", strings.Repeat("a", 64))); err != nil {
		t.Fatalf("blob file was not held: %v", err)
	}
	if _, err := os.Stat(AccountStorage_BlobAccountFolder(server.Cfg.DBPath, account.userID)); !os.IsNotExist(err) {
		t.Fatalf("blob folder stayed live: %v", err)
	}

	// Someone takes the alias meanwhile; the restored account goes without it.
	if _, err := store.Database.Exec("UPDATE server_users SET alias='Keeper' WHERE user_id_hash=?1", friend.userID); err != nil {
		t.Fatal(err)
	}
	login, status := account.login(t, handler, true)
	if status != http.StatusOK || login.HeldUntil != 0 || login.AccountAlias != "" {
		t.Fatalf("restoring login = %d %#v", status, login)
	}
	for table, want := range map[string]int{"server_users": 1, "server_encrypted_records": 1, "server_sessions": 1, "server_session_rounds": 1, "server_blobs": 1} {
		if got := holdCount(t, store.Database, "SELECT COUNT(*) FROM "+table+" WHERE user_id_hash=?1", account.userID); got != want {
			t.Fatalf("%s restored %d rows, want %d", table, got, want)
		}
	}
	if holdCount(t, store.Database, "SELECT COUNT(*) FROM server_friendships") != 1 {
		t.Fatal("the friendship did not come back")
	}
	if holdCount(t, store.Database, "SELECT COUNT(*) FROM server_account_holds") != 0 ||
		holdCount(t, store.Database, "SELECT COUNT(*) FROM server_account_tombstones") != 0 {
		t.Fatal("restoring left the hold or tombstone behind")
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("restored hold file stayed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(AccountStorage_BlobAccountFolder(server.Cfg.DBPath, account.userID), "inbe", strings.Repeat("a", 64))); err != nil {
		t.Fatalf("blob file did not come back: %v", err)
	}
	usedAfter := AccountStorage_Used(store.Database, t.Context(), account.userID)
	if usedAfter.Error != nil || usedAfter.Value != usedBefore.Value {
		t.Fatalf("restored usage %#v, want %d", usedAfter, usedBefore.Value)
	}
	assertStorageUsage(t, store, account.userID, friend.userID)
}

func TestAccountHoldPlainLoginStartsEmptyAndPurgesAfterThirtyDays(t *testing.T) {
	server, store, _ := testServer(t)
	handler := server.Routes()
	account := newHoldAccount(0x53)
	friend := newHoldAccount(0x54)
	account.login(t, handler, false)
	friend.login(t, handler, false)
	seedHeldAccount(t, server, store, account, friend)
	account.delete(t, handler)

	// A login without restore starts an empty account and reports the hold.
	login, status := account.login(t, handler, false)
	if status != http.StatusOK || login.HeldUntil == 0 {
		t.Fatalf("plain login during the hold = %d %#v", status, login)
	}
	if holdCount(t, store.Database, "SELECT COUNT(*) FROM server_encrypted_records WHERE user_id_hash=?1", account.userID) != 0 {
		t.Fatal("a plain login brought held data back")
	}
	// A restore cannot overwrite the new account.
	if _, status := account.login(t, handler, true); status != http.StatusOK {
		t.Fatalf("restore over a live account = %d", status)
	}
	if holdCount(t, store.Database, "SELECT COUNT(*) FROM server_encrypted_records WHERE user_id_hash=?1", account.userID) != 0 {
		t.Fatal("a restore merged held data into a live account")
	}

	file := server.Cfg.DBPath + ".held/" + account.userID + ".db"
	blobs := server.Cfg.DBPath + ".held/" + account.userID + ".blobs"
	early := time.Unix(login.HeldUntil-1, 0)
	if err := Retention_PruneFiles(store.Database, t.Context(), server.Cfg.DBPath, early); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("hold purged before 30 days: %v", err)
	}
	if err := Retention_PruneFiles(store.Database, t.Context(), server.Cfg.DBPath, time.Unix(login.HeldUntil, 0)); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{file, blobs} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s survived the hold: %v", path, err)
		}
	}
	if holdCount(t, store.Database, "SELECT COUNT(*) FROM server_account_holds") != 0 {
		t.Fatal("the hold row survived the purge")
	}
	login, _ = account.login(t, handler, false)
	if login.HeldUntil != 0 {
		t.Fatalf("purged hold still reported: %#v", login)
	}
}

func TestAccountHoldRestoreWithoutHoldIsAPlainLogin(t *testing.T) {
	server, store, _ := testServer(t)
	handler := server.Routes()
	account := newHoldAccount(0x55)
	if login, status := account.login(t, handler, true); status != http.StatusOK || login.HeldUntil != 0 {
		t.Fatalf("restore without a hold = %d %#v", status, login)
	}
	if holdCount(t, store.Database, "SELECT COUNT(*) FROM server_users WHERE user_id_hash=?1", account.userID) != 1 {
		t.Fatal("restore without a hold did not register the account")
	}
	// A second deletion replaces an earlier hold of the same key.
	account.delete(t, handler)
	account.login(t, handler, false)
	account.delete(t, handler)
	if holdCount(t, store.Database, "SELECT COUNT(*) FROM server_account_holds WHERE user_id_hash=?1", account.userID) != 1 {
		t.Fatal("repeated deletion did not keep exactly one hold")
	}
	if _, status := account.login(t, handler, true); status != http.StatusOK {
		t.Fatalf("restore after repeated deletion = %d", status)
	}
	// An operator may delete a held account early; restoring then just ends
	// the hold instead of refusing every login.
	account.delete(t, handler)
	if err := os.Remove(server.Cfg.DBPath + ".held/" + account.userID + ".db"); err != nil {
		t.Fatal(err)
	}
	login, status := account.login(t, handler, true)
	if status != http.StatusOK || login.HeldUntil != 0 {
		t.Fatalf("restore of a removed hold = %d %#v", status, login)
	}
	if holdCount(t, store.Database, "SELECT COUNT(*) FROM server_account_holds") != 0 {
		t.Fatal("a removed hold stayed recorded")
	}
}
