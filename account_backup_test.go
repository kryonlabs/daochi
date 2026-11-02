package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	testBackupSalt   = "00112233445566778899aabbccddeeff"
	testBackupPrefix = "waozi-account-backup-v3\nalgorithm=ML-DSA-44\nkdf=Argon2id\nmemory_kib=65536\npasses=3\nlanes=1\nsalt="
)

func sealedBackup(salt, sealed string) string {
	return testBackupPrefix + salt + "\n" + sealed
}

func storeBackup(t *testing.T, target any, token, backup, salt, verifier string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"backup": backup, "salt": salt, "verifier": verifier})
	if err != nil {
		t.Fatal(err)
	}
	return sendJSON(t, target, http.MethodPost, "/api/v1/account/backup", token, string(body))
}

func openBackup(t *testing.T, target any, account, proof string) *httptest.ResponseRecorder {
	t.Helper()
	return sendJSON(t, target, http.MethodPost, "/api/v1/account-backup/open", "", `{"account":"`+account+`","proof":"`+proof+`"}`)
}

func backupSalt(t *testing.T, target any, account string) string {
	t.Helper()
	response := sendJSON(t, target, http.MethodPost, "/api/v1/account-backup/salt", "", `{"account":"`+account+`"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("salt for %q: %d %s", account, response.Code, response.Body)
	}
	var reply struct {
		Salt string `json:"salt"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	if len(reply.Salt) != 32 {
		t.Fatalf("salt for %q is not 16 bytes of hex: %q", account, reply.Salt)
	}
	return reply.Salt
}

func TestAccountBackupReleasedOnlyForItsProof(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x41)
	proof, verifier := passkeyProof("right password")
	wrongProof, _ := passkeyProof("wrong password")
	backup := sealedBackup(testBackupSalt, "sealed")

	if response := storeBackup(t, handler, identity.Token, backup, testBackupSalt, verifier); response.Code != http.StatusOK {
		t.Fatalf("store: %d %s", response.Code, response.Body)
	}

	// The node keeps the sealed text and the proof's digest; never the proof.
	var storedBackup, storedVerifier string
	row := server.Store.Database.QueryRow(`SELECT backup,verifier FROM server_account_backups WHERE user_id_hash=?1`, identity.UserID)
	if err := row.Scan(&storedBackup, &storedVerifier); err != nil {
		t.Fatal(err)
	}
	if storedBackup != backup || storedVerifier != verifier || strings.Contains(storedBackup, proof) || storedVerifier == proof {
		t.Fatalf("node keeps something else: %q %q", storedBackup, storedVerifier)
	}

	if salt := backupSalt(t, handler, identity.UserID); salt != testBackupSalt {
		t.Fatalf("salt = %q", salt)
	}

	opened := openBackup(t, handler, identity.UserID, proof)
	if opened.Code != http.StatusOK {
		t.Fatalf("open: %d %s", opened.Code, opened.Body)
	}
	if cache := opened.Header().Get("Cache-Control"); !strings.Contains(cache, "no-store") {
		t.Fatalf("released backup may be cached: %q", cache)
	}
	var reply struct {
		Account string `json:"account_id"`
		Backup  string `json:"backup"`
	}
	if err := json.Unmarshal(opened.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	if reply.Account != identity.UserID || reply.Backup != backup {
		t.Fatalf("wrong reply: %+v", reply)
	}

	// A wrong password, an account without a backup and a name nobody holds
	// answer alike.
	without := newTestIdentity(t, handler, 0x42)
	wrong := openBackup(t, handler, identity.UserID, wrongProof)
	noBackup := openBackup(t, handler, without.UserID, proof)
	nobody := openBackup(t, handler, "nobody_here", proof)
	for _, refused := range []*httptest.ResponseRecorder{wrong, noBackup, nobody} {
		if refused.Code != http.StatusForbidden || refused.Body.String() != wrong.Body.String() {
			t.Fatalf("refusal differs: %d %s", refused.Code, refused.Body)
		}
		if strings.Contains(refused.Body.String(), "sealed") {
			t.Fatalf("refusal carries the backup: %s", refused.Body)
		}
	}
	if malformed := openBackup(t, handler, identity.UserID, "not-hex"); malformed.Code != http.StatusBadRequest {
		t.Fatalf("malformed proof: %d", malformed.Code)
	}
}

func TestAccountBackupSaltsDoNotShowWhoHasABackup(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x43)
	aliasBody := `{"user_id_hash":"` + identity.UserID + `","alias":"@saltcheck"}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/account/alias", strings.NewReader(aliasBody))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Ksync-User", identity.UserID)
	request.Header.Set("Authorization", "Bearer "+identity.Token)
	if response := serveTestRequest(t, handler, request); response.Code != http.StatusOK {
		t.Fatalf("alias: %d %s", response.Code, response.Body)
	}

	// Stable, and the same for a username and its public ID.
	decoy := backupSalt(t, handler, identity.UserID)
	if again := backupSalt(t, handler, identity.UserID); again != decoy {
		t.Fatalf("decoy salt changed: %q %q", decoy, again)
	}
	if byName := backupSalt(t, handler, "saltcheck"); byName != decoy {
		t.Fatalf("username and public ID differ: %q %q", byName, decoy)
	}
	unknown := backupSalt(t, handler, "nobody_here")
	if unknown == decoy {
		t.Fatal("two accounts share a decoy salt")
	}
	if again := backupSalt(t, handler, "NOBODY_HERE"); again != unknown {
		t.Fatalf("unknown name's salt depends on spelling: %q %q", unknown, again)
	}

	// Storing a backup answers its own salt by either name.
	_, verifier := passkeyProof("right password")
	if response := storeBackup(t, handler, identity.Token, sealedBackup(testBackupSalt, "sealed"), testBackupSalt, verifier); response.Code != http.StatusOK {
		t.Fatalf("store: %d %s", response.Code, response.Body)
	}
	for _, name := range []string{identity.UserID, "saltcheck", "@saltcheck"} {
		if salt := backupSalt(t, handler, name); salt != testBackupSalt {
			t.Fatalf("salt for %q = %q", name, salt)
		}
	}

	// Removing it goes back to the same decoy, so nothing shows it ever existed.
	if response := sendJSON(t, handler, http.MethodDelete, "/api/v1/account/backup", identity.Token, ""); response.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", response.Code, response.Body)
	}
	if salt := backupSalt(t, handler, identity.UserID); salt != decoy {
		t.Fatalf("salt after delete = %q, want %q", salt, decoy)
	}
}

func TestAccountBackupLocksAfterWrongProofs(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x44)
	proof, verifier := passkeyProof("right password")
	wrongProof, _ := passkeyProof("wrong password")
	if response := storeBackup(t, handler, identity.Token, sealedBackup(testBackupSalt, "sealed"), testBackupSalt, verifier); response.Code != http.StatusOK {
		t.Fatalf("store: %d %s", response.Code, response.Body)
	}

	for attempt := 1; attempt <= 5; attempt++ {
		if response := openBackup(t, handler, identity.UserID, wrongProof); response.Code != http.StatusForbidden {
			t.Fatalf("wrong proof %d: %d %s", attempt, response.Code, response.Body)
		}
	}

	// Locked: even the right proof waits, and failures stored across requests
	// are what hold the lock.
	locked := openBackup(t, handler, identity.UserID, proof)
	if locked.Code != http.StatusTooManyRequests || strings.Contains(locked.Body.String(), "sealed") {
		t.Fatalf("right proof while locked: %d %s", locked.Code, locked.Body)
	}
	retry, err := strconv.Atoi(locked.Header().Get("Retry-After"))
	if err != nil || retry < 1 || retry > 60 {
		t.Fatalf("Retry-After = %q", locked.Header().Get("Retry-After"))
	}

	// Each further wrong proof after the lock ends doubles the wait.
	database := server.Store.Database
	if _, err := database.Exec(`UPDATE server_account_backups SET locked_until=0 WHERE user_id_hash=?1`, identity.UserID); err != nil {
		t.Fatal(err)
	}
	if response := openBackup(t, handler, identity.UserID, wrongProof); response.Code != http.StatusForbidden {
		t.Fatalf("sixth wrong proof: %d", response.Code)
	}
	var failures, lockedUntil int64
	row := database.QueryRow(`SELECT failed_attempts,locked_until FROM server_account_backups WHERE user_id_hash=?1`, identity.UserID)
	if err := row.Scan(&failures, &lockedUntil); err != nil {
		t.Fatal(err)
	}
	remaining := lockedUntil - time.Now().Unix()
	if failures != 6 || remaining < 110 || remaining > 120 {
		t.Fatalf("failures=%d, lock remaining=%d", failures, remaining)
	}

	// The right proof clears the record once the lock has ended.
	if _, err := database.Exec(`UPDATE server_account_backups SET locked_until=0 WHERE user_id_hash=?1`, identity.UserID); err != nil {
		t.Fatal(err)
	}
	if response := openBackup(t, handler, identity.UserID, proof); response.Code != http.StatusOK {
		t.Fatalf("right proof after the lock: %d %s", response.Code, response.Body)
	}
	row = database.QueryRow(`SELECT failed_attempts,locked_until FROM server_account_backups WHERE user_id_hash=?1`, identity.UserID)
	if err := row.Scan(&failures, &lockedUntil); err != nil {
		t.Fatal(err)
	}
	if failures != 0 || lockedUntil != 0 {
		t.Fatalf("record kept after success: failures=%d locked_until=%d", failures, lockedUntil)
	}
}

func TestAccountBackupLockLooksTheSameForNamesWithoutABackup(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	proof, _ := passkeyProof("anything")
	for attempt := 1; attempt <= 5; attempt++ {
		if response := openBackup(t, handler, "nobody_locked", proof); response.Code != http.StatusForbidden {
			t.Fatalf("attempt %d: %d %s", attempt, response.Code, response.Body)
		}
	}
	if locked := openBackup(t, handler, "nobody_locked", proof); locked.Code != http.StatusTooManyRequests || locked.Header().Get("Retry-After") == "" {
		t.Fatalf("name without a backup does not lock: %d", locked.Code)
	}
}

func TestAccountBackupOpenIsLimitedPerAddress(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	proof, _ := passkeyProof("anything")
	// A new name each time, so only the address can be what refuses.
	for attempt := 0; attempt < 20; attempt++ {
		if response := openBackup(t, handler, fmt.Sprintf("nobody_%d", attempt), proof); response.Code != http.StatusForbidden {
			t.Fatalf("attempt %d: %d %s", attempt, response.Code, response.Body)
		}
	}
	if response := openBackup(t, handler, "nobody_last", proof); response.Code != http.StatusTooManyRequests {
		t.Fatalf("over the limit: %d", response.Code)
	}
}

func TestAccountBackupStoreRefusesWeakerSealsAndAnonymous(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x45)
	_, verifier := passkeyProof("right password")
	backup := sealedBackup(testBackupSalt, "sealed")

	if response := storeBackup(t, handler, "", backup, testBackupSalt, verifier); response.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous store: %d", response.Code)
	}
	otherSalt := strings.Repeat("a", 32)
	bad := []struct {
		name, backup, salt, verifier string
	}{
		{"weaker Argon2id", strings.Replace(backup, "memory_kib=65536", "memory_kib=1024", 1), testBackupSalt, verifier},
		{"older format", strings.Replace(backup, "backup-v3", "backup-v2", 1), testBackupSalt, verifier},
		{"salt line differs", sealedBackup(otherSalt, "sealed"), testBackupSalt, verifier},
		{"nothing sealed", sealedBackup(testBackupSalt, ""), testBackupSalt, verifier},
		{"short salt", backup, "0011", verifier},
		{"short verifier", backup, testBackupSalt, "abcd"},
		{"too large", sealedBackup(testBackupSalt, strings.Repeat("x", 17664)), testBackupSalt, verifier},
	}
	for _, input := range bad {
		if response := storeBackup(t, handler, identity.Token, input.backup, input.salt, input.verifier); response.Code != http.StatusBadRequest {
			t.Fatalf("%s accepted: %d", input.name, response.Code)
		}
	}
	if count := holdCount(t, server.Store.Database, "SELECT COUNT(*) FROM server_account_backups WHERE user_id_hash=?1", identity.UserID); count != 0 {
		t.Fatalf("refused backups were stored: %d", count)
	}
}

func TestAccountBackupReplaceAndRemove(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x46)
	other := newTestIdentity(t, handler, 0x47)
	oldProof, oldVerifier := passkeyProof("old password")
	newProof, newVerifier := passkeyProof("new password")
	newSalt := strings.Repeat("b", 32)

	status := sendJSON(t, handler, http.MethodGet, "/api/v1/account/backup", identity.Token, "")
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"stored":false`) {
		t.Fatalf("status before storing: %d %s", status.Code, status.Body)
	}
	if response := storeBackup(t, handler, identity.Token, sealedBackup(testBackupSalt, "old"), testBackupSalt, oldVerifier); response.Code != http.StatusOK {
		t.Fatalf("store: %d %s", response.Code, response.Body)
	}
	for attempt := 0; attempt < 4; attempt++ {
		if response := openBackup(t, handler, identity.UserID, newProof); response.Code != http.StatusForbidden {
			t.Fatalf("wrong proof: %d", response.Code)
		}
	}

	// Replacing it retires the old password and starts with no failures.
	if response := storeBackup(t, handler, identity.Token, sealedBackup(newSalt, "new"), newSalt, newVerifier); response.Code != http.StatusOK {
		t.Fatalf("replace: %d %s", response.Code, response.Body)
	}
	if response := openBackup(t, handler, identity.UserID, oldProof); response.Code != http.StatusForbidden {
		t.Fatalf("old password still opens: %d", response.Code)
	}
	opened := openBackup(t, handler, identity.UserID, newProof)
	if opened.Code != http.StatusOK || !strings.Contains(opened.Body.String(), "new") {
		t.Fatalf("new password: %d %s", opened.Code, opened.Body)
	}
	status = sendJSON(t, handler, http.MethodGet, "/api/v1/account/backup", identity.Token, "")
	if !strings.Contains(status.Body.String(), `"stored":true`) {
		t.Fatalf("status after storing: %s", status.Body)
	}

	// Another account's token removes nothing of this one's.
	if response := sendJSON(t, handler, http.MethodDelete, "/api/v1/account/backup", other.Token, ""); !strings.Contains(response.Body.String(), `"deleted":false`) {
		t.Fatalf("other account's delete: %d %s", response.Code, response.Body)
	}
	if response := openBackup(t, handler, identity.UserID, newProof); response.Code != http.StatusOK {
		t.Fatalf("backup gone after another account's delete: %d", response.Code)
	}
	if response := sendJSON(t, handler, http.MethodDelete, "/api/v1/account/backup", "", ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous delete: %d", response.Code)
	}
	if response := sendJSON(t, handler, http.MethodDelete, "/api/v1/account/backup", identity.Token, ""); !strings.Contains(response.Body.String(), `"deleted":true`) {
		t.Fatalf("delete: %d %s", response.Code, response.Body)
	}
	if response := openBackup(t, handler, identity.UserID, newProof); response.Code != http.StatusForbidden {
		t.Fatalf("released after delete: %d", response.Code)
	}
}

func TestDeletingAnAccountRemovesItsBackup(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x48)
	proof, verifier := passkeyProof("right password")
	if response := storeBackup(t, handler, identity.Token, sealedBackup(testBackupSalt, "sealed"), testBackupSalt, verifier); response.Code != http.StatusOK {
		t.Fatalf("store: %d %s", response.Code, response.Body)
	}
	transaction, err := server.Store.Database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := AccountState_DeleteTx(transaction, t.Context(), identity.UserID); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
	if response := openBackup(t, handler, identity.UserID, proof); response.Code != http.StatusForbidden {
		t.Fatalf("backup released after account deletion: %d", response.Code)
	}
	if count := holdCount(t, server.Store.Database, "SELECT COUNT(*) FROM server_account_backups WHERE user_id_hash=?1", identity.UserID); count != 0 {
		t.Fatalf("backup kept after account deletion: %d", count)
	}
}
