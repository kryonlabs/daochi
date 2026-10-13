package main

import (
	"bytes"
	"context"
	"database/sql"
	"net/http"
	"strings"
	"testing"
	"time"
)

func postSync(t *testing.T, handler http.Handler, identity testIdentity, body string) (int, string) {
	t.Helper()
	request := newTestRequest(t, http.MethodPost, "", "/api/v1/sync", bytes.NewReader([]byte(body)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Ksync-User", identity.UserID)
	request.Header.Set("Authorization", "Bearer "+identity.Token)
	response := serveTestRequest(t, handler, request)
	return response.Code, response.Body.String()
}

func syncRecordBody(identity testIdentity, protocol string, appID string, record string) string {
	app := ""
	if appID != "" {
		app = `"app_id":"` + appID + `",`
	}
	return `{"protocol_version":` + protocol + `,` + app + `"user_id_hash":"` + identity.UserID +
		`","client_id":"security-client","encrypted_records":[` + record + `]}`
}

func storedRecord(t *testing.T, store *Store, user string, collection string, id string) (string, string) {
	t.Helper()
	var ciphertext, updated string
	row := store.Database.QueryRow(
		"SELECT ciphertext,updated_at FROM server_encrypted_records WHERE user_id_hash=?1 AND collection=?2 AND id=?3",
		user, collection, id)
	if err := row.Scan(&ciphertext, &updated); err != nil {
		t.Fatalf("read %s/%s: %v", collection, id, err)
	}
	return ciphertext, updated
}

func storedCollections(t *testing.T, store *Store, user string) string {
	t.Helper()
	var collections sql.NullString
	row := store.Database.QueryRow(
		"SELECT group_concat(collection, ',') FROM (SELECT collection FROM server_encrypted_records WHERE user_id_hash=?1 ORDER BY collection)",
		user)
	if err := row.Scan(&collections); err != nil {
		t.Fatal(err)
	}
	return collections.String
}

// A bearer token alone must not reach another app's records by leaving out
// app_id or by naming a legacy-capable app; only that app's signed
// transactions may write its collections.
func TestSyncRejectsAnotherAppsCollection(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x71)
	now := time.Now().UTC().Format(time.RFC3339)
	record := func(collection string, deleted string) string {
		return `{"collection":"` + collection + `","id":"r1","key_id":"main","nonce":"n1","ciphertext":"c1","updated_at":"` +
			now + `"` + deleted + `}`
	}
	tests := []struct {
		name     string
		protocol string
		appID    string
		record   string
		allowed  bool
	}{
		{"app-less v5 into another app", "5", "", record("private.auth.v1.vault", ""), false},
		{"app-less v4 into another app", "4", "", record("private.auth.v1.vault", ""), false},
		{"app-less v1 into another app", "1", "", record("private.auth.v1.vault", ""), false},
		{"app-less delete in another app", "5", "", record("private.auth.v1.vault", `,"deleted_at":1`), false},
		{"app-less shared scope of another app", "5", "", record("shared.photos.v1.albums", ""), false},
		{"Inbe app_id into another app", "5", "inbe", record("private.photos.v1.media", ""), false},
		{"app-less own Inbe collection", "5", "", record("private.inbe.v1.notes", ""), true},
		{"app-less released Inbe collection", "5", "", record("inbe.habits", ""), true},
		{"app-less account-wide record", "5", "", record("account.v1.profile", ""), true},
		{"Inbe app_id own collection", "5", "inbe", record("private.inbe.v1.notes", ""), true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status, body := postSync(t, handler, identity, syncRecordBody(identity, test.protocol, test.appID, test.record))
			if test.allowed && status != http.StatusOK {
				t.Fatalf("status = %d body=%s; expected success", status, body)
			}
			if !test.allowed && (status != http.StatusBadRequest || !strings.Contains(body, "belongs to another app")) {
				t.Fatalf("status = %d body=%s; expected another-app rejection", status, body)
			}
		})
	}
}

// A full re-sync replaces the calling app's data, never every app's records.
func TestFullSyncReplacesOnlyTheCallingAppsRecords(t *testing.T) {
	server, store, _ := testServer(t)
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x72)
	now := time.Now().UTC().Format(time.RFC3339)
	inbeRecord := `{"collection":"inbe.habits","id":"habit-1","key_id":"main","nonce":"n1","ciphertext":"inbe","updated_at":"` + now + `"}`
	syncWithBody(t, handler, "", identity.UserID, identity.Token, []byte(syncRecordBody(identity, "5", "", inbeRecord)))
	seed := func(collection string) {
		t.Helper()
		item := EncryptedRecord{Collection: collection, ID: "record-1", KeyID: "main", Nonce: "n2",
			Ciphertext: "other", UpdatedAt: now}
		written := writesInTransaction(store, t.Context(), identity.UserID, func(ctx context.Context, tx *sql.Tx, user string) SyncWriteResult {
			return SyncWrites_UpsertRecord(tx, ctx, user, item)
		})
		if written.Error != nil || written.Applied != 1 {
			t.Fatalf("seed %s = %#v", collection, written)
		}
	}
	seed("private.photos.v1.media")
	seed("account.v1.profile")

	fullSync := `{"protocol_version":5,"user_id_hash":"` + identity.UserID + `","client_id":"security-client","full_sync_requested":true}`
	syncWithBody(t, handler, "", identity.UserID, identity.Token, []byte(fullSync))
	if got := storedCollections(t, store, identity.UserID); got != "private.photos.v1.media" {
		t.Fatalf("Inbe full sync left %q; expected only the other app's records", got)
	}

	syncWithBody(t, handler, "", identity.UserID, identity.Token, []byte(syncRecordBody(identity, "5", "", inbeRecord)))
	replaced := writesInTransaction(store, t.Context(), identity.UserID, func(ctx context.Context, tx *sql.Tx, user string) SyncWriteResult {
		return SyncWriteResult{Error: SyncWrites_ReplaceData(tx, ctx, user, "photos")}
	})
	if replaced.Error != nil {
		t.Fatal(replaced.Error)
	}
	if got := storedCollections(t, store, identity.UserID); got != "inbe.habits" {
		t.Fatalf("photos full sync left %q; expected Inbe's records untouched", got)
	}
}

func TestWriteTimeLimit(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	latest := "2026-10-13T12:05:00.000000000Z"
	tests := []struct {
		value    string
		expected string
	}{
		{"9999-12-31T23:59:59Z", latest},
		{"2026-10-13T12:05:00.000000001Z", latest},
		{"2026-10-13T12:05:00Z", latest},
		{"2026-10-13T12:04:59Z", "2026-10-13T12:04:59.000000000Z"},
		{"2026-10-13T14:00:00+02:00", "2026-10-13T12:00:00.000000000Z"},
		{"2020-01-01T00:00:00Z", "2020-01-01T00:00:00.000000000Z"},
		{"not a time", MinCanonicalTimestamp},
	}
	for _, test := range tests {
		if got := Timestamp_NormalizeWriteTime(test.value, now); got != test.expected {
			t.Fatalf("write time %q = %q; expected %q", test.value, got, test.expected)
		}
	}
	if got := Timestamp_WriteTimeLimit(now); got != latest {
		t.Fatalf("write time limit = %q; expected %q", got, latest)
	}
}

// Last-writer-wins must not let a far-future time freeze a record against
// every later edit, and records frozen before the limit existed must recover.
func TestRecordTimesCannotFreezeRecords(t *testing.T) {
	server, store, _ := testServer(t)
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x73)
	write := func(ciphertext string, updated string, deleted string) {
		t.Helper()
		record := `{"collection":"private.inbe.v1.notes","id":"note-1","key_id":"main","nonce":"n1","ciphertext":"` +
			ciphertext + `","updated_at":"` + updated + `"` + deleted + `}`
		syncWithBody(t, handler, "", identity.UserID, identity.Token, []byte(syncRecordBody(identity, "5", "", record)))
	}

	write("pinned", "9999-12-31T23:59:59Z", "")
	_, updated := storedRecord(t, store, identity.UserID, "private.inbe.v1.notes", "note-1")
	stored, err := time.Parse(time.RFC3339Nano, updated)
	if err != nil {
		t.Fatal(err)
	}
	if stored.After(time.Now().Add(5*time.Minute + time.Second)) {
		t.Fatalf("far-future time stored as %s", updated)
	}

	// A frozen row written before the limit existed still yields to a current edit.
	if _, err := store.Database.Exec(
		"UPDATE server_encrypted_records SET updated_at='9999-12-31T23:59:59.000000000Z' WHERE user_id_hash=?1",
		identity.UserID); err != nil {
		t.Fatal(err)
	}
	write("current", time.Now().UTC().Format(time.RFC3339Nano), "")
	if ciphertext, _ := storedRecord(t, store, identity.UserID, "private.inbe.v1.notes", "note-1"); ciphertext != "current" {
		t.Fatalf("current edit did not replace a frozen record: %q", ciphertext)
	}

	// A far-future deletion only holds until the clock passes the limit.
	write("", "9999-12-31T23:59:59Z", `,"deleted_at":1`)
	time.Sleep(10 * time.Millisecond)
	write("restored", time.Now().UTC().Add(5*time.Minute).Format(time.RFC3339Nano), "")
	if ciphertext, _ := storedRecord(t, store, identity.UserID, "private.inbe.v1.notes", "note-1"); ciphertext != "restored" {
		t.Fatalf("far-future deletion blocked a later edit: %q", ciphertext)
	}

	// An older edit still loses to a newer one.
	write("stale", "2020-01-01T00:00:00Z", "")
	if ciphertext, _ := storedRecord(t, store, identity.UserID, "private.inbe.v1.notes", "note-1"); ciphertext != "restored" {
		t.Fatalf("older edit replaced a newer record: %q", ciphertext)
	}
}

// Mesh peers follow the same limit for imported records and deletions.
func TestMeshImportCannotFreezeRecords(t *testing.T) {
	server, store, _ := testServer(t)
	user := newTestIdentity(t, server.Routes(), 0x74).UserID
	inTransaction := func(apply func(*sql.Tx) MeshImportResult) MeshImportResult {
		t.Helper()
		tx, err := store.Database.BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			_ = tx.Rollback()
		}()
		result := apply(tx)
		if result.Error != nil {
			t.Fatal(result.Error)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		return result
	}
	record := func(ciphertext string, updated string) EncryptedRecord {
		return EncryptedRecord{Collection: "private.inbe.v1.notes", ID: "note-1", KeyID: "main", Nonce: "n1",
			Ciphertext: ciphertext, UpdatedAt: updated}
	}

	inTransaction(func(tx *sql.Tx) MeshImportResult {
		return MeshStore_UpsertRecord(tx, t.Context(), user, record("pinned", "9999-12-31T23:59:59Z"))
	})
	_, updated := storedRecord(t, store, user, "private.inbe.v1.notes", "note-1")
	stored, err := time.Parse(time.RFC3339Nano, updated)
	if err != nil {
		t.Fatal(err)
	}
	if stored.After(time.Now().Add(5*time.Minute + time.Second)) {
		t.Fatalf("mesh import stored far-future time %s", updated)
	}

	if _, err := store.Database.Exec(
		"UPDATE server_encrypted_records SET updated_at='9999-12-31T23:59:59.000000000Z' WHERE user_id_hash=?1", user); err != nil {
		t.Fatal(err)
	}
	applied := inTransaction(func(tx *sql.Tx) MeshImportResult {
		return MeshStore_UpsertRecord(tx, t.Context(), user, record("current", time.Now().UTC().Format(time.RFC3339Nano)))
	})
	if ciphertext, _ := storedRecord(t, store, user, "private.inbe.v1.notes", "note-1"); applied.Value != 1 || ciphertext != "current" {
		t.Fatalf("mesh edit did not replace a frozen record: %d %q", applied.Value, ciphertext)
	}

	if _, err := store.Database.Exec(
		"UPDATE server_encrypted_records SET updated_at='9999-12-31T23:59:59.000000000Z' WHERE user_id_hash=?1", user); err != nil {
		t.Fatal(err)
	}
	deleted := inTransaction(func(tx *sql.Tx) MeshImportResult {
		return MeshStore_ApplyDeletion(tx, t.Context(), MeshEncryptedRecordDeletion{UserIDHash: user,
			Collection: "private.inbe.v1.notes", ID: "note-1", DeletedAt: time.Now().UTC().Format(time.RFC3339Nano)})
	})
	if deleted.Value != 1 {
		t.Fatal("mesh deletion did not remove a frozen record")
	}
}

// An omitted list in a paired peer's request must not mean "everything" when
// the approved policy names specific apps, collections or trust spaces.
func TestMeshRequestCannotWidenApprovedScopeByOmission(t *testing.T) {
	approved := NodeSyncPolicy{Direction: "push", Apps: []string{"inbe"},
		Collections: []string{"private.inbe.v1.*"}, Spaces: []string{"home"}, Data: []string{"encrypted_records"}}
	full := NodeSyncPolicy{Apps: []string{"inbe"}, Collections: []string{"private.inbe.v1.*"},
		Spaces: []string{"home"}, Data: []string{"encrypted_records"}}
	if !MeshPolicy_AllowsOperation(approved, full, "export") {
		t.Fatal("the approved scope itself was rejected")
	}
	omitted := []NodeSyncPolicy{
		{Collections: full.Collections, Spaces: full.Spaces, Data: full.Data},
		{Apps: full.Apps, Spaces: full.Spaces, Data: full.Data},
		{Apps: full.Apps, Collections: full.Collections, Data: full.Data},
	}
	for _, requested := range omitted {
		if MeshPolicy_AllowsOperation(approved, requested, "export") {
			t.Fatalf("omitted list widened the approved scope: %#v", requested)
		}
	}
}

// One account cannot flood the node with full-account syncs.
func TestSyncIsRateLimitedPerAccount(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x76)
	body := `{"protocol_version":5,"user_id_hash":"` + identity.UserID + `","client_id":"security-client"}`
	limited := 0
	for attempt := 0; attempt < 301; attempt++ {
		status, _ := postSync(t, handler, identity, body)
		if status == http.StatusTooManyRequests {
			limited++
		} else if status != http.StatusOK {
			t.Fatalf("sync %d status = %d", attempt, status)
		}
	}
	if limited != 1 {
		t.Fatalf("limited %d of 301 syncs; expected only the 301st", limited)
	}
}
