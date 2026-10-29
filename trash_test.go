package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDeletedRecordsKeepNoContentAndCostNothing(t *testing.T) {
	for _, pages := range []bool{false, true} {
		fixture := authorizationSetup(t)
		record := accountStorageRecord("cell.diary.file.gone", 400, "2026-10-10T00:00:00Z")
		if result := fixture.ownerSync(t, pages, record); result.Code != http.StatusOK {
			t.Fatalf("store record: %d %s", result.Code, result.Body.String())
		}
		before := AccountStorage_Used(fixture.store.Database, t.Context(), fixture.owner.UserID)
		if before.Error != nil {
			t.Fatal(before.Error)
		}
		// A deletion that still carries the old content keeps none of it.
		deleted := record
		deleted.DeletedAt = 1760054400
		deleted.UpdatedAt = "2026-10-10T00:00:01Z"
		if result := fixture.ownerSync(t, pages, deleted); result.Code != http.StatusOK {
			t.Fatalf("delete record: %d %s", result.Code, result.Body.String())
		}
		var nonce, ciphertext string
		var deletedAt int64
		if err := fixture.store.Database.QueryRow("SELECT nonce,ciphertext,deleted_at FROM server_encrypted_records WHERE id=?1", record.ID).Scan(&nonce, &ciphertext, &deletedAt); err != nil {
			t.Fatal(err)
		}
		if nonce != "" || ciphertext != "" || deletedAt != deleted.DeletedAt {
			t.Fatalf("tombstone kept content: nonce %q ciphertext %d bytes deleted %d", nonce, len(ciphertext), deletedAt)
		}
		after := AccountStorage_Used(fixture.store.Database, t.Context(), fixture.owner.UserID)
		if after.Error != nil || after.Value != before.Value-accountStorageBytes(record) {
			t.Fatalf("usage after deletion %#v, want %d", after, before.Value-accountStorageBytes(record))
		}
		assertStorageUsage(t, fixture.store, fixture.owner.UserID)
	}
}

func TestSchemaUpgradeDropsContentOfEarlierTombstones(t *testing.T) {
	_, store, _ := testServer(t)
	user := strings.Repeat("d", 64)
	if err := store.RegisterUser(t.Context(), user, []byte("fixture")); err != nil {
		t.Fatal(err)
	}
	// Tombstones written before this release kept their content.
	lifecycleExecute(t, store, "DROP TRIGGER server_encrypted_records_tombstone_insert")
	lifecycleExecute(t, store, "INSERT INTO server_encrypted_records(user_id_hash,collection,id,key_id,nonce,ciphertext,updated_at,deleted_at) VALUES(?1,'private.inbe.v1.cells','old','main','nonce',?2,'2026-10-01T00:00:00Z',1)", user, strings.Repeat("x", 100))
	if err := StoreSchema_Ensure(store.Database, t.Context()); err != nil {
		t.Fatal(err)
	}
	var ciphertext string
	if err := store.Database.QueryRow("SELECT ciphertext FROM server_encrypted_records WHERE id='old'").Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if ciphertext != "" {
		t.Fatal("upgrade kept the content of an earlier tombstone")
	}
	assertStorageUsage(t, store, user)
}

func TestBlobTrashStopsChargingRestoresWithRoomAndPurgesAfterThirtyDays(t *testing.T) {
	server, user, key := registryHTTPFixture(t)
	server.Verifier = testVerifier(&transactionVerifier{accept: true})
	server.Cfg.DBPath = filepath.Join(t.TempDir(), "node.sqlite")
	store := server.Store
	base := AccountStorage_Used(store.Database, t.Context(), user)
	if base.Error != nil {
		t.Fatal(base.Error)
	}
	data := bytes.Repeat([]byte{0x07}, 40)
	hash := Signing_SHA256Hex(data)
	address := "/api/v1/blobs/target/" + hash
	sequence := 0
	call := func(method, path string, body []byte) *httptest.ResponseRecorder {
		t.Helper()
		sequence++
		recorder := httptest.NewRecorder()
		nonce := fmt.Sprintf("trash-request-%02d", sequence)
		Server_HandleBlobHttpRoute(server, recorder, blobRequest(t, server, user, key, method, path, body, nonce))
		return recorder
	}
	used := func() int64 {
		t.Helper()
		value := AccountStorage_Used(store.Database, t.Context(), user)
		if value.Error != nil {
			t.Fatal(value.Error)
		}
		return value.Value
	}
	if result := call("PUT", address, data); result.Code != http.StatusNoContent {
		t.Fatalf("put = %d", result.Code)
	}
	if used() != base.Value+40 {
		t.Fatal("stored blob not charged")
	}

	if result := call("POST", address+"/trash", nil); result.Code != http.StatusNoContent {
		t.Fatalf("trash = %d %s", result.Code, result.Body.String())
	}
	if used() != base.Value {
		t.Fatal("trashed blob still charged")
	}
	if result := call("GET", address, nil); result.Code != http.StatusOK || !bytes.Equal(result.Body.Bytes(), data) {
		t.Fatalf("trashed blob unreadable: %d", result.Code)
	}
	if result := call("POST", address+"/trash", nil); result.Code != http.StatusNoContent {
		t.Fatalf("trashing again = %d", result.Code)
	}
	other := "/api/v1/blobs/target/" + strings.Repeat("e", 64)
	if result := call("POST", other+"/trash", nil); result.Code != http.StatusNotFound {
		t.Fatalf("trashing an unknown blob = %d", result.Code)
	}
	if result := call("POST", address, nil); result.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST without an action = %d", result.Code)
	}
	if result := call("PUT", address+"/trash", data); result.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT to an action = %d", result.Code)
	}
	if result := call("POST", address+"/empty", nil); result.Code != http.StatusBadRequest {
		t.Fatalf("unknown action = %d", result.Code)
	}

	// Coming back out of the trash, or being stored again, needs room.
	server.Cfg.AccountStorageLimitBytes = base.Value + 10
	if result := call("POST", address+"/restore", nil); result.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("restore into a full account = %d", result.Code)
	}
	if result := call("PUT", address, data); result.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("storing a trashed blob into a full account = %d", result.Code)
	}
	if used() != base.Value {
		t.Fatal("refused restore changed usage")
	}
	server.Cfg.AccountStorageLimitBytes = 0
	if result := call("POST", address+"/restore", nil); result.Code != http.StatusNoContent {
		t.Fatalf("restore = %d", result.Code)
	}
	if used() != base.Value+40 {
		t.Fatal("restored blob not charged")
	}
	if result := call("POST", address+"/trash", nil); result.Code != http.StatusNoContent {
		t.Fatalf("trash before storing again = %d", result.Code)
	}
	if result := call("PUT", address, data); result.Code != http.StatusNoContent || used() != base.Value+40 {
		t.Fatalf("storing a trashed blob again = %d, used %d", result.Code, used())
	}
	if result := call("POST", address+"/trash", nil); result.Code != http.StatusNoContent {
		t.Fatalf("trash before purge = %d", result.Code)
	}

	file := filepath.Join(AccountStorage_BlobAccountFolder(server.Cfg.DBPath, user), "target", hash)
	if err := Retention_PruneFiles(store.Database, t.Context(), server.Cfg.DBPath, time.Now().Add(29*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("trashed blob deleted before 30 days: %v", err)
	}
	if err := Retention_PruneFiles(store.Database, t.Context(), server.Cfg.DBPath, time.Now().Add(30*24*time.Hour+time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("trashed blob file survived 30 days: %v", err)
	}
	stored := AccountStorage_BlobStored(store.Database, t.Context(), user, "target", hash)
	if stored.Error != nil || stored.Value {
		t.Fatalf("trashed blob row survived 30 days: %#v", stored)
	}
	if result := call("GET", address, nil); result.Code != http.StatusNotFound {
		t.Fatalf("purged blob still readable: %d", result.Code)
	}
	assertStorageUsage(t, store, user)
}
