package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func scopedRecord(id string, seed byte) MeshEncryptedRecord {
	item := meshPortRecord(id, 1)
	key := []byte{seed, seed + 1, seed + 2}
	digest := sha256.Sum256(key)
	item.UserIDHash = hex.EncodeToString(digest[:])
	item.PublicKey = hex.EncodeToString(key)
	return item
}

func TestMeshAccountScopeCannotBeOmittedOrWidened(t *testing.T) {
	account := strings.Repeat("a", 64)
	other := strings.Repeat("b", 64)
	approved := NodeSyncPolicy{
		Direction: "bidirectional", Apps: []string{"source"},
		Data: []string{"encrypted_records"}, Accounts: []string{account},
	}
	for _, op := range []string{"import", "export"} {
		for _, requested := range []NodeSyncPolicy{
			{Apps: approved.Apps, Data: approved.Data},
			{Apps: approved.Apps, Data: approved.Data, Accounts: []string{other}},
			{Apps: approved.Apps, Data: approved.Data, Accounts: []string{account, other}},
		} {
			if MeshPolicy_AllowsOperation(approved, requested, op) {
				t.Fatalf("%s widened account scope: %#v", op, requested)
			}
		}
		if !MeshPolicy_AllowsOperation(approved, approved, op) {
			t.Fatal("exact account scope rejected")
		}
	}
	for _, invalid := range []string{"*", "account", "", strings.Repeat("z", 64)} {
		approved.Accounts = []string{invalid}
		if MeshPolicy_ValidInbound(approved) {
			t.Fatalf("invalid account accepted: %q", invalid)
		}
	}
	legacy := NodeSyncPolicy{Direction: "bidirectional", Apps: []string{"source"}, Data: []string{"encrypted_records"}}
	encoded, err := json.Marshal(legacy)
	if err != nil || strings.Contains(string(encoded), "accounts") {
		t.Fatal("legacy policy wire shape changed", err)
	}
}

func TestMeshAccountScopedImportExportAndTombstones(t *testing.T) {
	ctx := context.Background()
	store := meshPortFixture(t)
	first, second := scopedRecord("first", 10), scopedRecord("second", 20)
	full := NodeSyncPolicy{Apps: []string{"source"}, Data: []string{"encrypted_records"}}
	imported := MeshStore_ImportEncryptedRecords(store.Database, ctx, full, []MeshEncryptedRecord{first, second}, 0, false)
	if imported.Error != nil || imported.Value != 2 {
		t.Fatal("fixture import failed", imported)
	}
	scoped := full
	scoped.Accounts = []string{first.UserIDHash}
	exported := MeshStore_ExportEncryptedRecords(store.Database, ctx, scoped, "", 100)
	if exported.Error != nil || len(exported.Records) != 1 || exported.Records[0].UserIDHash != first.UserIDHash {
		t.Fatal("export leaked another account", exported)
	}
	remote := meshPortFixture(t)
	imported = MeshStore_ImportEncryptedRecords(remote.Database, ctx, scoped, []MeshEncryptedRecord{first, second}, 0, false)
	if imported.Error != nil || imported.Value != 1 {
		t.Fatal("scoped import accepted another account", imported)
	}
	var count int
	if err := remote.Database.QueryRow("SELECT COUNT(*) FROM server_users WHERE user_id_hash=?", second.UserIDHash).Scan(&count); err != nil || count != 0 {
		t.Fatal("foreign identity persisted", count, err)
	}
	deletions := []MeshEncryptedRecordDeletion{
		{UserIDHash: first.UserIDHash, Collection: first.Record.Collection, ID: first.Record.ID, DeletedAt: "2026-10-04T00:00:00Z"},
		{UserIDHash: second.UserIDHash, Collection: second.Record.Collection, ID: second.Record.ID, DeletedAt: "2026-10-04T00:00:00Z"},
	}
	deleted := MeshStore_ImportEncryptedBatch(store.Database, ctx, scoped, nil, deletions, 0, false)
	if deleted.Error != nil || deleted.Value != 1 {
		t.Fatal("account scoped deletion failed", deleted)
	}
	if err := store.Database.QueryRow("SELECT COUNT(*) FROM server_encrypted_records WHERE user_id_hash=? AND id=?", second.UserIDHash, second.Record.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("foreign tombstone deleted a record", count, err)
	}
	exported = MeshStore_ExportEncryptedRecords(store.Database, ctx, scoped, "", 100)
	if exported.Error != nil {
		t.Fatal(exported.Error)
	}
	for _, item := range exported.Deletions {
		if item.UserIDHash != first.UserIDHash {
			t.Fatal("export leaked foreign tombstone")
		}
	}
}
