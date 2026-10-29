package main

import (
	"strings"
	"testing"
)

func applyStorageMeshRecord(t *testing.T, store *Store, user string, record EncryptedRecord) {
	t.Helper()
	transaction, err := store.Database.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ignoreCleanupError(transaction.Rollback)
	result := MeshStore_UpsertRecord(transaction, t.Context(), user, record)
	if result.Error != nil {
		t.Fatal(result.Error)
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestStorageMetadataSurvivesEqualTimeMeshSync(t *testing.T) {
	legacy := accountStorageRecord("session", 200, "2026-10-10T00:00:00Z")
	legacy.Collection = "private.inbe.v1.sessions"
	legacy.Ciphertext = strings.Repeat("z", 200)
	legacy.ContentHash = strings.Repeat("b", 64)
	legacy.SchemaVersion = 1
	upgraded := legacy
	upgraded.Ciphertext = strings.Repeat("a", 200)
	upgraded.Nonce = "fresh-nonce"
	upgraded.FreeBytes = accountStorageBytes(upgraded) - 4

	for _, legacyFirst := range []bool{true, false} {
		name := "upgraded-first"
		if legacyFirst {
			name = "legacy-first"
		}
		t.Run(name, func(t *testing.T) {
			_, store, _ := testServer(t)
			user := strings.Repeat("a", 64)
			if err := store.RegisterUser(t.Context(), user, []byte("fixture")); err != nil {
				t.Fatal(err)
			}
			records := []EncryptedRecord{upgraded, legacy}
			if legacyFirst {
				records = []EncryptedRecord{legacy, upgraded}
			}
			for _, record := range records {
				applyStorageMeshRecord(t, store, user, record)
			}
			used := AccountStorage_Used(store.Database, t.Context(), user)
			if used.Error != nil || used.Value != 4 {
				t.Fatalf("mesh restored charges for unchanged tracking fields: got %#v, want 4 note bytes", used)
			}
		})
	}
}

func TestStorageMetadataPreservesOtherMeshConflictRules(t *testing.T) {
	cases := []struct {
		name   string
		change func(*EncryptedRecord)
	}{
		{"deletion", func(record *EncryptedRecord) { record.DeletedAt = 1 }},
		{"key", func(record *EncryptedRecord) { record.KeyID = "other-key" }},
		{"schema", func(record *EncryptedRecord) { record.SchemaVersion = 2 }},
		{"parent", func(record *EncryptedRecord) { record.ParentID = "parent" }},
		{"content", func(record *EncryptedRecord) { record.ContentHash = strings.Repeat("c", 64) }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, store, _ := testServer(t)
			user := strings.Repeat("a", 64)
			if err := store.RegisterUser(t.Context(), user, []byte("fixture")); err != nil {
				t.Fatal(err)
			}
			incoming := accountStorageRecord("session", 200, "2026-10-10T00:00:00Z")
			incoming.Collection = "private.inbe.v1.sessions"
			incoming.Ciphertext = strings.Repeat("a", 200)
			incoming.ContentHash = strings.Repeat("b", 64)
			incoming.SchemaVersion = 1
			incoming.FreeBytes = accountStorageBytes(incoming) - 4
			stored := incoming
			stored.FreeBytes = 0
			stored.Ciphertext = strings.Repeat("z", 200)
			test.change(&stored)
			applyStorageMeshRecord(t, store, user, stored)
			applyStorageMeshRecord(t, store, user, incoming)
			var ciphertext string
			var freeBytes, deletedAt int64
			if err := store.Database.QueryRow(`SELECT ciphertext,free_bytes,deleted_at FROM server_encrypted_records WHERE user_id_hash=?1`, user).Scan(&ciphertext, &freeBytes, &deletedAt); err != nil {
				t.Fatal(err)
			}
			// A deleted record keeps no content, but stays deleted.
			want := stored.Ciphertext
			if stored.DeletedAt != 0 {
				want = ""
			}
			if ciphertext != want || freeBytes != 0 || deletedAt != stored.DeletedAt {
				t.Fatalf("accounting metadata changed the existing content conflict rule: %d content bytes, %d free, deleted %d",
					len(ciphertext), freeBytes, deletedAt)
			}
		})
	}
}
