package main

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

// TestMigrateUpgradesLegacyMeshChanges verifies the real pre-tombstone
// database shape upgrades in place: the delete trigger references the op
// column, so the column must exist by the time migrate() creates it.
func TestMigrateUpgradesLegacyMeshChanges(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy-mesh.db")
	db, err := sql.Open("sqlite3", dbPath+"?_busy_timeout=5000&_foreign_keys=on")
	if err != nil {
		t.Fatal(err)
	}
	// Minimal pre-tombstone schema for the pieces migrate() touches first.
	if _, err := db.Exec(`
CREATE TABLE server_users (
	user_id_hash TEXT PRIMARY KEY,
	public_key BLOB NOT NULL,
	alias TEXT UNIQUE,
	profile_icon INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE server_encrypted_records (
	user_id_hash TEXT NOT NULL,
	collection TEXT NOT NULL,
	id TEXT NOT NULL,
	key_id TEXT NOT NULL DEFAULT '',
	nonce TEXT NOT NULL DEFAULT '',
	ciphertext TEXT NOT NULL DEFAULT '',
	updated_at TEXT NOT NULL,
	deleted_at INTEGER NOT NULL DEFAULT 0,
	content_hash TEXT NOT NULL DEFAULT '',
	schema_version INTEGER NOT NULL DEFAULT 0,
	parent_id TEXT NOT NULL DEFAULT '',
	server_version INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY(user_id_hash, collection, id)
);
CREATE TABLE server_mesh_changes (
	seq INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id_hash TEXT NOT NULL,
	collection TEXT NOT NULL,
	record_id TEXT NOT NULL,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO server_users(user_id_hash,public_key) VALUES('legacy-user',x'00');
INSERT INTO server_encrypted_records(user_id_hash,collection,id,ciphertext,updated_at)
VALUES('legacy-user','inbe.habits','legacy-1','data','2026-01-01T10:00:00Z');
`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("open legacy store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()

	// The upgrade must leave a delete trigger that actually logs tombstones.
	if _, err := store.db.ExecContext(ctx,
		`DELETE FROM server_encrypted_records WHERE user_id_hash='legacy-user'`); err != nil {
		t.Fatal(err)
	}
	var deletedAt string
	if err := store.db.QueryRowContext(ctx,
		`SELECT deleted_at FROM server_mesh_changes WHERE record_id='legacy-1' AND op='delete'`).Scan(&deletedAt); err != nil {
		t.Fatalf("no tombstone logged after delete: %v", err)
	}
	if deletedAt == "" {
		t.Fatal("tombstone row has empty deleted_at")
	}
	// Old upsert rows must default to op='upsert'.
	var upserts int
	if err := store.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM server_mesh_changes WHERE op='upsert'`).Scan(&upserts); err != nil {
		t.Fatal(err)
	}
	if upserts == 0 {
		t.Fatal("legacy change rows were not defaulted to op='upsert'")
	}
}
