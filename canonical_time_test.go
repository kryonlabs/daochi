package main

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeTimeCanonicalFormat(t *testing.T) {
	cases := []struct {
		name     string
		primary  string
		fallback string
		want     string
	}{
		{"whole second Z", "2026-01-02T10:00:00Z", "", "2026-01-02T10:00:00.000000000Z"},
		{"fractional second", "2026-01-02T10:00:00.5Z", "", "2026-01-02T10:00:00.500000000Z"},
		{"nine digit fraction", "2026-01-02T10:00:00.123456789Z", "", "2026-01-02T10:00:00.123456789Z"},
		{"offset converts to UTC", "2026-01-02T12:00:00+02:00", "", "2026-01-02T10:00:00.000000000Z"},
		{"sqlite CURRENT_TIMESTAMP format", "2026-01-02 10:00:00", "", "2026-01-02T10:00:00.000000000Z"},
		{"garbage is oldest", "not-a-timestamp", "", minCanonicalTimestamp},
		{"empty falls back", "", "2026-01-02T10:00:00Z", "2026-01-02T10:00:00.000000000Z"},
		{"empty with garbage fallback", "", "garbage", minCanonicalTimestamp},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeTime(tc.primary, tc.fallback)
			if got != tc.want {
				t.Fatalf("normalizeTime(%q, %q) = %q, want %q", tc.primary, tc.fallback, got, tc.want)
			}
		})
	}
	if got := normalizeTime("", ""); !strings.HasSuffix(got, "Z") || len(got) != len(minCanonicalTimestamp) {
		t.Fatalf("normalizeTime empty/empty = %q, want canonical now", got)
	}
}

// TestCanonicalTimestampOrdering pins the core property: canonical strings
// sort chronologically. RFC3339Nano output violated this — "…:00.5Z"
// sorted before "…:00Z" because '.' < 'Z'.
func TestCanonicalTimestampOrdering(t *testing.T) {
	pairs := []struct {
		earlier string
		later   string
	}{
		{"2026-01-02T10:00:00Z", "2026-01-02T10:00:00.5Z"},
		{"2026-01-02T10:00:00.5Z", "2026-01-02T10:00:01Z"},
		{"2026-01-02T09:59:59.999999999Z", "2026-01-02T10:00:00Z"},
		{"2026-01-02T10:00:00.000000001Z", "2026-01-02T10:00:00.000000002Z"},
		{"2026-01-02T12:00:00+02:00", "2026-01-02T11:00:01Z"},
		{"2026-01-02 10:00:00", "2026-01-02T10:00:00.000000001Z"},
	}
	for _, pair := range pairs {
		a, b := normalizeTime(pair.earlier, ""), normalizeTime(pair.later, "")
		if a >= b {
			t.Fatalf("canonical(%q)=%q not before canonical(%q)=%q", pair.earlier, a, pair.later, b)
		}
	}
	if a, b := normalizeTime("2026-01-02T12:00:00+02:00", ""), normalizeTime("2026-01-02T10:00:00Z", ""); a != b {
		t.Fatalf("same instant canonicalized differently: %q vs %q", a, b)
	}
}

// TestEncryptedRecordFractionalSecondLWW is the regression test for the
// original bug: a write timestamped half a second after a whole-second
// write used to lose the lexicographic last-write-wins comparison.
func TestEncryptedRecordFractionalSecondLWW(t *testing.T) {
	_, store, _ := testServer(t)
	ctx := context.Background()
	const userID = "lww-user"
	base := func(updatedAt, ciphertext string) SyncRequest {
		return SyncRequest{
			UserIDHash:      userID,
			ProtocolVersion: 5,
			EncryptedRecords: []EncryptedRecord{{
				Collection: "private.inbe.v1.habits",
				ID:         "record-1",
				Ciphertext: ciphertext,
				UpdatedAt:  updatedAt,
			}},
		}
	}
	stored := func() (string, string) {
		var ciphertext, updatedAt string
		if err := store.db.QueryRowContext(ctx,
			`SELECT ciphertext,updated_at FROM server_encrypted_records
			 WHERE user_id_hash=?1 AND collection=?2 AND id=?3`,
			userID, "private.inbe.v1.habits", "record-1").Scan(&ciphertext, &updatedAt); err != nil {
			t.Fatal(err)
		}
		return ciphertext, updatedAt
	}

	if _, err := store.ApplySync(ctx, base("2026-01-02T10:00:00Z", "first"), []byte("pub")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApplySync(ctx, base("2026-01-02T10:00:00.5Z", "second"), []byte("pub")); err != nil {
		t.Fatal(err)
	}
	if ciphertext, updatedAt := stored(); ciphertext != "second" || updatedAt != "2026-01-02T10:00:00.500000000Z" {
		t.Fatalf("fractional-second write lost: ciphertext=%q updated_at=%q", ciphertext, updatedAt)
	}
	if _, err := store.ApplySync(ctx, base("2026-01-02T10:00:00.25Z", "third"), []byte("pub")); err != nil {
		t.Fatal(err)
	}
	if ciphertext, _ := stored(); ciphertext != "second" {
		t.Fatalf("older write overwrote newer: ciphertext=%q", ciphertext)
	}
}

// TestHabitFractionalSecondLWW covers the same comparison shape on the
// typed habit tables.
func TestHabitFractionalSecondLWW(t *testing.T) {
	_, store, _ := testServer(t)
	ctx := context.Background()
	const userID = "lww-habit-user"
	sync := func(updatedAt, name string) SyncRequest {
		return SyncRequest{
			UserIDHash:      userID,
			ProtocolVersion: 5,
			Habits:          []Habit{{ID: "habit-1", Name: name, UpdatedAt: updatedAt}},
		}
	}
	stored := func() (string, string) {
		var name, updatedAt string
		// habit IDs are canonicalized on write, so look up by user.
		if err := store.db.QueryRowContext(ctx,
			`SELECT name,updated_at FROM server_habits WHERE user_id_hash=?1`,
			userID).Scan(&name, &updatedAt); err != nil {
			t.Fatal(err)
		}
		return name, updatedAt
	}

	if _, err := store.ApplySync(ctx, sync("2026-01-02T10:00:00Z", "first"), []byte("pub")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApplySync(ctx, sync("2026-01-02T10:00:00.5Z", "second"), []byte("pub")); err != nil {
		t.Fatal(err)
	}
	if name, updatedAt := stored(); name != "second" || updatedAt != "2026-01-02T10:00:00.500000000Z" {
		t.Fatalf("fractional-second habit write lost: name=%q updated_at=%q", name, updatedAt)
	}
}

// TestCompactSyncOpsUsesRecentClientFloor is the regression test for the
// CURRENT_TIMESTAMP vs RFC3339 cutoff mismatch: server_clients.last_seen_at
// was written in SQLite's "YYYY-MM-DD HH:MM:SS" format and compared against
// an RFC3339 cutoff, so the active-client floor never matched and sync ops
// were never compacted.
func TestCompactSyncOpsUsesRecentClientFloor(t *testing.T) {
	_, store, _ := testServer(t)
	ctx := context.Background()
	const userID = "compact-user"
	// One real write so the user's server_version is bumped past the op's.
	if _, err := store.ApplySync(ctx, SyncRequest{
		UserIDHash:      userID,
		ProtocolVersion: 5,
		EncryptedRecords: []EncryptedRecord{{
			Collection: "private.inbe.v1.habits",
			ID:         "seed-1",
			Ciphertext: "data",
			UpdatedAt:  "2026-01-02T10:00:00Z",
		}},
	}, []byte("pub")); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordClientSync(ctx, userID, "client-1", 0, 0, 2, 42); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `
INSERT INTO server_sync_ops(user_id_hash,op_id,client_id,seq,entity_type,entity_id,local_date,op_type,payload_json,created_at,server_version)
VALUES(?1,'op-1','client-1',1,'habit','habit-1',0,'upsert','{}',?2,1)`,
		userID, canonicalNow()); err != nil {
		t.Fatal(err)
	}
	if err := store.CompactSyncOps(ctx, userID); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err := store.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM server_sync_ops WHERE user_id_hash=?1`, userID).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("sync op not compacted despite active client floor: %d remaining", remaining)
	}
}

// TestCanonicalizeStoredTimestampsMigration plants legacy-format timestamp
// rows, rewinds PRAGMA user_version, and reopens the store to verify the
// one-time canonicalization rewrite preserves instants.
func TestCanonicalizeStoredTimestampsMigration(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "ts-migration.db")
	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite3", dbPath+"?_busy_timeout=5000&_foreign_keys=on")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version=0`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO server_users(user_id_hash,public_key,created_at,last_seen_at)
		VALUES('ts-user',x'00','2026-01-01 09:00:00','2026-01-01 09:30:00')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO server_habits(user_id_hash,id,name,color_r,color_g,color_b,sync_mode,sync_activity,counter_enabled,sort_order,deleted_at,updated_at,server_version)
		VALUES('ts-user','habit-1','legacy',0,0,0,0,0,0,0,0,'2026-01-01 10:00:00',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO server_encrypted_records(user_id_hash,collection,id,key_id,nonce,ciphertext,updated_at,deleted_at,content_hash,schema_version,parent_id,server_version)
		VALUES('ts-user','private.inbe.v1.habits','record-1','','','data','2026-01-01T10:00:00Z',0,'',0,'',1)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = OpenStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()

	var habitUpdated, recordUpdated, userSeen string
	if err := store.db.QueryRowContext(ctx,
		`SELECT updated_at FROM server_habits WHERE user_id_hash='ts-user'`).Scan(&habitUpdated); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(ctx,
		`SELECT updated_at FROM server_encrypted_records WHERE user_id_hash='ts-user' AND id='record-1'`).Scan(&recordUpdated); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(ctx,
		`SELECT last_seen_at FROM server_users WHERE user_id_hash='ts-user'`).Scan(&userSeen); err != nil {
		t.Fatal(err)
	}
	if want := "2026-01-01T10:00:00.000000000Z"; habitUpdated != want || recordUpdated != want {
		t.Fatalf("migration did not canonicalize: habit=%q record=%q want=%q", habitUpdated, recordUpdated, want)
	}
	if want := "2026-01-01T09:30:00.000000000Z"; userSeen != want {
		t.Fatalf("migration did not canonicalize user last_seen_at: %q want %q", userSeen, want)
	}
	var version int
	if err := store.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != timestampSchemaVersion {
		t.Fatalf("user_version = %d, want %d", version, timestampSchemaVersion)
	}

	// Reopening must not rewrite again (guard works).
	if err := store.canonicalizeStoredTimestamps(ctx); err != nil {
		t.Fatal(err)
	}
}
