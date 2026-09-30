package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"
)

// baselineTimestampSchemaVersion gates the one-time stored-timestamp rewrite via
// PRAGMA user_version. Bump it whenever a new rewrite pass is added.
const baselineTimestampSchemaVersion = 1

// baselineTimestampColumns lists every stored column that participates in
// lexicographic timestamp comparisons (last-write-wins guards, cutoffs,
// max()). All of them must hold baselineCanonicalTimestampLayout values.
var baselineTimestampColumns = []struct{ table, column string }{
	{"server_habits", "updated_at"},
	{"server_habit_days", "updated_at"},
	{"server_sessions", "updated_at"},
	{"server_sessions", "started_at"},
	{"server_meditation_logs", "completed_at"},
	{"server_encrypted_records", "updated_at"},
	{"server_social_snapshots", "updated_at"},
	{"server_sync_ops", "created_at"},
	{"server_users", "created_at"},
	{"server_users", "last_seen_at"},
	{"server_clients", "last_seen_at"},
	{"server_clients", "last_login_at"},
	{"server_clients", "last_sync_at"},
	{"server_encrypted_payloads", "created_at"},
}

// canonicalizeStoredTimestamps rewrites legacy timestamp text (RFC 3339
// with trimmed fractions, SQLite CURRENT_TIMESTAMP output) into
// baselineCanonicalTimestampLayout, preserving the parsed instant. Unparseable
// values are left as-is; baselineNormalizeTime treats them as the oldest possible
// timestamp. The rewrite bumps server_encrypted_records.updated_at, so
// the mesh change log records one harmless re-export pass per upgrade;
// peers skip those rows as no-op ties.
func baselineCanonicalizeStoredTimestamps(db *sql.DB, ctx context.Context) error {
	var version int
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version >= baselineTimestampSchemaVersion {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rewritten := 0
	for _, target := range baselineTimestampColumns {
		count, err := baselineCanonicalizeColumn(ctx, tx, target.table, target.column)
		if err != nil {
			return fmt.Errorf("canonicalize %s.%s: %w", target.table, target.column, err)
		}
		rewritten += count
	}
	if _, err := tx.ExecContext(ctx,
		fmt.Sprintf(`PRAGMA user_version=%d`, baselineTimestampSchemaVersion)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if rewritten > 0 {
		slog.Info("canonicalized stored timestamps", "values_rewritten", rewritten)
	}
	return nil
}

func baselineCanonicalizeColumn(ctx context.Context, tx *sql.Tx, table, column string) (int, error) {
	rows, err := tx.QueryContext(ctx, fmt.Sprintf(`SELECT rowid, %s FROM %s`, column, table))
	if err != nil {
		return 0, err
	}
	type pendingRewrite struct {
		rowid int64
		value string
	}
	pending := []pendingRewrite{}
	for rows.Next() {
		var rowid int64
		var value sql.NullString
		if err := rows.Scan(&rowid, &value); err != nil {
			rows.Close()
			return 0, err
		}
		if !value.Valid || value.String == "" {
			continue
		}
		t, ok := baselineParseTimestamp(value.String)
		if !ok {
			continue
		}
		if canonical := baselineCanonicalTimestamp(t); canonical != value.String {
			pending = append(pending, pendingRewrite{rowid: rowid, value: canonical})
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	for _, item := range pending {
		if _, err := tx.ExecContext(ctx,
			fmt.Sprintf(`UPDATE %s SET %s=?2 WHERE rowid=?1`, table, column),
			item.rowid, item.value); err != nil {
			return 0, err
		}
	}
	return len(pending), nil
}

// baselineCanonicalTimestampLayout is RFC 3339 with a fixed-width nanosecond
// fraction and UTC offset: every canonical timestamp has the same length,
// so lexicographic string order equals chronological order. Stored
// timestamps must use this layout — time.RFC3339Nano trims trailing
// fraction zeros, which makes "…:00.5Z" sort before "…:00Z".
const baselineCanonicalTimestampLayout = "2006-01-02T15:04:05.000000000Z07:00"

// baselineMinCanonicalTimestamp is the smallest canonical timestamp. Values that
// cannot be parsed are mapped to it so they deterministically lose
// last-write-wins comparisons instead of comparing unpredictably.
const baselineMinCanonicalTimestamp = "0001-01-01T00:00:00.000000000Z"

func baselineCanonicalNow() string {
	return time.Now().UTC().Format(baselineCanonicalTimestampLayout)
}

func baselineCanonicalTimestamp(t time.Time) string {
	return t.UTC().Format(baselineCanonicalTimestampLayout)
}

// baselineParseTimestamp accepts RFC 3339 timestamps plus the space-separated
// format SQLite's CURRENT_TIMESTAMP produces.
func baselineParseTimestamp(value string) (time.Time, bool) {
	if t, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return t, true
	}
	if t, err := time.Parse("2006-01-02 15:04:05", value); err == nil {
		return t, true
	}
	return time.Time{}, false
}

func baselineNormalizeTime(primary, fallback string) string {
	value := primary
	if value == "" {
		value = fallback
	}
	if value == "" {
		return baselineCanonicalNow()
	}
	if t, ok := baselineParseTimestamp(value); ok {
		return baselineCanonicalTimestamp(t)
	}
	return baselineMinCanonicalTimestamp
}

func TestZiranTimestampParsingAndNormalizationAgainstBaseline(t *testing.T) {
	values := []string{
		"", "garbage", "2026-01-02 03:04:05", "2026-01-02T03:04:05Z",
		"2026-01-02T03:04:05.123456789Z", "2026-01-02T03:04:05,5Z",
		"2026-01-02T03:04:05+05:30", "0000-01-01T00:00:00Z",
		"9999-12-31T23:59:59.999999999-23:59", "2025-02-29T00:00:00Z",
		"2024-02-29T00:00:00Z", " 2026-01-02T03:04:05Z ", "\xff",
	}
	for _, value := range values {
		got := Timestamp_ParseTimestamp(value)
		want, valid := baselineParseTimestamp(value)
		if got.Valid != valid || !got.Value.Equal(want) {
			t.Fatalf("timestamp %q: got %#v, want %v/%v", value, got, want, valid)
		}
		if got, expected := Timestamp_CanonicalTimestamp(want), baselineCanonicalTimestamp(want); got != expected {
			t.Fatalf("canonical timestamp %q: got %q, want %q", value, got, expected)
		}
		for _, fallback := range []string{"garbage", "2026-01-01 00:00:00"} {
			if got, expected := Timestamp_NormalizeTime(value, fallback), baselineNormalizeTime(value, fallback); got != expected {
				t.Fatalf("normalized timestamp %q: got %q, want %q", value, got, expected)
			}
		}
	}
	before := time.Now()
	now, err := time.Parse(CanonicalTimestampLayout, Timestamp_NormalizeTime("", ""))
	if err != nil || now.Before(before) || now.After(time.Now()) {
		t.Fatalf("empty timestamps must use current time: %v/%v", now, err)
	}
}

func timestampFixture(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	columns := make(map[string][]string)
	for _, target := range baselineTimestampColumns {
		columns[target.table] = append(columns[target.table], target.column+" TEXT")
	}
	for table, fields := range columns {
		if _, err := db.Exec(fmt.Sprintf("CREATE TABLE %s(%s)", table, strings.Join(fields, ","))); err != nil {
			t.Fatal(err)
		}
	}
	for _, target := range baselineTimestampColumns {
		for _, value := range []any{nil, "", "garbage", "2026-01-02 03:04:05", "2026-01-02T03:04:05.5+02:00", "2026-01-02T03:04:05.000000000Z"} {
			if _, err := db.Exec(fmt.Sprintf("INSERT INTO %s(%s) VALUES(?)", target.table, target.column), value); err != nil {
				t.Fatal(err)
			}
		}
	}
	return db
}

func timestampSnapshot(t *testing.T, db *sql.DB) [][]sql.NullString {
	t.Helper()
	result := make([][]sql.NullString, len(baselineTimestampColumns))
	for i, target := range baselineTimestampColumns {
		rows, err := db.Query(fmt.Sprintf("SELECT %s FROM %s ORDER BY rowid", target.column, target.table))
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var value sql.NullString
			if err := rows.Scan(&value); err != nil {
				t.Fatal(err)
			}
			result[i] = append(result[i], value)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return result
}

func TestZiranTimestampMigrationAgainstBaseline(t *testing.T) {
	actual := timestampFixture(t)
	expected := timestampFixture(t)
	if err := StoreTimestamps_Canonicalize(actual, context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := baselineCanonicalizeStoredTimestamps(expected, context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, want := timestampSnapshot(t, actual), timestampSnapshot(t, expected); !reflect.DeepEqual(got, want) {
		t.Fatalf("migrated timestamps differ: got %#v, want %#v", got, want)
	}
	if _, err := actual.Exec("INSERT INTO server_habits(updated_at) VALUES('2026-01-03 00:00:00')"); err != nil {
		t.Fatal(err)
	}
	if err := StoreTimestamps_Canonicalize(actual, context.Background()); err != nil {
		t.Fatal(err)
	}
	var value string
	if err := actual.QueryRow("SELECT updated_at FROM server_habits ORDER BY rowid DESC LIMIT 1").Scan(&value); err != nil {
		t.Fatal(err)
	}
	if value != "2026-01-03 00:00:00" {
		t.Fatal("schema version did not prevent a second migration")
	}
}

func TestZiranTimestampMigrationRollbackAndCancellation(t *testing.T) {
	actual := timestampFixture(t)
	expected := timestampFixture(t)
	trigger := "CREATE TRIGGER reject_rewrite BEFORE UPDATE ON server_clients BEGIN SELECT RAISE(ABORT, 'rewrite rejected'); END"
	for _, db := range []*sql.DB{actual, expected} {
		if _, err := db.Exec(trigger); err != nil {
			t.Fatal(err)
		}
	}
	before := timestampSnapshot(t, actual)
	got := StoreTimestamps_Canonicalize(actual, context.Background())
	want := baselineCanonicalizeStoredTimestamps(expected, context.Background())
	if got == nil || want == nil || got.Error() != want.Error() || errors.Unwrap(got) == nil {
		t.Fatalf("rewrite failure: got %v, want %v", got, want)
	}
	if after := timestampSnapshot(t, actual); !reflect.DeepEqual(after, before) {
		t.Fatal("failed migration retained earlier column updates")
	}
	var version int
	if err := actual.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 0 {
		t.Fatalf("failed migration advanced the schema version: %d/%v", version, err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := StoreTimestamps_Canonicalize(actual, canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("context cancellation identity lost: %v", err)
	}
	if _, err := actual.Exec("DROP TRIGGER reject_rewrite"); err != nil {
		t.Fatal(err)
	}
	if err := StoreTimestamps_Canonicalize(actual, context.Background()); err != nil {
		t.Fatalf("rollback left the connection or transaction unusable: %v", err)
	}
}
