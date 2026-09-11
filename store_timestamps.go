package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
)

// timestampSchemaVersion gates the one-time stored-timestamp rewrite via
// PRAGMA user_version. Bump it whenever a new rewrite pass is added.
const timestampSchemaVersion = 1

// canonicalTimestampColumns lists every stored column that participates in
// lexicographic timestamp comparisons (last-write-wins guards, cutoffs,
// max()). All of them must hold canonicalTimestampLayout values.
var canonicalTimestampColumns = []struct{ table, column string }{
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
// canonicalTimestampLayout, preserving the parsed instant. Unparseable
// values are left as-is; normalizeTime treats them as the oldest possible
// timestamp. The rewrite bumps server_encrypted_records.updated_at, so
// the mesh change log records one harmless re-export pass per upgrade;
// peers skip those rows as no-op ties.
func (s *Store) canonicalizeStoredTimestamps(ctx context.Context) error {
	var version int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version >= timestampSchemaVersion {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rewritten := 0
	for _, target := range canonicalTimestampColumns {
		count, err := canonicalizeColumn(ctx, tx, target.table, target.column)
		if err != nil {
			return fmt.Errorf("canonicalize %s.%s: %w", target.table, target.column, err)
		}
		rewritten += count
	}
	if _, err := tx.ExecContext(ctx,
		fmt.Sprintf(`PRAGMA user_version=%d`, timestampSchemaVersion)); err != nil {
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

func canonicalizeColumn(ctx context.Context, tx *sql.Tx, table, column string) (int, error) {
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
		t, ok := parseTimestamp(value.String)
		if !ok {
			continue
		}
		if canonical := canonicalTimestamp(t); canonical != value.String {
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
