package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

type InspectOptions struct {
	DBPath string
	Full   bool
	Out    io.Writer
}

func runInspect(ctx context.Context, args []string, opts InspectOptions) error {
	if opts.Out == nil {
		opts.Out = os.Stdout
	}
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(opts.Out)
	fs.StringVar(&opts.DBPath, "db", opts.DBPath, "SQLite database path")
	fs.BoolVar(&opts.Full, "full", opts.Full, "show full user IDs and public keys")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if opts.DBPath == "" {
		opts.DBPath = envString("DAOCHI_DB", envString("KSYNC_DB", "daochi.db"))
	}
	rest := fs.Args()
	if len(rest) == 0 {
		rest = []string{"summary"}
	}

	db, err := openInspectDB(opts.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()

	switch rest[0] {
	case "summary":
		return inspectSummary(ctx, db, opts.Out)
	case "users":
		return inspectUsers(ctx, db, opts.Out, opts.Full)
	case "doctor":
		if len(rest) != 2 {
			return fmt.Errorf("usage: daochi inspect doctor <user_id_hash>")
		}
		return inspectDoctor(ctx, db, opts.Out, rest[1], opts.Full)
	case "user":
		if len(rest) != 2 {
			return fmt.Errorf("usage: daochi inspect user <user_id_hash>")
		}
		return inspectUser(ctx, db, opts.Out, rest[1], opts.Full)
	default:
		return fmt.Errorf("unknown inspect command %q", rest[0])
	}
}

func openInspectDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?mode=ro&_query_only=1", path))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func inspectSummary(ctx context.Context, db *sql.DB, out io.Writer) error {
	tables := []string{
		"server_users",
		"server_habits",
		"server_habit_days",
		"server_sessions",
		"server_session_rounds",
		"server_meditation_logs",
		"server_encrypted_records",
		"server_encrypted_payloads",
		"server_sync_audit",
	}
	fmt.Fprintln(out, "Daochi data summary")
	for _, table := range tables {
		n, err := inspectCount(ctx, db, table, "")
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%-24s %d\n", table, n)
	}
	return nil
}

func inspectUsers(ctx context.Context, db *sql.DB, out io.Writer, full bool) error {
	rows, err := db.QueryContext(ctx, `
SELECT user_id_hash, hex(public_key), created_at, last_seen_at
FROM server_users
ORDER BY last_seen_at DESC`)
	if err != nil {
		return err
	}
	defer rows.Close()

	fmt.Fprintln(out, "Users")
	for rows.Next() {
		var userID, publicKey, createdAt, lastSeenAt string
		if err := rows.Scan(&userID, &publicKey, &createdAt, &lastSeenAt); err != nil {
			return err
		}
		fmt.Fprintf(out, "%s  key=%s  created=%s  last_seen=%s\n",
			redactID(userID, full), redactID(strings.ToLower(publicKey), full),
			createdAt, lastSeenAt)
	}
	return rows.Err()
}

func inspectUser(ctx context.Context, db *sql.DB, out io.Writer, userID string, full bool) error {
	userID = strings.ToLower(strings.TrimSpace(userID))
	if !validUserID(userID) {
		return fmt.Errorf("invalid user_id_hash")
	}

	var publicKey, createdAt, lastSeenAt string
	err := db.QueryRowContext(ctx, `
SELECT hex(public_key), created_at, last_seen_at
FROM server_users
WHERE user_id_hash=?1`, userID).Scan(&publicKey, &createdAt, &lastSeenAt)
	if err == sql.ErrNoRows {
		return fmt.Errorf("user not found")
	}
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "User %s\n", redactID(userID, full))
	fmt.Fprintf(out, "public_key=%s\n", redactID(strings.ToLower(publicKey), full))
	fmt.Fprintf(out, "created=%s\nlast_seen=%s\n", createdAt, lastSeenAt)

	for _, table := range []string{"server_habits", "server_habit_days", "server_sessions", "server_session_rounds", "server_meditation_logs", "server_encrypted_records"} {
		n, err := inspectCount(ctx, db, table, "WHERE user_id_hash=?1", userID)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%-24s %d\n", table, n)
	}
	if err := inspectUserHabits(ctx, db, out, userID); err != nil {
		return err
	}
	return inspectUserSessions(ctx, db, out, userID)
}

func inspectDoctor(ctx context.Context, db *sql.DB, out io.Writer, userID string, full bool) error {
	userID = strings.ToLower(strings.TrimSpace(userID))
	if !validUserID(userID) {
		return fmt.Errorf("invalid user_id_hash")
	}

	var createdAt, lastSeenAt string
	err := db.QueryRowContext(ctx, `
SELECT created_at,last_seen_at
FROM server_users
WHERE user_id_hash=?1`, userID).Scan(&createdAt, &lastSeenAt)
	if err == sql.ErrNoRows {
		return fmt.Errorf("user not found")
	}
	if err != nil {
		return err
	}

	var version int64
	_ = db.QueryRowContext(ctx, `
SELECT server_version
FROM server_sync_state
WHERE user_id_hash=?1`, userID).Scan(&version)
	var compactedThrough int64
	_ = db.QueryRowContext(ctx, `
SELECT compacted_through_version
FROM server_sync_compaction
WHERE user_id_hash=?1`, userID).Scan(&compactedThrough)

	fmt.Fprintf(out, "Daochi doctor %s\n", redactID(userID, full))
	fmt.Fprintf(out, "status=ok server_version=%d compacted_through=%d\n", version, compactedThrough)
	fmt.Fprintf(out, "created=%s last_seen=%s\n", createdAt, lastSeenAt)

	for _, table := range []string{
		"server_habits",
		"server_habit_days",
		"server_sessions",
		"server_meditation_logs",
		"server_encrypted_records",
		"server_encrypted_payloads",
		"server_sync_ops",
		"server_clients",
		"server_sync_audit",
	} {
		n, err := inspectCount(ctx, db, table, "WHERE user_id_hash=?1", userID)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%-28s %d\n", table, n)
	}
	if err := inspectDoctorWarnings(ctx, db, out, userID); err != nil {
		return err
	}
	if err := inspectDoctorClients(ctx, db, out, userID); err != nil {
		return err
	}
	return inspectDoctorAudit(ctx, db, out, userID)
}

func inspectDoctorWarnings(ctx context.Context, db *sql.DB, out io.Writer, userID string) error {
	warnings := []string{}
	var legacyClients int
	if err := db.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM server_clients
WHERE user_id_hash=?1 AND protocol_version>0 AND protocol_version<5`, userID).Scan(&legacyClients); err != nil {
		return err
	}
	if legacyClients > 0 {
		warnings = append(warnings, fmt.Sprintf("%d legacy clients below protocol 5 seen recently", legacyClients))
	}
	var payloadCount int
	var payloadBytes sql.NullInt64
	if err := db.QueryRowContext(ctx, `
SELECT COUNT(*),SUM(LENGTH(payload_json))
FROM server_encrypted_payloads
WHERE user_id_hash=?1`, userID).Scan(&payloadCount, &payloadBytes); err != nil {
		return err
	}
	if payloadCount > 1000 {
		warnings = append(warnings, fmt.Sprintf("%d encrypted payloads queued; consider pagination/retention tuning", payloadCount))
	}
	if payloadBytes.Valid && payloadBytes.Int64 > 64<<20 {
		warnings = append(warnings, fmt.Sprintf("%d encrypted payload bytes stored; check account quota/retention", payloadBytes.Int64))
	}
	var fullSnapshots int
	if err := db.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM (
	SELECT full_snapshot_required
	FROM server_sync_audit
	WHERE user_id_hash=?1
	ORDER BY id DESC
	LIMIT 8
)
WHERE full_snapshot_required!=0`, userID).Scan(&fullSnapshots); err != nil {
		return err
	}
	if fullSnapshots >= 3 {
		warnings = append(warnings, fmt.Sprintf("%d recent syncs required full snapshots", fullSnapshots))
	}
	fmt.Fprintln(out, "\nWarnings")
	if len(warnings) == 0 {
		fmt.Fprintln(out, "- none")
		return nil
	}
	for _, warning := range warnings {
		fmt.Fprintf(out, "- %s\n", warning)
	}
	return nil
}

func inspectDoctorClients(ctx context.Context, db *sql.DB, out io.Writer, userID string) error {
	rows, err := db.QueryContext(ctx, `
SELECT client_id,protocol_version,last_login_at,last_sync_at,last_seen_server_version,last_client_clock
FROM server_clients
WHERE user_id_hash=?1
ORDER BY last_seen_at DESC,client_id
LIMIT 12`, userID)
	if err != nil {
		return err
	}
	defer rows.Close()

	fmt.Fprintln(out, "\nClients")
	for rows.Next() {
		var clientID string
		var loginAt, syncAt sql.NullString
		var protocol int
		var seenVersion, clientClock int64
		if err := rows.Scan(&clientID, &protocol, &loginAt, &syncAt, &seenVersion, &clientClock); err != nil {
			return err
		}
		status := "current"
		if protocol > 0 && protocol < 5 {
			status = "legacy"
		}
		fmt.Fprintf(out, "%s protocol=%d status=%s last_login=%s last_sync=%s seen=%d clock=%d\n",
			clientID, protocol, status, nullText(loginAt), nullText(syncAt), seenVersion, clientClock)
	}
	return rows.Err()
}

func inspectDoctorAudit(ctx context.Context, db *sql.DB, out io.Writer, userID string) error {
	rows, err := db.QueryContext(ctx, `
SELECT client_id,protocol_version,server_version,remote_ops,full_snapshot_required,
       snapshot_reason,encrypted_payload,encrypted_payload_bytes,created_at
FROM server_sync_audit
WHERE user_id_hash=?1
ORDER BY id DESC
LIMIT 8`, userID)
	if err != nil {
		return err
	}
	defer rows.Close()

	fmt.Fprintln(out, "\nRecent sync audit")
	for rows.Next() {
		var clientID, snapshotReason, createdAt string
		var protocol, remoteOps, fullSnapshot, encryptedPayload int
		var version, encryptedBytes int64
		if err := rows.Scan(&clientID, &protocol, &version, &remoteOps, &fullSnapshot,
			&snapshotReason, &encryptedPayload, &encryptedBytes, &createdAt); err != nil {
			return err
		}
		fmt.Fprintf(out, "%s protocol=%d version=%d remote_ops=%d full_snapshot=%t reason=%s encrypted_payload=%t bytes=%d at=%s\n",
			clientID, protocol, version, remoteOps, fullSnapshot != 0, emptyText(snapshotReason, "-"),
			encryptedPayload != 0, encryptedBytes, createdAt)
	}
	return rows.Err()
}

func inspectUserHabits(ctx context.Context, db *sql.DB, out io.Writer, userID string) error {
	rows, err := db.QueryContext(ctx, `
SELECT id, name, sync_mode, sync_activity, deleted_at, updated_at
FROM server_habits
WHERE user_id_hash=?1
ORDER BY sort_order, id
LIMIT 50`, userID)
	if err != nil {
		return err
	}
	defer rows.Close()

	fmt.Fprintln(out, "\nHabits")
	for rows.Next() {
		var id, name, updatedAt string
		var syncMode, syncActivity, deletedAt int
		if err := rows.Scan(&id, &name, &syncMode, &syncActivity, &deletedAt, &updatedAt); err != nil {
			return err
		}
		fmt.Fprintf(out, "%s  %q  sync=%d/%d  deleted=%d  updated=%s\n",
			id, name, syncMode, syncActivity, deletedAt, updatedAt)
	}
	return rows.Err()
}

func inspectUserSessions(ctx context.Context, db *sql.DB, out io.Writer, userID string) error {
	rows, err := db.QueryContext(ctx, `
SELECT id, started_at, local_date, topic, activity, deleted_at, updated_at
FROM server_sessions
WHERE user_id_hash=?1
ORDER BY started_at DESC
LIMIT 25`, userID)
	if err != nil {
		return err
	}
	defer rows.Close()

	fmt.Fprintln(out, "\nRecent sessions")
	for rows.Next() {
		var id, startedAt, topic, updatedAt string
		var localDate, activity, deletedAt int
		if err := rows.Scan(&id, &startedAt, &localDate, &topic, &activity, &deletedAt, &updatedAt); err != nil {
			return err
		}
		fmt.Fprintf(out, "%s  started=%s  local_date=%d  topic=%s  activity=%d  deleted=%d  updated=%s\n",
			id, startedAt, localDate, topic, activity, deletedAt, updatedAt)
	}
	return rows.Err()
}

func inspectCount(ctx context.Context, db *sql.DB, table, where string, args ...any) (int, error) {
	var n int
	query := "SELECT COUNT(*) FROM " + table
	if where != "" {
		query += " " + where
	}
	err := db.QueryRowContext(ctx, query, args...).Scan(&n)
	return n, err
}

func redactID(value string, full bool) string {
	if full || len(value) <= 16 {
		return value
	}
	return value[:12] + "..." + value[len(value)-8:]
}

func nullText(value sql.NullString) string {
	if !value.Valid || value.String == "" {
		return "-"
	}
	return value.String
}

func emptyText(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
