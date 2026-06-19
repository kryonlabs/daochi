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
		opts.DBPath = envString("LYRA_DB", "lyra.db")
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
	case "user":
		if len(rest) != 2 {
			return fmt.Errorf("usage: lyra inspect user <user_id_hash>")
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
		"server_preferences",
		"server_habits",
		"server_habit_days",
		"server_sessions",
		"server_session_rounds",
		"server_meditation_logs",
	}
	fmt.Fprintln(out, "Lyra data summary")
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

	for _, table := range []string{"server_preferences", "server_habits", "server_habit_days", "server_sessions", "server_session_rounds", "server_meditation_logs"} {
		n, err := inspectCount(ctx, db, table, "WHERE user_id_hash=?1", userID)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%-24s %d\n", table, n)
	}
	if err := inspectUserPreferences(ctx, db, out, userID); err != nil {
		return err
	}
	if err := inspectUserHabits(ctx, db, out, userID); err != nil {
		return err
	}
	return inspectUserSessions(ctx, db, out, userID)
}

func inspectUserPreferences(ctx context.Context, db *sql.DB, out io.Writer, userID string) error {
	rows, err := db.QueryContext(ctx, `
SELECT pref_key, pref_value, updated_at
FROM server_preferences
WHERE user_id_hash=?1
ORDER BY pref_key`, userID)
	if err != nil {
		return err
	}
	defer rows.Close()

	fmt.Fprintln(out, "\nPreferences")
	for rows.Next() {
		var key, value, updatedAt string
		if err := rows.Scan(&key, &value, &updatedAt); err != nil {
			return err
		}
		fmt.Fprintf(out, "%s=%s  updated=%s\n", key, value, updatedAt)
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
