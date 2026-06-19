package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Store struct {
	db *sql.DB
}

func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite3", path+"?_busy_timeout=5000&_foreign_keys=on")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &Store{db: db}
	if err := store.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS server_users (
	user_id_hash TEXT PRIMARY KEY,
	public_key BLOB NOT NULL,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS server_meditation_logs (
	id TEXT PRIMARY KEY,
	user_id_hash TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	session_id TEXT NOT NULL,
	duration_seconds INTEGER NOT NULL DEFAULT 0,
	completed_at TEXT NOT NULL,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS server_preferences (
	user_id_hash TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	pref_key TEXT NOT NULL,
	pref_value TEXT NOT NULL DEFAULT '',
	updated_at TEXT NOT NULL,
	PRIMARY KEY(user_id_hash, pref_key)
);

CREATE TABLE IF NOT EXISTS server_habits (
	user_id_hash TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	id TEXT NOT NULL,
	name TEXT NOT NULL,
	color_r INTEGER NOT NULL DEFAULT 0,
	color_g INTEGER NOT NULL DEFAULT 0,
	color_b INTEGER NOT NULL DEFAULT 0,
	sync_mode INTEGER NOT NULL DEFAULT 0,
	sync_activity INTEGER NOT NULL DEFAULT 0,
	sort_order INTEGER NOT NULL DEFAULT 0,
	deleted_at INTEGER NOT NULL DEFAULT 0,
	updated_at TEXT NOT NULL,
	PRIMARY KEY(user_id_hash, id)
);

CREATE TABLE IF NOT EXISTS server_habit_days (
	user_id_hash TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	habit_id TEXT NOT NULL,
	local_date INTEGER NOT NULL,
	completed INTEGER NOT NULL DEFAULT 0,
	updated_at TEXT NOT NULL,
	PRIMARY KEY(user_id_hash, habit_id, local_date)
);

CREATE TABLE IF NOT EXISTS server_sessions (
	user_id_hash TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	id TEXT NOT NULL,
	started_at TEXT NOT NULL,
	local_date INTEGER NOT NULL DEFAULT 0,
	topic TEXT NOT NULL DEFAULT '',
	activity INTEGER NOT NULL DEFAULT 0,
	source TEXT NOT NULL DEFAULT '',
	rounds_hash TEXT NOT NULL DEFAULT '',
	deleted_at INTEGER NOT NULL DEFAULT 0,
	updated_at TEXT NOT NULL,
	PRIMARY KEY(user_id_hash, id)
);

CREATE TABLE IF NOT EXISTS server_session_rounds (
	user_id_hash TEXT NOT NULL,
	session_id TEXT NOT NULL,
	round_index INTEGER NOT NULL,
	breaths INTEGER NOT NULL DEFAULT 0,
	hold_seconds INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY(user_id_hash, session_id, round_index),
	FOREIGN KEY(user_id_hash, session_id) REFERENCES server_sessions(user_id_hash, id) ON DELETE CASCADE
);
`)
	return err
}

func (s *Store) PublicKey(ctx context.Context, userID string) ([]byte, bool, error) {
	var key []byte
	err := s.db.QueryRowContext(ctx, `SELECT public_key FROM server_users WHERE user_id_hash=?1`, userID).Scan(&key)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return key, true, nil
}

func (s *Store) ApplySync(ctx context.Context, req SyncRequest, publicKey []byte) (SyncResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SyncResult{}, err
	}
	defer tx.Rollback()

	if err := upsertUser(ctx, tx, req.UserIDHash, publicKey); err != nil {
		return SyncResult{}, err
	}

	result := SyncResult{}
	for _, item := range req.MeditationLogs {
		res, err := tx.ExecContext(ctx, `
INSERT INTO server_meditation_logs(id,user_id_hash,session_id,duration_seconds,completed_at)
VALUES(?1,?2,?3,?4,?5)
ON CONFLICT(id) DO NOTHING`, item.ID, req.UserIDHash, item.SessionID, item.DurationSeconds, normalizeTime(item.CompletedAt, item.Timestamp))
		if err != nil {
			return SyncResult{}, err
		}
		result.MeditationLogs += rowsAffected(res)
	}
	for _, pref := range req.Preferences {
		_, err := tx.ExecContext(ctx, `
INSERT INTO server_preferences(user_id_hash,pref_key,pref_value,updated_at)
VALUES(?1,?2,?3,?4)
ON CONFLICT(user_id_hash,pref_key) DO UPDATE SET
	pref_value=excluded.pref_value,
	updated_at=excluded.updated_at
WHERE excluded.updated_at >= server_preferences.updated_at`, req.UserIDHash, pref.Key, pref.Value, normalizeTime(pref.UpdatedAt, ""))
		if err != nil {
			return SyncResult{}, err
		}
		result.Preferences++
	}
	for _, habit := range req.Habits {
		_, err := tx.ExecContext(ctx, `
INSERT INTO server_habits(user_id_hash,id,name,color_r,color_g,color_b,sync_mode,sync_activity,sort_order,deleted_at,updated_at)
VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
ON CONFLICT(user_id_hash,id) DO UPDATE SET
	name=excluded.name,
	color_r=excluded.color_r,
	color_g=excluded.color_g,
	color_b=excluded.color_b,
	sync_mode=excluded.sync_mode,
	sync_activity=excluded.sync_activity,
	sort_order=excluded.sort_order,
	deleted_at=excluded.deleted_at,
	updated_at=excluded.updated_at
WHERE excluded.updated_at >= server_habits.updated_at`,
			req.UserIDHash, habit.ID, habit.Name, habit.ColorR, habit.ColorG, habit.ColorB,
			habit.SyncMode, habit.SyncActivity, habit.SortOrder, habit.DeletedAt, normalizeTime(habit.UpdatedAt, ""))
		if err != nil {
			return SyncResult{}, err
		}
		result.Habits++
	}
	for _, day := range req.HabitDays {
		_, err := tx.ExecContext(ctx, `
INSERT INTO server_habit_days(user_id_hash,habit_id,local_date,completed,updated_at)
VALUES(?1,?2,?3,?4,?5)
ON CONFLICT(user_id_hash,habit_id,local_date) DO UPDATE SET
	completed=excluded.completed,
	updated_at=excluded.updated_at
WHERE excluded.updated_at >= server_habit_days.updated_at`,
			req.UserIDHash, day.HabitID, day.LocalDate, boolInt(day.Completed), normalizeTime(day.UpdatedAt, ""))
		if err != nil {
			return SyncResult{}, err
		}
		result.HabitDays++
	}
	for _, session := range req.Sessions {
		if err := upsertSession(ctx, tx, req.UserIDHash, session); err != nil {
			return SyncResult{}, err
		}
		result.Sessions++
	}
	if err := tx.Commit(); err != nil {
		return SyncResult{}, err
	}
	return result, nil
}

func (s *Store) DeleteAccount(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM server_users WHERE user_id_hash=?1`, userID)
	return err
}

func upsertUser(ctx context.Context, tx *sql.Tx, userID string, publicKey []byte) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO server_users(user_id_hash,public_key)
VALUES(?1,?2)
ON CONFLICT(user_id_hash) DO UPDATE SET last_seen_at=CURRENT_TIMESTAMP`, userID, publicKey)
	return err
}

func upsertSession(ctx context.Context, tx *sql.Tx, userID string, session Session) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO server_sessions(user_id_hash,id,started_at,local_date,topic,activity,source,rounds_hash,deleted_at,updated_at)
VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
ON CONFLICT(user_id_hash,id) DO UPDATE SET
	started_at=excluded.started_at,
	local_date=excluded.local_date,
	topic=excluded.topic,
	activity=excluded.activity,
	source=excluded.source,
	rounds_hash=excluded.rounds_hash,
	deleted_at=excluded.deleted_at,
	updated_at=excluded.updated_at
WHERE excluded.updated_at >= server_sessions.updated_at`,
		userID, session.ID, normalizeTime(session.StartedAt, ""), session.LocalDate, session.Topic,
		session.Activity, session.Source, session.RoundsHash, session.DeletedAt, normalizeTime(session.UpdatedAt, ""))
	if err != nil {
		return err
	}
	if len(session.Rounds) == 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM server_session_rounds WHERE user_id_hash=?1 AND session_id=?2`, userID, session.ID); err != nil {
		return err
	}
	for _, round := range session.Rounds {
		_, err := tx.ExecContext(ctx, `
INSERT INTO server_session_rounds(user_id_hash,session_id,round_index,breaths,hold_seconds)
VALUES(?1,?2,?3,?4,?5)`, userID, session.ID, round.RoundIndex, round.Breaths, round.HoldSeconds)
		if err != nil {
			return err
		}
	}
	return nil
}

func validateUserIDForPublicKey(userID string, publicKey []byte) error {
	sum := sha256.Sum256(publicKey)
	actual := hex.EncodeToString(sum[:])
	if userID != actual {
		return fmt.Errorf("public key hash mismatch")
	}
	return nil
}

func rowsAffected(res sql.Result) int {
	n, err := res.RowsAffected()
	if err != nil {
		return 0
	}
	return int(n)
}

func normalizeTime(primary, fallback string) string {
	value := primary
	if value == "" {
		value = fallback
	}
	if value == "" {
		return time.Now().UTC().Format(time.RFC3339Nano)
	}
	if t, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return t.UTC().Format(time.RFC3339Nano)
	}
	return value
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
