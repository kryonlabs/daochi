package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Store struct {
	db *sql.DB
}

type PublicStats struct {
	UserCount        int64
	StorageUsedBytes int64
	StorageUsedGB    int64
	StorageUsedText  string
	AvailableBytes   int64
	AvailableGB      int64
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

CREATE TABLE IF NOT EXISTS server_sync_state (
	user_id_hash TEXT PRIMARY KEY REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	server_version INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS server_clients (
	user_id_hash TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	client_id TEXT NOT NULL,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_login_at TEXT,
	last_sync_at TEXT,
	last_since_server_version INTEGER NOT NULL DEFAULT 0,
	last_seen_server_version INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY(user_id_hash, client_id)
);

CREATE TABLE IF NOT EXISTS server_meditation_logs (
	id TEXT PRIMARY KEY,
	user_id_hash TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	session_id TEXT NOT NULL,
	duration_seconds INTEGER NOT NULL DEFAULT 0,
	completed_at TEXT NOT NULL,
	server_version INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
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
	counter_enabled INTEGER NOT NULL DEFAULT 0,
	sort_order INTEGER NOT NULL DEFAULT 0,
	deleted_at INTEGER NOT NULL DEFAULT 0,
	updated_at TEXT NOT NULL,
	server_version INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY(user_id_hash, id)
);

CREATE TABLE IF NOT EXISTS server_habit_days (
	user_id_hash TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	habit_id TEXT NOT NULL,
	local_date INTEGER NOT NULL,
	completed INTEGER NOT NULL DEFAULT 0,
	count INTEGER NOT NULL DEFAULT 0,
	updated_at TEXT NOT NULL,
	server_version INTEGER NOT NULL DEFAULT 0,
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
	server_version INTEGER NOT NULL DEFAULT 0,
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
	if err != nil {
		return err
	}
	for _, stmt := range []string{
		`ALTER TABLE server_meditation_logs ADD COLUMN server_version INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE server_habits ADD COLUMN server_version INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE server_habits ADD COLUMN counter_enabled INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE server_habit_days ADD COLUMN server_version INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE server_habit_days ADD COLUMN count INTEGER NOT NULL DEFAULT 0`,
		`UPDATE server_habit_days SET count=CASE WHEN completed!=0 THEN 1 ELSE 0 END WHERE count=0`,
		`ALTER TABLE server_sessions ADD COLUMN server_version INTEGER NOT NULL DEFAULT 0`,
	} {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return err
		}
	}
	return nil
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

	if publicKey != nil {
		if err := upsertUser(ctx, tx, req.UserIDHash, publicKey); err != nil {
			return SyncResult{}, err
		}
	} else if err := touchUser(ctx, tx, req.UserIDHash); err != nil {
		return SyncResult{}, err
	}
	if req.FullSyncRequested {
		if err := replaceUserData(ctx, tx, req.UserIDHash); err != nil {
			return SyncResult{}, err
		}
	}

	result := SyncResult{}
	for _, item := range req.MeditationLogs {
		version, err := nextUserVersion(ctx, tx, req.UserIDHash)
		if err != nil {
			return SyncResult{}, err
		}
		res, err := tx.ExecContext(ctx, `
INSERT INTO server_meditation_logs(id,user_id_hash,session_id,duration_seconds,completed_at,server_version)
VALUES(?1,?2,?3,?4,?5,?6)
ON CONFLICT(id) DO NOTHING`, item.ID, req.UserIDHash, item.SessionID, item.DurationSeconds, normalizeTime(item.CompletedAt, item.Timestamp), version)
		if err != nil {
			return SyncResult{}, err
		}
		result.MeditationLogs += rowsAffected(res)
	}
	for _, habit := range req.Habits {
		if req.Bootstrap && habit.DeletedAt > 0 {
			continue
		}
		version, err := nextUserVersion(ctx, tx, req.UserIDHash)
		if err != nil {
			return SyncResult{}, err
		}
		res, err := tx.ExecContext(ctx, `
INSERT INTO server_habits(user_id_hash,id,name,color_r,color_g,color_b,sync_mode,sync_activity,counter_enabled,sort_order,deleted_at,updated_at,server_version)
VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
ON CONFLICT(user_id_hash,id) DO UPDATE SET
	name=excluded.name,
	color_r=excluded.color_r,
	color_g=excluded.color_g,
	color_b=excluded.color_b,
	sync_mode=excluded.sync_mode,
	sync_activity=excluded.sync_activity,
	counter_enabled=excluded.counter_enabled,
	sort_order=excluded.sort_order,
	deleted_at=excluded.deleted_at,
	updated_at=excluded.updated_at,
	server_version=excluded.server_version
WHERE excluded.updated_at >= server_habits.updated_at`,
			req.UserIDHash, habit.ID, habit.Name, habit.ColorR, habit.ColorG, habit.ColorB,
			habit.SyncMode, habit.SyncActivity, habit.CounterEnabled, habit.SortOrder,
			habit.DeletedAt, normalizeTime(habit.UpdatedAt, ""), version)
		if err != nil {
			return SyncResult{}, err
		}
		result.Habits += rowsAffected(res)
	}
	for _, day := range req.HabitDays {
		if req.Bootstrap && !day.Completed && day.Count <= 0 {
			continue
		}
		version, err := nextUserVersion(ctx, tx, req.UserIDHash)
		if err != nil {
			return SyncResult{}, err
		}
		res, err := tx.ExecContext(ctx, `
INSERT INTO server_habit_days(user_id_hash,habit_id,local_date,completed,count,updated_at,server_version)
VALUES(?1,?2,?3,?4,?5,?6,?7)
ON CONFLICT(user_id_hash,habit_id,local_date) DO UPDATE SET
	completed=excluded.completed,
	count=excluded.count,
	updated_at=excluded.updated_at,
	server_version=excluded.server_version
WHERE excluded.updated_at > server_habit_days.updated_at
OR excluded.updated_at = server_habit_days.updated_at`,
			req.UserIDHash, day.HabitID, day.LocalDate, boolInt(day.Completed), normalizedHabitDayCount(day), normalizeTime(day.UpdatedAt, ""), version)
		if err != nil {
			return SyncResult{}, err
		}
		result.HabitDays += rowsAffected(res)
	}
	for _, session := range req.Sessions {
		if req.Bootstrap && session.DeletedAt > 0 {
			continue
		}
		applied, err := upsertSession(ctx, tx, req.UserIDHash, session)
		if err != nil {
			return SyncResult{}, err
		}
		result.Sessions += applied
	}
	if err := tx.Commit(); err != nil {
		return SyncResult{}, err
	}
	return result, nil
}

func (s *Store) RegisterUser(ctx context.Context, userID string, publicKey []byte) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := upsertUser(ctx, tx, userID, publicKey); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RecordClientLogin(ctx context.Context, userID, clientID string) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO server_clients(user_id_hash,client_id,last_seen_at,last_login_at)
VALUES(?1,?2,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
ON CONFLICT(user_id_hash,client_id) DO UPDATE SET
	last_seen_at=CURRENT_TIMESTAMP,
	last_login_at=CURRENT_TIMESTAMP`, userID, clientID)
	return err
}

func (s *Store) RecordClientSync(ctx context.Context, userID, clientID string, sinceVersion, serverVersion int64) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO server_clients(user_id_hash,client_id,last_seen_at,last_sync_at,last_since_server_version,last_seen_server_version)
VALUES(?1,?2,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,?3,?4)
ON CONFLICT(user_id_hash,client_id) DO UPDATE SET
	last_seen_at=CURRENT_TIMESTAMP,
	last_sync_at=CURRENT_TIMESTAMP,
	last_since_server_version=excluded.last_since_server_version,
	last_seen_server_version=excluded.last_seen_server_version`, userID, clientID, sinceVersion, serverVersion)
	return err
}

func (s *Store) DeleteAccount(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM server_users WHERE user_id_hash=?1`, userID)
	return err
}

func (s *Store) PublicStats(ctx context.Context, dbPath string) (PublicStats, error) {
	var stats PublicStats
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM server_users`).Scan(&stats.UserCount); err != nil {
		return PublicStats{}, err
	}
	used, err := sqliteFileSetSize(dbPath)
	if err != nil {
		return PublicStats{}, err
	}
	stats.StorageUsedBytes = used
	stats.StorageUsedGB = bytesToFloorGB(used)
	stats.StorageUsedText = storageUsedText(stats.StorageUsedGB)
	available, err := diskAvailableBytes(dbPath)
	if err != nil {
		return PublicStats{}, err
	}
	stats.AvailableBytes = available - (1 << 30)
	if stats.AvailableBytes < 0 {
		stats.AvailableBytes = 0
	}
	stats.AvailableGB = bytesToFloorGB(stats.AvailableBytes)
	return stats, nil
}

func (s *Store) ChangesSince(ctx context.Context, userID string, sinceVersion int64) (SyncChanges, int64, error) {
	var changes SyncChanges
	var err error

	changes.Habits, err = s.snapshotHabits(ctx, userID, sinceVersion)
	if err != nil {
		return changes, 0, err
	}
	changes.HabitDays, err = s.snapshotHabitDays(ctx, userID, sinceVersion)
	if err != nil {
		return changes, 0, err
	}
	changes.Sessions, err = s.snapshotSessions(ctx, userID, sinceVersion)
	if err != nil {
		return changes, 0, err
	}
	changes.MeditationLogs, err = s.snapshotMeditationLogs(ctx, userID, sinceVersion)
	if err != nil {
		return changes, 0, err
	}
	version, err := s.currentUserVersion(ctx, userID)
	if err != nil {
		return changes, 0, err
	}
	return changes, version, nil
}

func (s *Store) StateHash(ctx context.Context, userID string) (string, error) {
	h := sha256.New()

	if err := s.hashHabits(ctx, h, userID); err != nil {
		return "", err
	}
	if err := s.hashHabitDays(ctx, h, userID); err != nil {
		return "", err
	}
	if err := s.hashSessions(ctx, h, userID); err != nil {
		return "", err
	}
	if err := s.hashMeditationLogs(ctx, h, userID); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (s *Store) hashHabits(ctx context.Context, h interface{ Write([]byte) (int, error) }, userID string) error {
	rows, err := s.db.QueryContext(ctx, `
SELECT id,name,color_r,color_g,color_b,sync_mode,sync_activity,counter_enabled,sort_order,deleted_at,updated_at
FROM server_habits
WHERE user_id_hash=?1
ORDER BY id`, userID)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var id, name, updatedAt string
		var colorR, colorG, colorB, syncMode, syncActivity, counterEnabled, sortOrder int
		var deletedAt int64
		if err := rows.Scan(&id, &name, &colorR, &colorG, &colorB, &syncMode, &syncActivity,
			&counterEnabled, &sortOrder, &deletedAt, &updatedAt); err != nil {
			return err
		}
		fmt.Fprintf(h, "habit\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%s\n",
			id, name, colorR, colorG, colorB, syncMode, syncActivity, counterEnabled,
			sortOrder, deletedAt, updatedAt)
	}
	return rows.Err()
}

func (s *Store) hashHabitDays(ctx context.Context, h interface{ Write([]byte) (int, error) }, userID string) error {
	rows, err := s.db.QueryContext(ctx, `
SELECT habit_id,local_date,completed,count,updated_at
FROM server_habit_days
WHERE user_id_hash=?1
ORDER BY habit_id,local_date`, userID)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var habitID, updatedAt string
		var localDate, completed, count int
		if err := rows.Scan(&habitID, &localDate, &completed, &count, &updatedAt); err != nil {
			return err
		}
		fmt.Fprintf(h, "habit_day\t%s\t%d\t%d\t%d\t%s\n",
			habitID, localDate, completed, count, updatedAt)
	}
	return rows.Err()
}

func (s *Store) hashSessions(ctx context.Context, h interface{ Write([]byte) (int, error) }, userID string) error {
	rows, err := s.db.QueryContext(ctx, `
SELECT id,started_at,local_date,topic,activity,source,rounds_hash,deleted_at,updated_at
FROM server_sessions
WHERE user_id_hash=?1
ORDER BY id`, userID)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var id, startedAt, topic, source, roundsHash, updatedAt string
		var localDate, activity int
		var deletedAt int64
		if err := rows.Scan(&id, &startedAt, &localDate, &topic, &activity, &source,
			&roundsHash, &deletedAt, &updatedAt); err != nil {
			return err
		}
		fmt.Fprintf(h, "session\t%s\t%s\t%d\t%s\t%d\t%s\t%s\t%d\t%s\n",
			id, startedAt, localDate, topic, activity, source, roundsHash, deletedAt, updatedAt)
		if err := s.hashSessionRounds(ctx, h, userID, id); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (s *Store) hashSessionRounds(ctx context.Context, h interface{ Write([]byte) (int, error) }, userID, sessionID string) error {
	rows, err := s.db.QueryContext(ctx, `
SELECT round_index,breaths,hold_seconds
FROM server_session_rounds
WHERE user_id_hash=?1 AND session_id=?2
ORDER BY round_index`, userID, sessionID)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var roundIndex, breaths, holdSeconds int
		if err := rows.Scan(&roundIndex, &breaths, &holdSeconds); err != nil {
			return err
		}
		fmt.Fprintf(h, "round\t%s\t%d\t%d\t%d\n", sessionID, roundIndex, breaths, holdSeconds)
	}
	return rows.Err()
}

func (s *Store) hashMeditationLogs(ctx context.Context, h interface{ Write([]byte) (int, error) }, userID string) error {
	rows, err := s.db.QueryContext(ctx, `
SELECT id,session_id,duration_seconds,completed_at
FROM server_meditation_logs
WHERE user_id_hash=?1
ORDER BY id`, userID)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var id, sessionID, completedAt string
		var durationSeconds int
		if err := rows.Scan(&id, &sessionID, &durationSeconds, &completedAt); err != nil {
			return err
		}
		fmt.Fprintf(h, "meditation_log\t%s\t%s\t%d\t%s\n", id, sessionID, durationSeconds, completedAt)
	}
	return rows.Err()
}

func (s *Store) snapshotHabits(ctx context.Context, userID string, sinceVersion int64) ([]Habit, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id,name,color_r,color_g,color_b,sync_mode,sync_activity,counter_enabled,sort_order,deleted_at,updated_at,server_version
FROM (
	SELECT id,name,color_r,color_g,color_b,sync_mode,sync_activity,counter_enabled,sort_order,deleted_at,updated_at,server_version
	FROM server_habits
	WHERE user_id_hash=?1 AND server_version>?2
	UNION ALL
	SELECT hd.habit_id,
	       'Recovered ' || hd.habit_id,
	       99,196,165,
	       0,0,0,
	       1000,
	       0,
	       MAX(hd.updated_at),
	       MAX(hd.server_version)
	FROM server_habit_days hd
	WHERE hd.user_id_hash=?1
	  AND hd.server_version>?2
	  AND NOT EXISTS (
		SELECT 1 FROM server_habits h
		WHERE h.user_id_hash=hd.user_id_hash AND h.id=hd.habit_id
	  )
	GROUP BY hd.habit_id
)
ORDER BY server_version,sort_order,id`, userID, sinceVersion)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []Habit{}
	for rows.Next() {
		var item Habit
		var serverVersion int64
		if err := rows.Scan(&item.ID, &item.Name, &item.ColorR, &item.ColorG, &item.ColorB,
			&item.SyncMode, &item.SyncActivity, &item.CounterEnabled, &item.SortOrder,
			&item.DeletedAt, &item.UpdatedAt, &serverVersion); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) snapshotHabitDays(ctx context.Context, userID string, sinceVersion int64) ([]HabitDay, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT habit_id,local_date,completed,count,updated_at
FROM server_habit_days
WHERE user_id_hash=?1 AND server_version>?2
ORDER BY server_version,habit_id,local_date`, userID, sinceVersion)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []HabitDay{}
	for rows.Next() {
		var item HabitDay
		var completed int
		if err := rows.Scan(&item.HabitID, &item.LocalDate, &completed, &item.Count, &item.UpdatedAt); err != nil {
			return nil, err
		}
		item.Completed = completed != 0
		if item.Count <= 0 && item.Completed {
			item.Count = 1
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) snapshotSessions(ctx context.Context, userID string, sinceVersion int64) ([]Session, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id,started_at,local_date,topic,activity,source,rounds_hash,deleted_at,updated_at
FROM server_sessions
WHERE user_id_hash=?1 AND server_version>?2
ORDER BY server_version,started_at,id`, userID, sinceVersion)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []Session{}
	for rows.Next() {
		var item Session
		if err := rows.Scan(&item.ID, &item.StartedAt, &item.LocalDate, &item.Topic,
			&item.Activity, &item.Source, &item.RoundsHash, &item.DeletedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()

	for i := range items {
		rounds, err := s.snapshotSessionRounds(ctx, userID, items[i].ID)
		if err != nil {
			return nil, err
		}
		items[i].Rounds = rounds
	}
	return items, nil
}

func (s *Store) snapshotSessionRounds(ctx context.Context, userID, sessionID string) ([]SessionRound, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT round_index,breaths,hold_seconds
FROM server_session_rounds
WHERE user_id_hash=?1 AND session_id=?2
ORDER BY round_index`, userID, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []SessionRound{}
	for rows.Next() {
		var item SessionRound
		if err := rows.Scan(&item.RoundIndex, &item.Breaths, &item.HoldSeconds); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) snapshotMeditationLogs(ctx context.Context, userID string, sinceVersion int64) ([]MeditationLog, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id,session_id,duration_seconds,completed_at
FROM server_meditation_logs
WHERE user_id_hash=?1 AND server_version>?2
ORDER BY server_version,completed_at,id`, userID, sinceVersion)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []MeditationLog{}
	for rows.Next() {
		var item MeditationLog
		if err := rows.Scan(&item.ID, &item.SessionID, &item.DurationSeconds, &item.CompletedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func upsertUser(ctx context.Context, tx *sql.Tx, userID string, publicKey []byte) error {
	if _, err := tx.ExecContext(ctx, `
INSERT INTO server_users(user_id_hash,public_key)
VALUES(?1,?2)
ON CONFLICT(user_id_hash) DO UPDATE SET last_seen_at=CURRENT_TIMESTAMP`, userID, publicKey); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `
INSERT OR IGNORE INTO server_sync_state(user_id_hash,server_version)
VALUES(?1,0)`, userID)
	return err
}

func touchUser(ctx context.Context, tx *sql.Tx, userID string) error {
	res, err := tx.ExecContext(ctx, `
UPDATE server_users
SET last_seen_at=CURRENT_TIMESTAMP
WHERE user_id_hash=?1`, userID)
	if err != nil {
		return err
	}
	if rowsAffected(res) == 0 {
		return errors.New("sync user not found")
	}
	_, err = tx.ExecContext(ctx, `
INSERT OR IGNORE INTO server_sync_state(user_id_hash,server_version)
VALUES(?1,0)`, userID)
	return err
}

func replaceUserData(ctx context.Context, tx *sql.Tx, userID string) error {
	for _, query := range []string{
		`DELETE FROM server_session_rounds WHERE user_id_hash=?1`,
		`DELETE FROM server_sessions WHERE user_id_hash=?1`,
		`DELETE FROM server_habit_days WHERE user_id_hash=?1`,
		`DELETE FROM server_habits WHERE user_id_hash=?1`,
		`DELETE FROM server_meditation_logs WHERE user_id_hash=?1`,
	} {
		if _, err := tx.ExecContext(ctx, query, userID); err != nil {
			return err
		}
	}
	_, err := nextUserVersion(ctx, tx, userID)
	return err
}

func upsertSession(ctx context.Context, tx *sql.Tx, userID string, session Session) (int, error) {
	version, err := nextUserVersion(ctx, tx, userID)
	if err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx, `
INSERT INTO server_sessions(user_id_hash,id,started_at,local_date,topic,activity,source,rounds_hash,deleted_at,updated_at,server_version)
VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
ON CONFLICT(user_id_hash,id) DO UPDATE SET
	started_at=excluded.started_at,
	local_date=excluded.local_date,
	topic=excluded.topic,
	activity=excluded.activity,
	source=excluded.source,
	rounds_hash=excluded.rounds_hash,
	deleted_at=excluded.deleted_at,
	updated_at=excluded.updated_at,
	server_version=excluded.server_version
WHERE excluded.updated_at >= server_sessions.updated_at`,
		userID, session.ID, normalizeTime(session.StartedAt, ""), session.LocalDate, session.Topic,
		session.Activity, session.Source, session.RoundsHash, session.DeletedAt, normalizeTime(session.UpdatedAt, ""), version)
	if err != nil {
		return 0, err
	}
	applied := rowsAffected(res)
	if applied == 0 || len(session.Rounds) == 0 {
		return applied, nil
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM server_session_rounds WHERE user_id_hash=?1 AND session_id=?2`, userID, session.ID); err != nil {
		return 0, err
	}
	for _, round := range session.Rounds {
		_, err := tx.ExecContext(ctx, `
INSERT INTO server_session_rounds(user_id_hash,session_id,round_index,breaths,hold_seconds)
VALUES(?1,?2,?3,?4,?5)`, userID, session.ID, round.RoundIndex, round.Breaths, round.HoldSeconds)
		if err != nil {
			return 0, err
		}
	}
	return applied, nil
}

func nextUserVersion(ctx context.Context, tx *sql.Tx, userID string) (int64, error) {
	if _, err := tx.ExecContext(ctx, `
INSERT OR IGNORE INTO server_sync_state(user_id_hash,server_version)
VALUES(?1,0)`, userID); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE server_sync_state
SET server_version=server_version+1
WHERE user_id_hash=?1`, userID); err != nil {
		return 0, err
	}
	var version int64
	err := tx.QueryRowContext(ctx, `
SELECT server_version
FROM server_sync_state
WHERE user_id_hash=?1`, userID).Scan(&version)
	return version, err
}

func (s *Store) currentUserVersion(ctx context.Context, userID string) (int64, error) {
	var version int64
	err := s.db.QueryRowContext(ctx, `
SELECT server_version
FROM server_sync_state
WHERE user_id_hash=?1`, userID).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return version, err
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

func normalizedHabitDayCount(day HabitDay) int {
	if !day.Completed {
		return 0
	}
	if day.Count > 0 {
		return day.Count
	}
	return 1
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func sqliteFileSetSize(dbPath string) (int64, error) {
	var total int64
	for _, path := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		info, err := os.Stat(path)
		if err == nil {
			total += info.Size()
			continue
		}
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		return 0, err
	}
	return total, nil
}

func diskAvailableBytes(path string) (int64, error) {
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(dir, &stat); err != nil {
		return 0, err
	}
	return int64(stat.Bavail) * int64(stat.Bsize), nil
}

func bytesToFloorGB(bytes int64) int64 {
	if bytes <= 0 {
		return 0
	}
	return bytes / (1 << 30)
}

func storageUsedText(gb int64) string {
	if gb <= 0 {
		return "under 1 GB"
	}
	return fmt.Sprintf("%d GB", gb)
}
