package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Store struct {
	db *sql.DB
}

var ErrSyncUserNotFound = errors.New("sync user not found")

const syncClientActiveRetention = 90 * 24 * time.Hour

func newCanonicalHabitID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func isCanonicalHabitID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, ch := range id {
		switch i {
		case 8, 13, 18, 23:
			if ch != '-' {
				return false
			}
		default:
			if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
				return false
			}
		}
	}
	return true
}

type PublicStats struct {
	UserCount        int64
	StorageUsedBytes int64
	StorageUsedGB    int64
	StorageUsedText  string
	AvailableBytes   int64
	AvailableGB      int64
}

func (s *Store) ExportAccount(ctx context.Context, userID string) (AccountExportResponse, error) {
	var alias sql.NullString
	var profileIcon int
	response := AccountExportResponse{
		Status:     "ok",
		UserIDHash: userID,
		Tables:     make(map[string][]map[string]any),
	}
	if err := s.db.QueryRowContext(ctx, `
SELECT alias,profile_icon
FROM server_users
WHERE user_id_hash=?1`, userID).Scan(&alias, &profileIcon); err != nil {
		return AccountExportResponse{}, err
	}
	if alias.Valid {
		response.AccountAlias = alias.String
	}
	response.ProfileIcon = profileIcon

	queries := []struct {
		name       string
		query      string
		jsonFields map[string]bool
	}{
		{
			name:  "users",
			query: `SELECT user_id_hash, alias, profile_icon, created_at, last_seen_at FROM server_users WHERE user_id_hash=?1`,
		},
		{
			name:  "clients",
			query: `SELECT client_id, created_at, last_seen_at, last_login_at, last_sync_at, last_since_server_version, last_seen_server_version, protocol_version, last_client_clock FROM server_clients WHERE user_id_hash=?1 ORDER BY last_seen_at DESC, client_id`,
		},
		{
			name:  "sync_state",
			query: `SELECT server_version FROM server_sync_state WHERE user_id_hash=?1`,
		},
		{
			name:  "sync_compaction",
			query: `SELECT compacted_through_version, updated_at FROM server_sync_compaction WHERE user_id_hash=?1`,
		},
		{
			name:  "habits",
			query: `SELECT id, name, color_r, color_g, color_b, sync_mode, sync_activity, counter_enabled, sort_order, deleted_at, updated_at, server_version FROM server_habits WHERE user_id_hash=?1 ORDER BY sort_order, id`,
		},
		{
			name:  "habit_days",
			query: `SELECT habit_id, local_date, completed, count, updated_at, server_version FROM server_habit_days WHERE user_id_hash=?1 ORDER BY local_date DESC, habit_id`,
		},
		{
			name:  "sessions",
			query: `SELECT id, started_at, local_date, topic, activity, source, rounds_hash, deleted_at, updated_at, server_version FROM server_sessions WHERE user_id_hash=?1 ORDER BY started_at DESC, id`,
		},
		{
			name:  "session_rounds",
			query: `SELECT session_id, round_index, breaths, hold_seconds FROM server_session_rounds WHERE user_id_hash=?1 ORDER BY session_id, round_index`,
		},
		{
			name:  "meditation_logs",
			query: `SELECT id, session_id, duration_seconds, completed_at, server_version, created_at FROM server_meditation_logs WHERE user_id_hash=?1 ORDER BY completed_at DESC, id`,
		},
		{
			name:       "social_snapshots",
			query:      `SELECT kind, json, updated_at, server_version FROM server_social_snapshots WHERE user_id_hash=?1 ORDER BY kind`,
			jsonFields: map[string]bool{"json": true},
		},
		{
			name:       "sync_ops",
			query:      `SELECT op_id, client_id, seq, entity_type, entity_id, local_date, op_type, payload_json, created_at, server_version FROM server_sync_ops WHERE user_id_hash=?1 ORDER BY server_version, client_id, seq`,
			jsonFields: map[string]bool{"payload_json": true},
		},
		{
			name:  "friend_requests",
			query: `SELECT id, requester_user_id_hash, target_user_id_hash, status, created_at, updated_at FROM server_friend_requests WHERE requester_user_id_hash=?1 OR target_user_id_hash=?1 ORDER BY updated_at DESC, id`,
		},
		{
			name:  "friendships",
			query: `SELECT user_id_a, user_id_b, created_at FROM server_friendships WHERE user_id_a=?1 OR user_id_b=?1 ORDER BY created_at DESC, user_id_a, user_id_b`,
		},
		{
			name:  "profile_stats",
			query: `SELECT app, practice, metric, value, label, local_date, updated_at FROM server_profile_stats WHERE user_id_hash=?1 ORDER BY app, practice, metric`,
		},
		{
			name:  "leaderboard_stats",
			query: `SELECT app, practice, metric, source_version, calc_version, value, label, local_date, updated_at FROM server_leaderboard_stats WHERE user_id_hash=?1 ORDER BY app, practice, metric`,
		},
		{
			name:  "uku_processes",
			query: `SELECT id, owner_user_id_hash, question, description, visibility, proposal_minutes, voting_minutes, negative_weight, created_at, updated_at, deleted_at FROM uku_processes WHERE owner_user_id_hash=?1 ORDER BY updated_at DESC, id`,
		},
		{
			name:  "uku_proposals",
			query: `SELECT process_id, id, author_user_id_hash, title, description, created_at, updated_at, deleted_at FROM uku_proposals WHERE author_user_id_hash=?1 ORDER BY updated_at DESC, process_id, id`,
		},
		{
			name:       "uku_votes",
			query:      `SELECT process_id, voter_user_id_hash, display_name, scores_json, created_at, updated_at FROM uku_votes WHERE voter_user_id_hash=?1 ORDER BY updated_at DESC, process_id`,
			jsonFields: map[string]bool{"scores_json": true},
		},
	}
	for _, item := range queries {
		rows, err := s.queryAccountRows(ctx, item.query, userID, item.jsonFields)
		if err != nil {
			return AccountExportResponse{}, err
		}
		response.Tables[item.name] = rows
	}
	return response, nil
}

func (s *Store) queryAccountRows(ctx context.Context, query string, userID string, jsonFields map[string]bool) ([]map[string]any, error) {
	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for rows.Next() {
		values := make([]any, len(columns))
		dest := make([]any, len(columns))
		for i := range values {
			dest[i] = &values[i]
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		item := make(map[string]any, len(columns))
		for i, column := range columns {
			item[column] = exportRowValue(column, values[i], jsonFields)
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func exportRowValue(column string, value any, jsonFields map[string]bool) any {
	if value == nil {
		return nil
	}
	if bytes, ok := value.([]byte); ok {
		text := string(bytes)
		if jsonFields[column] {
			var raw any
			if err := json.Unmarshal(bytes, &raw); err == nil {
				return raw
			}
		}
		return text
	}
	return value
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
	if err := store.AutoMigrateAllAccounts(context.Background()); err != nil {
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
	alias TEXT UNIQUE,
	profile_icon INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS server_sync_state (
	user_id_hash TEXT PRIMARY KEY REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	server_version INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS server_sync_compaction (
	user_id_hash TEXT PRIMARY KEY REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	compacted_through_version INTEGER NOT NULL DEFAULT 0,
	updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
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
	protocol_version INTEGER NOT NULL DEFAULT 1,
	last_client_clock INTEGER NOT NULL DEFAULT 0,
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

CREATE TABLE IF NOT EXISTS server_social_snapshots (
	user_id_hash TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	kind TEXT NOT NULL,
	json TEXT NOT NULL DEFAULT '{}',
	updated_at TEXT NOT NULL,
	server_version INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY(user_id_hash, kind)
);

CREATE TABLE IF NOT EXISTS server_sync_ops (
	user_id_hash TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	op_id TEXT NOT NULL,
	client_id TEXT NOT NULL,
	seq INTEGER NOT NULL,
	entity_type TEXT NOT NULL,
	entity_id TEXT NOT NULL,
	local_date INTEGER NOT NULL DEFAULT 0,
	op_type TEXT NOT NULL,
	payload_json TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	server_version INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY(user_id_hash, op_id),
	UNIQUE(user_id_hash, client_id, seq)
);

CREATE TABLE IF NOT EXISTS server_habit_id_migrations (
	user_id_hash TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	old_id TEXT NOT NULL,
	new_id TEXT NOT NULL,
	source TEXT NOT NULL DEFAULT '',
	migrated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY(user_id_hash, old_id)
);

CREATE TABLE IF NOT EXISTS uku_processes (
	id TEXT PRIMARY KEY,
	owner_user_id_hash TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	question TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	visibility TEXT NOT NULL DEFAULT 'public',
	proposal_minutes INTEGER NOT NULL,
	voting_minutes INTEGER NOT NULL,
	negative_weight INTEGER NOT NULL,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	deleted_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS uku_proposals (
	process_id TEXT NOT NULL REFERENCES uku_processes(id) ON DELETE CASCADE,
	id TEXT NOT NULL,
	author_user_id_hash TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	title TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	deleted_at INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY(process_id, id)
);

CREATE TABLE IF NOT EXISTS uku_votes (
	process_id TEXT NOT NULL REFERENCES uku_processes(id) ON DELETE CASCADE,
	voter_user_id_hash TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	display_name TEXT NOT NULL DEFAULT '',
	scores_json TEXT NOT NULL,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY(process_id, voter_user_id_hash)
);

CREATE TABLE IF NOT EXISTS server_friend_requests (
	id TEXT PRIMARY KEY,
	requester_user_id_hash TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	target_user_id_hash TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	status TEXT NOT NULL DEFAULT 'pending',
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CHECK(requester_user_id_hash<>target_user_id_hash),
	UNIQUE(requester_user_id_hash,target_user_id_hash)
);

CREATE TABLE IF NOT EXISTS server_friendships (
	user_id_a TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	user_id_b TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY(user_id_a,user_id_b),
	CHECK(user_id_a<user_id_b)
);

CREATE TABLE IF NOT EXISTS server_profile_stats (
	user_id_hash TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	app TEXT NOT NULL,
	practice TEXT NOT NULL,
	metric TEXT NOT NULL,
	value REAL NOT NULL,
	label TEXT NOT NULL DEFAULT '',
	local_date INTEGER NOT NULL DEFAULT 0,
	updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY(user_id_hash,app,practice,metric)
);

CREATE TABLE IF NOT EXISTS server_leaderboard_stats (
	user_id_hash TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	app TEXT NOT NULL,
	practice TEXT NOT NULL,
	metric TEXT NOT NULL,
	source_version INTEGER NOT NULL DEFAULT 0,
	calc_version INTEGER NOT NULL DEFAULT 0,
	value REAL NOT NULL,
	label TEXT NOT NULL DEFAULT '',
	local_date INTEGER NOT NULL DEFAULT 0,
	updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY(user_id_hash,app,practice,metric)
);
`)
	if err != nil {
		return err
	}
	if err := s.migrateMeditationLogPrimaryKey(ctx); err != nil {
		return err
	}
	if err := s.migrateSocialCacheTable(ctx); err != nil {
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
		`ALTER TABLE server_social_snapshots ADD COLUMN server_version INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE server_users ADD COLUMN alias TEXT`,
		`ALTER TABLE server_users ADD COLUMN profile_icon INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE server_clients ADD COLUMN protocol_version INTEGER NOT NULL DEFAULT 1`,
		`ALTER TABLE server_clients ADD COLUMN last_client_clock INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE server_leaderboard_stats ADD COLUMN source_version INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE server_leaderboard_stats ADD COLUMN calc_version INTEGER NOT NULL DEFAULT 0`,
	} {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return err
		}
	}
	if _, err := s.db.ExecContext(ctx, `
CREATE UNIQUE INDEX IF NOT EXISTS server_users_alias_unique
ON server_users(alias)
WHERE alias IS NOT NULL AND alias<>''`); err != nil {
		return err
	}
	for _, stmt := range []string{
		`CREATE INDEX IF NOT EXISTS server_friend_requests_target_status ON server_friend_requests(target_user_id_hash,status,updated_at)`,
		`CREATE INDEX IF NOT EXISTS server_friend_requests_requester_status ON server_friend_requests(requester_user_id_hash,status,updated_at)`,
		`CREATE INDEX IF NOT EXISTS server_profile_stats_lookup ON server_profile_stats(app,practice,metric,value)`,
		`CREATE INDEX IF NOT EXISTS server_leaderboard_stats_lookup ON server_leaderboard_stats(app,practice,metric,value)`,
	} {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) migrateMeditationLogPrimaryKey(ctx context.Context) error {
	var userIDPK int
	var idPK int
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(server_meditation_logs)`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var defaultValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			rows.Close()
			return err
		}
		switch name {
		case "user_id_hash":
			userIDPK = pk
		case "id":
			idPK = pk
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if userIDPK == 1 && idPK == 2 {
		return nil
	}
	_, err = s.db.ExecContext(ctx, `
PRAGMA foreign_keys=OFF;
BEGIN;
CREATE TABLE IF NOT EXISTS server_meditation_logs_new (
	user_id_hash TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	id TEXT NOT NULL,
	session_id TEXT NOT NULL,
	duration_seconds INTEGER NOT NULL DEFAULT 0,
	completed_at TEXT NOT NULL,
	server_version INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY(user_id_hash, id)
);
INSERT OR IGNORE INTO server_meditation_logs_new(user_id_hash,id,session_id,duration_seconds,completed_at,server_version,created_at)
SELECT user_id_hash,id,session_id,duration_seconds,completed_at,server_version,created_at
FROM server_meditation_logs;
DROP TABLE server_meditation_logs;
ALTER TABLE server_meditation_logs_new RENAME TO server_meditation_logs;
COMMIT;
PRAGMA foreign_keys=ON;`)
	if err != nil {
		_, _ = s.db.ExecContext(ctx, `ROLLBACK; PRAGMA foreign_keys=ON;`)
		return err
	}
	return nil
}

func (s *Store) migrateSocialCacheTable(ctx context.Context) error {
	var exists int
	if err := s.db.QueryRowContext(ctx, `
SELECT EXISTS(
	SELECT 1 FROM sqlite_master
	WHERE type='table' AND name='server_social_cache'
)`).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
INSERT OR REPLACE INTO server_social_snapshots(user_id_hash,kind,json,updated_at,server_version)
SELECT user_id_hash,kind,json,updated_at,server_version
FROM server_social_cache;
DROP TABLE server_social_cache;`)
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
	result, _, err := s.ApplySyncDetailed(ctx, req, publicKey)
	return result, err
}

func (s *Store) ApplySyncDetailed(ctx context.Context, req SyncRequest, publicKey []byte) (SyncResult, []string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SyncResult{}, nil, err
	}
	defer tx.Rollback()

	if publicKey != nil {
		if err := upsertUser(ctx, tx, req.UserIDHash, publicKey); err != nil {
			return SyncResult{}, nil, err
		}
	} else if err := touchUser(ctx, tx, req.UserIDHash); err != nil {
		return SyncResult{}, nil, err
	}
	if req.FullSyncRequested {
		if err := replaceUserData(ctx, tx, req.UserIDHash); err != nil {
			return SyncResult{}, nil, err
		}
	}
	if len(req.SocialCache) > 0 {
		return SyncResult{}, nil, fmt.Errorf("social_cache is server-owned")
	}

	result := SyncResult{}
	deletedHabitIDs := map[string]bool{}
	for _, item := range req.MeditationLogs {
		version, err := nextUserVersion(ctx, tx, req.UserIDHash)
		if err != nil {
			return SyncResult{}, nil, err
		}
		res, err := tx.ExecContext(ctx, `
INSERT INTO server_meditation_logs(user_id_hash,id,session_id,duration_seconds,completed_at,server_version)
VALUES(?1,?2,?3,?4,?5,?6)
ON CONFLICT(user_id_hash,id) DO NOTHING`, req.UserIDHash, item.ID, item.SessionID, item.DurationSeconds, normalizeTime(item.CompletedAt, item.Timestamp), version)
		if err != nil {
			return SyncResult{}, nil, err
		}
		result.MeditationLogs += rowsAffected(res)
	}
	for _, habit := range req.Habits {
		originalID := habit.ID
		canonicalID, _, err := canonicalHabitIDForWrite(ctx, tx, req.UserIDHash, habit.ID, "legacy-write")
		if err != nil {
			return SyncResult{}, nil, err
		}
		habit.ID = canonicalID
		if req.Bootstrap && habit.DeletedAt > 0 {
			deletedHabitIDs[habit.ID] = true
			deletedHabitIDs[originalID] = true
			continue
		}
		if habit.DeletedAt > 0 {
			deletedHabitIDs[habit.ID] = true
			deletedHabitIDs[originalID] = true
			applied, err := deleteHabit(ctx, tx, req.UserIDHash, habit)
			if err != nil {
				return SyncResult{}, nil, err
			}
			result.Habits += applied
			continue
		}
		version, err := nextUserVersion(ctx, tx, req.UserIDHash)
		if err != nil {
			return SyncResult{}, nil, err
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
			return SyncResult{}, nil, err
		}
		result.Habits += rowsAffected(res)
	}
	for _, day := range req.HabitDays {
		originalID := day.HabitID
		if deletedHabitIDs[originalID] {
			continue
		}
		canonicalID, _, err := canonicalHabitIDForWrite(ctx, tx, req.UserIDHash, day.HabitID, "legacy-day-write")
		if err != nil {
			return SyncResult{}, nil, err
		}
		day.HabitID = canonicalID
		if deletedHabitIDs[day.HabitID] {
			continue
		}
		version, err := nextUserVersion(ctx, tx, req.UserIDHash)
		if err != nil {
			return SyncResult{}, nil, err
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
			return SyncResult{}, nil, err
		}
		result.HabitDays += rowsAffected(res)
	}
	for _, session := range req.Sessions {
		if req.Bootstrap && session.DeletedAt > 0 {
			continue
		}
		if session.DeletedAt > 0 {
			applied, err := deleteSession(ctx, tx, req.UserIDHash, session)
			if err != nil {
				return SyncResult{}, nil, err
			}
			result.Sessions += applied
			continue
		}
		applied, err := upsertSession(ctx, tx, req.UserIDHash, session)
		if err != nil {
			return SyncResult{}, nil, err
		}
		result.Sessions += applied
	}
	acceptedOps, err := applySyncOps(ctx, tx, req.UserIDHash, req.Ops, &result)
	if err != nil {
		return SyncResult{}, nil, err
	}
	if err := tx.Commit(); err != nil {
		return SyncResult{}, nil, err
	}
	return result, acceptedOps, nil
}

func applySyncOps(ctx context.Context, tx *sql.Tx, userID string, ops []SyncOp, result *SyncResult) ([]string, error) {
	accepted := []string{}
	for _, op := range ops {
		if op.OpID == "" || op.ClientID == "" || op.Seq <= 0 {
			return nil, fmt.Errorf("invalid sync op identity")
		}
		exists, err := syncOpExists(ctx, tx, userID, op.OpID)
		if err != nil {
			return nil, err
		}
		if exists {
			accepted = append(accepted, op.OpID)
			continue
		}
		if err := canonicalizeSyncOpHabitIDs(ctx, tx, userID, &op); err != nil {
			return nil, err
		}
		if err := materializeSyncOp(ctx, tx, userID, op, result); err != nil {
			return nil, err
		}
		version, err := currentUserVersionTx(ctx, tx, userID)
		if err != nil {
			return nil, err
		}
		if version <= 0 {
			version, err = nextUserVersion(ctx, tx, userID)
			if err != nil {
				return nil, err
			}
		}
		payload := string(op.Payload)
		createdAt := normalizeTime(op.CreatedAt, "")
		if createdAt == "" {
			createdAt = time.Now().UTC().Format(time.RFC3339)
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO server_sync_ops(user_id_hash,op_id,client_id,seq,entity_type,entity_id,local_date,op_type,payload_json,created_at,server_version)
VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)`,
			userID, op.OpID, op.ClientID, op.Seq, op.EntityType, op.EntityID,
			op.LocalDate, op.OpType, payload, createdAt, version); err != nil {
			return nil, err
		}
		accepted = append(accepted, op.OpID)
	}
	return accepted, nil
}

func canonicalizeSyncOpHabitIDs(ctx context.Context, tx *sql.Tx, userID string, op *SyncOp) error {
	if op == nil {
		return nil
	}
	if op.EntityType != "habit" && op.EntityType != "habit_day" {
		return nil
	}
	id := strings.TrimSpace(op.EntityID)
	if id == "" && len(op.Payload) > 0 {
		var obj struct {
			ID      string `json:"id"`
			HabitID string `json:"habit_id"`
		}
		if err := json.Unmarshal(op.Payload, &obj); err == nil {
			if obj.HabitID != "" {
				id = obj.HabitID
			} else {
				id = obj.ID
			}
		}
	}
	if id == "" {
		return fmt.Errorf("habit op missing id")
	}
	canonicalID, _, err := canonicalHabitIDForWrite(ctx, tx, userID, id, "legacy-op")
	if err != nil {
		return err
	}
	op.EntityID = canonicalID
	op.Payload = rewriteHabitPayloadID(op.Payload, canonicalID)
	return nil
}

func syncOpExists(ctx context.Context, tx *sql.Tx, userID, opID string) (bool, error) {
	var exists int
	err := tx.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM server_sync_ops WHERE user_id_hash=?1 AND op_id=?2)`,
		userID, opID).Scan(&exists)
	return exists != 0, err
}

func materializeSyncOp(ctx context.Context, tx *sql.Tx, userID string, op SyncOp, result *SyncResult) error {
	switch op.EntityType {
	case "habit":
		var habit Habit
		if len(op.Payload) == 0 {
			return fmt.Errorf("habit op missing payload")
		}
		if err := json.Unmarshal(op.Payload, &habit); err != nil {
			return err
		}
		if habit.ID == "" {
			habit.ID = op.EntityID
		}
		if op.OpType == "delete" && habit.DeletedAt <= 0 {
			habit.DeletedAt = time.Now().Unix()
		}
		if habit.DeletedAt > 0 || op.OpType == "delete" {
			applied, err := deleteHabit(ctx, tx, userID, habit)
			if err != nil {
				return err
			}
			result.Habits += applied
			return nil
		}
		version, err := nextUserVersion(ctx, tx, userID)
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `
INSERT INTO server_habits(user_id_hash,id,name,color_r,color_g,color_b,sync_mode,sync_activity,counter_enabled,sort_order,deleted_at,updated_at,server_version)
VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
ON CONFLICT(user_id_hash,id) DO UPDATE SET
	name=excluded.name,color_r=excluded.color_r,color_g=excluded.color_g,color_b=excluded.color_b,
	sync_mode=excluded.sync_mode,sync_activity=excluded.sync_activity,counter_enabled=excluded.counter_enabled,
	sort_order=excluded.sort_order,deleted_at=excluded.deleted_at,updated_at=excluded.updated_at,
	server_version=excluded.server_version
WHERE excluded.updated_at >= server_habits.updated_at`,
			userID, habit.ID, habit.Name, habit.ColorR, habit.ColorG, habit.ColorB,
			habit.SyncMode, habit.SyncActivity, habit.CounterEnabled, habit.SortOrder,
			habit.DeletedAt, normalizeTime(habit.UpdatedAt, ""), version)
		if err != nil {
			return err
		}
		result.Habits += rowsAffected(res)
	case "habit_day":
		var day HabitDay
		if len(op.Payload) == 0 {
			return fmt.Errorf("habit_day op missing payload")
		}
		if err := json.Unmarshal(op.Payload, &day); err != nil {
			return err
		}
		if day.HabitID == "" {
			day.HabitID = op.EntityID
		}
		if day.LocalDate == 0 {
			day.LocalDate = op.LocalDate
		}
		if op.OpType == "delete" {
			applied, err := deleteHabitDay(ctx, tx, userID, day)
			if err != nil {
				return err
			}
			result.HabitDays += applied
			return nil
		}
		version, err := nextUserVersion(ctx, tx, userID)
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `
INSERT INTO server_habit_days(user_id_hash,habit_id,local_date,completed,count,updated_at,server_version)
VALUES(?1,?2,?3,?4,?5,?6,?7)
ON CONFLICT(user_id_hash,habit_id,local_date) DO UPDATE SET
	completed=excluded.completed,count=excluded.count,updated_at=excluded.updated_at,server_version=excluded.server_version
WHERE excluded.updated_at >= server_habit_days.updated_at`,
			userID, day.HabitID, day.LocalDate, boolInt(day.Completed),
			normalizedHabitDayCount(day), normalizeTime(day.UpdatedAt, ""), version)
		if err != nil {
			return err
		}
		result.HabitDays += rowsAffected(res)
	case "session":
		var session Session
		if len(op.Payload) == 0 {
			return fmt.Errorf("session op missing payload")
		}
		if err := json.Unmarshal(op.Payload, &session); err != nil {
			return err
		}
		if session.ID == "" {
			session.ID = op.EntityID
		}
		if op.OpType == "delete" && session.DeletedAt <= 0 {
			session.DeletedAt = time.Now().Unix()
		}
		if session.DeletedAt > 0 || op.OpType == "delete" {
			applied, err := deleteSession(ctx, tx, userID, session)
			if err != nil {
				return err
			}
			result.Sessions += applied
			return nil
		}
		applied, err := upsertSession(ctx, tx, userID, session)
		if err != nil {
			return err
		}
		result.Sessions += applied
	case "social_snapshots":
		return fmt.Errorf("social_cache is server-owned")
	default:
		if _, err := nextUserVersion(ctx, tx, userID); err != nil {
			return err
		}
	}
	return nil
}

func currentUserVersionTx(ctx context.Context, tx *sql.Tx, userID string) (int64, error) {
	var version int64
	err := tx.QueryRowContext(ctx, `
SELECT server_version
FROM server_sync_state
WHERE user_id_hash=?1`, userID).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return version, err
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

func (s *Store) AccountAlias(ctx context.Context, userID string) (string, error) {
	var alias sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT alias FROM server_users WHERE user_id_hash=?1`, userID).Scan(&alias)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !alias.Valid {
		return "", nil
	}
	return alias.String, nil
}

func (s *Store) SetAccountAlias(ctx context.Context, userID, alias string) error {
	res, err := s.db.ExecContext(ctx, `
UPDATE server_users
SET alias=?2,last_seen_at=CURRENT_TIMESTAMP
WHERE user_id_hash=?1`, userID, alias)
	if err != nil {
		return err
	}
	if rowsAffected(res) == 0 {
		return ErrSyncUserNotFound
	}
	return nil
}

func (s *Store) AccountProfileIcon(ctx context.Context, userID string) (int, error) {
	var profileIcon int
	err := s.db.QueryRowContext(ctx, `SELECT profile_icon FROM server_users WHERE user_id_hash=?1`, userID).Scan(&profileIcon)
	if errors.Is(err, sql.ErrNoRows) {
		return ProfileIconNone, nil
	}
	if err != nil {
		return ProfileIconNone, err
	}
	return profileIcon, nil
}

func (s *Store) SetAccountProfileIcon(ctx context.Context, userID string, profileIcon int) error {
	res, err := s.db.ExecContext(ctx, `
UPDATE server_users
SET profile_icon=?2,last_seen_at=CURRENT_TIMESTAMP
WHERE user_id_hash=?1`, userID, profileIcon)
	if err != nil {
		return err
	}
	if rowsAffected(res) == 0 {
		return ErrSyncUserNotFound
	}
	return nil
}

func (s *Store) ResolveAccountRef(ctx context.Context, ref string) (string, bool, error) {
	ref = strings.TrimSpace(ref)
	if strings.HasPrefix(ref, "@") {
		ref = strings.TrimPrefix(ref, "@")
	}
	if validUserID(strings.ToLower(ref)) {
		userID := strings.ToLower(ref)
		var exists int
		err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM server_users WHERE user_id_hash=?1)`, userID).Scan(&exists)
		return userID, exists != 0, err
	}
	alias := strings.ToLower(ref)
	if !accountAliasPattern.MatchString(alias) {
		return "", false, nil
	}
	var userID string
	err := s.db.QueryRowContext(ctx, `SELECT user_id_hash FROM server_users WHERE alias=?1`, alias).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return userID, true, err
}

func friendPair(a, b string) (string, string) {
	if a < b {
		return a, b
	}
	return b, a
}

func (s *Store) CreateFriendRequest(ctx context.Context, id, requester, target string) (FriendRequest, error) {
	if requester == target {
		return FriendRequest{}, errors.New("cannot friend self")
	}
	a, b := friendPair(requester, target)
	var alreadyFriends int
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM server_friendships WHERE user_id_a=?1 AND user_id_b=?2)`, a, b).Scan(&alreadyFriends); err != nil {
		return FriendRequest{}, err
	}
	if alreadyFriends != 0 {
		return FriendRequest{}, errors.New("already friends")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO server_friend_requests(id,requester_user_id_hash,target_user_id_hash,status,created_at,updated_at)
VALUES(?1,?2,?3,'pending',?4,?4)
ON CONFLICT(requester_user_id_hash,target_user_id_hash) DO UPDATE SET
	status=CASE WHEN server_friend_requests.status='declined' THEN 'pending' ELSE server_friend_requests.status END,
	updated_at=CASE WHEN server_friend_requests.status='declined' THEN excluded.updated_at ELSE server_friend_requests.updated_at END`,
		id, requester, target, now); err != nil {
		return FriendRequest{}, err
	}
	return s.friendRequestByUsers(ctx, requester, target)
}

func (s *Store) friendRequestByUsers(ctx context.Context, requester, target string) (FriendRequest, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT fr.id,fr.requester_user_id_hash,COALESCE(ru.alias,''),fr.target_user_id_hash,COALESCE(tu.alias,''),fr.status,fr.created_at,fr.updated_at
FROM server_friend_requests fr
JOIN server_users ru ON ru.user_id_hash=fr.requester_user_id_hash
JOIN server_users tu ON tu.user_id_hash=fr.target_user_id_hash
WHERE fr.requester_user_id_hash=?1 AND fr.target_user_id_hash=?2`, requester, target)
	return scanFriendRequest(row)
}

func (s *Store) FriendRequest(ctx context.Context, id string) (FriendRequest, bool, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT fr.id,fr.requester_user_id_hash,COALESCE(ru.alias,''),fr.target_user_id_hash,COALESCE(tu.alias,''),fr.status,fr.created_at,fr.updated_at
FROM server_friend_requests fr
JOIN server_users ru ON ru.user_id_hash=fr.requester_user_id_hash
JOIN server_users tu ON tu.user_id_hash=fr.target_user_id_hash
WHERE fr.id=?1`, id)
	req, err := scanFriendRequest(row)
	if errors.Is(err, sql.ErrNoRows) {
		return FriendRequest{}, false, nil
	}
	return req, err == nil, err
}

func scanFriendRequest(row interface{ Scan(...any) error }) (FriendRequest, error) {
	var req FriendRequest
	err := row.Scan(&req.ID, &req.RequesterUserID, &req.RequesterAlias, &req.TargetUserID, &req.TargetAlias, &req.Status, &req.CreatedAt, &req.UpdatedAt)
	return req, err
}

func (s *Store) ListFriendRequests(ctx context.Context, userID string) ([]FriendRequest, []FriendRequest, error) {
	query := func(where string) ([]FriendRequest, error) {
		rows, err := s.db.QueryContext(ctx, `
SELECT fr.id,fr.requester_user_id_hash,COALESCE(ru.alias,''),fr.target_user_id_hash,COALESCE(tu.alias,''),fr.status,fr.created_at,fr.updated_at
FROM server_friend_requests fr
JOIN server_users ru ON ru.user_id_hash=fr.requester_user_id_hash
JOIN server_users tu ON tu.user_id_hash=fr.target_user_id_hash
WHERE `+where+` AND fr.status='pending'
ORDER BY fr.updated_at DESC`, userID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		items := []FriendRequest{}
		for rows.Next() {
			req, err := scanFriendRequest(rows)
			if err != nil {
				return nil, err
			}
			items = append(items, req)
		}
		return items, rows.Err()
	}
	incoming, err := query("fr.target_user_id_hash=?1")
	if err != nil {
		return nil, nil, err
	}
	outgoing, err := query("fr.requester_user_id_hash=?1")
	return incoming, outgoing, err
}

func (s *Store) AcceptFriendRequest(ctx context.Context, userID, id string) (FriendRequest, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return FriendRequest{}, err
	}
	defer tx.Rollback()
	var req FriendRequest
	row := tx.QueryRowContext(ctx, `
SELECT fr.id,fr.requester_user_id_hash,COALESCE(ru.alias,''),fr.target_user_id_hash,COALESCE(tu.alias,''),fr.status,fr.created_at,fr.updated_at
FROM server_friend_requests fr
JOIN server_users ru ON ru.user_id_hash=fr.requester_user_id_hash
JOIN server_users tu ON tu.user_id_hash=fr.target_user_id_hash
WHERE fr.id=?1`, id)
	if err := row.Scan(&req.ID, &req.RequesterUserID, &req.RequesterAlias, &req.TargetUserID, &req.TargetAlias, &req.Status, &req.CreatedAt, &req.UpdatedAt); err != nil {
		return FriendRequest{}, err
	}
	if req.TargetUserID != userID {
		return FriendRequest{}, ErrSyncUserNotFound
	}
	if req.Status != "pending" {
		return FriendRequest{}, errors.New("request not pending")
	}
	a, b := friendPair(req.RequesterUserID, req.TargetUserID)
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := tx.ExecContext(ctx, `UPDATE server_friend_requests SET status='accepted',updated_at=?2 WHERE id=?1`, id, now); err != nil {
		return FriendRequest{}, err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT OR IGNORE INTO server_friendships(user_id_a,user_id_b,created_at)
VALUES(?1,?2,?3)`, a, b, now); err != nil {
		return FriendRequest{}, err
	}
	if err := tx.Commit(); err != nil {
		return FriendRequest{}, err
	}
	req.Status = "accepted"
	req.UpdatedAt = now
	return req, nil
}

func (s *Store) DeclineFriendRequest(ctx context.Context, userID, id string) (FriendRequest, error) {
	req, found, err := s.FriendRequest(ctx, id)
	if err != nil {
		return FriendRequest{}, err
	}
	if !found {
		return FriendRequest{}, sql.ErrNoRows
	}
	if req.TargetUserID != userID && req.RequesterUserID != userID {
		return FriendRequest{}, ErrSyncUserNotFound
	}
	if req.Status != "pending" {
		return FriendRequest{}, errors.New("request not pending")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.db.ExecContext(ctx, `UPDATE server_friend_requests SET status='declined',updated_at=?2 WHERE id=?1`, id, now); err != nil {
		return FriendRequest{}, err
	}
	req.Status = "declined"
	req.UpdatedAt = now
	return req, nil
}

func (s *Store) ListFriends(ctx context.Context, userID string) ([]Friend, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT u.user_id_hash,COALESCE(u.alias,''),u.profile_icon,f.created_at
FROM server_friendships f
JOIN server_users u ON u.user_id_hash=CASE WHEN f.user_id_a=?1 THEN f.user_id_b ELSE f.user_id_a END
WHERE f.user_id_a=?1 OR f.user_id_b=?1
ORDER BY COALESCE(u.alias,u.user_id_hash),u.user_id_hash`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Friend{}
	for rows.Next() {
		var item Friend
		if err := rows.Scan(&item.UserIDHash, &item.Alias, &item.ProfileIcon, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) RemoveFriend(ctx context.Context, userID, friendID string) error {
	a, b := friendPair(userID, friendID)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM server_friendships WHERE user_id_a=?1 AND user_id_b=?2`, a, b); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM server_friend_requests
WHERE (requester_user_id_hash=?1 AND target_user_id_hash=?2)
   OR (requester_user_id_hash=?2 AND target_user_id_hash=?1)`, userID, friendID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) UpsertProfileStats(ctx context.Context, userID, app string, metrics []ProfileMetric) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339)
	applied := 0
	for _, metric := range metrics {
		practice := strings.TrimSpace(metric.Practice)
		name := strings.TrimSpace(metric.Metric)
		if practice == "" || name == "" {
			continue
		}
		res, err := tx.ExecContext(ctx, `
INSERT INTO server_profile_stats(user_id_hash,app,practice,metric,value,label,local_date,updated_at)
VALUES(?1,?2,?3,?4,?5,?6,?7,?8)
ON CONFLICT(user_id_hash,app,practice,metric) DO UPDATE SET
	value=excluded.value,label=excluded.label,local_date=excluded.local_date,updated_at=excluded.updated_at
WHERE excluded.value != server_profile_stats.value
   OR excluded.label != server_profile_stats.label
   OR excluded.local_date != server_profile_stats.local_date`,
			userID, app, practice, name, metric.Value, metric.Label, metric.LocalDate, now)
		if err != nil {
			return 0, err
		}
		applied += rowsAffected(res)
	}
	return applied, tx.Commit()
}

type visibleStatsUser struct {
	UserIDHash    string
	Alias         string
	ProfileIcon   int
	SourceVersion int64
}

const leaderboardStatsCalcVersion = 3

func leaderboardActivity(practice string) int {
	switch practice {
	case "meditation":
		return 1
	case "sun_salutation":
		return 2
	default:
		return 0
	}
}

func leaderboardTimeLabel(seconds int) string {
	if seconds < 0 {
		seconds = 0
	}
	return fmt.Sprintf("%d:%02d", seconds/3600, (seconds%3600)/60)
}

func (s *Store) visibleStatsUsers(ctx context.Context, userID string) ([]visibleStatsUser, error) {
	rows, err := s.db.QueryContext(ctx, `
WITH visible_users AS (
  SELECT u.user_id_hash, COALESCE(u.alias,'') AS alias, u.profile_icon
  FROM server_users u
  WHERE u.user_id_hash=?1
  UNION
  SELECT u.user_id_hash, COALESCE(u.alias,'') AS alias, u.profile_icon
  FROM server_friendships f
  JOIN server_users u ON u.user_id_hash=CASE
      WHEN f.user_id_a=?1 THEN f.user_id_b
      ELSE f.user_id_a
  END
  WHERE f.user_id_a=?1 OR f.user_id_b=?1
)
SELECT vu.user_id_hash, vu.alias, vu.profile_icon, COALESCE(ss.server_version,0)
FROM visible_users vu
LEFT JOIN server_sync_state ss ON ss.user_id_hash=vu.user_id_hash`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := []visibleStatsUser{}
	for rows.Next() {
		var user visibleStatsUser
		if err := rows.Scan(&user.UserIDHash, &user.Alias, &user.ProfileIcon, &user.SourceVersion); err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

func (s *Store) cachedLeaderboardStat(ctx context.Context, user visibleStatsUser, app, practice, metric string) (FriendStatRow, bool, error) {
	var row FriendStatRow
	var sourceVersion int64
	var calcVersion int
	err := s.db.QueryRowContext(ctx, `
SELECT source_version,calc_version,value,label,local_date,updated_at
FROM server_leaderboard_stats
WHERE user_id_hash=?1 AND app=?2 AND practice=?3 AND metric=?4`,
		user.UserIDHash, app, practice, metric).Scan(&sourceVersion, &calcVersion, &row.Value, &row.Label, &row.LocalDate, &row.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return row, false, nil
	}
	if err != nil {
		return row, false, err
	}
	if sourceVersion != user.SourceVersion || calcVersion != leaderboardStatsCalcVersion {
		return row, false, nil
	}
	row.UserIDHash = user.UserIDHash
	row.Alias = user.Alias
	row.ProfileIcon = user.ProfileIcon
	row.App = app
	row.Practice = practice
	row.Metric = metric
	return row, true, nil
}

func (s *Store) activityStreak(ctx context.Context, userID string, activity int) (int, int, string, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT local_date, updated_at FROM server_sessions
WHERE user_id_hash=?1 AND deleted_at=0 AND activity=?2 AND local_date>0
UNION
SELECT CAST(strftime('%Y%m%d', completed_at) AS INTEGER), completed_at
FROM server_meditation_logs
WHERE user_id_hash=?1 AND ?2=1 AND duration_seconds>0`, userID, activity)
	if err != nil {
		return 0, 0, "", err
	}
	defer rows.Close()
	seen := map[int]bool{}
	updatedAt := ""
	latestDate := 0
	for rows.Next() {
		var localDate int
		var updated string
		if err := rows.Scan(&localDate, &updated); err != nil {
			return 0, 0, "", err
		}
		if localDate > 0 {
			seen[localDate] = true
			if localDate > latestDate {
				latestDate = localDate
			}
		}
		if updated > updatedAt {
			updatedAt = updated
		}
	}
	if err := rows.Err(); err != nil {
		return 0, 0, "", err
	}
	today := time.Now().UTC()
	todayDate := today.Year()*10000 + int(today.Month())*100 + today.Day()
	start := today
	if !seen[todayDate] && latestDate > 0 {
		start = time.Date(latestDate/10000, time.Month((latestDate/100)%100), latestDate%100, 12, 0, 0, 0, time.UTC)
	}
	streak := 0
	for ; streak <= 370; streak++ {
		day := start.AddDate(0, 0, -streak)
		localDate := day.Year()*10000 + int(day.Month())*100 + day.Day()
		if !seen[localDate] {
			break
		}
	}
	return streak, todayDate, updatedAt, nil
}

func (s *Store) activityAverage(ctx context.Context, userID string, practice, metric string) (float64, string, error) {
	switch metric {
	case "avg_hold":
		if practice != "whm" {
			return 0, "0", nil
		}
		var value float64
		err := s.db.QueryRowContext(ctx, `
SELECT COALESCE(AVG(sr.hold_seconds),0)
FROM server_sessions s
JOIN server_session_rounds sr ON sr.user_id_hash=s.user_id_hash AND sr.session_id=s.id
WHERE s.user_id_hash=?1 AND s.deleted_at=0 AND s.activity=0 AND sr.hold_seconds>0`, userID).Scan(&value)
		return value, fmt.Sprintf("%.0f", value), err
	case "avg_time":
		if practice != "meditation" {
			return 0, leaderboardTimeLabel(0), nil
		}
		var value float64
		err := s.db.QueryRowContext(ctx, `
WITH session_totals AS (
  SELECT s.id, SUM(sr.hold_seconds) AS seconds
  FROM server_sessions s
  JOIN server_session_rounds sr ON sr.user_id_hash=s.user_id_hash AND sr.session_id=s.id
  WHERE s.user_id_hash=?1 AND s.deleted_at=0 AND s.activity=1 AND sr.hold_seconds>0
  GROUP BY s.id
),
log_totals AS (
  SELECT ml.session_id AS id, ml.duration_seconds AS seconds
  FROM server_meditation_logs ml
  WHERE ml.user_id_hash=?1 AND ml.duration_seconds>0
    AND NOT EXISTS (SELECT 1 FROM session_totals st WHERE st.id=ml.session_id)
),
all_totals AS (
  SELECT seconds FROM session_totals
  UNION ALL
  SELECT seconds FROM log_totals
)
SELECT COALESCE(AVG(seconds),0) FROM all_totals`, userID).Scan(&value)
		return value, leaderboardTimeLabel(int(value + 0.5)), err
	default:
		return 0, "0", nil
	}
}

func (s *Store) computeLeaderboardStat(ctx context.Context, user visibleStatsUser, app, practice, metric string) (FriendStatRow, error) {
	activity := leaderboardActivity(practice)
	streak, todayDate, updatedAt, err := s.activityStreak(ctx, user.UserIDHash, activity)
	if err != nil {
		return FriendStatRow{}, err
	}
	row := FriendStatRow{
		UserIDHash:  user.UserIDHash,
		Alias:       user.Alias,
		ProfileIcon: user.ProfileIcon,
		App:         app,
		Practice:    practice,
		Metric:      metric,
		LocalDate:   todayDate,
		UpdatedAt:   updatedAt,
	}
	if metric == "streak" {
		row.Value = float64(streak)
		row.Label = fmt.Sprintf("%d", streak)
	} else {
		value, label, err := s.activityAverage(ctx, user.UserIDHash, practice, metric)
		if err != nil {
			return row, err
		}
		row.Value = value
		row.Label = label
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO server_leaderboard_stats(user_id_hash,app,practice,metric,source_version,calc_version,value,label,local_date,updated_at)
VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
ON CONFLICT(user_id_hash,app,practice,metric) DO UPDATE SET
	source_version=excluded.source_version,
	calc_version=excluded.calc_version,
	value=excluded.value,
	label=excluded.label,
	local_date=excluded.local_date,
	updated_at=excluded.updated_at`,
		user.UserIDHash, app, practice, metric, user.SourceVersion, leaderboardStatsCalcVersion,
		row.Value, row.Label, row.LocalDate, row.UpdatedAt)
	return row, err
}

func (s *Store) FriendStats(ctx context.Context, userID, app, practice, metric string) ([]FriendStatRow, error) {
	users, err := s.visibleStatsUsers(ctx, userID)
	if err != nil {
		return nil, err
	}
	items := make([]FriendStatRow, 0, len(users))
	for _, user := range users {
		row, ok, err := s.cachedLeaderboardStat(ctx, user, app, practice, metric)
		if err != nil {
			return nil, err
		}
		if !ok {
			row, err = s.computeLeaderboardStat(ctx, user, app, practice, metric)
			if err != nil {
				return nil, err
			}
		}
		items = append(items, row)
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Value != items[j].Value {
			return items[i].Value > items[j].Value
		}
		left := items[i].Alias
		if left == "" {
			left = items[i].UserIDHash
		}
		right := items[j].Alias
		if right == "" {
			right = items[j].UserIDHash
		}
		if left != right {
			return left < right
		}
		return items[i].UserIDHash < items[j].UserIDHash
	})
	return items, nil
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

func (s *Store) RecordClientSync(ctx context.Context, userID, clientID string, sinceVersion, serverVersion int64, protocolVersion int, clientClock int64) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO server_clients(user_id_hash,client_id,last_seen_at,last_sync_at,last_since_server_version,last_seen_server_version,protocol_version,last_client_clock)
VALUES(?1,?2,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,?3,?4,?5,?6)
ON CONFLICT(user_id_hash,client_id) DO UPDATE SET
	last_seen_at=CURRENT_TIMESTAMP,
	last_sync_at=CURRENT_TIMESTAMP,
	last_since_server_version=excluded.last_since_server_version,
	last_seen_server_version=excluded.last_seen_server_version,
	protocol_version=excluded.protocol_version,
	last_client_clock=excluded.last_client_clock`, userID, clientID, sinceVersion, serverVersion, protocolVersion, clientClock)
	return err
}

func (s *Store) SyncOpsCompacted(ctx context.Context, userID string, clientClock int64) (bool, int64, error) {
	var compactedThrough int64
	err := s.db.QueryRowContext(ctx, `
SELECT compacted_through_version
FROM server_sync_compaction
WHERE user_id_hash=?1`, userID).Scan(&compactedThrough)
	if errors.Is(err, sql.ErrNoRows) {
		return false, 0, nil
	}
	if err != nil {
		return false, 0, err
	}
	return compactedThrough > 0 && clientClock < compactedThrough, compactedThrough, nil
}

func (s *Store) CompactSyncOps(ctx context.Context, userID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	currentVersion, err := currentUserVersionTx(ctx, tx, userID)
	if err != nil {
		return err
	}
	if currentVersion <= 0 {
		return tx.Commit()
	}

	cutoff := time.Now().UTC().Add(-syncClientActiveRetention).Format(time.RFC3339)
	var floor sql.NullInt64
	if err := tx.QueryRowContext(ctx, `
SELECT MIN(last_client_clock)
FROM server_clients
WHERE user_id_hash=?1
  AND protocol_version>=2
	AND last_client_clock>0
	AND last_seen_at>=?2`, userID, cutoff).Scan(&floor); err != nil {
		return err
	}
	if !floor.Valid || floor.Int64 <= 0 {
		return tx.Commit()
	}

	compactThrough := floor.Int64
	if compactThrough > currentVersion {
		compactThrough = currentVersion
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM server_sync_ops
WHERE user_id_hash=?1 AND server_version<=?2`, userID, compactThrough); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO server_sync_compaction(user_id_hash,compacted_through_version,updated_at)
VALUES(?1,?2,CURRENT_TIMESTAMP)
ON CONFLICT(user_id_hash) DO UPDATE SET
	compacted_through_version=MAX(server_sync_compaction.compacted_through_version,excluded.compacted_through_version),
	updated_at=CURRENT_TIMESTAMP`, userID, compactThrough); err != nil {
		return err
	}
	return tx.Commit()
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

func (s *Store) ListUkuPublicProcesses(ctx context.Context, limit int) ([]UkuProcess, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id,owner_user_id_hash,question,description,visibility,proposal_minutes,voting_minutes,negative_weight,created_at,updated_at
FROM uku_processes
WHERE deleted_at=0 AND visibility='public'
ORDER BY created_at DESC
LIMIT ?1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanUkuProcesses(rows)
}

func (s *Store) UkuProcess(ctx context.Context, id string) (UkuProcess, bool, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id,owner_user_id_hash,question,description,visibility,proposal_minutes,voting_minutes,negative_weight,created_at,updated_at
FROM uku_processes
WHERE id=?1 AND deleted_at=0`, id)
	process, err := scanUkuProcess(row)
	if errors.Is(err, sql.ErrNoRows) {
		return UkuProcess{}, false, nil
	}
	if err != nil {
		return UkuProcess{}, false, err
	}
	proposals, err := s.UkuProposals(ctx, id)
	if err != nil {
		return UkuProcess{}, false, err
	}
	votes, err := s.UkuVotes(ctx, id)
	if err != nil {
		return UkuProcess{}, false, err
	}
	process.Proposals = proposals
	process.Votes = votes
	return process, true, nil
}

func (s *Store) CreateUkuProcess(ctx context.Context, req UkuCreateProcessRequest) (UkuProcess, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO uku_processes(id,owner_user_id_hash,question,description,visibility,proposal_minutes,voting_minutes,negative_weight,created_at,updated_at)
VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?9)`,
		req.ID, req.UserIDHash, req.Question, req.Description, req.Visibility,
		req.ProposalMinutes, req.VotingMinutes, req.NegativeWeight, now); err != nil {
		return UkuProcess{}, err
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO uku_proposals(process_id,id,author_user_id_hash,title,description,created_at,updated_at)
VALUES(?1,'status-quo',?2,'Status quo','keep things the way they are',?3,?3),
      (?1,'repeat-process',?2,'Repeat process','repeat the process and look for other options',?3,?3)`,
		req.ID, req.UserIDHash, now); err != nil {
		return UkuProcess{}, err
	}
	process, _, err := s.UkuProcess(ctx, req.ID)
	return process, err
}

func (s *Store) UpdateUkuProcess(ctx context.Context, processID string, req UkuUpdateProcessRequest) (UkuProcess, error) {
	current, found, err := s.UkuProcess(ctx, processID)
	if err != nil {
		return UkuProcess{}, err
	}
	if !found {
		return UkuProcess{}, sql.ErrNoRows
	}
	if current.OwnerUserIDHash != req.UserIDHash {
		return UkuProcess{}, ErrSyncUserNotFound
	}
	question := current.Question
	description := current.Description
	visibility := current.Visibility
	if strings.TrimSpace(req.Question) != "" {
		question = strings.TrimSpace(req.Question)
	}
	if req.Description != "" {
		description = strings.TrimSpace(req.Description)
	}
	if strings.TrimSpace(req.Visibility) != "" {
		visibility = strings.TrimSpace(req.Visibility)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.db.ExecContext(ctx, `
UPDATE uku_processes
SET question=?2,description=?3,visibility=?4,updated_at=?5
WHERE id=?1 AND owner_user_id_hash=?6 AND deleted_at=0`,
		processID, question, description, visibility, now, req.UserIDHash); err != nil {
		return UkuProcess{}, err
	}
	process, _, err := s.UkuProcess(ctx, processID)
	return process, err
}

func (s *Store) DeleteUkuProcess(ctx context.Context, processID, userID string) error {
	current, found, err := s.UkuProcess(ctx, processID)
	if err != nil {
		return err
	}
	if !found {
		return sql.ErrNoRows
	}
	if current.OwnerUserIDHash != userID {
		return ErrSyncUserNotFound
	}
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `
UPDATE uku_processes
SET deleted_at=?2,updated_at=?3
WHERE id=?1 AND owner_user_id_hash=?4 AND deleted_at=0`,
		processID, now.Unix(), now.Format(time.RFC3339), userID)
	if err != nil {
		return err
	}
	if rowsAffected(res) == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) UpsertUkuProposal(ctx context.Context, processID string, req UkuProposalRequest) (UkuProcess, error) {
	if _, found, err := s.UkuProcess(ctx, processID); err != nil {
		return UkuProcess{}, err
	} else if !found {
		return UkuProcess{}, sql.ErrNoRows
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO uku_proposals(process_id,id,author_user_id_hash,title,description,created_at,updated_at)
VALUES(?1,?2,?3,?4,?5,?6,?6)
ON CONFLICT(process_id,id) DO UPDATE SET
	title=excluded.title,
	description=excluded.description,
	updated_at=excluded.updated_at
WHERE uku_proposals.author_user_id_hash=excluded.author_user_id_hash`,
		processID, req.ID, req.UserIDHash, req.Title, req.Description, now); err != nil {
		return UkuProcess{}, err
	}
	process, _, err := s.UkuProcess(ctx, processID)
	return process, err
}

func (s *Store) DeleteUkuProposal(ctx context.Context, processID, proposalID, userID string) (UkuProcess, error) {
	if _, found, err := s.UkuProcess(ctx, processID); err != nil {
		return UkuProcess{}, err
	} else if !found {
		return UkuProcess{}, sql.ErrNoRows
	}
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `
UPDATE uku_proposals
SET deleted_at=?3,updated_at=?4
WHERE process_id=?1 AND id=?2 AND author_user_id_hash=?5 AND deleted_at=0`,
		processID, proposalID, now.Unix(), now.Format(time.RFC3339), userID)
	if err != nil {
		return UkuProcess{}, err
	}
	if rowsAffected(res) == 0 {
		var exists int
		err := s.db.QueryRowContext(ctx, `
SELECT 1
FROM uku_proposals
WHERE process_id=?1 AND id=?2 AND deleted_at=0`,
			processID, proposalID).Scan(&exists)
		if errors.Is(err, sql.ErrNoRows) {
			return UkuProcess{}, sql.ErrNoRows
		}
		if err != nil {
			return UkuProcess{}, err
		}
		return UkuProcess{}, ErrSyncUserNotFound
	}
	process, _, err := s.UkuProcess(ctx, processID)
	return process, err
}

func (s *Store) UpsertUkuVote(ctx context.Context, processID string, req UkuVoteRequest) (UkuProcess, error) {
	if _, found, err := s.UkuProcess(ctx, processID); err != nil {
		return UkuProcess{}, err
	} else if !found {
		return UkuProcess{}, sql.ErrNoRows
	}
	scores, err := json.Marshal(req.Scores)
	if err != nil {
		return UkuProcess{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO uku_votes(process_id,voter_user_id_hash,display_name,scores_json,created_at,updated_at)
VALUES(?1,?2,?3,?4,?5,?5)
ON CONFLICT(process_id,voter_user_id_hash) DO UPDATE SET
	display_name=excluded.display_name,
	scores_json=excluded.scores_json,
	updated_at=excluded.updated_at`,
		processID, req.UserIDHash, req.DisplayName, string(scores), now); err != nil {
		return UkuProcess{}, err
	}
	process, _, err := s.UkuProcess(ctx, processID)
	return process, err
}

func (s *Store) UkuProposals(ctx context.Context, processID string) ([]UkuProposal, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id,author_user_id_hash,title,description,created_at,updated_at,deleted_at
FROM uku_proposals
WHERE process_id=?1 AND deleted_at=0
ORDER BY created_at,id`, processID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	proposals := []UkuProposal{}
	for rows.Next() {
		var item UkuProposal
		if err := rows.Scan(&item.ID, &item.AuthorUserIDHash, &item.Title, &item.Description, &item.CreatedAt, &item.UpdatedAt, &item.DeletedAt); err != nil {
			return nil, err
		}
		proposals = append(proposals, item)
	}
	return proposals, rows.Err()
}

func (s *Store) UkuVotes(ctx context.Context, processID string) ([]UkuVote, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT voter_user_id_hash,display_name,scores_json,created_at,updated_at
FROM uku_votes
WHERE process_id=?1
ORDER BY updated_at,voter_user_id_hash`, processID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	votes := []UkuVote{}
	for rows.Next() {
		var item UkuVote
		var scores string
		if err := rows.Scan(&item.VoterUserIDHash, &item.DisplayName, &scores, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(scores), &item.Scores); err != nil {
			return nil, err
		}
		votes = append(votes, item)
	}
	return votes, rows.Err()
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
	changes.SocialCache, err = s.snapshotSocialCache(ctx, userID, sinceVersion)
	if err != nil {
		return changes, 0, err
	}
	version, err := s.currentUserVersion(ctx, userID)
	if err != nil {
		return changes, 0, err
	}
	return changes, version, nil
}

func (s *Store) OpsSince(ctx context.Context, userID string, sinceVersion int64) ([]SyncOp, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT op_id,client_id,seq,entity_type,entity_id,local_date,op_type,payload_json,created_at
FROM server_sync_ops
WHERE user_id_hash=?1 AND server_version>?2
ORDER BY server_version,client_id,seq,op_id`, userID, sinceVersion)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ops := []SyncOp{}
	for rows.Next() {
		var op SyncOp
		var payload string
		if err := rows.Scan(&op.OpID, &op.ClientID, &op.Seq, &op.EntityType,
			&op.EntityID, &op.LocalDate, &op.OpType, &payload, &op.CreatedAt); err != nil {
			return nil, err
		}
		if payload != "" {
			op.Payload = json.RawMessage(payload)
		}
		ops = append(ops, op)
	}
	return ops, rows.Err()
}

func (s *Store) CleanData(ctx context.Context, userID string) (*CleanData, error) {
	habits, err := s.cleanHabits(ctx, userID)
	if err != nil {
		return nil, err
	}
	habitDays, err := s.cleanHabitDays(ctx, userID)
	if err != nil {
		return nil, err
	}
	sessions, err := s.cleanSessions(ctx, userID)
	if err != nil {
		return nil, err
	}
	meditationLogs, err := s.cleanMeditationLogs(ctx, userID)
	if err != nil {
		return nil, err
	}
	social, err := s.cleanSocialCache(ctx, userID)
	if err != nil {
		return nil, err
	}
	friends := json.RawMessage(`{"friends":[]}`)
	friendRequests := json.RawMessage(`{"incoming":[],"outgoing":[]}`)
	for _, item := range social {
		switch item.Kind {
		case "friends.list":
			friends = item.JSON
		case "friends.requests":
			friendRequests = item.JSON
		}
	}
	return &CleanData{
		Habits:         habits,
		HabitDays:      habitDays,
		Sessions:       sessions,
		MeditationLogs: meditationLogs,
		Social:         social,
		Friends:        friends,
		FriendRequests: friendRequests,
	}, nil
}

func (s *Store) cleanHabits(ctx context.Context, userID string) ([]Habit, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id,name,color_r,color_g,color_b,sync_mode,sync_activity,counter_enabled,sort_order,deleted_at,updated_at
FROM server_habits
WHERE user_id_hash=?1 AND deleted_at=0
ORDER BY sort_order,id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []Habit{}
	for rows.Next() {
		var item Habit
		if err := rows.Scan(&item.ID, &item.Name, &item.ColorR, &item.ColorG, &item.ColorB,
			&item.SyncMode, &item.SyncActivity, &item.CounterEnabled, &item.SortOrder,
			&item.DeletedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) cleanHabitDays(ctx context.Context, userID string) ([]CleanHabitDay, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT hd.habit_id,h.name,hd.local_date,hd.completed,hd.count,hd.updated_at
FROM server_habit_days hd
JOIN server_habits h ON h.user_id_hash=hd.user_id_hash AND h.id=hd.habit_id
WHERE hd.user_id_hash=?1
  AND h.deleted_at=0
  AND (hd.completed!=0 OR hd.count>0)
ORDER BY hd.local_date DESC,h.sort_order,hd.habit_id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []CleanHabitDay{}
	for rows.Next() {
		var item CleanHabitDay
		var completed int
		if err := rows.Scan(&item.HabitID, &item.HabitName, &item.LocalDate,
			&completed, &item.Count, &item.UpdatedAt); err != nil {
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

func (s *Store) cleanSessions(ctx context.Context, userID string) ([]Session, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id,started_at,local_date,topic,activity,source,rounds_hash,deleted_at,updated_at
FROM server_sessions
WHERE user_id_hash=?1 AND deleted_at=0
ORDER BY started_at DESC,id`, userID)
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

func (s *Store) cleanMeditationLogs(ctx context.Context, userID string) ([]MeditationLog, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id,session_id,duration_seconds,completed_at
FROM server_meditation_logs
WHERE user_id_hash=?1
ORDER BY completed_at DESC,id`, userID)
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

func (s *Store) cleanSocialCache(ctx context.Context, userID string) ([]SocialCache, error) {
	return s.snapshotSocialCache(ctx, userID, 0)
}

func (s *Store) SyncLogs(ctx context.Context, userID string, sinceVersion int64) ([]SyncLog, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT server_version,entity_type,entity_id,local_date,op_type,payload_json,created_at
FROM server_sync_ops
WHERE user_id_hash=?1 AND server_version>?2
ORDER BY server_version,client_id,seq,op_id`, userID, sinceVersion)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []SyncLog{}
	for rows.Next() {
		var item SyncLog
		var payload string
		if err := rows.Scan(&item.ServerVersion, &item.EntityType, &item.EntityID,
			&item.LocalDate, &item.OpType, &payload, &item.CreatedAt); err != nil {
			return nil, err
		}
		item.Kind = "op"
		if payload != "" {
			item.Payload = json.RawMessage(payload)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) DeleteLogs(ctx context.Context, userID string, sinceVersion int64) ([]SyncLog, error) {
	logs, err := s.SyncLogs(ctx, userID, sinceVersion)
	if err != nil {
		return nil, err
	}
	deletes := []SyncLog{}
	for _, item := range logs {
		if item.OpType == "delete" {
			item.Kind = "delete"
			deletes = append(deletes, item)
		}
	}
	return deletes, nil
}

func (s *Store) LegacyClients(ctx context.Context, userID string, minProtocol int) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT client_id
FROM server_clients
WHERE user_id_hash=?1 AND protocol_version<?2
ORDER BY last_seen_at DESC,client_id`, userID, minProtocol)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	clients := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		clients = append(clients, id)
	}
	return clients, rows.Err()
}

func (s *Store) CleanupOrphanHabitDays(ctx context.Context, userID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	changed, err := cleanupOrphanHabitDays(ctx, tx, userID)
	if err != nil {
		return err
	}
	if changed {
		if _, err := nextUserVersion(ctx, tx, userID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func cleanupOrphanHabitDays(ctx context.Context, tx *sql.Tx, userID string) (bool, error) {
	res, err := tx.ExecContext(ctx, `
DELETE FROM server_habit_days
WHERE user_id_hash=?1
  AND NOT EXISTS (
	SELECT 1 FROM server_habits h
	WHERE h.user_id_hash=server_habit_days.user_id_hash
	  AND h.id=server_habit_days.habit_id
  )
  AND (
	(completed=0 AND count=0)
	OR EXISTS (
		SELECT 1 FROM server_sync_ops op
		WHERE op.user_id_hash=server_habit_days.user_id_hash
		  AND op.entity_type='habit'
		  AND op.entity_id=server_habit_days.habit_id
		  AND op.op_type='delete'
	)
  )`, userID)
	if err != nil {
		return false, err
	}
	return rowsAffected(res) > 0, nil
}

func canonicalHabitIDForWrite(ctx context.Context, tx *sql.Tx, userID, id, source string) (string, bool, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return "", false, fmt.Errorf("empty habit id")
	}
	if isCanonicalHabitID(id) {
		return strings.ToLower(id), false, nil
	}
	var mapped string
	err := tx.QueryRowContext(ctx, `
SELECT new_id
FROM server_habit_id_migrations
WHERE user_id_hash=?1 AND old_id=?2`, userID, id).Scan(&mapped)
	if err == nil && mapped != "" {
		return mapped, true, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", false, err
	}
	canonical, err := newCanonicalHabitID()
	if err != nil {
		return "", false, err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT OR REPLACE INTO server_habit_id_migrations(user_id_hash,old_id,new_id,source)
VALUES(?1,?2,?3,?4)`, userID, id, canonical, source); err != nil {
		return "", false, err
	}
	return canonical, true, nil
}

func canonicalHabitIDForRead(ctx context.Context, tx *sql.Tx, userID, id string) (string, bool, error) {
	id = strings.TrimSpace(id)
	if id == "" || isCanonicalHabitID(id) {
		return strings.ToLower(id), false, nil
	}
	var mapped string
	err := tx.QueryRowContext(ctx, `
SELECT new_id
FROM server_habit_id_migrations
WHERE user_id_hash=?1 AND old_id=?2`, userID, id).Scan(&mapped)
	if errors.Is(err, sql.ErrNoRows) {
		return id, false, nil
	}
	if err != nil {
		return "", false, err
	}
	return mapped, mapped != id, nil
}

func rewriteHabitPayloadID(payload json.RawMessage, canonicalID string) json.RawMessage {
	if len(payload) == 0 || canonicalID == "" {
		return payload
	}
	var obj map[string]any
	if err := json.Unmarshal(payload, &obj); err != nil {
		return payload
	}
	changed := false
	if _, ok := obj["id"]; ok {
		obj["id"] = canonicalID
		changed = true
	}
	if _, ok := obj["habit_id"]; ok {
		obj["habit_id"] = canonicalID
		changed = true
	}
	if !changed {
		return payload
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return payload
	}
	return json.RawMessage(out)
}

func (s *Store) AutoMigrateAccountForProtocol(ctx context.Context, userID string, protocol int) error {
	if protocol < 3 {
		return nil
	}
	return s.autoMigrateAccount(ctx, userID)
}

func (s *Store) AutoMigrateAllAccounts(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT user_id_hash FROM server_users ORDER BY user_id_hash`)
	if err != nil {
		return err
	}
	users := []string{}
	for rows.Next() {
		var userID string
		if err := rows.Scan(&userID); err != nil {
			rows.Close()
			return err
		}
		users = append(users, userID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, userID := range users {
		if err := s.autoMigrateAccount(ctx, userID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) autoMigrateAccount(ctx context.Context, userID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	changed, err := migrateAllHabitIDsToCanonicalUUIDs(ctx, tx, userID)
	if err != nil {
		return err
	}
	materialized, err := materializeLegacyHabitDays(ctx, tx, userID)
	if err != nil {
		return err
	}
	cleaned, err := cleanupOrphanHabitDays(ctx, tx, userID)
	if err != nil {
		return err
	}
	changed = changed || materialized || cleaned
	if changed {
		if _, err := nextUserVersion(ctx, tx, userID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func migrateAllHabitIDsToCanonicalUUIDs(ctx context.Context, tx *sql.Tx, userID string) (bool, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT id
FROM server_habits
WHERE user_id_hash=?1
ORDER BY sort_order,id`, userID)
	if err != nil {
		return false, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return false, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return false, err
	}
	rows.Close()

	changed := false
	for _, oldID := range ids {
		if oldID == "" || isCanonicalHabitID(oldID) {
			continue
		}
		newID, mapped, err := canonicalHabitIDForWrite(ctx, tx, userID, oldID, "protocol-v3-canonical")
		if err != nil {
			return false, err
		}
		if newID == oldID {
			continue
		}
		if err := mergeHabitRows(ctx, tx, userID, newID, oldID); err != nil {
			return false, err
		}
		changed = changed || mapped
	}
	opsChanged, err := canonicalizeExistingHabitOps(ctx, tx, userID)
	if err != nil {
		return false, err
	}
	changed = changed || opsChanged
	return changed, nil
}

func canonicalizeExistingHabitOps(ctx context.Context, tx *sql.Tx, userID string) (bool, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT op_id,entity_id,payload_json
FROM server_sync_ops
WHERE user_id_hash=?1
  AND entity_type IN ('habit','habit_day')
ORDER BY server_version,op_id`, userID)
	if err != nil {
		return false, err
	}
	type opRow struct {
		opID     string
		entityID string
		payload  string
	}
	items := []opRow{}
	for rows.Next() {
		var item opRow
		if err := rows.Scan(&item.opID, &item.entityID, &item.payload); err != nil {
			rows.Close()
			return false, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return false, err
	}
	rows.Close()

	changed := false
	for _, item := range items {
		canonicalID, mapped, err := canonicalHabitIDForRead(ctx, tx, userID, item.entityID)
		if err != nil {
			return false, err
		}
		if !mapped {
			continue
		}
		payload := rewriteHabitPayloadID(json.RawMessage(item.payload), canonicalID)
		res, err := tx.ExecContext(ctx, `
UPDATE server_sync_ops
SET entity_id=?3,payload_json=?4
WHERE user_id_hash=?1 AND op_id=?2`, userID, item.opID, canonicalID, string(payload))
		if err != nil {
			return false, err
		}
		changed = changed || rowsAffected(res) > 0
	}
	return changed, nil
}

func mergeHabitRows(ctx context.Context, tx *sql.Tx, userID, keeperID, duplicateID string) error {
	var keeperExists int
	var duplicateExists int
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS(SELECT 1 FROM server_habits WHERE user_id_hash=?1 AND id=?2)`,
		userID, keeperID).Scan(&keeperExists); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS(SELECT 1 FROM server_habits WHERE user_id_hash=?1 AND id=?2)`,
		userID, duplicateID).Scan(&duplicateExists); err != nil {
		return err
	}
	if duplicateExists != 0 {
		if keeperExists == 0 {
			if _, err := tx.ExecContext(ctx, `
UPDATE server_habits
SET id=?3
WHERE user_id_hash=?1 AND id=?2`, userID, duplicateID, keeperID); err != nil {
				return err
			}
		} else {
			if _, err := tx.ExecContext(ctx, `
UPDATE server_habits
SET name=CASE WHEN name='' THEN (SELECT name FROM server_habits d WHERE d.user_id_hash=?1 AND d.id=?2) ELSE name END,
	color_r=CASE WHEN color_r=0 THEN (SELECT color_r FROM server_habits d WHERE d.user_id_hash=?1 AND d.id=?2) ELSE color_r END,
	color_g=CASE WHEN color_g=0 THEN (SELECT color_g FROM server_habits d WHERE d.user_id_hash=?1 AND d.id=?2) ELSE color_g END,
	color_b=CASE WHEN color_b=0 THEN (SELECT color_b FROM server_habits d WHERE d.user_id_hash=?1 AND d.id=?2) ELSE color_b END,
	sync_mode=MAX(sync_mode,(SELECT sync_mode FROM server_habits d WHERE d.user_id_hash=?1 AND d.id=?2)),
	sync_activity=(sync_activity | (SELECT sync_activity FROM server_habits d WHERE d.user_id_hash=?1 AND d.id=?2)),
	counter_enabled=MAX(counter_enabled,(SELECT counter_enabled FROM server_habits d WHERE d.user_id_hash=?1 AND d.id=?2)),
	sort_order=MIN(sort_order,(SELECT sort_order FROM server_habits d WHERE d.user_id_hash=?1 AND d.id=?2)),
	deleted_at=CASE WHEN deleted_at=0 THEN 0 ELSE MIN(deleted_at,(SELECT deleted_at FROM server_habits d WHERE d.user_id_hash=?1 AND d.id=?2)) END,
	updated_at=MAX(updated_at,(SELECT updated_at FROM server_habits d WHERE d.user_id_hash=?1 AND d.id=?2)),
	server_version=MAX(server_version,(SELECT server_version FROM server_habits d WHERE d.user_id_hash=?1 AND d.id=?2))
WHERE user_id_hash=?1 AND id=?3`, userID, duplicateID, keeperID); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `
DELETE FROM server_habits
WHERE user_id_hash=?1 AND id=?2`, userID, duplicateID); err != nil {
				return err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO server_habit_days(user_id_hash,habit_id,local_date,completed,count,updated_at,server_version)
SELECT user_id_hash,?3,local_date,completed,count,updated_at,server_version
FROM server_habit_days
WHERE user_id_hash=?1 AND habit_id=?2
ON CONFLICT(user_id_hash,habit_id,local_date) DO UPDATE SET
	completed=MAX(server_habit_days.completed,excluded.completed),
	count=MAX(server_habit_days.count,excluded.count),
	updated_at=MAX(server_habit_days.updated_at,excluded.updated_at),
	server_version=MAX(server_habit_days.server_version,excluded.server_version)`,
		userID, duplicateID, keeperID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM server_habit_days
WHERE user_id_hash=?1 AND habit_id=?2`, userID, duplicateID); err != nil {
		return err
	}
	return nil
}

func materializeLegacyHabitDays(ctx context.Context, tx *sql.Tx, userID string) (bool, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT hd.habit_id, MAX(hd.updated_at), MAX(hd.server_version)
FROM server_habit_days hd
WHERE hd.user_id_hash=?1
  AND (hd.completed!=0 OR hd.count>0)
  AND NOT EXISTS (
	SELECT 1 FROM server_habits h
	WHERE h.user_id_hash=hd.user_id_hash
	  AND h.id=hd.habit_id
  )
  AND NOT EXISTS (
	SELECT 1 FROM server_sync_ops op
	WHERE op.user_id_hash=hd.user_id_hash
	  AND op.entity_type='habit'
	  AND op.entity_id=hd.habit_id
	  AND op.op_type='delete'
  )
GROUP BY hd.habit_id
ORDER BY hd.habit_id`, userID)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	type legacyHabit struct {
		id            string
		updatedAt     string
		serverVersion int64
	}
	habits := []legacyHabit{}
	for rows.Next() {
		var item legacyHabit
		if err := rows.Scan(&item.id, &item.updatedAt, &item.serverVersion); err != nil {
			return false, err
		}
		habits = append(habits, item)
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	if len(habits) == 0 {
		return false, nil
	}

	changed := false
	for index, habit := range habits {
		updatedAt := normalizeTime(habit.updatedAt, "")
		if updatedAt == "" {
			updatedAt = time.Now().UTC().Format(time.RFC3339)
		}
		canonicalID, _, err := canonicalHabitIDForWrite(ctx, tx, userID, habit.id, "protocol-v3-orphan")
		if err != nil {
			return false, err
		}
		res, err := tx.ExecContext(ctx, `
INSERT INTO server_habits(user_id_hash,id,name,color_r,color_g,color_b,sync_mode,sync_activity,counter_enabled,sort_order,deleted_at,updated_at,server_version)
VALUES(?1,?2,?3,99,196,165,0,0,0,?4,0,?5,?6)
ON CONFLICT(user_id_hash,id) DO NOTHING`,
			userID, canonicalID, legacyHabitDisplayName(habit.id), 1000+index, updatedAt, habit.serverVersion)
		if err != nil {
			return false, err
		}
		changed = changed || rowsAffected(res) > 0
		if err := mergeHabitRows(ctx, tx, userID, canonicalID, habit.id); err != nil {
			return false, err
		}
	}
	return changed, nil
}

func legacyHabitDisplayName(id string) string {
	switch id {
	case "sun-salutation":
		return "Sun Salutation"
	case "whm":
		return "Wim Hof"
	case "meditation":
		return "Meditation"
	case "yoga":
		return "Yoga"
	}
	name := strings.TrimSpace(strings.ReplaceAll(id, "-", " "))
	if name == "" {
		return "Habit"
	}
	parts := strings.Fields(name)
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}

func migrateSunSalutationHabitID(ctx context.Context, tx *sql.Tx, userID string) (bool, error) {
	const oldID = "yoga"
	const newID = "sun-salutation"
	const sunSalutationMask = 1 << 2
	var syncActivity int
	var deletedAt int64
	var oldExists int
	var newExists int

	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS(SELECT 1 FROM server_habit_id_migrations WHERE user_id_hash=?1 AND old_id=?2)`,
		userID, oldID).Scan(&oldExists); err != nil {
		return false, err
	}
	if oldExists != 0 {
		return false, nil
	}
	err := tx.QueryRowContext(ctx, `
SELECT sync_activity,deleted_at
FROM server_habits
WHERE user_id_hash=?1 AND id=?2`, userID, oldID).Scan(&syncActivity, &deletedAt)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = tx.ExecContext(ctx, `
INSERT OR IGNORE INTO server_habit_id_migrations(user_id_hash,old_id,new_id,source)
VALUES(?1,?2,?3,'not-present')`, userID, oldID, newID)
		return false, err
	}
	if err != nil {
		return false, err
	}
	if deletedAt != 0 || syncActivity&sunSalutationMask == 0 {
		_, err = tx.ExecContext(ctx, `
INSERT OR IGNORE INTO server_habit_id_migrations(user_id_hash,old_id,new_id,source)
VALUES(?1,?2,?3,'not-sun-salutation')`, userID, oldID, newID)
		return false, err
	}
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS(SELECT 1 FROM server_habits WHERE user_id_hash=?1 AND id=?2)`,
		userID, newID).Scan(&newExists); err != nil {
		return false, err
	}
	if newExists == 0 {
		if _, err := tx.ExecContext(ctx, `
UPDATE server_habits
SET id=?3
WHERE user_id_hash=?1 AND id=?2`, userID, oldID, newID); err != nil {
			return false, err
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE server_habit_days
SET habit_id=?3
WHERE user_id_hash=?1 AND habit_id=?2`, userID, oldID, newID); err != nil {
			return false, err
		}
	} else {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO server_habit_days(user_id_hash,habit_id,local_date,completed,count,updated_at,server_version)
SELECT user_id_hash,?3,local_date,completed,count,updated_at,server_version
FROM server_habit_days
WHERE user_id_hash=?1 AND habit_id=?2
ON CONFLICT(user_id_hash,habit_id,local_date) DO UPDATE SET
	completed=MAX(server_habit_days.completed,excluded.completed),
	count=MAX(server_habit_days.count,excluded.count),
	updated_at=MAX(server_habit_days.updated_at,excluded.updated_at),
	server_version=MAX(server_habit_days.server_version,excluded.server_version)`,
			userID, oldID, newID); err != nil {
			return false, err
		}
		if _, err := tx.ExecContext(ctx, `
DELETE FROM server_habit_days
WHERE user_id_hash=?1 AND habit_id=?2`, userID, oldID); err != nil {
			return false, err
		}
		if _, err := tx.ExecContext(ctx, `
DELETE FROM server_habits
WHERE user_id_hash=?1 AND id=?2`, userID, oldID); err != nil {
			return false, err
		}
	}
	if _, err := tx.ExecContext(ctx, `
INSERT OR REPLACE INTO server_habit_id_migrations(user_id_hash,old_id,new_id,source)
VALUES(?1,?2,?3,'protocol-v3')`, userID, oldID, newID); err != nil {
		return false, err
	}
	return true, nil
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
	if err := s.hashSocialCache(ctx, h, userID); err != nil {
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
	sessionIDs := []string{}
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
		sessionIDs = append(sessionIDs, id)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, id := range sessionIDs {
		if err := s.hashSessionRounds(ctx, h, userID, id); err != nil {
			return err
		}
	}
	return nil
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

func (s *Store) hashSocialCache(ctx context.Context, h interface{ Write([]byte) (int, error) }, userID string) error {
	rows, err := s.db.QueryContext(ctx, `
SELECT kind,json,updated_at
FROM server_social_snapshots
WHERE user_id_hash=?1
ORDER BY kind`, userID)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var kind, payload, updatedAt string
		if err := rows.Scan(&kind, &payload, &updatedAt); err != nil {
			return err
		}
		fmt.Fprintf(h, "social_cache\t%s\t%s\t%s\n", kind, payload, updatedAt)
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

func (s *Store) snapshotSocialCache(ctx context.Context, userID string, sinceVersion int64) ([]SocialCache, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT kind,json,updated_at
FROM server_social_snapshots
WHERE user_id_hash=?1 AND server_version>?2
ORDER BY server_version,kind`, userID, sinceVersion)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []SocialCache{}
	for rows.Next() {
		var item SocialCache
		var payload string
		if err := rows.Scan(&item.Kind, &payload, &item.UpdatedAt); err != nil {
			return nil, err
		}
		if payload == "" {
			payload = "{}"
		}
		item.JSON = json.RawMessage(payload)
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
		return ErrSyncUserNotFound
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
		`DELETE FROM server_social_snapshots WHERE user_id_hash=?1`,
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

func upsertSocialCache(ctx context.Context, tx *sql.Tx, userID string, item SocialCache) (int, error) {
	kind := strings.TrimSpace(item.Kind)
	payload := item.JSON
	var same int

	if kind == "" || len(kind) > 96 {
		return 0, fmt.Errorf("invalid social_cache kind")
	}
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	}
	if !json.Valid(payload) {
		return 0, fmt.Errorf("invalid social_cache json")
	}
	if err := tx.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM server_social_snapshots WHERE user_id_hash=?1 AND kind=?2 AND json=?3)`,
		userID, kind, string(payload)).Scan(&same); err != nil {
		return 0, err
	}
	if same != 0 {
		return 0, nil
	}
	version, err := nextUserVersion(ctx, tx, userID)
	if err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx, `
INSERT INTO server_social_snapshots(user_id_hash,kind,json,updated_at,server_version)
VALUES(?1,?2,?3,?4,?5)
ON CONFLICT(user_id_hash,kind) DO UPDATE SET
	json=excluded.json,
	updated_at=excluded.updated_at,
	server_version=excluded.server_version
WHERE excluded.json != server_social_snapshots.json`,
		userID, kind, string(payload), normalizeTime(item.UpdatedAt, ""), version)
	if err != nil {
		return 0, err
	}
	return rowsAffected(res), nil
}

func (s *Store) SetSocialCacheJSON(ctx context.Context, userID, kind string, payload []byte) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	applied, err := upsertSocialCache(ctx, tx, userID, SocialCache{
		Kind: kind,
		JSON: json.RawMessage(payload),
	})
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return applied, nil
}

func deleteHabit(ctx context.Context, tx *sql.Tx, userID string, habit Habit) (int, error) {
	updatedAt := normalizeTime(habit.UpdatedAt, "")
	res, err := tx.ExecContext(ctx, `
DELETE FROM server_habits
WHERE user_id_hash=?1 AND id=?2 AND updated_at<=?3`, userID, habit.ID, updatedAt)
	if err != nil {
		return 0, err
	}
	applied := rowsAffected(res)
	if applied == 0 {
		return 0, nil
	}
	res, err = tx.ExecContext(ctx, `
DELETE FROM server_habit_days
WHERE user_id_hash=?1 AND habit_id=?2`, userID, habit.ID)
	if err != nil {
		return 0, err
	}
	applied += rowsAffected(res)
	if _, err := nextUserVersion(ctx, tx, userID); err != nil {
		return 0, err
	}
	return applied, nil
}

func deleteHabitDay(ctx context.Context, tx *sql.Tx, userID string, day HabitDay) (int, error) {
	updatedAt := normalizeTime(day.UpdatedAt, "")
	res, err := tx.ExecContext(ctx, `
DELETE FROM server_habit_days
WHERE user_id_hash=?1 AND habit_id=?2 AND local_date=?3 AND updated_at<=?4`,
		userID, day.HabitID, day.LocalDate, updatedAt)
	if err != nil {
		return 0, err
	}
	applied := rowsAffected(res)
	if applied == 0 {
		return 0, nil
	}
	if _, err := nextUserVersion(ctx, tx, userID); err != nil {
		return 0, err
	}
	return applied, nil
}

func deleteSession(ctx context.Context, tx *sql.Tx, userID string, session Session) (int, error) {
	updatedAt := normalizeTime(session.UpdatedAt, session.StartedAt)
	res, err := tx.ExecContext(ctx, `
DELETE FROM server_sessions
WHERE user_id_hash=?1 AND id=?2 AND updated_at<=?3`, userID, session.ID, updatedAt)
	if err != nil {
		return 0, err
	}
	applied := rowsAffected(res)
	if applied == 0 {
		return 0, nil
	}
	res, err = tx.ExecContext(ctx, `
DELETE FROM server_session_rounds
WHERE user_id_hash=?1 AND session_id=?2`, userID, session.ID)
	if err != nil {
		return 0, err
	}
	applied += rowsAffected(res)
	if _, err := nextUserVersion(ctx, tx, userID); err != nil {
		return 0, err
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

type ukuProcessScanner interface {
	Scan(dest ...any) error
}

func scanUkuProcess(row ukuProcessScanner) (UkuProcess, error) {
	var process UkuProcess
	err := row.Scan(&process.ID, &process.OwnerUserIDHash, &process.Question, &process.Description,
		&process.Visibility, &process.ProposalMinutes, &process.VotingMinutes,
		&process.NegativeWeight, &process.CreatedAt, &process.UpdatedAt)
	return process, err
}

func scanUkuProcesses(rows *sql.Rows) ([]UkuProcess, error) {
	processes := []UkuProcess{}
	for rows.Next() {
		process, err := scanUkuProcess(rows)
		if err != nil {
			return nil, err
		}
		processes = append(processes, process)
	}
	return processes, rows.Err()
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
