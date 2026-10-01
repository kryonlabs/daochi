package main

// Original database startup and schema at 43aee08.
import (
	"context"
	"database/sql"
	"strings"
)

func baselineSchemaOpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite3", path+"?_busy_timeout=5000&_foreign_keys=on")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &Store{db: db, path: path}
	if err := store.baselineSchemaMigrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := TrustStore_EnsureSchema(store.db, context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := StoreTimestamps_Canonicalize(store.db, context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.AutoMigrateAllAccounts(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := TokenAssets_Seed(store.db, context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := AppStore_SeedBuiltin(store.db, context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) baselineSchemaMigrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
`); err != nil {
		return err
	}

	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS server_users (
	user_id_hash TEXT PRIMARY KEY,
	public_key BLOB NOT NULL,
	alias TEXT UNIQUE,
	profile_icon INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS server_account_tombstones (
	user_id_hash TEXT PRIMARY KEY,
	deleted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
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
		mood_before INTEGER NOT NULL DEFAULT 0,
		mood_after INTEGER NOT NULL DEFAULT 0,
		energy INTEGER NOT NULL DEFAULT 0,
		stress INTEGER NOT NULL DEFAULT 0,
		note TEXT NOT NULL DEFAULT '',
		tags TEXT NOT NULL DEFAULT '',
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

CREATE TABLE IF NOT EXISTS server_encrypted_records (
	user_id_hash TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
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

CREATE TABLE IF NOT EXISTS server_mesh_changes (
	seq INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id_hash TEXT NOT NULL,
	collection TEXT NOT NULL,
	record_id TEXT NOT NULL,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	op TEXT NOT NULL DEFAULT 'upsert',
	deleted_at TEXT NOT NULL DEFAULT ''
);

CREATE TRIGGER IF NOT EXISTS server_encrypted_records_mesh_insert
AFTER INSERT ON server_encrypted_records
BEGIN
	INSERT INTO server_mesh_changes(user_id_hash,collection,record_id)
	VALUES(NEW.user_id_hash,NEW.collection,NEW.id);
END;

CREATE TRIGGER IF NOT EXISTS server_encrypted_records_mesh_update
AFTER UPDATE ON server_encrypted_records
BEGIN
	INSERT INTO server_mesh_changes(user_id_hash,collection,record_id)
	VALUES(NEW.user_id_hash,NEW.collection,NEW.id);
END;

CREATE TRIGGER IF NOT EXISTS server_encrypted_records_mesh_delete
AFTER DELETE ON server_encrypted_records
BEGIN
	INSERT INTO server_mesh_changes(user_id_hash,collection,record_id,op,deleted_at)
	VALUES(OLD.user_id_hash,OLD.collection,OLD.id,'delete',
		strftime('%Y-%m-%dT%H:%M:%S','now')||'.000000000Z');
END;

CREATE TABLE IF NOT EXISTS server_apps (
	app_id TEXT PRIMARY KEY,
	display_name TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	homepage_url TEXT NOT NULL DEFAULT '',
	source_url TEXT NOT NULL DEFAULT '',
	public_key TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT 'active',
	app_schema_version INTEGER NOT NULL DEFAULT 0,
	min_supported_client_version TEXT NOT NULL DEFAULT '',
	current_client_version TEXT NOT NULL DEFAULT '',
	compatibility_until TEXT NOT NULL DEFAULT '',
	features_json TEXT NOT NULL DEFAULT '[]',
	legacy_protocols_json TEXT NOT NULL DEFAULT '[]',
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS server_app_collections (
	app_id TEXT NOT NULL REFERENCES server_apps(app_id) ON DELETE CASCADE,
	collection_prefix TEXT NOT NULL,
	visibility TEXT NOT NULL DEFAULT 'private',
	schema_version INTEGER NOT NULL DEFAULT 0,
	description TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY(app_id, collection_prefix)
);

CREATE TABLE IF NOT EXISTS server_app_capabilities (
	app_id TEXT NOT NULL REFERENCES server_apps(app_id) ON DELETE CASCADE,
	capability TEXT NOT NULL,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY(app_id, capability)
);

CREATE TABLE IF NOT EXISTS server_app_manifests (
	app_id TEXT PRIMARY KEY REFERENCES server_apps(app_id) ON DELETE CASCADE,
	manifest_version INTEGER NOT NULL,
	manifest_json TEXT NOT NULL,
	manifest_hash TEXT NOT NULL UNIQUE,
	manifest_signature TEXT NOT NULL,
	approval_signature TEXT NOT NULL,
	expires_at INTEGER NOT NULL DEFAULT 0,
	status TEXT NOT NULL DEFAULT 'active',
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS server_app_keys (
	app_id TEXT NOT NULL REFERENCES server_apps(app_id) ON DELETE CASCADE,
	key_id TEXT NOT NULL,
	algorithm TEXT NOT NULL,
	public_key TEXT NOT NULL,
	purpose TEXT NOT NULL DEFAULT 'signing',
	status TEXT NOT NULL DEFAULT 'active',
	expires_at INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY(app_id, key_id)
);

CREATE TABLE IF NOT EXISTS server_device_keys (
	account_id TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	app_id TEXT NOT NULL REFERENCES server_apps(app_id) ON DELETE CASCADE,
	device_key_id TEXT NOT NULL,
	client_id TEXT NOT NULL,
	public_key TEXT NOT NULL,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_used_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	revoked_at TEXT NOT NULL DEFAULT '',
	PRIMARY KEY(account_id, app_id, device_key_id)
);

CREATE TABLE IF NOT EXISTS server_device_registration_nonces (
	account_id TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	nonce TEXT NOT NULL,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY(account_id, nonce)
);

CREATE TABLE IF NOT EXISTS server_app_revocations (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	app_id TEXT NOT NULL REFERENCES server_apps(app_id) ON DELETE CASCADE,
	key_id TEXT NOT NULL DEFAULT '',
	reason TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS server_app_grants (
	id TEXT PRIMARY KEY,
	user_id_hash TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	source_app_id TEXT NOT NULL REFERENCES server_apps(app_id) ON DELETE CASCADE,
	target_app_id TEXT NOT NULL REFERENCES server_apps(app_id) ON DELETE CASCADE,
	collection_prefix TEXT NOT NULL,
	permission TEXT NOT NULL DEFAULT 'read',
	status TEXT NOT NULL DEFAULT 'active',
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	revoked_at TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS server_app_grant_audit (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	grant_id TEXT NOT NULL,
	user_id_hash TEXT NOT NULL,
	action TEXT NOT NULL,
	payload_json TEXT NOT NULL DEFAULT '{}',
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS server_signed_transactions (
	account_id TEXT NOT NULL,
	tx_id TEXT NOT NULL,
	app_id TEXT NOT NULL,
	nonce TEXT NOT NULL,
	expires_at INTEGER NOT NULL,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY(account_id, tx_id),
	UNIQUE(account_id, app_id, nonce)
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

CREATE TABLE IF NOT EXISTS server_encrypted_payloads (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id_hash TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	client_id TEXT NOT NULL DEFAULT '',
	payload_json TEXT NOT NULL,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	server_version INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS server_sync_audit (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id_hash TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	client_id TEXT NOT NULL DEFAULT '',
	app_id TEXT NOT NULL DEFAULT '',
	protocol_version INTEGER NOT NULL DEFAULT 0,
	since_server_version INTEGER NOT NULL DEFAULT 0,
	client_clock INTEGER NOT NULL DEFAULT 0,
	server_version INTEGER NOT NULL DEFAULT 0,
	applied_json TEXT NOT NULL DEFAULT '{}',
	remote_ops INTEGER NOT NULL DEFAULT 0,
	full_snapshot_required INTEGER NOT NULL DEFAULT 0,
	snapshot_reason TEXT NOT NULL DEFAULT '',
	encrypted_payload INTEGER NOT NULL DEFAULT 0,
	encrypted_payload_bytes INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS server_habit_id_migrations (
	user_id_hash TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	old_id TEXT NOT NULL,
	new_id TEXT NOT NULL,
	source TEXT NOT NULL DEFAULT '',
	migrated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY(user_id_hash, old_id)
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

CREATE TABLE IF NOT EXISTS token_assets (
	issuer_id TEXT NOT NULL,
	asset_id TEXT PRIMARY KEY,
	display_name TEXT NOT NULL,
	decimals INTEGER NOT NULL DEFAULT 6,
	status TEXT NOT NULL DEFAULT 'active',
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS token_ledger (
	ledger_seq INTEGER PRIMARY KEY,
	receipt_id TEXT NOT NULL UNIQUE,
	issuer_id TEXT NOT NULL,
	asset_id TEXT NOT NULL REFERENCES token_assets(asset_id),
	account_id TEXT NOT NULL,
	app_id TEXT NOT NULL DEFAULT '',
	event_type TEXT NOT NULL,
	amount_delta INTEGER NOT NULL,
	source_type TEXT NOT NULL,
	source_ref TEXT NOT NULL,
	previous_hash TEXT NOT NULL,
	event_hash TEXT NOT NULL UNIQUE,
	signature TEXT NOT NULL,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS token_processed_payments (
	provider TEXT NOT NULL,
	provider_payment_id TEXT NOT NULL,
	account_id TEXT NOT NULL,
	asset_id TEXT NOT NULL,
	amount INTEGER NOT NULL,
	receipt_id TEXT NOT NULL,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY(provider, provider_payment_id)
);

CREATE TABLE IF NOT EXISTS token_spend_nonces (
	account_id TEXT NOT NULL,
	app_id TEXT NOT NULL,
	idempotency_key TEXT NOT NULL,
	receipt_id TEXT NOT NULL,
	request_hash TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY(account_id, app_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS token_payment_intents (
	id TEXT PRIMARY KEY,
	provider TEXT NOT NULL,
	account_id TEXT NOT NULL,
	app_id TEXT NOT NULL DEFAULT '',
	product_id TEXT NOT NULL,
	asset_id TEXT NOT NULL,
	token_units INTEGER NOT NULL,
	provider_amount INTEGER NOT NULL DEFAULT 0,
	provider_address TEXT NOT NULL DEFAULT '',
	provider_ref TEXT NOT NULL DEFAULT '',
	provider_payment_id TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT 'pending',
	receipt_id TEXT NOT NULL DEFAULT '',
	expires_at TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS monero_account_addresses (
	account_id TEXT PRIMARY KEY,
	account_index INTEGER NOT NULL DEFAULT 0,
	address_index INTEGER NOT NULL UNIQUE,
	address TEXT NOT NULL UNIQUE,
	allocation_id TEXT NOT NULL UNIQUE,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	disabled_at TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS monero_deposits (
	tx_id TEXT NOT NULL,
	account_index INTEGER NOT NULL,
	address_index INTEGER NOT NULL,
	account_id TEXT NOT NULL,
	amount_atomic INTEGER NOT NULL,
	block_height INTEGER NOT NULL DEFAULT 0,
	confirmations INTEGER NOT NULL DEFAULT 0,
	unlock_time INTEGER NOT NULL DEFAULT 0,
	locked INTEGER NOT NULL DEFAULT 1,
	double_spend_seen INTEGER NOT NULL DEFAULT 0,
	status TEXT NOT NULL DEFAULT 'confirming',
	rate_atomic_amount INTEGER NOT NULL,
	rate_token_units INTEGER NOT NULL,
	token_units INTEGER NOT NULL DEFAULT 0,
	receipt_id TEXT NOT NULL DEFAULT '',
	first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	confirmed_at TEXT NOT NULL DEFAULT '',
	credited_at TEXT NOT NULL DEFAULT '',
	updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY(tx_id, account_index, address_index)
);

CREATE TABLE IF NOT EXISTS monero_wallet_state (
	wallet_id TEXT PRIMARY KEY,
	last_height INTEGER NOT NULL DEFAULT 0,
	updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS token_checkpoints (
	ledger_seq INTEGER PRIMARY KEY,
	issuer_id TEXT NOT NULL,
	asset_id TEXT NOT NULL,
	ledger_root TEXT NOT NULL,
	signature TEXT NOT NULL,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS token_app_permissions (
	app_id TEXT NOT NULL REFERENCES server_apps(app_id) ON DELETE CASCADE,
	asset_id TEXT NOT NULL REFERENCES token_assets(asset_id) ON DELETE CASCADE,
	permission TEXT NOT NULL,
	status TEXT NOT NULL DEFAULT 'active',
	legacy_unsigned_until INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY(app_id, asset_id, permission)
);

CREATE TABLE IF NOT EXISTS node_sync_cursors (
	peer_key TEXT PRIMARY KEY,
	cursor TEXT NOT NULL,
	updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO server_mesh_changes(user_id_hash,collection,record_id)
SELECT r.user_id_hash,r.collection,r.id
FROM server_encrypted_records r
WHERE NOT EXISTS (
	SELECT 1 FROM server_mesh_changes c
	WHERE c.user_id_hash=r.user_id_hash AND c.collection=r.collection AND c.record_id=r.id
)`); err != nil {
		return err
	}
	if err := s.baselineSchemaEnsureMeshChangeColumns(ctx); err != nil {
		return err
	}
	if err := s.baselineSchemaMigrateMeditationLogPrimaryKey(ctx); err != nil {
		return err
	}
	if err := s.baselineSchemaMigrateSocialCacheTable(ctx); err != nil {
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
		`ALTER TABLE server_sessions ADD COLUMN mood_before INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE server_sessions ADD COLUMN mood_after INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE server_sessions ADD COLUMN energy INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE server_sessions ADD COLUMN stress INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE server_sessions ADD COLUMN note TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE server_sessions ADD COLUMN tags TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE server_social_snapshots ADD COLUMN server_version INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE server_users ADD COLUMN alias TEXT`,
		`ALTER TABLE server_users ADD COLUMN profile_icon INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE server_clients ADD COLUMN protocol_version INTEGER NOT NULL DEFAULT 1`,
		`ALTER TABLE server_clients ADD COLUMN last_client_clock INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE server_encrypted_records ADD COLUMN content_hash TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE server_encrypted_records ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE server_encrypted_records ADD COLUMN parent_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE server_apps ADD COLUMN app_schema_version INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE server_apps ADD COLUMN min_supported_client_version TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE server_apps ADD COLUMN current_client_version TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE server_apps ADD COLUMN compatibility_until TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE server_apps ADD COLUMN features_json TEXT NOT NULL DEFAULT '[]'`,
		`ALTER TABLE server_apps ADD COLUMN legacy_protocols_json TEXT NOT NULL DEFAULT '[]'`,
		`ALTER TABLE token_payment_intents ADD COLUMN provider_payment_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE token_app_permissions ADD COLUMN legacy_unsigned_until INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE token_spend_nonces ADD COLUMN request_hash TEXT NOT NULL DEFAULT ''`,
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
		`CREATE INDEX IF NOT EXISTS server_app_grants_user_status ON server_app_grants(user_id_hash,status,updated_at)`,
		`CREATE INDEX IF NOT EXISTS server_app_grants_lookup ON server_app_grants(user_id_hash,source_app_id,target_app_id,collection_prefix,status)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS server_app_grants_active_unique ON server_app_grants(user_id_hash,source_app_id,target_app_id,collection_prefix,permission) WHERE status='active'`,
		`CREATE INDEX IF NOT EXISTS server_signed_transactions_expiry ON server_signed_transactions(expires_at)`,
		`CREATE INDEX IF NOT EXISTS server_device_keys_active ON server_device_keys(account_id,app_id,revoked_at,last_used_at)`,
		`CREATE INDEX IF NOT EXISTS server_encrypted_records_collection ON server_encrypted_records(user_id_hash,collection,server_version)`,
		`CREATE INDEX IF NOT EXISTS server_encrypted_payloads_user_version ON server_encrypted_payloads(user_id_hash,server_version,id)`,
		`CREATE INDEX IF NOT EXISTS server_sync_audit_user_created ON server_sync_audit(user_id_hash,created_at,id)`,
		`CREATE INDEX IF NOT EXISTS token_ledger_account_asset ON token_ledger(account_id,asset_id,ledger_seq)`,
		`CREATE INDEX IF NOT EXISTS token_ledger_source ON token_ledger(source_type,source_ref)`,
		`CREATE INDEX IF NOT EXISTS token_payment_intents_account ON token_payment_intents(account_id,provider,status,created_at)`,
		`CREATE INDEX IF NOT EXISTS token_app_permissions_lookup ON token_app_permissions(asset_id,permission,status)`,
		`CREATE INDEX IF NOT EXISTS monero_deposits_account ON monero_deposits(account_id,first_seen_at)`,
		`CREATE INDEX IF NOT EXISTS monero_deposits_status ON monero_deposits(status,confirmations,updated_at)`,
	} {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) baselineSchemaMigrateMeditationLogPrimaryKey(ctx context.Context) error {
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

// baselineSchemaEnsureMeshChangeColumns upgrades pre-tombstone databases in place so
// delete propagation has somewhere to be recorded.

func (s *Store) baselineSchemaEnsureMeshChangeColumns(ctx context.Context) error {
	if err := s.baselineSchemaAddColumnIfMissing(ctx, "server_mesh_changes", "op",
		`ALTER TABLE server_mesh_changes ADD COLUMN op TEXT NOT NULL DEFAULT 'upsert'`); err != nil {
		return err
	}
	return s.baselineSchemaAddColumnIfMissing(ctx, "server_mesh_changes", "deleted_at",
		`ALTER TABLE server_mesh_changes ADD COLUMN deleted_at TEXT NOT NULL DEFAULT ''`)
}

func (s *Store) baselineSchemaAddColumnIfMissing(ctx context.Context, table, column, ddl string) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT 1 FROM pragma_table_info(?1) WHERE name=?2`, table, column)
	if err != nil {
		return err
	}
	defer rows.Close()
	if rows.Next() {
		return nil
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, ddl)
	return err
}

func (s *Store) baselineSchemaMigrateSocialCacheTable(ctx context.Context) error {
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
