package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Preserve the handwritten storage implementation at c2a2b82.
const baselineClientActiveRetention = 90 * 24 * time.Hour
const baselineLegacyWriteWindow = 180 * 24 * time.Hour

func baselineLifecycleNextVersion(ctx context.Context, tx *sql.Tx, userID string) (int64, error) {
	if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO server_sync_state(user_id_hash,server_version) VALUES(?1,0)", userID); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE server_sync_state SET server_version=server_version+1 WHERE user_id_hash=?1", userID); err != nil {
		return 0, err
	}
	var version int64
	err := tx.QueryRowContext(ctx, "SELECT server_version FROM server_sync_state WHERE user_id_hash=?1", userID).Scan(&version)
	return version, err
}

func (s *Store) baselineLifecycleRecordClientLogin(ctx context.Context, userID, clientID string) error {
	_, err := s.Database.ExecContext(ctx, `
INSERT INTO server_clients(user_id_hash,client_id,last_seen_at,last_login_at)
VALUES(?1,?2,?3,?3)
ON CONFLICT(user_id_hash,client_id) DO UPDATE SET
	last_seen_at=excluded.last_seen_at,
	last_login_at=excluded.last_login_at`, userID, clientID, Timestamp_CanonicalNow())
	return err
}

func (s *Store) baselineLifecycleRecordClientSync(ctx context.Context, userID, clientID string, sinceVersion, serverVersion int64, protocolVersion int, clientClock int64) error {
	_, err := s.Database.ExecContext(ctx, `
INSERT INTO server_clients(user_id_hash,client_id,last_seen_at,last_sync_at,last_since_server_version,last_seen_server_version,protocol_version,last_client_clock)
VALUES(?1,?2,?3,?3,?4,?5,?6,?7)
ON CONFLICT(user_id_hash,client_id) DO UPDATE SET
	last_seen_at=excluded.last_seen_at,
	last_sync_at=excluded.last_sync_at,
	last_since_server_version=excluded.last_since_server_version,
	last_seen_server_version=excluded.last_seen_server_version,
	protocol_version=excluded.protocol_version,
	last_client_clock=excluded.last_client_clock`, userID, clientID, Timestamp_CanonicalNow(), sinceVersion, serverVersion, protocolVersion, clientClock)
	return err
}

func (s *Store) baselineLifecycleStoreEncryptedPayload(ctx context.Context, userID, clientID string, payload []byte) (int64, error) {
	tx, err := s.Database.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if err := AccountState_Touch(tx, ctx, userID, ErrSyncUserNotFound); err != nil {
		return 0, err
	}
	version, err := baselineLifecycleNextVersion(ctx, tx, userID)
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO server_encrypted_payloads(user_id_hash,client_id,payload_json,server_version,created_at)
VALUES(?1,?2,?3,?4,?5)`, userID, clientID, string(payload), version, Timestamp_CanonicalNow()); err != nil {
		return 0, err
	}
	return version, tx.Commit()
}

func (s *Store) baselineLifecycleEncryptedPayloadsSince(ctx context.Context, userID string, sinceVersion int64, limit int) ([]EncryptedPayload, bool, error) {
	limitClause := ""
	queryLimit := limit
	if queryLimit > 0 {
		queryLimit++
		limitClause = " LIMIT ?3"
	}
	query := `
SELECT id,client_id,payload_json,created_at,server_version
FROM server_encrypted_payloads
WHERE user_id_hash=?1 AND server_version>?2
ORDER BY server_version,id` + limitClause
	var rows *sql.Rows
	var err error
	if queryLimit > 0 {
		rows, err = s.Database.QueryContext(ctx, query, userID, sinceVersion, queryLimit)
	} else {
		rows, err = s.Database.QueryContext(ctx, query, userID, sinceVersion)
	}
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	payloads := []EncryptedPayload{}
	for rows.Next() {
		var item EncryptedPayload
		var payload string
		if err := rows.Scan(&item.ID, &item.ClientID, &payload, &item.CreatedAt, &item.ServerVersion); err != nil {
			return nil, false, err
		}
		item.Payload = json.RawMessage(payload)
		payloads = append(payloads, item)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	truncated := false
	if limit > 0 && len(payloads) > limit {
		truncated = true
		payloads = payloads[:limit]
	}
	return payloads, truncated, nil
}

func (s *Store) baselineLifecycleRecentEncryptedPayloads(ctx context.Context, userID string, limit int) ([]EncryptedPayload, error) {
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	rows, err := s.Database.QueryContext(ctx, `
SELECT id,client_id,payload_json,created_at,server_version
FROM server_encrypted_payloads
WHERE user_id_hash=?1
ORDER BY id DESC
LIMIT ?2`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	payloads := []EncryptedPayload{}
	for rows.Next() {
		var item EncryptedPayload
		var payload string
		if err := rows.Scan(&item.ID, &item.ClientID, &payload, &item.CreatedAt, &item.ServerVersion); err != nil {
			return nil, err
		}
		item.Payload = json.RawMessage(payload)
		payloads = append(payloads, item)
	}
	return payloads, rows.Err()
}

func (s *Store) baselineLifecycleEncryptedPayloadBytes(ctx context.Context, userID string) (int64, error) {
	var bytes sql.NullInt64
	if err := s.Database.QueryRowContext(ctx, `
SELECT SUM(LENGTH(payload_json))
FROM server_encrypted_payloads
WHERE user_id_hash=?1`, userID).Scan(&bytes); err != nil {
		return 0, err
	}
	if !bytes.Valid {
		return 0, nil
	}
	return bytes.Int64, nil
}

func (s *Store) baselineLifecyclePruneEncryptedPayloads(ctx context.Context, userID string, maxAge time.Duration, maxBytes int64) (EncryptedPayloadPruneResult, error) {
	result := EncryptedPayloadPruneResult{}
	if maxAge <= 0 && maxBytes <= 0 {
		return result, nil
	}
	tx, err := s.Database.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	if maxAge > 0 {
		cutoff := time.Now().UTC().Add(-maxAge).Format(CanonicalTimestampLayout)
		res, err := tx.ExecContext(ctx, `
DELETE FROM server_encrypted_payloads
WHERE user_id_hash=?1 AND created_at<?2`, userID, cutoff)
		if err != nil {
			return result, err
		}
		deleted, _ := res.RowsAffected()
		result.Deleted += deleted
	}
	if maxBytes > 0 {
		for {
			var total sql.NullInt64
			if err := tx.QueryRowContext(ctx, `
SELECT SUM(LENGTH(payload_json))
FROM server_encrypted_payloads
WHERE user_id_hash=?1`, userID).Scan(&total); err != nil {
				return result, err
			}
			if !total.Valid || total.Int64 <= maxBytes {
				break
			}
			res, err := tx.ExecContext(ctx, `
DELETE FROM server_encrypted_payloads
WHERE id=(
	SELECT id
	FROM server_encrypted_payloads
	WHERE user_id_hash=?1
	ORDER BY server_version,id
	LIMIT 1
)`, userID)
			if err != nil {
				return result, err
			}
			deleted, _ := res.RowsAffected()
			if deleted == 0 {
				break
			}
			result.Deleted += deleted
		}
	}
	return result, tx.Commit()
}

func (s *Store) baselineLifecycleRecordSyncAudit(ctx context.Context, entry SyncAuditEntry) error {
	applied, err := json.Marshal(entry.Applied)
	if err != nil {
		return err
	}
	_, err = s.Database.ExecContext(ctx, `
INSERT INTO server_sync_audit(
	user_id_hash,client_id,app_id,protocol_version,since_server_version,client_clock,
	server_version,applied_json,remote_ops,full_snapshot_required,snapshot_reason,
	encrypted_payload,encrypted_payload_bytes)
VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)`,
		entry.UserIDHash, entry.ClientID, entry.AppID, entry.ProtocolVersion,
		entry.SinceServerVersion, entry.ClientClock, entry.ServerVersion,
		string(applied), entry.RemoteOps, boolInt(entry.FullSnapshotRequired),
		entry.SnapshotReason, boolInt(entry.EncryptedPayload), entry.EncryptedPayloadBytes)
	return err
}

func (s *Store) baselineLifecycleRecentSyncAudit(ctx context.Context, userID string, limit int) ([]SyncAuditEntry, error) {
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	rows, err := s.Database.QueryContext(ctx, `
SELECT id,user_id_hash,client_id,app_id,protocol_version,since_server_version,client_clock,
       server_version,applied_json,remote_ops,full_snapshot_required,snapshot_reason,
       encrypted_payload,encrypted_payload_bytes,created_at
FROM server_sync_audit
WHERE user_id_hash=?1
ORDER BY id DESC
LIMIT ?2`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []SyncAuditEntry{}
	for rows.Next() {
		var item SyncAuditEntry
		var applied string
		var fullSnapshot, encryptedPayload int
		if err := rows.Scan(&item.ID, &item.UserIDHash, &item.ClientID, &item.AppID,
			&item.ProtocolVersion, &item.SinceServerVersion, &item.ClientClock,
			&item.ServerVersion, &applied, &item.RemoteOps, &fullSnapshot,
			&item.SnapshotReason, &encryptedPayload, &item.EncryptedPayloadBytes,
			&item.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(applied), &item.Applied)
		item.FullSnapshotRequired = fullSnapshot != 0
		item.EncryptedPayload = encryptedPayload != 0
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) baselineLifecycleSyncOpsCompacted(ctx context.Context, userID string, clientClock int64) (bool, int64, error) {
	var compactedThrough int64
	err := s.Database.QueryRowContext(ctx, `
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

func (s *Store) baselineLifecycleCompactSyncOps(ctx context.Context, userID string) error {
	tx, err := s.Database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	currentVersion, err := baselineLifecycleCurrentUserVersionTx(ctx, tx, userID)
	if err != nil {
		return err
	}
	if currentVersion <= 0 {
		return tx.Commit()
	}

	cutoff := time.Now().UTC().Add(-baselineClientActiveRetention).Format(CanonicalTimestampLayout)
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

func (s *Store) baselineLifecycleDeleteAccount(ctx context.Context, userID string) error {
	tx, err := s.Database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
INSERT INTO server_account_tombstones(user_id_hash,deleted_at)
VALUES(?1,CURRENT_TIMESTAMP)
ON CONFLICT(user_id_hash) DO UPDATE SET deleted_at=CURRENT_TIMESTAMP`, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE monero_account_addresses SET disabled_at=CURRENT_TIMESTAMP
WHERE account_id=?1 AND disabled_at=''`, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM server_users WHERE user_id_hash=?1`, userID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) baselineLifecycleSyncLogs(ctx context.Context, userID string, sinceVersion int64) ([]SyncLog, error) {
	rows, err := s.Database.QueryContext(ctx, `
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

func (s *Store) baselineLifecycleDeleteLogs(ctx context.Context, userID string, sinceVersion int64) ([]SyncLog, error) {
	logs, err := s.baselineLifecycleSyncLogs(ctx, userID, sinceVersion)
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

func (s *Store) baselineLifecycleLegacyClients(ctx context.Context, userID string, minProtocol int) ([]string, error) {
	rows, err := s.Database.QueryContext(ctx, `
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

func (s *Store) baselineLifecycleLegacyWritePolicy(ctx context.Context, userID string) (bool, int64, error) {
	cutoff := Timestamp_CanonicalTimestamp(time.Now().Add(-baselineLegacyWriteWindow))
	var latest sql.NullString
	err := s.Database.QueryRowContext(ctx, `
SELECT MAX(last_sync_at)
FROM server_clients
WHERE user_id_hash=?1 AND protocol_version<?2 AND last_sync_at>=?3`,
		userID, LatestProtocol, cutoff).Scan(&latest)
	if err != nil {
		return false, 0, err
	}
	if !latest.Valid || latest.String == "" {
		return false, 0, nil
	}
	lastSync, err := time.Parse(CanonicalTimestampLayout, latest.String)
	if err != nil {
		return false, 0, err
	}
	return true, lastSync.Unix(), nil
}

func baselineLifecycleCurrentUserVersionTx(ctx context.Context, tx *sql.Tx, userID string) (int64, error) {
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

func (s *Store) baselineLifecycleCurrentUserVersion(ctx context.Context, userID string) (int64, error) {
	var version int64
	err := s.Database.QueryRowContext(ctx, `
SELECT server_version
FROM server_sync_state
WHERE user_id_hash=?1`, userID).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return version, err
}

// Retained from the original Go storage implementation for its independent oracle.
func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
