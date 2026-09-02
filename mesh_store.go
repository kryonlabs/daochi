package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

func (s *Store) ExportMeshEncryptedRecords(ctx context.Context, policy NodeSyncPolicy, rawCursor string, limit int) ([]MeshEncryptedRecord, string, bool, error) {
	cursor, err := decodeMeshCursor(rawCursor)
	if err != nil {
		return nil, "", false, err
	}
	if !nodePolicyIncludesData(&policy, "encrypted_records") {
		return []MeshEncryptedRecord{}, "", false, nil
	}
	matchers, err := s.appCollectionMatchers(ctx)
	if err != nil {
		return nil, "", false, err
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT r.user_id_hash,u.public_key,u.created_at,u.last_seen_at,
       r.collection,r.id,r.key_id,r.nonce,r.ciphertext,r.updated_at,r.deleted_at,
       r.content_hash,r.schema_version,r.parent_id
FROM server_encrypted_records r
JOIN server_users u ON u.user_id_hash=r.user_id_hash
WHERE r.updated_at>?1
   OR (r.updated_at=?1 AND r.user_id_hash>?2)
   OR (r.updated_at=?1 AND r.user_id_hash=?2 AND r.collection>?3)
   OR (r.updated_at=?1 AND r.user_id_hash=?2 AND r.collection=?3 AND r.id>?4)
ORDER BY r.updated_at,r.user_id_hash,r.collection,r.id`,
		cursor.UpdatedAt, cursor.UserIDHash, cursor.Collection, cursor.ID)
	if err != nil {
		return nil, "", false, err
	}
	defer rows.Close()

	limit = meshBatchLimit(limit, limit)
	records := make([]MeshEncryptedRecord, 0, limit)
	var last meshCursor
	for rows.Next() {
		var item MeshEncryptedRecord
		var publicKey []byte
		if err := rows.Scan(&item.UserIDHash, &publicKey, &item.CreatedAt, &item.LastSeenAt,
			&item.Record.Collection, &item.Record.ID, &item.Record.KeyID, &item.Record.Nonce,
			&item.Record.Ciphertext, &item.Record.UpdatedAt, &item.Record.DeletedAt,
			&item.Record.ContentHash, &item.Record.SchemaVersion, &item.Record.ParentID); err != nil {
			return nil, "", false, err
		}
		if !meshPolicyAllowsRecord(policy, matchers, item.Record.Collection) {
			continue
		}
		item.PublicKey = hex.EncodeToString(publicKey)
		records = append(records, item)
		last = meshCursor{
			UpdatedAt:  item.Record.UpdatedAt,
			UserIDHash: item.UserIDHash,
			Collection: item.Record.Collection,
			ID:         item.Record.ID,
		}
		if len(records) == limit {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return nil, "", false, err
	}
	if len(records) < limit {
		return records, "", false, nil
	}
	nextCursor, err := encodeMeshCursor(last)
	if err != nil {
		return nil, "", false, err
	}
	return records, nextCursor, true, nil
}

func (s *Store) ImportMeshEncryptedRecords(ctx context.Context, policy NodeSyncPolicy, records []MeshEncryptedRecord) (int, error) {
	if !nodePolicyIncludesData(&policy, "encrypted_records") {
		return 0, nil
	}
	matchers, err := s.appCollectionMatchers(ctx)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	applied := 0
	for _, item := range records {
		if !validUserID(item.UserIDHash) {
			return 0, fmt.Errorf("invalid mesh user_id_hash")
		}
		publicKey, err := hex.DecodeString(strings.TrimSpace(item.PublicKey))
		if err != nil || len(publicKey) == 0 {
			return 0, fmt.Errorf("invalid mesh public_key")
		}
		if err := validateUserIDForPublicKey(item.UserIDHash, publicKey); err != nil {
			return 0, err
		}
		if !validEncryptedRecordForProtocol(item.Record, ksyncLatestProtocol) {
			return 0, fmt.Errorf("invalid mesh encrypted record")
		}
		if !meshPolicyAllowsRecord(policy, matchers, item.Record.Collection) {
			continue
		}
		if err := upsertMeshUser(ctx, tx, item, publicKey); err != nil {
			return 0, err
		}
		n, err := upsertMeshEncryptedRecord(ctx, tx, item.UserIDHash, item.Record)
		if err != nil {
			return 0, err
		}
		applied += n
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return applied, nil
}

func upsertMeshUser(ctx context.Context, tx *sql.Tx, item MeshEncryptedRecord, publicKey []byte) error {
	createdAt := normalizeTime(item.CreatedAt, "")
	lastSeenAt := normalizeTime(item.LastSeenAt, createdAt)
	if _, err := tx.ExecContext(ctx, `
INSERT INTO server_users(user_id_hash,public_key,created_at,last_seen_at)
VALUES(?1,?2,?3,?4)
ON CONFLICT(user_id_hash) DO UPDATE SET
	last_seen_at=max(server_users.last_seen_at,excluded.last_seen_at)`,
		item.UserIDHash, publicKey, createdAt, lastSeenAt); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `
INSERT OR IGNORE INTO server_sync_state(user_id_hash,server_version)
VALUES(?1,0)`, item.UserIDHash)
	return err
}

func upsertMeshEncryptedRecord(ctx context.Context, tx *sql.Tx, userID string, item EncryptedRecord) (int, error) {
	updatedAt := normalizeTime(item.UpdatedAt, "")
	var existing EncryptedRecord
	err := tx.QueryRowContext(ctx, `
SELECT key_id,nonce,ciphertext,updated_at,deleted_at,content_hash,schema_version,parent_id
FROM server_encrypted_records
WHERE user_id_hash=?1 AND collection=?2 AND id=?3`,
		userID, item.Collection, item.ID).Scan(&existing.KeyID, &existing.Nonce,
		&existing.Ciphertext, &existing.UpdatedAt, &existing.DeletedAt,
		&existing.ContentHash, &existing.SchemaVersion, &existing.ParentID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if err == nil {
		if updatedAt <= normalizeTime(existing.UpdatedAt, "") {
			return 0, nil
		}
	}
	version, err := nextUserVersion(ctx, tx, userID)
	if err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx, `
INSERT INTO server_encrypted_records(user_id_hash,collection,id,key_id,nonce,ciphertext,updated_at,deleted_at,content_hash,schema_version,parent_id,server_version)
VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)
ON CONFLICT(user_id_hash,collection,id) DO UPDATE SET
	key_id=excluded.key_id,
	nonce=excluded.nonce,
	ciphertext=excluded.ciphertext,
	updated_at=excluded.updated_at,
	deleted_at=excluded.deleted_at,
	content_hash=excluded.content_hash,
	schema_version=excluded.schema_version,
	parent_id=excluded.parent_id,
	server_version=excluded.server_version
WHERE excluded.updated_at > server_encrypted_records.updated_at`,
		userID, item.Collection, item.ID, item.KeyID, item.Nonce, item.Ciphertext,
		updatedAt, item.DeletedAt, item.ContentHash, item.SchemaVersion, item.ParentID, version)
	if err != nil {
		return 0, err
	}
	return rowsAffected(res), nil
}

func meshPolicyAllowsRecord(policy NodeSyncPolicy, matchers []appCollectionMatcher, collection string) bool {
	if len(policy.Collections) > 0 && !meshCollectionAllowed(policy.Collections, collection) {
		return false
	}
	if len(policy.Apps) == 0 {
		return true
	}
	matcher := bestCollectionMatcher(collection, matchers)
	if matcher == nil {
		return false
	}
	for _, app := range policy.Apps {
		if strings.EqualFold(strings.TrimSpace(app), matcher.AppID) {
			return true
		}
	}
	return false
}

func meshCollectionAllowed(allowed []string, collection string) bool {
	for _, pattern := range allowed {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if strings.HasSuffix(pattern, ".*") {
			if strings.HasPrefix(collection, strings.TrimSuffix(pattern, "*")) {
				return true
			}
			continue
		}
		if collection == pattern {
			return true
		}
	}
	return false
}
