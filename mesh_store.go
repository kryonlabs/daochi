package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ExportMeshEncryptedRecords walks the change log in seq order and emits
// both record upserts and deletion tombstones. Upsert entries whose
// record row is gone (deleted later in the log) are skipped; their
// tombstone follows in the same stream, so consumers still converge.
func (s *Store) ExportMeshEncryptedRecords(ctx context.Context, policy NodeSyncPolicy, rawCursor string, limit int) ([]MeshEncryptedRecord, []MeshEncryptedRecordDeletion, string, bool, error) {
	cursor, err := decodeMeshCursor(rawCursor)
	if err != nil {
		return nil, nil, "", false, err
	}
	if !nodePolicyIncludesData(&policy, "encrypted_records") {
		return []MeshEncryptedRecord{}, nil, "", false, nil
	}
	matchers, err := s.appCollectionMatchers(ctx)
	if err != nil {
		return nil, nil, "", false, err
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT e.seq,e.op,e.user_id_hash,e.collection,e.record_id,e.deleted_at,
       r.id,r.key_id,r.nonce,r.ciphertext,r.updated_at,r.deleted_at,
       r.content_hash,r.schema_version,r.parent_id,u.public_key,u.created_at,u.last_seen_at
FROM server_mesh_changes e
LEFT JOIN server_encrypted_records r
  ON e.op!='delete' AND r.user_id_hash=e.user_id_hash AND r.collection=e.collection AND r.id=e.record_id
LEFT JOIN server_users u ON u.user_id_hash=e.user_id_hash
WHERE e.seq>?1
ORDER BY e.seq`, cursor.Seq)
	if err != nil {
		return nil, nil, "", false, err
	}
	defer rows.Close()

	limit = meshBatchLimit(limit, limit)
	records := make([]MeshEncryptedRecord, 0, limit)
	deletions := []MeshEncryptedRecordDeletion{}
	var lastSeq int64
	emitted := 0
	for rows.Next() {
		var seq int64
		var op, changeUser, changeCollection, changeRecord, changeDeletedAt string
		var recordID, keyID, nonce, ciphertext, updatedAt, contentHash, parentID sql.NullString
		var recordDeletedAt, schemaVersion sql.NullInt64
		var publicKey []byte
		var userCreatedAt, userLastSeenAt sql.NullString
		if err := rows.Scan(&seq, &op, &changeUser, &changeCollection, &changeRecord, &changeDeletedAt,
			&recordID, &keyID, &nonce, &ciphertext, &updatedAt, &recordDeletedAt,
			&contentHash, &schemaVersion, &parentID, &publicKey, &userCreatedAt, &userLastSeenAt); err != nil {
			return nil, nil, "", false, err
		}
		if !meshPolicyAllowsRecord(policy, matchers, changeCollection) {
			continue
		}
		if op == "delete" {
			deletions = append(deletions, MeshEncryptedRecordDeletion{
				UserIDHash:  changeUser,
				Collection:  changeCollection,
				ID:          changeRecord,
				DeletedAt:   changeDeletedAt,
				MeshVersion: seq,
			})
			lastSeq = seq
			emitted++
			if emitted == limit {
				break
			}
			continue
		}
		if !recordID.Valid || !userCreatedAt.Valid {
			// Record (or its user) no longer exists; a tombstone for it
			// appears later in the log.
			continue
		}
		item := MeshEncryptedRecord{
			UserIDHash:  changeUser,
			CreatedAt:   userCreatedAt.String,
			LastSeenAt:  userLastSeenAt.String,
			MeshVersion: seq,
			Record: EncryptedRecord{
				Collection: changeCollection,
				ID:         changeRecord,
			},
		}
		item.Record.KeyID = keyID.String
		item.Record.Nonce = nonce.String
		item.Record.Ciphertext = ciphertext.String
		item.Record.UpdatedAt = updatedAt.String
		item.Record.DeletedAt = recordDeletedAt.Int64
		item.Record.ContentHash = contentHash.String
		item.Record.SchemaVersion = int(schemaVersion.Int64)
		item.Record.ParentID = parentID.String
		item.PublicKey = hex.EncodeToString(publicKey)
		records = append(records, item)
		lastSeq = seq
		emitted++
		if emitted == limit {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, "", false, err
	}
	if emitted < limit {
		return records, deletions, "", false, nil
	}
	nextCursor, err := encodeMeshCursor(meshCursor{Seq: lastSeq})
	if err != nil {
		return nil, nil, "", false, err
	}
	return records, deletions, nextCursor, true, nil
}

func (s *Store) ImportMeshEncryptedRecords(ctx context.Context, policy NodeSyncPolicy, records []MeshEncryptedRecord) (int, error) {
	return s.ImportMeshEncryptedBatch(ctx, policy, records, nil)
}

// ImportMeshEncryptedBatch applies upserts and deletions together,
// ordered by their change-log seq so a delete-then-recreate sequence in
// one batch converges to the recreated record.
func (s *Store) ImportMeshEncryptedBatch(ctx context.Context, policy NodeSyncPolicy, records []MeshEncryptedRecord, deletions []MeshEncryptedRecordDeletion) (int, error) {
	if !nodePolicyIncludesData(&policy, "encrypted_records") {
		return 0, nil
	}
	matchers, err := s.appCollectionMatchers(ctx)
	if err != nil {
		return 0, err
	}
	type meshChange struct {
		seq      int64
		record   *MeshEncryptedRecord
		deletion *MeshEncryptedRecordDeletion
	}
	changes := make([]meshChange, 0, len(records)+len(deletions))
	for i := range records {
		changes = append(changes, meshChange{seq: records[i].MeshVersion, record: &records[i]})
	}
	for i := range deletions {
		changes = append(changes, meshChange{seq: deletions[i].MeshVersion, deletion: &deletions[i]})
	}
	sort.SliceStable(changes, func(i, j int) bool { return changes[i].seq < changes[j].seq })

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	tombstonedUsers := map[string]bool{}
	userTombstoned := func(userID string) (bool, error) {
		if cached, ok := tombstonedUsers[userID]; ok {
			return cached, nil
		}
		var deleted int
		if err := tx.QueryRowContext(ctx, `
SELECT EXISTS(SELECT 1 FROM server_account_tombstones WHERE user_id_hash=?1)`, userID).Scan(&deleted); err != nil {
			return false, err
		}
		tombstonedUsers[userID] = deleted != 0
		return deleted != 0, nil
	}

	applied := 0
	for _, change := range changes {
		if change.deletion != nil {
			if !validUserID(change.deletion.UserIDHash) {
				return 0, fmt.Errorf("invalid mesh deletion user_id_hash")
			}
			if !meshPolicyAllowsRecord(policy, matchers, change.deletion.Collection) {
				continue
			}
			deleted, err := userTombstoned(change.deletion.UserIDHash)
			if err != nil {
				return 0, err
			}
			if deleted {
				continue
			}
			n, err := applyMeshRecordDeletion(ctx, tx, *change.deletion)
			if err != nil {
				return 0, err
			}
			applied += n
			continue
		}
		item := *change.record
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
		if !validEncryptedRecordForProtocol(item.Record, latestProtocol) {
			return 0, fmt.Errorf("invalid mesh encrypted record")
		}
		if !meshPolicyAllowsRecord(policy, matchers, item.Record.Collection) {
			continue
		}
		deleted, err := userTombstoned(item.UserIDHash)
		if err != nil {
			return 0, err
		}
		if deleted {
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

// applyMeshRecordDeletion removes a record when the tombstone is at least
// as new as the stored row. The local delete trigger then logs our own
// tombstone, so the deletion keeps propagating to further peers.
func applyMeshRecordDeletion(ctx context.Context, tx *sql.Tx, deletion MeshEncryptedRecordDeletion) (int, error) {
	if !validNamespace(strings.TrimSpace(deletion.Collection)) ||
		!encryptedRecordIDPattern.MatchString(strings.TrimSpace(deletion.ID)) {
		return 0, fmt.Errorf("invalid mesh deletion target")
	}
	deletedAt := normalizeTime(deletion.DeletedAt, "")
	res, err := tx.ExecContext(ctx, `
DELETE FROM server_encrypted_records
WHERE user_id_hash=?1 AND collection=?2 AND id=?3 AND updated_at<=?4`,
		deletion.UserIDHash, deletion.Collection, deletion.ID, deletedAt)
	if err != nil {
		return 0, err
	}
	applied := rowsAffected(res)
	if applied > 0 {
		if _, err := nextUserVersion(ctx, tx, deletion.UserIDHash); err != nil {
			return 0, err
		}
	}
	return applied, nil
}

func (s *Store) LoadNodeSyncCursor(ctx context.Context, peerKey string) (string, error) {
	var cursor string
	err := s.db.QueryRowContext(ctx, `
SELECT cursor
FROM node_sync_cursors
WHERE peer_key=?1`, peerKey).Scan(&cursor)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return cursor, nil
}

func (s *Store) SaveNodeSyncCursor(ctx context.Context, peerKey, cursor string) error {
	if strings.TrimSpace(cursor) == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO node_sync_cursors(peer_key,cursor,updated_at)
VALUES(?1,?2,CURRENT_TIMESTAMP)
ON CONFLICT(peer_key) DO UPDATE SET
	cursor=excluded.cursor,
	updated_at=CURRENT_TIMESTAMP`, peerKey, cursor)
	return err
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

// meshRecordContentKey breaks exact-timestamp ties deterministically so
// every node converges to the same record regardless of pull order.
func meshRecordContentKey(item EncryptedRecord) string {
	return item.ContentHash + "\x00" + item.Ciphertext
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
		existingUpdated := normalizeTime(existing.UpdatedAt, "")
		if updatedAt < existingUpdated ||
			(updatedAt == existingUpdated && meshRecordContentKey(item) <= meshRecordContentKey(existing)) {
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
WHERE excluded.updated_at >= server_encrypted_records.updated_at`,
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
