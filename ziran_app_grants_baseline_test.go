package main

// Original grant storage retained as an independent migration oracle.
import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

func (s *Store) baselineCreateAppGrant(ctx context.Context, userID string, req AppGrantRequest) (AppGrant, error) {
	id, err := baselineRandomResourceID()
	if err != nil {
		return AppGrant{}, err
	}
	if req.Permission == "" {
		req.Permission = appGrantRead
	}
	existence := baselineAppExistsResult(s, ctx, req.SourceAppID)
	if exists, err := existence.Value, existence.Error; err != nil || !exists {
		if err != nil {
			return AppGrant{}, err
		}
		return AppGrant{}, sql.ErrNoRows
	}
	existence = baselineAppExistsResult(s, ctx, req.TargetAppID)
	if exists, err := existence.Value, existence.Error; err != nil || !exists {
		if err != nil {
			return AppGrant{}, err
		}
		return AppGrant{}, sql.ErrNoRows
	}
	visibility, ok, err := s.baselineAppCollectionVisibility(ctx, req.SourceAppID, req.CollectionPrefix)
	if err != nil {
		return AppGrant{}, err
	}
	if !ok {
		return AppGrant{}, fmt.Errorf("collection is not registered for source app")
	}
	if visibility == "private" {
		return AppGrant{}, fmt.Errorf("private collections cannot be granted across apps")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AppGrant{}, err
	}
	defer tx.Rollback()
	if err := baselineTouchUser(ctx, tx, userID); err != nil {
		return AppGrant{}, err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO server_app_grants(id,user_id_hash,source_app_id,target_app_id,collection_prefix,permission,status)
VALUES(?1,?2,?3,?4,?5,?6,'active')`,
		id, userID, req.SourceAppID, req.TargetAppID, req.CollectionPrefix, req.Permission); err != nil {
		return AppGrant{}, err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO server_app_grant_audit(grant_id,user_id_hash,action,payload_json)
VALUES(?1,?2,'create',?3)`, id, userID, baselineAuditJSON(req)); err != nil {
		return AppGrant{}, err
	}
	if err := tx.Commit(); err != nil {
		return AppGrant{}, err
	}
	return s.baselineAppGrantByID(ctx, userID, id)
}

func (s *Store) baselineAppGrantByID(ctx context.Context, userID, id string) (AppGrant, error) {
	var grant AppGrant
	err := s.db.QueryRowContext(ctx, `
SELECT id,user_id_hash,source_app_id,target_app_id,collection_prefix,permission,status,created_at,updated_at,revoked_at
FROM server_app_grants
WHERE user_id_hash=?1 AND id=?2`, userID, id).Scan(&grant.ID, &grant.UserIDHash,
		&grant.SourceAppID, &grant.TargetAppID, &grant.CollectionPrefix, &grant.Permission,
		&grant.Status, &grant.CreatedAt, &grant.UpdatedAt, &grant.RevokedAt)
	return grant, err
}

func (s *Store) baselineListAppGrants(ctx context.Context, userID string) ([]AppGrant, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id,user_id_hash,source_app_id,target_app_id,collection_prefix,permission,status,created_at,updated_at,revoked_at
FROM server_app_grants
WHERE user_id_hash=?1
ORDER BY updated_at DESC,id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []AppGrant{}
	for rows.Next() {
		var item AppGrant
		if err := rows.Scan(&item.ID, &item.UserIDHash, &item.SourceAppID, &item.TargetAppID,
			&item.CollectionPrefix, &item.Permission, &item.Status, &item.CreatedAt,
			&item.UpdatedAt, &item.RevokedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) baselineRevokeAppGrant(ctx context.Context, userID, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `
UPDATE server_app_grants
SET status='revoked', revoked_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP
WHERE user_id_hash=?1 AND id=?2 AND status='active'`, userID, id)
	if err != nil {
		return err
	}
	if baselineRowsAffected(res) == 0 {
		return sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO server_app_grant_audit(grant_id,user_id_hash,action)
VALUES(?1,?2,'revoke')`, id, userID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) baselineAuthorizedAppRecords(ctx context.Context, userID, sourceAppID, targetAppID, collectionPrefix string) ([]EncryptedRecord, error) {
	sourceAppID = strings.TrimSpace(sourceAppID)
	targetAppID = strings.TrimSpace(targetAppID)
	collectionPrefix = strings.TrimSpace(collectionPrefix)
	if sourceAppID == "" || targetAppID == "" || collectionPrefix == "" {
		return nil, fmt.Errorf("source_app_id, target_app_id, and collection_prefix are required")
	}
	if _, ok, err := s.baselineAppCollectionVisibility(ctx, sourceAppID, collectionPrefix); err != nil {
		return nil, err
	} else if !ok {
		return nil, errAppScopeNotOwned
	}
	existence := baselineAppExistsResult(s, ctx, targetAppID)
	if exists, err := existence.Value, existence.Error; err != nil {
		return nil, err
	} else if !exists {
		return nil, sql.ErrNoRows
	}
	if sourceAppID != targetAppID {
		var exists int
		err := s.db.QueryRowContext(ctx, `
SELECT EXISTS(
	SELECT 1 FROM server_app_grants
	WHERE user_id_hash=?1 AND source_app_id=?2 AND target_app_id=?3
	  AND collection_prefix=?4 AND permission='read' AND status='active'
)`, userID, sourceAppID, targetAppID, collectionPrefix).Scan(&exists)
		if err != nil {
			return nil, err
		}
		if exists == 0 {
			return nil, ErrSyncUserNotFound
		}
	}
	return s.baselineSnapshotEncryptedRecordsByCollectionPrefix(ctx, userID, collectionPrefix)
}

func (s *Store) baselineAppCollectionVisibility(ctx context.Context, appID, collectionPrefix string) (string, bool, error) {
	var visibility string
	err := s.db.QueryRowContext(ctx, `
SELECT visibility
FROM server_app_collections
WHERE app_id=?1 AND collection_prefix=?2`, appID, collectionPrefix).Scan(&visibility)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return visibility, true, nil
}

func (s *Store) baselineSnapshotEncryptedRecordsByCollectionPrefix(ctx context.Context, userID, collectionPrefix string) ([]EncryptedRecord, error) {
	query := `
SELECT collection,id,key_id,nonce,ciphertext,updated_at,deleted_at,content_hash,schema_version,parent_id
FROM server_encrypted_records
WHERE user_id_hash=?1 AND collection=?2
ORDER BY collection,id`
	args := []any{userID, collectionPrefix}
	if strings.HasSuffix(collectionPrefix, ".*") {
		query = `
SELECT collection,id,key_id,nonce,ciphertext,updated_at,deleted_at,content_hash,schema_version,parent_id
FROM server_encrypted_records
WHERE user_id_hash=?1 AND collection LIKE ?2 ESCAPE '\'
ORDER BY collection,id`
		args[1] = Scope_LikePatternForCollectionPrefix(collectionPrefix)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []EncryptedRecord{}
	for rows.Next() {
		var item EncryptedRecord
		if err := rows.Scan(&item.Collection, &item.ID, &item.KeyID, &item.Nonce,
			&item.Ciphertext, &item.UpdatedAt, &item.DeletedAt, &item.ContentHash,
			&item.SchemaVersion, &item.ParentID); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func baselineTouchUser(ctx context.Context, tx *sql.Tx, userID string) error {
	res, err := tx.ExecContext(ctx, `
UPDATE server_users
SET last_seen_at=?2
WHERE user_id_hash=?1`, userID, Timestamp_CanonicalNow())
	if err != nil {
		return err
	}
	if baselineRowsAffected(res) == 0 {
		return ErrSyncUserNotFound
	}
	_, err = tx.ExecContext(ctx, `
INSERT OR IGNORE INTO server_sync_state(user_id_hash,server_version)
VALUES(?1,0)`, userID)
	return err
}

func baselineRowsAffected(res sql.Result) int {
	n, err := res.RowsAffected()
	if err != nil {
		return 0
	}
	return int(n)
}

func baselineRandomResourceID() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes[:]), nil
}

func baselineAuditJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func baselineAppExistsResult(s *Store, ctx context.Context, appID string) ExistsResult {
	value, err := s.baselineAppExists(ctx, appID)
	return ExistsResult{Value: value, Error: err}
}
