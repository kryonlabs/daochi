// Original mesh and shared storage logic from b1fd717, retained only as a port regression oracle.
package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

type baselineMeshEncryptedRecord struct {
	UserIDHash  string `json:"user_id_hash"`
	PublicKey   string `json:"public_key"`
	CreatedAt   string `json:"created_at,omitempty"`
	LastSeenAt  string `json:"last_seen_at,omitempty"`
	MeshVersion int64  `json:"mesh_version,omitempty"`
	Record      EncryptedRecord
}

// baselineMeshEncryptedRecordDeletion is a tombstone for a record removed on a
// peer node. It rides in a separate payload field so older nodes that do
// not understand deletions keep working unchanged.
type baselineMeshEncryptedRecordDeletion struct {
	UserIDHash  string `json:"user_id_hash"`
	Collection  string `json:"collection"`
	ID          string `json:"id"`
	DeletedAt   string `json:"deleted_at"`
	MeshVersion int64  `json:"mesh_version,omitempty"`
}

type baselineNodeMeshExportRequest struct {
	Cursor string         `json:"cursor,omitempty"`
	Limit  int            `json:"limit,omitempty"`
	Policy NodeSyncPolicy `json:"policy,omitempty"`
}

type baselineNodeMeshExportResponse struct {
	Status     string                                `json:"status"`
	Apps       []SignedAppRegistrationRequest        `json:"apps,omitempty"`
	Records    []baselineMeshEncryptedRecord         `json:"records"`
	Deletions  []baselineMeshEncryptedRecordDeletion `json:"deletions,omitempty"`
	Spaces     []MeshTrustSpace                      `json:"spaces,omitempty"`
	Names      []NameClaim                           `json:"names,omitempty"`
	NextCursor string                                `json:"next_cursor,omitempty"`
	Truncated  bool                                  `json:"truncated,omitempty"`
}

type baselineNodeMeshImportRequest struct {
	Apps      []SignedAppRegistrationRequest        `json:"apps,omitempty"`
	Records   []baselineMeshEncryptedRecord         `json:"records"`
	Deletions []baselineMeshEncryptedRecordDeletion `json:"deletions,omitempty"`
	Spaces    []MeshTrustSpace                      `json:"spaces,omitempty"`
	Names     []NameClaim                           `json:"names,omitempty"`
	Policy    NodeSyncPolicy                        `json:"policy,omitempty"`
}

type baselineNodeMeshImportResponse struct {
	Status  string `json:"status"`
	Records int    `json:"records"`
	Applied int    `json:"applied"`
}

type baselineMeshCursor struct {
	Seq        int64  `json:"seq,omitempty"`
	UpdatedAt  string `json:"updated_at"`
	UserIDHash string `json:"user_id_hash"`
	Collection string `json:"collection"`
	ID         string `json:"id"`
}

type baselineAppCollectionMatcher struct {
	AppID       string
	DisplayName string
	Prefix      string
	MatchPrefix string
	Wildcard    bool
	Specificity int
}

func baselineEncodeMeshCursor(cursor baselineMeshCursor) (string, error) {
	data, err := json.Marshal(cursor)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func baselineDecodeMeshCursor(raw string) (baselineMeshCursor, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return baselineMeshCursor{}, nil
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return baselineMeshCursor{}, errors.New("invalid mesh cursor")
	}
	var cursor baselineMeshCursor
	if err := json.Unmarshal(data, &cursor); err != nil {
		return baselineMeshCursor{}, errors.New("invalid mesh cursor")
	}
	return cursor, nil
}

func baselineMeshPeerCursorKey(baseURL string, policy NodeSyncPolicy) string {
	body, _ := json.Marshal(policy)
	sum := sha256.Sum256([]byte(strings.TrimRight(baseURL, "/") + "\x00" + string(body)))
	return hex.EncodeToString(sum[:])
}

func baselineMeshBatchLimit(requested, configured int) int {
	limit := configured
	if limit <= 0 {
		limit = 500
	}
	if requested > 0 && requested < limit {
		limit = requested
	}
	if limit > 2000 {
		return 2000
	}
	return limit
}

func baselinePolicyAllowsOperation(approved, requested NodeSyncPolicy, operation string) bool {
	direction := strings.ToLower(strings.TrimSpace(approved.Direction))
	if operation == "export" && direction != "push" && direction != "bidirectional" {
		return false
	}
	if operation == "import" && direction != "pull" && direction != "bidirectional" {
		return false
	}
	return baselineStringSetContains(approved.Apps, requested.Apps) &&
		baselineStringSetContains(approved.Collections, requested.Collections) &&
		baselineStringSetContains(approved.Spaces, requested.Spaces) &&
		baselineStringSetContains(approved.Data, requested.Data)
}

func baselineStringSetContains(approved, requested []string) bool {
	if len(requested) == 0 {
		return true
	}
	allowed := make(map[string]bool, len(approved))
	for _, value := range approved {
		allowed[strings.ToLower(strings.TrimSpace(value))] = true
	}
	for _, value := range requested {
		if !allowed[strings.ToLower(strings.TrimSpace(value))] {
			return false
		}
	}
	return true
}

func baselineBearerToken(header string) string {
	if before, after, ok := strings.Cut(strings.TrimSpace(header), " "); ok && strings.EqualFold(before, "Bearer") {
		return strings.TrimSpace(after)
	}
	return ""
}

func baselineNodePolicyAllowsPull(policy *NodeSyncPolicy) bool {
	if policy == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(policy.Direction)) {
	case "pull", "bidirectional":
		return MeshPolicy_IncludesData(policy, "encrypted_records") ||
			MeshPolicy_IncludesData(policy, "names") ||
			MeshPolicy_IncludesData(policy, "app_registry")
	default:
		return false
	}
}

func baselineEffectiveNodeSyncPolicy(policy *NodeSyncPolicy) NodeSyncPolicy {
	if policy == nil {
		return NodeSyncPolicy{}
	}
	return *policy
}

// baselineExportMeshEncryptedRecords walks the change log in seq order and emits
// both record upserts and deletion tombstones. Upsert entries whose
// record row is gone (deleted later in the log) are skipped; their
// tombstone follows in the same stream, so consumers still converge.
func (s *Store) baselineExportMeshEncryptedRecords(ctx context.Context, policy NodeSyncPolicy, rawCursor string, limit int) ([]baselineMeshEncryptedRecord, []baselineMeshEncryptedRecordDeletion, string, bool, error) {
	cursor, err := baselineDecodeMeshCursor(rawCursor)
	if err != nil {
		return nil, nil, "", false, err
	}
	if !MeshPolicy_IncludesData(&policy, "encrypted_records") {
		return []baselineMeshEncryptedRecord{}, nil, "", false, nil
	}
	matchers, err := s.baselineAppCollectionMatchers(ctx)
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

	limit = baselineMeshBatchLimit(limit, limit)
	records := make([]baselineMeshEncryptedRecord, 0, limit)
	deletions := []baselineMeshEncryptedRecordDeletion{}
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
		if !baselineMeshPolicyAllowsRecord(policy, matchers, changeCollection) {
			continue
		}
		if op == "delete" {
			deletions = append(deletions, baselineMeshEncryptedRecordDeletion{
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
		item := baselineMeshEncryptedRecord{
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
	nextCursor, err := baselineEncodeMeshCursor(baselineMeshCursor{Seq: lastSeq})
	if err != nil {
		return nil, nil, "", false, err
	}
	return records, deletions, nextCursor, true, nil
}

func (s *Store) baselineImportMeshEncryptedRecords(ctx context.Context, policy NodeSyncPolicy, records []baselineMeshEncryptedRecord) (int, error) {
	return s.baselineImportMeshEncryptedBatch(ctx, policy, records, nil)
}

// baselineImportMeshEncryptedBatch applies upserts and deletions together,
// ordered by their change-log seq so a delete-then-recreate sequence in
// one batch converges to the recreated record.
func (s *Store) baselineImportMeshEncryptedBatch(ctx context.Context, policy NodeSyncPolicy, records []baselineMeshEncryptedRecord, deletions []baselineMeshEncryptedRecordDeletion) (int, error) {
	if !MeshPolicy_IncludesData(&policy, "encrypted_records") {
		return 0, nil
	}
	matchers, err := s.baselineAppCollectionMatchers(ctx)
	if err != nil {
		return 0, err
	}
	type meshChange struct {
		seq      int64
		record   *baselineMeshEncryptedRecord
		deletion *baselineMeshEncryptedRecordDeletion
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
			if !Identity_ValidUserID(change.deletion.UserIDHash) {
				return 0, fmt.Errorf("invalid mesh deletion user_id_hash")
			}
			if !baselineMeshPolicyAllowsRecord(policy, matchers, change.deletion.Collection) {
				continue
			}
			deleted, err := userTombstoned(change.deletion.UserIDHash)
			if err != nil {
				return 0, err
			}
			if deleted {
				continue
			}
			n, err := baselineApplyMeshRecordDeletion(ctx, tx, *change.deletion)
			if err != nil {
				return 0, err
			}
			applied += n
			continue
		}
		item := *change.record
		if !Identity_ValidUserID(item.UserIDHash) {
			return 0, fmt.Errorf("invalid mesh user_id_hash")
		}
		publicKey, err := hex.DecodeString(strings.TrimSpace(item.PublicKey))
		if err != nil || len(publicKey) == 0 {
			return 0, fmt.Errorf("invalid mesh public_key")
		}
		if err := baselineValidateUserIDForPublicKey(item.UserIDHash, publicKey); err != nil {
			return 0, err
		}
		if !baselineValidEncryptedRecordForProtocol(item.Record, LatestProtocol) {
			return 0, fmt.Errorf("invalid mesh encrypted record")
		}
		if !baselineMeshPolicyAllowsRecord(policy, matchers, item.Record.Collection) {
			continue
		}
		deleted, err := userTombstoned(item.UserIDHash)
		if err != nil {
			return 0, err
		}
		if deleted {
			continue
		}
		if err := baselineUpsertMeshUser(ctx, tx, item, publicKey); err != nil {
			return 0, err
		}
		n, err := baselineUpsertMeshEncryptedRecord(ctx, tx, item.UserIDHash, item.Record)
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

// baselineApplyMeshRecordDeletion removes a record when the tombstone is at least
// as new as the stored row. The local delete trigger then logs our own
// tombstone, so the deletion keeps propagating to further peers.
func baselineApplyMeshRecordDeletion(ctx context.Context, tx *sql.Tx, deletion baselineMeshEncryptedRecordDeletion) (int, error) {
	if !Identity_ValidNamespace(strings.TrimSpace(deletion.Collection)) ||
		!Identity_ValidEncryptedRecordID(strings.TrimSpace(deletion.ID)) {
		return 0, fmt.Errorf("invalid mesh deletion target")
	}
	deletedAt := Timestamp_NormalizeTime(deletion.DeletedAt, "")
	res, err := tx.ExecContext(ctx, `
DELETE FROM server_encrypted_records
WHERE user_id_hash=?1 AND collection=?2 AND id=?3 AND updated_at<=?4`,
		deletion.UserIDHash, deletion.Collection, deletion.ID, deletedAt)
	if err != nil {
		return 0, err
	}
	applied := baselineMeshRowsAffected(res)
	if applied > 0 {
		if _, err := baselineNextUserVersion(ctx, tx, deletion.UserIDHash); err != nil {
			return 0, err
		}
	}
	return applied, nil
}

func (s *Store) baselineLoadNodeSyncCursor(ctx context.Context, peerKey string) (string, error) {
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

func (s *Store) baselineSaveNodeSyncCursor(ctx context.Context, peerKey, cursor string) error {
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

func baselineUpsertMeshUser(ctx context.Context, tx *sql.Tx, item baselineMeshEncryptedRecord, publicKey []byte) error {
	createdAt := Timestamp_NormalizeTime(item.CreatedAt, "")
	lastSeenAt := Timestamp_NormalizeTime(item.LastSeenAt, createdAt)
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

// baselineMeshRecordContentKey breaks exact-timestamp ties deterministically so
// every node converges to the same record regardless of pull order.
func baselineMeshRecordContentKey(item EncryptedRecord) string {
	return item.ContentHash + "\x00" + item.Ciphertext
}

func baselineUpsertMeshEncryptedRecord(ctx context.Context, tx *sql.Tx, userID string, item EncryptedRecord) (int, error) {
	updatedAt := Timestamp_NormalizeTime(item.UpdatedAt, "")
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
		existingUpdated := Timestamp_NormalizeTime(existing.UpdatedAt, "")
		if updatedAt < existingUpdated ||
			(updatedAt == existingUpdated && baselineMeshRecordContentKey(item) <= baselineMeshRecordContentKey(existing)) {
			return 0, nil
		}
	}
	version, err := baselineNextUserVersion(ctx, tx, userID)
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
	return baselineMeshRowsAffected(res), nil
}

func baselineMeshPolicyAllowsRecord(policy NodeSyncPolicy, matchers []baselineAppCollectionMatcher, collection string) bool {
	if len(policy.Collections) > 0 && !baselineMeshCollectionAllowed(policy.Collections, collection) {
		return false
	}
	if len(policy.Apps) == 0 {
		return true
	}
	matcher := baselineBestCollectionMatcher(collection, matchers)
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

func baselineMeshCollectionAllowed(allowed []string, collection string) bool {
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

func baselineNextUserVersion(ctx context.Context, tx *sql.Tx, userID string) (int64, error) {
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

func (s *Store) baselineAppCollectionMatchers(ctx context.Context) ([]baselineAppCollectionMatcher, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT a.app_id,a.display_name,c.collection_prefix
FROM server_apps a
JOIN server_app_collections c ON c.app_id=a.app_id
ORDER BY a.app_id,c.collection_prefix`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var matchers []baselineAppCollectionMatcher
	for rows.Next() {
		var matcher baselineAppCollectionMatcher
		if err := rows.Scan(&matcher.AppID, &matcher.DisplayName, &matcher.Prefix); err != nil {
			return nil, err
		}
		matcher.MatchPrefix = strings.TrimSuffix(matcher.Prefix, "*")
		matcher.Wildcard = matcher.MatchPrefix != matcher.Prefix
		matcher.Specificity = len(matcher.MatchPrefix)
		matchers = append(matchers, matcher)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return matchers, nil
}

func baselineBestCollectionMatcher(collection string, matchers []baselineAppCollectionMatcher) *baselineAppCollectionMatcher {
	var best *baselineAppCollectionMatcher
	for i := range matchers {
		matcher := &matchers[i]
		matches := false
		if matcher.Wildcard {
			matches = strings.HasPrefix(collection, matcher.MatchPrefix)
		} else {
			matches = collection == matcher.MatchPrefix
		}
		if !matches {
			continue
		}
		if best == nil || matcher.Specificity > best.Specificity {
			best = matcher
		}
	}
	return best
}

func baselineValidateUserIDForPublicKey(userID string, publicKey []byte) error {
	sum := sha256.Sum256(publicKey)
	actual := hex.EncodeToString(sum[:])
	if userID != actual {
		return fmt.Errorf("public key hash mismatch")
	}
	return nil
}

func baselineMeshRowsAffected(res sql.Result) int {
	n, err := res.RowsAffected()
	if err != nil {
		return 0
	}
	return int(n)
}

func baselineValidEncryptedRecord(item EncryptedRecord) bool {
	if !Identity_ValidNamespace(strings.TrimSpace(item.Collection)) ||
		!Identity_ValidEncryptedRecordID(strings.TrimSpace(item.ID)) {
		return false
	}
	if strings.TrimSpace(item.UpdatedAt) == "" {
		return false
	}
	if item.DeletedAt == 0 && strings.TrimSpace(item.Ciphertext) == "" {
		return false
	}
	return len(item.Ciphertext) <= 262144 &&
		len(item.Nonce) <= 256 &&
		len(item.KeyID) <= 128 &&
		baselineValidEncryptedRecordMetadata(item)
}

func baselineValidEncryptedRecordForProtocol(item EncryptedRecord, protocolVersion int) bool {
	if !baselineValidEncryptedRecord(item) {
		return false
	}
	if protocolVersion >= 5 {
		return Identity_ValidEncryptedHierarchyCollection(item.Collection) ||
			Identity_ValidLegacyEncryptedCollection(item.Collection)
	}
	return true
}

func baselineValidEncryptedRecordMetadata(item EncryptedRecord) bool {
	contentHash := strings.TrimSpace(item.ContentHash)
	parentID := strings.TrimSpace(item.ParentID)
	if contentHash != "" && !Identity_ValidUserID(contentHash) {
		return false
	}
	if parentID != "" && !Identity_ValidEncryptedRecordID(parentID) {
		return false
	}
	return item.SchemaVersion >= 0 && item.SchemaVersion <= 65535
}
