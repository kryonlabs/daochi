package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Store struct {
	db   *sql.DB
	path string
}

var ErrSyncUserNotFound = errors.New("sync user not found")

func OpenStore(path string) (*Store, error) {
	result := StoreOpen_Open(path)
	if result.Error != nil {
		return nil, result.Error
	}
	return &Store{db: result.Value, path: path}, nil
}

func (s *Store) Close() error {
	return StoreOpen_Close(s.db)
}

func (s *Store) ApplySync(ctx context.Context, req SyncRequest, publicKey []byte) (SyncResult, error) {
	result, _, err := s.ApplySyncDetailed(ctx, req, publicKey)
	return result, err
}

func (s *Store) ApplySyncDetailed(ctx context.Context, req SyncRequest, publicKey []byte) (SyncResult, []string, error) {
	result := SyncApplication_Apply(s.db, ctx, req, publicKey, ErrSyncUserNotFound)
	return result.Value, result.Accepted, result.Error
}

func currentUserVersionTx(ctx context.Context, tx *sql.Tx, userID string) (int64, error) {
	result := AccountState_CurrentVersionTx(tx, ctx, userID)
	return result.Value, result.Error
}

func (s *Store) RegisterUser(ctx context.Context, userID string, publicKey []byte) error {
	return AccountState_Register(s.db, ctx, userID, publicKey)
}

func (s *Store) AccountAlias(ctx context.Context, userID string) (string, error) {
	result := AccountProfile_Alias(s.db, ctx, userID)
	return result.Value, result.Error
}

func (s *Store) SetAccountAlias(ctx context.Context, userID, alias string) error {
	return AccountProfile_SetAlias(s.db, ctx, userID, alias, ErrSyncUserNotFound)
}

func (s *Store) AccountProfileIcon(ctx context.Context, userID string) (int, error) {
	result := AccountProfile_Icon(s.db, ctx, userID)
	return result.Value, result.Error
}

func (s *Store) SetAccountProfileIcon(ctx context.Context, userID string, profileIcon int) error {
	return AccountProfile_SetIcon(s.db, ctx, userID, profileIcon, ErrSyncUserNotFound)
}

func (s *Store) ResolveAccountRef(ctx context.Context, ref string) (string, bool, error) {
	result := AccountLookup_Resolve(s.db, ctx, ref)
	return result.Value, result.Found, result.Error
}

func (s *Store) CreateFriendRequest(ctx context.Context, id, requester, target string) (FriendRequest, error) {
	result := FriendStore_CreateRequest(s.db, ctx, id, requester, target)
	return result.Value, result.Error
}

func (s *Store) FriendRequest(ctx context.Context, id string) (FriendRequest, bool, error) {
	result := FriendStore_Request(s.db, ctx, id)
	return result.Value, result.Found, result.Error
}

func (s *Store) ListFriendRequests(ctx context.Context, userID string) ([]FriendRequest, []FriendRequest, error) {
	result := FriendStore_Requests(s.db, ctx, userID)
	return result.Incoming, result.Outgoing, result.Error
}

func (s *Store) AcceptFriendRequest(ctx context.Context, userID, id string) (FriendRequest, error) {
	result := FriendStore_Accept(s.db, ctx, userID, id, ErrSyncUserNotFound)
	return result.Value, result.Error
}

func (s *Store) DeclineFriendRequest(ctx context.Context, userID, id string) (FriendRequest, error) {
	result := FriendStore_Decline(s.db, ctx, userID, id, ErrSyncUserNotFound)
	return result.Value, result.Error
}

func (s *Store) ListFriends(ctx context.Context, userID string) ([]Friend, error) {
	result := FriendStore_Friends(s.db, ctx, userID)
	return result.Value, result.Error
}

func (s *Store) AuthoritativeSocial(ctx context.Context, userID string) ([]SocialSnapshot, error) {
	result := FriendStore_Authoritative(s.db, ctx, userID)
	return result.Value, result.Error
}

func (s *Store) RemoveFriend(ctx context.Context, userID, friendID string) error {
	return FriendStore_Remove(s.db, ctx, userID, friendID)
}

func (s *Store) UpsertProfileStats(ctx context.Context, userID, app string, metrics []ProfileMetric) (int, error) {
	result := FriendStore_UpsertStats(s.db, ctx, userID, app, metrics)
	return result.Applied, result.Error
}

func (s *Store) FriendStats(ctx context.Context, userID, app, practice, metric string) ([]FriendStatRow, error) {
	result := Leaderboard_Friends(s.db, ctx, userID, app, practice, metric)
	return result.Value, result.Error
}

func (s *Store) RecordClientLogin(ctx context.Context, userID, clientID string) error {
	return SyncClients_RecordLogin(s.db, ctx, userID, clientID)
}

func (s *Store) RecordClientSync(ctx context.Context, userID, clientID string, sinceVersion, serverVersion int64, protocolVersion int, clientClock int64) error {
	return SyncClients_RecordSync(s.db, ctx, userID, clientID, sinceVersion, serverVersion, protocolVersion, clientClock)
}

func (s *Store) StoreEncryptedPayload(ctx context.Context, userID, clientID string, payload []byte) (int64, error) {
	result := EncryptedPayloads_Store(s.db, ctx, userID, clientID, payload, ErrSyncUserNotFound)
	return result.Version, result.Error
}

func (s *Store) EncryptedPayloadsSince(ctx context.Context, userID string, sinceVersion int64, limit int) ([]EncryptedPayload, bool, error) {
	result := EncryptedPayloads_Since(s.db, ctx, userID, sinceVersion, limit)
	return result.Value, result.Truncated, result.Error
}

func (s *Store) RecentEncryptedPayloads(ctx context.Context, userID string, limit int) ([]EncryptedPayload, error) {
	result := EncryptedPayloads_Recent(s.db, ctx, userID, limit)
	return result.Value, result.Error
}

func (s *Store) EncryptedPayloadBytes(ctx context.Context, userID string) (int64, error) {
	result := EncryptedPayloads_Bytes(s.db, ctx, userID)
	return result.Value, result.Error
}

func (s *Store) PruneEncryptedPayloads(ctx context.Context, userID string, maxAge time.Duration, maxBytes int64) (EncryptedPayloadPruneResult, error) {
	result := EncryptedPayloads_Prune(s.db, ctx, userID, maxAge, maxBytes)
	return result.Value, result.Error
}

func (s *Store) RecordSyncAudit(ctx context.Context, entry SyncAuditEntry) error {
	return SyncAudit_Record(s.db, ctx, entry)
}

func (s *Store) RecentSyncAudit(ctx context.Context, userID string, limit int) ([]SyncAuditEntry, error) {
	result := SyncAudit_Recent(s.db, ctx, userID, limit)
	return result.Value, result.Error
}

func (s *Store) SyncOpsCompacted(ctx context.Context, userID string, clientClock int64) (bool, int64, error) {
	result := SyncClients_Compacted(s.db, ctx, userID, clientClock)
	return result.Compacted, result.Through, result.Error
}

func (s *Store) CompactSyncOps(ctx context.Context, userID string) error {
	return SyncClients_Compact(s.db, ctx, userID)
}

func (s *Store) DeleteAccount(ctx context.Context, userID string) error {
	return AccountState_Delete(s.db, ctx, userID)
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
	result := SyncViews_Changes(s.db, ctx, userID, sinceVersion)
	return result.Value, result.Version, result.Error
}

func (s *Store) OpsSince(ctx context.Context, userID string, sinceVersion int64) ([]SyncOp, error) {
	result := SyncViews_OperationsSince(s.db, ctx, userID, sinceVersion)
	return result.Value, result.Error
}

func (s *Store) CleanData(ctx context.Context, userID string) (*CleanData, error) {
	result := SyncViews_Clean(s.db, ctx, userID)
	return result.Value, result.Error
}

func (s *Store) SyncLogs(ctx context.Context, userID string, sinceVersion int64) ([]SyncLog, error) {
	result := SyncAudit_Logs(s.db, ctx, userID, sinceVersion)
	return result.Value, result.Error
}

func (s *Store) DeleteLogs(ctx context.Context, userID string, sinceVersion int64) ([]SyncLog, error) {
	result := SyncAudit_Deletes(s.db, ctx, userID, sinceVersion)
	return result.Value, result.Error
}

func (s *Store) LegacyClients(ctx context.Context, userID string, minProtocol int) ([]string, error) {
	result := SyncClients_Legacy(s.db, ctx, userID, minProtocol)
	return result.Value, result.Error
}

func (s *Store) LegacyWritePolicy(ctx context.Context, userID string) (bool, int64, error) {
	result := SyncClients_LegacyWritePolicy(s.db, ctx, userID)
	return result.Required, result.Epoch, result.Error
}

func (s *Store) CleanupOrphanHabitDays(ctx context.Context, userID string) error {
	return HabitMigration_Cleanup(s.db, ctx, userID)
}

func (s *Store) AutoMigrateAccountForProtocol(ctx context.Context, userID string, protocol int) error {
	return HabitMigration_ForProtocol(s.db, ctx, userID, protocol)
}

func (s *Store) AutoMigrateAllAccounts(ctx context.Context) error {
	return HabitMigration_AllAccounts(s.db, ctx)
}

func (s *Store) StateHash(ctx context.Context, userID string) (string, error) {
	result := StateHash_State(s.db, ctx, userID)
	return result.Value, result.Error
}

func upsertUser(ctx context.Context, tx *sql.Tx, userID string, publicKey []byte) error {
	return AccountState_Upsert(tx, ctx, userID, publicKey)
}

func replaceUserData(ctx context.Context, tx *sql.Tx, userID string) error {
	return SyncWrites_ReplaceData(tx, ctx, userID)
}

func upsertSession(ctx context.Context, tx *sql.Tx, userID string, session Session) (int, error) {
	result := SyncWrites_UpsertSession(tx, ctx, userID, session)
	return result.Applied, result.Error
}

func upsertSocialCache(ctx context.Context, tx *sql.Tx, userID string, item SocialSnapshot) (int, error) {
	result := SocialCache_Upsert(tx, ctx, userID, item)
	return result.Applied, result.Error
}

func (s *Store) SetSocialCacheJSON(ctx context.Context, userID, kind string, payload []byte) (int, error) {
	result := SocialCache_Set(s.db, ctx, userID, kind, payload)
	return result.Applied, result.Error
}

func upsertEncryptedRecord(ctx context.Context, tx *sql.Tx, userID string, item EncryptedRecord) (int, error) {
	result := SyncWrites_UpsertRecord(tx, ctx, userID, item)
	return result.Applied, result.Error
}

func deleteHabit(ctx context.Context, tx *sql.Tx, userID string, habit Habit) (int, error) {
	result := SyncWrites_DeleteHabit(tx, ctx, userID, habit)
	return result.Applied, result.Error
}

func deleteHabitDay(ctx context.Context, tx *sql.Tx, userID string, day HabitDay) (int, error) {
	result := SyncWrites_DeleteHabitDay(tx, ctx, userID, day)
	return result.Applied, result.Error
}

func deleteSession(ctx context.Context, tx *sql.Tx, userID string, session Session) (int, error) {
	result := SyncWrites_DeleteSession(tx, ctx, userID, session)
	return result.Applied, result.Error
}

func nextUserVersion(ctx context.Context, tx *sql.Tx, userID string) (int64, error) {
	advanced := AccountState_NextVersion(tx, ctx, userID)
	return advanced.Value, advanced.Error
}

func (s *Store) currentUserVersion(ctx context.Context, userID string) (int64, error) {
	result := AccountState_CurrentVersion(s.db, ctx, userID)
	return result.Value, result.Error
}

func (s *Store) Health(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return err
	}
	var ok string
	if err := s.db.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&ok); err != nil {
		return err
	}
	if ok != "ok" {
		return fmt.Errorf("sqlite quick_check: %s", ok)
	}
	var exists int
	if err := s.db.QueryRowContext(ctx, `
SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='server_users')`).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return fmt.Errorf("schema not migrated")
	}
	return nil
}

func (s *Store) NodeUsage(ctx context.Context, now time.Time) (NodeUsage, error) {
	cutoff := now.UTC().Add(-30 * 24 * time.Hour).Format("2006-01-02 15:04:05")
	usage := NodeUsage{RecentActivityWindowDays: 30}
	queries := []struct {
		target *int
		query  string
		args   []any
	}{
		{&usage.RegisteredUsers, `SELECT COUNT(*) FROM server_users`, nil},
		{&usage.ActiveUsers30d, `SELECT COUNT(*) FROM server_users WHERE last_seen_at>=?1`, []any{cutoff}},
		{&usage.RegisteredClients, `SELECT COUNT(*) FROM server_clients`, nil},
		{&usage.ActiveClients30d, `SELECT COUNT(*) FROM server_clients WHERE last_seen_at>=?1`, []any{cutoff}},
	}
	for _, item := range queries {
		if err := s.db.QueryRowContext(ctx, item.query, item.args...).Scan(item.target); err != nil {
			return NodeUsage{}, err
		}
	}
	return usage, nil
}

func (s *Store) NodeStorageUsage(ctx context.Context) (NodeStorageUsage, error) {
	usage := NodeStorageUsage{}

	if s.path != "" && s.path != ":memory:" {
		usage.DatabaseFileBytes = fileSizeOrZero(s.path)
		usage.DatabaseWALBytes = fileSizeOrZero(s.path + "-wal")
		usage.DatabaseSHMBytes = fileSizeOrZero(s.path + "-shm")
		usage.DatabaseTotalBytes = usage.DatabaseFileBytes + usage.DatabaseWALBytes + usage.DatabaseSHMBytes
	}
	if err := s.db.QueryRowContext(ctx, `SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()`).Scan(&usage.SQLitePageBytes); err != nil {
		return NodeStorageUsage{}, err
	}

	apps, err := s.appStorageUsage(ctx)
	if err != nil {
		return NodeStorageUsage{}, err
	}
	usage.Apps = apps
	for _, app := range apps {
		usage.EncryptedRecordBytes += app.RecordBytes
		usage.LogicalBytes += app.LogicalBytes
		if app.AppID == "unregistered" {
			usage.UnassignedBytes += app.LogicalBytes
		}
	}

	var payloadCount int
	if err := s.db.QueryRowContext(ctx, `
SELECT COUNT(*), COALESCE(SUM(LENGTH(client_id)+LENGTH(payload_json)),0)
FROM server_encrypted_payloads`).Scan(&payloadCount, &usage.EncryptedPayloadBytes); err != nil {
		return NodeStorageUsage{}, err
	}
	usage.UnassignedEncryptedPayloads = StorageBucketUsage{
		LogicalBytes: usage.EncryptedPayloadBytes,
		Count:        payloadCount,
	}
	usage.UnassignedBytes += usage.EncryptedPayloadBytes
	usage.LogicalBytes += usage.EncryptedPayloadBytes

	return usage, nil
}

type collectionStorageRow struct {
	Collection string
	Count      int
	Bytes      int64
}

func (s *Store) appStorageUsage(ctx context.Context) ([]AppStorageUsage, error) {
	loadedMatchers := CollectionScope_Load(s.db, ctx)
	matchers, err := loadedMatchers.Value, loadedMatchers.Error
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT collection,
       COUNT(*),
       COALESCE(SUM(LENGTH(collection)+LENGTH(id)+LENGTH(key_id)+LENGTH(nonce)+LENGTH(ciphertext)+LENGTH(content_hash)+LENGTH(parent_id)),0)
FROM server_encrypted_records
GROUP BY collection
ORDER BY collection`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	appsByID := map[string]*AppStorageUsage{}
	for _, matcher := range matchers {
		if _, ok := appsByID[matcher.AppID]; !ok {
			appsByID[matcher.AppID] = &AppStorageUsage{
				AppID:       matcher.AppID,
				DisplayName: matcher.DisplayName,
				Collections: []CollectionStorageUsage{},
			}
		}
	}
	for rows.Next() {
		var row collectionStorageRow
		if err := rows.Scan(&row.Collection, &row.Count, &row.Bytes); err != nil {
			return nil, err
		}
		matcher := CollectionScope_Best(row.Collection, matchers)
		appID := "unregistered"
		displayName := "Unregistered collections"
		collectionPrefix := ""
		if matcher != nil {
			appID = matcher.AppID
			displayName = matcher.DisplayName
			collectionPrefix = matcher.Prefix
		}
		app, ok := appsByID[appID]
		if !ok {
			app = &AppStorageUsage{
				AppID:       appID,
				DisplayName: displayName,
				Collections: []CollectionStorageUsage{},
			}
			appsByID[appID] = app
		}
		app.LogicalBytes += row.Bytes
		app.RecordBytes += row.Bytes
		app.RecordCount += row.Count
		app.Collections = append(app.Collections, CollectionStorageUsage{
			CollectionPrefix: collectionPrefix,
			Collection:       row.Collection,
			LogicalBytes:     row.Bytes,
			RecordBytes:      row.Bytes,
			RecordCount:      row.Count,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	apps := make([]AppStorageUsage, 0, len(appsByID))
	for _, app := range appsByID {
		sort.Slice(app.Collections, func(i, j int) bool {
			return app.Collections[i].Collection < app.Collections[j].Collection
		})
		apps = append(apps, *app)
	}
	sort.Slice(apps, func(i, j int) bool {
		if apps[i].LogicalBytes != apps[j].LogicalBytes {
			return apps[i].LogicalBytes > apps[j].LogicalBytes
		}
		return apps[i].AppID < apps[j].AppID
	})
	return apps, nil
}

func fileSizeOrZero(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

func (s *Store) SyncDiagnosticReport(ctx context.Context, userID string) (SyncDiagnosticReport, error) {
	version, err := s.currentUserVersion(ctx, userID)
	if err != nil {
		return SyncDiagnosticReport{}, err
	}
	hash, err := s.StateHash(ctx, userID)
	if err != nil {
		return SyncDiagnosticReport{}, err
	}
	_, compactedThrough, err := s.SyncOpsCompacted(ctx, userID, version)
	if err != nil {
		return SyncDiagnosticReport{}, err
	}
	counts, err := s.accountTableCounts(ctx, userID)
	if err != nil {
		return SyncDiagnosticReport{}, err
	}
	legacyClients, err := s.LegacyClients(ctx, userID, 3)
	if err != nil {
		return SyncDiagnosticReport{}, err
	}
	recentAudit, err := s.RecentSyncAudit(ctx, userID, 10)
	if err != nil {
		return SyncDiagnosticReport{}, err
	}
	recentPayloads, err := s.RecentEncryptedPayloads(ctx, userID, 5)
	if err != nil {
		return SyncDiagnosticReport{}, err
	}
	payloadBytes, err := s.EncryptedPayloadBytes(ctx, userID)
	if err != nil {
		return SyncDiagnosticReport{}, err
	}
	return SyncDiagnosticReport{
		Status:                   "ok",
		UserIDHash:               userID,
		ServerVersion:            version,
		StateHash:                hash,
		CompactedThroughVersion:  compactedThrough,
		TableCounts:              counts,
		EncryptedPayloadBytes:    payloadBytes,
		LegacyClients:            legacyClients,
		ActiveWebSocketSupported: true,
		RecentSyncAudit:          recentAudit,
		RecentEncryptedPayloads:  recentPayloads,
	}, nil
}

func (s *Store) accountTableCounts(ctx context.Context, userID string) (map[string]int, error) {
	tables := []string{
		"server_habits",
		"server_habit_days",
		"server_sessions",
		"server_session_rounds",
		"server_meditation_logs",
		"server_social_snapshots",
		"server_encrypted_records",
		"server_sync_ops",
		"server_clients",
		"server_encrypted_payloads",
		"server_sync_audit",
	}
	counts := make(map[string]int, len(tables))
	for _, table := range tables {
		var n int
		if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table+" WHERE user_id_hash=?1", userID).Scan(&n); err != nil {
			return nil, err
		}
		counts[table] = n
	}
	return counts, nil
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
