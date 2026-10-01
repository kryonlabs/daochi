package main

import (
	"context"
	"database/sql"
	"errors"
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
	result := StoreStats_Public(s.db, ctx, dbPath)
	return result.Value, result.Error
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

func (s *Store) SetSocialCacheJSON(ctx context.Context, userID, kind string, payload []byte) (int, error) {
	result := SocialCache_Set(s.db, ctx, userID, kind, payload)
	return result.Applied, result.Error
}

func (s *Store) currentUserVersion(ctx context.Context, userID string) (int64, error) {
	result := AccountState_CurrentVersion(s.db, ctx, userID)
	return result.Value, result.Error
}

func (s *Store) Health(ctx context.Context) error {
	return StoreDiagnostics_Health(s.db, ctx)
}

func (s *Store) NodeUsage(ctx context.Context, now time.Time) (NodeUsage, error) {
	result := StoreStats_Usage(s.db, ctx, now)
	return result.Value, result.Error
}

func (s *Store) NodeStorageUsage(ctx context.Context) (NodeStorageUsage, error) {
	result := StoreStats_Storage(s.db, ctx, s.path)
	return result.Value, result.Error
}

func (s *Store) SyncDiagnosticReport(ctx context.Context, userID string) (SyncDiagnosticReport, error) {
	result := StoreDiagnostics_Report(s.db, ctx, userID)
	return result.Value, result.Error
}
