package main

// Original operational storage implementation at ab1fd4c.
import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"
)

type baselineStatsCollectionRow struct {
	Collection string
	Count      int
	Bytes      int64
}

func (s *Store) baselineStatsPublicStats(ctx context.Context, dbPath string) (PublicStats, error) {
	var stats PublicStats
	if err := s.Database.QueryRowContext(ctx, `SELECT COUNT(*) FROM server_users`).Scan(&stats.UserCount); err != nil {
		return PublicStats{}, err
	}
	used, err := baselineStatsSqliteFileSetSize(dbPath)
	if err != nil {
		return PublicStats{}, err
	}
	stats.StorageUsedBytes = used
	stats.StorageUsedGB = baselineStatsBytesToFloorGB(used)
	stats.StorageUsedText = baselineStatsStorageUsedText(stats.StorageUsedGB)
	available, err := baselineStatsDiskAvailableBytes(dbPath)
	if err != nil {
		return PublicStats{}, err
	}
	stats.AvailableBytes = available - (1 << 30)
	if stats.AvailableBytes < 0 {
		stats.AvailableBytes = 0
	}
	stats.AvailableGB = baselineStatsBytesToFloorGB(stats.AvailableBytes)
	return stats, nil
}

func (s *Store) baselineStatsHealth(ctx context.Context) error {
	if err := s.Database.PingContext(ctx); err != nil {
		return err
	}
	var ok string
	if err := s.Database.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&ok); err != nil {
		return err
	}
	if ok != "ok" {
		return fmt.Errorf("sqlite quick_check: %s", ok)
	}
	var exists int
	if err := s.Database.QueryRowContext(ctx, `
SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='server_users')`).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return fmt.Errorf("schema not migrated")
	}
	return nil
}

func (s *Store) baselineStatsNodeUsage(ctx context.Context, now time.Time) (NodeUsage, error) {
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
		if err := s.Database.QueryRowContext(ctx, item.query, item.args...).Scan(item.target); err != nil {
			return NodeUsage{}, err
		}
	}
	return usage, nil
}

func (s *Store) baselineStatsNodeStorageUsage(ctx context.Context) (NodeStorageUsage, error) {
	usage := NodeStorageUsage{}

	if s.Path != "" && s.Path != ":memory:" {
		usage.DatabaseFileBytes = baselineStatsFileSizeOrZero(s.Path)
		usage.DatabaseWALBytes = baselineStatsFileSizeOrZero(s.Path + "-wal")
		usage.DatabaseSHMBytes = baselineStatsFileSizeOrZero(s.Path + "-shm")
		usage.DatabaseTotalBytes = usage.DatabaseFileBytes + usage.DatabaseWALBytes + usage.DatabaseSHMBytes
	}
	if err := s.Database.QueryRowContext(ctx, `SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()`).Scan(&usage.SQLitePageBytes); err != nil {
		return NodeStorageUsage{}, err
	}

	apps, err := s.baselineStatsAppStorageUsage(ctx)
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
	if err := s.Database.QueryRowContext(ctx, `
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

func (s *Store) baselineStatsAppStorageUsage(ctx context.Context) ([]AppStorageUsage, error) {
	loadedMatchers := CollectionScope_Load(s.Database, ctx)
	matchers, err := loadedMatchers.Value, loadedMatchers.Error
	if err != nil {
		return nil, err
	}
	rows, err := s.Database.QueryContext(ctx, `
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
		var row baselineStatsCollectionRow
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

func baselineStatsFileSizeOrZero(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

func (s *Store) baselineStatsSyncDiagnosticReport(ctx context.Context, userID string) (SyncDiagnosticReport, error) {
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
	counts, err := s.baselineStatsAccountTableCounts(ctx, userID)
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

func (s *Store) baselineStatsAccountTableCounts(ctx context.Context, userID string) (map[string]int, error) {
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
		if err := s.Database.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table+" WHERE user_id_hash=?1", userID).Scan(&n); err != nil {
			return nil, err
		}
		counts[table] = n
	}
	return counts, nil
}

func baselineStatsSqliteFileSetSize(dbPath string) (int64, error) {
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

func baselineStatsDiskAvailableBytes(path string) (int64, error) {
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

func baselineStatsBytesToFloorGB(bytes int64) int64 {
	if bytes <= 0 {
		return 0
	}
	return bytes / (1 << 30)
}

func baselineStatsStorageUsedText(gb int64) string {
	if gb <= 0 {
		return "under 1 GB"
	}
	return fmt.Sprintf("%d GB", gb)
}
