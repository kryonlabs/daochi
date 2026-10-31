package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func meshHistoryFixture(t *testing.T) (*Store, context.Context, string) {
	t.Helper()
	opened := Store_Open(filepath.Join(t.TempDir(), "mesh-history-test.db"))
	if opened.Error != nil {
		t.Fatal(opened.Error)
	}
	store := opened.Value
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	if _, err := store.Database.ExecContext(ctx, MeshHistory_SchemaSQL()); err != nil {
		t.Fatal(err)
	}
	user := strings.Repeat("d", 64)
	if _, err := store.Database.ExecContext(ctx,
		`INSERT INTO server_users(user_id_hash,public_key) VALUES(?1,?2)`,
		user, []byte("mesh-history-user")); err != nil {
		t.Fatal(err)
	}
	return store, ctx, user
}

func meshHistoryWrite(t *testing.T, store *Store, ctx context.Context, user, id string, version int) {
	t.Helper()
	if _, err := store.Database.ExecContext(ctx, `
INSERT INTO server_encrypted_records
(user_id_hash,collection,id,key_id,nonce,ciphertext,updated_at)
VALUES(?1,'private.mesh.history',?2,'key',?3,?4,?5)
ON CONFLICT(user_id_hash,collection,id) DO UPDATE SET
key_id=excluded.key_id,
nonce=excluded.nonce,
ciphertext=excluded.ciphertext,
updated_at=excluded.updated_at`,
		user, id, fmt.Sprintf("nonce-%d", version), fmt.Sprintf("ciphertext-%d", version),
		fmt.Sprintf("2026-10-%02dT00:00:00Z", version%28+1)); err != nil {
		t.Fatal(err)
	}
}

func meshHistoryDelete(t *testing.T, store *Store, ctx context.Context, user, id string) {
	t.Helper()
	if _, err := store.Database.ExecContext(ctx,
		`DELETE FROM server_encrypted_records
WHERE user_id_hash=?1 AND collection='private.mesh.history' AND id=?2`,
		user, id); err != nil {
		t.Fatal(err)
	}
}

func meshHistoryCount(t *testing.T, store *Store, ctx context.Context, query string, arguments ...any) int {
	t.Helper()
	var count int
	if err := store.Database.QueryRowContext(ctx, query, arguments...).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func meshHistoryCursor(t *testing.T, sequence int64) string {
	t.Helper()
	encoded := MeshCursor_Encode(MeshCursor{Seq: sequence})
	if encoded.Error != nil {
		t.Fatal(encoded.Error)
	}
	return encoded.Value
}

func meshHistoryAcknowledge(t *testing.T, store *Store, ctx context.Context, peer, cursor string, epoch int64) {
	t.Helper()
	if err := MeshHistory_AcknowledgeCursor(store.Database, ctx, peer, cursor, epoch); err != nil {
		t.Fatal(err)
	}
}

func TestMeshHistoryBoundedRewrite(t *testing.T) {
	store, ctx, user := meshHistoryFixture(t)
	retention := MeshHistoryRetention{MaxChanges: 4, MaxTombstones: 8, MaxPeerCursors: 4, CursorExpirySeconds: 86400}
	for version := 1; version <= 64; version++ {
		meshHistoryWrite(t, store, ctx, user, "same-record", version)
	}
	if count := meshHistoryCount(t, store, ctx, `SELECT COUNT(*) FROM server_mesh_changes`); count != 1 {
		t.Fatalf("trigger coalescing retained %d rewrite rows; want 1", count)
	}
	acknowledged := meshHistoryCursor(t, 1)
	for index := 0; index < 8; index++ {
		meshHistoryAcknowledge(t, store, ctx, fmt.Sprintf("peer-%d", index), acknowledged, 1)
	}
	compacted := MeshHistory_CompactMeshHistory(store.Database, ctx, retention)
	if compacted.Error != nil || compacted.Compacted {
		t.Fatal("first compaction failed", compacted)
	}
	if count := meshHistoryCount(t, store, ctx, `SELECT COUNT(*) FROM server_mesh_changes`); count != 1 {
		t.Fatalf("first compaction retained %d changes; want 1", count)
	}
	state := MeshHistory_LoadState(store.Database, ctx)
	if state.Error != nil || state.CompactedThrough != 0 || !state.TombstonesComplete {
		t.Fatal("invalid first compaction state", state)
	}
	if !compacted.PeerCursorsCompacted || meshHistoryCount(t, store, ctx,
		`SELECT COUNT(*) FROM server_mesh_peer_cursors`) != 4 {
		t.Fatal("peer cursor retention was not bounded")
	}

	for version := 1; version <= 8; version++ {
		meshHistoryWrite(t, store, ctx, user, fmt.Sprintf("unique-%d", version), version)
	}
	var latest int64
	if err := store.Database.QueryRow("SELECT MAX(seq) FROM server_mesh_changes").Scan(&latest); err != nil {
		t.Fatal(err)
	}
	compacted = MeshHistory_CompactMeshHistory(store.Database, ctx, retention)
	if compacted.Error != nil || !compacted.Compacted || compacted.CompactedThrough != latest-4 {
		t.Fatal("second compaction failed", compacted)
	}
	if count := meshHistoryCount(t, store, ctx, `SELECT COUNT(*) FROM server_mesh_changes`); count != 4 {
		t.Fatalf("repeated rewrite retained %d changes; want 4", count)
	}
	epoch := compacted.SnapshotEpoch
	compacted = MeshHistory_CompactMeshHistory(store.Database, ctx, retention)
	if compacted.Error != nil || compacted.Compacted || compacted.SnapshotEpoch != epoch {
		t.Fatal("idle compaction changed state", compacted)
	}
}

func TestMeshCursorExpiredSnapshotRecovery(t *testing.T) {
	store, ctx, user := meshHistoryFixture(t)
	for version := 1; version <= 8; version++ {
		meshHistoryWrite(t, store, ctx, user, "record", version)
	}
	acknowledged := meshHistoryCursor(t, 5)
	for version := 1; version <= 12; version++ {
		meshHistoryWrite(t, store, ctx, user, fmt.Sprintf("record-%d", version), version)
	}
	meshHistoryAcknowledge(t, store, ctx, "peer", acknowledged, 1)
	var latest int64
	if err := store.Database.QueryRow("SELECT MAX(seq) FROM server_mesh_changes").Scan(&latest); err != nil {
		t.Fatal(err)
	}
	compacted := MeshHistory_CompactMeshHistory(store.Database, ctx,
		MeshHistoryRetention{MaxChanges: 2, MaxTombstones: 8, CursorExpirySeconds: 86400})
	if compacted.Error != nil || compacted.CompactedThrough != latest-2 {
		t.Fatal("compaction failed", compacted)
	}
	recovered := MeshHistory_PrepareExport(store.Database, ctx, "peer", acknowledged, LatestProtocol)
	if recovered.Error != nil || !recovered.CursorExpired || !recovered.FullSnapshot || !recovered.ResetSnapshot {
		t.Fatal("protocol 6 did not request safe recovery", recovered)
	}
	legacy := MeshHistory_PrepareExport(store.Database, ctx, "peer", acknowledged, LatestProtocol-1)
	if !errors.Is(legacy.Error, ErrMeshHistoryCursorExpired) || legacy.FullSnapshot {
		t.Fatal("legacy peer received unsafe recovery", legacy)
	}
	if err := MeshHistory_AcknowledgeCursor(store.Database, ctx, "peer", acknowledged, 1); !errors.Is(err, ErrMeshHistoryCursorExpired) {
		t.Fatal("expired cursor was acknowledged", err)
	}
}

func TestMeshPartitionDeletionRecovery(t *testing.T) {
	store, ctx, user := meshHistoryFixture(t)
	meshHistoryWrite(t, store, ctx, user, "offline-one", 1)
	meshHistoryDelete(t, store, ctx, user, "offline-one")
	meshHistoryWrite(t, store, ctx, user, "offline-two", 2)
	meshHistoryDelete(t, store, ctx, user, "offline-two")

	compacted := MeshHistory_CompactMeshHistory(store.Database, ctx,
		MeshHistoryRetention{MaxChanges: 1, MaxTombstones: 8, CursorExpirySeconds: 86400})
	if compacted.Error != nil || compacted.CompactedThrough != 3 || !compacted.TombstonesComplete {
		t.Fatal("deletion compaction failed", compacted)
	}
	if count := meshHistoryCount(t, store, ctx,
		`SELECT COUNT(*) FROM server_mesh_history_tombstones WHERE record_id='offline-one'`); count != 1 {
		t.Fatal("first partition deletion was not retained", count)
	}
	partitioned := meshHistoryCursor(t, 1)
	recovered := MeshHistory_PrepareExport(store.Database, ctx, "partitioned-peer", partitioned, LatestProtocol)
	if recovered.Error != nil || !recovered.CursorExpired || !recovered.ResetSnapshot {
		t.Fatal("partitioned peer did not receive reset recovery", recovered)
	}

	for index := 3; index <= 8; index++ {
		id := fmt.Sprintf("offline-%d", index)
		meshHistoryWrite(t, store, ctx, user, id, index)
		meshHistoryDelete(t, store, ctx, user, id)
	}
	compacted = MeshHistory_CompactMeshHistory(store.Database, ctx,
		MeshHistoryRetention{MaxChanges: 1, MaxTombstones: 2, CursorExpirySeconds: 86400})
	if compacted.Error != nil || !compacted.TombstonesComplete || !compacted.TombstoneLimitExceeded {
		t.Fatal("tombstone limit did not preserve exact provenance", compacted)
	}
	if count := meshHistoryCount(t, store, ctx, `SELECT COUNT(*) FROM server_mesh_history_tombstones`); count != 8 {
		t.Fatalf("tombstone table retained %d rows; want all 8 exact keys", count)
	}
	transaction, err := store.Database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	oldUpdate := "2000-01-01T00:00:00.000000000Z"
	newUpdate := "2999-01-01T00:00:00.000000000Z"
	sameKeyOld := MeshHistory_ResurrectionBlocked(transaction, ctx, user,
		"private.mesh.history", "offline-one", oldUpdate)
	if sameKeyOld.Error != nil || !sameKeyOld.Blocked {
		t.Fatal("old write for a deleted key was not blocked", sameKeyOld)
	}
	sameKeyNew := MeshHistory_ResurrectionBlocked(transaction, ctx, user,
		"private.mesh.history", "offline-one", newUpdate)
	if sameKeyNew.Error != nil || sameKeyNew.Blocked {
		t.Fatal("newer recreation for a deleted key was blocked", sameKeyNew)
	}
	unrelatedOld := MeshHistory_ResurrectionBlocked(transaction, ctx, user,
		"private.mesh.history", "never-deleted", oldUpdate)
	if unrelatedOld.Error != nil || unrelatedOld.Blocked {
		t.Fatal("unrelated valid older record was blocked", unrelatedOld)
	}
	differentAccount := MeshHistory_ResurrectionBlocked(transaction, ctx, strings.Repeat("e", 64),
		"private.mesh.history", "offline-one", oldUpdate)
	if differentAccount.Error != nil || differentAccount.Blocked {
		t.Fatal("another account was blocked by this account's deletion", differentAccount)
	}
	if err := transaction.Rollback(); err != nil {
		t.Fatal(err)
	}
	recovered = MeshHistory_PrepareExport(store.Database, ctx, "partitioned-peer", partitioned, LatestProtocol)
	if recovered.Error != nil || !recovered.CursorExpired || !recovered.ResetSnapshot {
		t.Fatal("bounded tombstone recovery lost reset semantics", recovered)
	}
}

func TestMeshCompactionConcurrentExport(t *testing.T) {
	store, ctx, user := meshHistoryFixture(t)
	for version := 1; version <= 100; version++ {
		meshHistoryWrite(t, store, ctx, user, fmt.Sprintf("concurrent-%d", version), version)
	}
	current := meshHistoryCursor(t, 50)
	const readers = 16
	var group sync.WaitGroup
	failures := make(chan MeshHistoryExportPlan, readers)
	for index := 0; index < readers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			transaction, err := store.Database.BeginTx(ctx, nil)
			if err != nil {
				failures <- MeshHistoryExportPlan{Error: err}
				return
			}
			plan := MeshHistory_PrepareExportTx(transaction, ctx, "concurrent-peer", current, LatestProtocol)
			rollbackError := transaction.Rollback()
			if rollbackError != nil {
				failures <- MeshHistoryExportPlan{Error: rollbackError}
				return
			}
			if plan.Error != nil {
				failures <- plan
				return
			}
			if plan.CursorExpired && (!plan.FullSnapshot || !plan.ResetSnapshot) {
				failures <- plan
				return
			}
			if !plan.CursorExpired && plan.StartSequence != 50 {
				failures <- plan
			}
		}()
	}
	compaction := make(chan MeshHistoryCompactionResult, 1)
	go func() {
		compaction <- MeshHistory_CompactMeshHistory(store.Database, ctx,
			MeshHistoryRetention{MaxChanges: 5, MaxTombstones: 8, CursorExpirySeconds: 86400})
	}()
	group.Wait()
	close(failures)
	for failure := range failures {
		t.Fatal("unsafe concurrent export plan", failure)
	}
	if result := <-compaction; result.Error != nil {
		t.Fatal("concurrent compaction failed", result)
	}
	if count := meshHistoryCount(t, store, ctx, `SELECT COUNT(*) FROM server_mesh_changes`); count > 5 {
		t.Fatalf("concurrent compaction retained %d changes; want at most 5", count)
	}
}

func TestMeshMixedVersionRetention(t *testing.T) {
	store, ctx, user := meshHistoryFixture(t)
	for version := 1; version <= 6; version++ {
		meshHistoryWrite(t, store, ctx, user, fmt.Sprintf("mixed-%d", version), version)
	}
	legacyEmpty := MeshHistory_PrepareExport(store.Database, ctx, "legacy-peer", "", LatestProtocol-1)
	if legacyEmpty.Error != nil || legacyEmpty.FullSnapshot || legacyEmpty.ResetSnapshot {
		t.Fatal("uncompacted legacy bootstrap changed behavior", legacyEmpty)
	}
	if result := MeshHistory_CompactMeshHistory(store.Database, ctx,
		MeshHistoryRetention{MaxChanges: 2, MaxTombstones: 4, CursorExpirySeconds: 86400}); result.Error != nil {
		t.Fatal(result.Error)
	}
	for protocol := MinSupportedProtocol; protocol < LatestProtocol; protocol++ {
		plan := MeshHistory_PrepareExport(store.Database, ctx, "legacy-peer", "", protocol)
		if !errors.Is(plan.Error, ErrMeshHistoryCursorExpired) {
			t.Fatalf("protocol %d did not receive recoverable expiry error: %+v", protocol, plan)
		}
	}
	recovered := MeshHistory_PrepareExport(store.Database, ctx, "current-peer", "", LatestProtocol)
	if recovered.Error != nil || !recovered.FullSnapshot || !recovered.ResetSnapshot {
		t.Fatal("current protocol did not receive bounded snapshot recovery", recovered)
	}
}
