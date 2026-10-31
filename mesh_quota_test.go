package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func meshQuotaRecord(id string, ciphertextSize int) MeshEncryptedRecord {
	item := scopedRecord("quota-identity", 10)
	item.Record.ID = id
	item.Record.Ciphertext = strings.Repeat("x", ciphertextSize)
	item.Record.UpdatedAt = "2026-10-30T12:00:00Z"
	return item
}

func meshQuotaBytes(item MeshEncryptedRecord) int64 {
	record := item.Record
	return int64(len(record.Collection) + len(record.ID) + len(record.KeyID) +
		len(record.Nonce) + len(record.Ciphertext) + len(record.ContentHash) + len(record.ParentID))
}

func meshQuotaImport(t *testing.T, store *Store, ctx context.Context, limit int64,
	plansEnabled bool, records []MeshEncryptedRecord, deletions []MeshEncryptedRecordDeletion) MeshImportResult {
	t.Helper()
	return MeshStore_ImportEncryptedBatch(store.Database, ctx, meshQuotaPolicy(),
		records, deletions, limit, plansEnabled)
}

func meshQuotaPolicy() NodeSyncPolicy {
	return NodeSyncPolicy{
		Collections: []string{"shared.source.v1.*"},
		Data:        []string{"encrypted_records"},
	}
}

func meshQuotaCount(t *testing.T, store *Store, query string, arguments ...any) int {
	t.Helper()
	var count int
	if err := store.Database.QueryRow(query, arguments...).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestMeshImportQuota(t *testing.T) {
	_, store, _ := testServer(t)
	ctx := context.Background()
	first := meshQuotaRecord("first", 100)
	second := meshQuotaRecord("second", 101)
	limit := meshQuotaBytes(first)

	accepted := meshQuotaImport(t, store, ctx, limit, false, []MeshEncryptedRecord{first}, nil)
	if accepted.Error != nil || accepted.Value != 1 {
		t.Fatal("import within the account allowance failed", accepted)
	}

	rejected := meshQuotaImport(t, store, ctx, limit, false, []MeshEncryptedRecord{second}, nil)
	if !errors.Is(rejected.Error, ErrStorageFull) {
		t.Fatalf("growth past the allowance = %+v", rejected)
	}
	if rejected.Storage.UsedBytes != limit || rejected.Storage.LimitBytes != limit {
		t.Fatalf("storage report did not describe usage before rejection: %+v", rejected.Storage)
	}
	if used := AccountStorage_Used(store.Database, ctx, first.UserIDHash); used.Error != nil || used.Value != limit {
		t.Fatal("rejected import changed stored usage", used)
	}
	if count := meshQuotaCount(t, store,
		"SELECT COUNT(*) FROM server_encrypted_records WHERE user_id_hash=?1 AND id=?2",
		first.UserIDHash, second.Record.ID); count != 0 {
		t.Fatal("over-quota record persisted")
	}
}

func TestMeshImportQuotaAtomicRollback(t *testing.T) {
	_, store, _ := testServer(t)
	ctx := context.Background()
	within := meshQuotaRecord("within", 100)
	over := meshQuotaRecord("over", 180)
	limit := meshQuotaBytes(within) + 10

	rejected := meshQuotaImport(t, store, ctx, limit, false,
		[]MeshEncryptedRecord{within, over}, nil)
	if !errors.Is(rejected.Error, ErrStorageFull) {
		t.Fatalf("partial over-quota batch = %+v", rejected)
	}
	if count := meshQuotaCount(t, store,
		"SELECT COUNT(*) FROM server_encrypted_records WHERE user_id_hash=?1", within.UserIDHash); count != 0 {
		t.Fatal("quota rollback retained an earlier record")
	}
	if count := meshQuotaCount(t, store,
		"SELECT COUNT(*) FROM server_users WHERE user_id_hash=?1", within.UserIDHash); count != 0 {
		t.Fatal("quota rollback retained an account")
	}
	if used := AccountStorage_Used(store.Database, ctx, within.UserIDHash); used.Error != nil || used.Value != 0 {
		t.Fatal("quota rollback changed storage usage", used)
	}
}

func TestMeshImportMultiAccountQuota(t *testing.T) {
	_, store, _ := testServer(t)
	ctx := context.Background()
	first := meshQuotaRecord("first", 100)
	second := scopedRecord("second", 20)
	second.Record.Ciphertext = strings.Repeat("x", 180)
	limit := meshQuotaBytes(first) + 10

	rejected := meshQuotaImport(t, store, ctx, limit, false,
		[]MeshEncryptedRecord{first, second}, nil)
	if !errors.Is(rejected.Error, ErrStorageFull) {
		t.Fatalf("multi-account over-quota batch = %+v", rejected)
	}
	for _, item := range []MeshEncryptedRecord{first, second} {
		if count := meshQuotaCount(t, store,
			"SELECT COUNT(*) FROM server_encrypted_records WHERE user_id_hash=?1", item.UserIDHash); count != 0 {
			t.Fatal("multi-account quota rollback retained a record")
		}
		if count := meshQuotaCount(t, store,
			"SELECT COUNT(*) FROM server_users WHERE user_id_hash=?1", item.UserIDHash); count != 0 {
			t.Fatal("multi-account quota rollback retained an account")
		}
	}
}

func TestMeshImportQuotaShrinkDelete(t *testing.T) {
	_, store, _ := testServer(t)
	ctx := context.Background()
	large := meshQuotaRecord("same-record", 180)
	smaller := large
	smaller.Record.Ciphertext = strings.Repeat("x", 80)

	if accepted := meshQuotaImport(t, store, ctx, 0, false, []MeshEncryptedRecord{large}, nil); accepted.Error != nil {
		t.Fatal("fixture import failed", accepted)
	}
	limit := meshQuotaBytes(smaller)

	deletion := MeshEncryptedRecordDeletion{
		UserIDHash: large.UserIDHash, Collection: large.Record.Collection,
		ID: large.Record.ID, DeletedAt: "2026-10-30T13:00:00Z",
	}
	deleted := meshQuotaImport(t, store, ctx, limit, false, nil, []MeshEncryptedRecordDeletion{deletion})
	if deleted.Error != nil || deleted.Value != 1 {
		t.Fatal("over-quota deletion was blocked", deleted)
	}

	shrunk := meshQuotaImport(t, store, ctx, limit, false, []MeshEncryptedRecord{smaller}, nil)
	if shrunk.Error != nil || shrunk.Value != 1 {
		t.Fatal("shrinking replacement was blocked", shrunk)
	}
	if used := AccountStorage_Used(store.Database, ctx, large.UserIDHash); used.Error != nil || used.Value != limit {
		t.Fatal("shrinking replacement stored the wrong usage", used)
	}
}

func TestMeshImportQuotaReplacement(t *testing.T) {
	_, store, _ := testServer(t)
	ctx := context.Background()
	initial := meshQuotaRecord("same-record", 100)
	growth := initial
	growth.Record.Ciphertext = strings.Repeat("x", 130)
	growth.Record.UpdatedAt = "2026-10-30T12:00:01Z"
	overLimit := growth
	overLimit.Record.ContentHash = strings.Repeat("a", 64)
	overLimit.Record.UpdatedAt = "2026-10-30T12:00:04Z"
	overLimit.Record.FreeBytes = 524288
	limit := meshQuotaBytes(growth)

	if accepted := meshQuotaImport(t, store, ctx, 0, false, []MeshEncryptedRecord{initial}, nil); accepted.Error != nil {
		t.Fatal("fixture import failed", accepted)
	}
	accepted := meshQuotaImport(t, store, ctx, limit, false, []MeshEncryptedRecord{growth}, nil)
	if accepted.Error != nil || accepted.Value != 1 {
		t.Fatal("replacement growth within its effective delta was blocked", accepted)
	}

	noGrowth := growth
	noGrowth.Record.Nonce = "noise"
	noGrowth.Record.UpdatedAt = "2026-10-30T12:00:03Z"
	unchanged := meshQuotaImport(t, store, ctx, limit, false, []MeshEncryptedRecord{noGrowth}, nil)
	if unchanged.Error != nil || unchanged.Value != 1 {
		t.Fatal("no-growth replacement was blocked above the prior delta", unchanged)
	}

	rejected := meshQuotaImport(t, store, ctx, limit, false, []MeshEncryptedRecord{overLimit}, nil)
	if !errors.Is(rejected.Error, ErrStorageFull) {
		t.Fatalf("replacement growth past the allowance = %+v", rejected)
	}
	var ciphertext string
	if err := store.Database.QueryRowContext(ctx,
		"SELECT ciphertext FROM server_encrypted_records WHERE user_id_hash=?1 AND id=?2",
		initial.UserIDHash, initial.Record.ID).Scan(&ciphertext); err != nil || ciphertext != growth.Record.Ciphertext {
		t.Fatal("rejected replacement changed the committed record", ciphertext, err)
	}
	if rejected.Storage.UsedBytes != meshQuotaBytes(growth) {
		t.Fatalf("replacement report omitted prior usage: %+v", rejected.Storage)
	}
}

func TestMeshImportPaidAndExpiredPlans(t *testing.T) {
	_, store, _ := testServer(t)
	ctx := context.Background()
	account := meshQuotaRecord("plan-account", 180)
	if created := meshQuotaImport(t, store, ctx, 0, false, []MeshEncryptedRecord{account}, nil); created.Error != nil {
		t.Fatal("fixture import failed", created)
	}
	first := meshQuotaRecord("active-plan", 180)
	afterExpiry := meshQuotaRecord("expired-plan", 181)
	if _, err := store.Database.ExecContext(ctx,
		"INSERT INTO server_storage_plans(user_id,period,expires_at,size) VALUES(?1,'monthly',?2,'1gb')",
		account.UserIDHash, time.Now().Add(24*time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}

	active := meshQuotaImport(t, store, ctx, 20, true, []MeshEncryptedRecord{first}, nil)
	if active.Error != nil || active.Value != 1 {
		t.Fatal("active paid plan did not raise the import allowance", active)
	}
	if _, err := store.Database.ExecContext(ctx,
		"UPDATE server_storage_plans SET expires_at=0 WHERE user_id=?1", account.UserIDHash); err != nil {
		t.Fatal(err)
	}

	expired := meshQuotaImport(t, store, ctx, 20, true, []MeshEncryptedRecord{afterExpiry}, nil)
	if !errors.Is(expired.Error, ErrStorageFull) {
		t.Fatalf("expired paid plan retained the import allowance: %+v", expired)
	}
	if count := meshQuotaCount(t, store,
		"SELECT COUNT(*) FROM server_encrypted_records WHERE user_id_hash=?1 AND id=?2",
		account.UserIDHash, afterExpiry.Record.ID); count != 0 {
		t.Fatal("expired plan allowed another record")
	}
}

func TestMeshImportQuotaConcurrency(t *testing.T) {
	_, store, _ := testServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	store.Database.SetMaxOpenConns(1)
	first := meshQuotaRecord("concurrent-first", 180)
	second := meshQuotaRecord("concurrent-second", 180)
	limit := meshQuotaBytes(first) + 10

	const importers = 2
	results := make(chan MeshImportResult, importers)
	var group sync.WaitGroup
	for _, item := range []MeshEncryptedRecord{first, second} {
		group.Add(1)
		go func(record MeshEncryptedRecord) {
			defer group.Done()
			results <- meshQuotaImport(t, store, ctx, limit, false, []MeshEncryptedRecord{record}, nil)
		}(item)
	}
	group.Wait()
	close(results)

	accepted := 0
	for result := range results {
		if result.Error == nil {
			accepted++
			continue
		}
		if !errors.Is(result.Error, ErrStorageFull) {
			t.Fatalf("concurrent import failed unexpectedly: %+v", result)
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted %d concurrent imports; want 1", accepted)
	}
	if count := meshQuotaCount(t, store,
		"SELECT COUNT(*) FROM server_encrypted_records WHERE user_id_hash=?1", first.UserIDHash); count != 1 {
		t.Fatal("concurrent quota enforcement committed the wrong number of records")
	}
	used := AccountStorage_Used(store.Database, ctx, first.UserIDHash)
	if used.Error != nil || used.Value > limit {
		t.Fatal("concurrent imports grew the account past its allowance", used)
	}
}
