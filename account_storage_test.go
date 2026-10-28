package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccountStorageExceedsOnlyGrowthPastLimit(t *testing.T) {
	cases := []struct {
		before int64
		after  int64
		limit  int64
		want   bool
	}{
		{before: 0, after: 500, limit: 0, want: false},
		{before: 0, after: 100, limit: 100, want: false},
		{before: 0, after: 101, limit: 100, want: true},
		{before: 150, after: 120, limit: 100, want: false},
		{before: 150, after: 150, limit: 100, want: false},
		{before: 150, after: 151, limit: 100, want: true},
	}
	for _, test := range cases {
		if got := AccountStorage_Exceeds(test.before, test.after, test.limit); got != test.want {
			t.Fatalf("Exceeds(%d, %d, %d) = %v, want %v", test.before, test.after, test.limit, got, test.want)
		}
	}
	if report := AccountStorage_Report(42, -1); report.UsedBytes != 42 || report.LimitBytes != 0 {
		t.Fatalf("negative limit reported as a limit: %#v", report)
	}
}

func accountStorageRecord(id string, size int, updatedAt string) EncryptedRecord {
	return EncryptedRecord{Collection: "private.inbe.v1.cells", ID: id, KeyID: "main", Nonce: "nonce",
		Ciphertext: strings.Repeat("x", size), UpdatedAt: updatedAt}
}

func accountStorageBytes(records ...EncryptedRecord) int64 {
	var total int
	for _, record := range records {
		total += len(record.Collection) + len(record.ID) + len(record.KeyID) + len(record.Nonce) +
			len(record.Ciphertext) + len(record.ContentHash) + len(record.ParentID)
	}
	return int64(total)
}

func (fixture *authorizationFixture) ownerSync(t *testing.T, pages bool, records ...EncryptedRecord) *httptest.ResponseRecorder {
	t.Helper()
	input := SyncRequest{ProtocolVersion: 6, AppID: "inbe", UserIDHash: fixture.owner.UserID,
		ClientID: strings.Repeat("a", 64), EncryptedRecords: records}
	if !pages {
		return fixture.ownerCall(t, "/api/v1/sync", input)
	}
	fields := map[string]any{}
	raw, _ := json.Marshal(input)
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	fields["encrypted_records_only"] = true
	return fixture.ownerCall(t, "/api/v1/sync", fields)
}

func accountStorageStored(t *testing.T, store *Store, id string) bool {
	t.Helper()
	var count int
	if err := store.Database.QueryRow("SELECT COUNT(*) FROM server_encrypted_records WHERE id=?1", id).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count > 0
}

func expectStorageFull(t *testing.T, result *httptest.ResponseRecorder, used int64, limit int64) {
	t.Helper()
	var full StorageFullResponse
	if result.Code != http.StatusRequestEntityTooLarge || json.Unmarshal(result.Body.Bytes(), &full) != nil {
		t.Fatalf("growth past the limit was not refused: %d %s", result.Code, result.Body.String())
	}
	if full.Code != "storage_full" || full.AccountStorage.UsedBytes != used || full.AccountStorage.LimitBytes != limit {
		t.Fatalf("storage full response lacks usage before the request: %s", result.Body.String())
	}
}

func TestAccountStorageLimitRejectsGrowthAndReportsUsage(t *testing.T) {
	for _, pages := range []bool{false, true} {
		fixture := authorizationSetup(t)
		first := accountStorageRecord("cell.diary.file.first", 400, "2026-10-10T00:00:00Z")
		used := accountStorageBytes(first)
		limit := used + 100
		fixture.server.Cfg.AccountStorageLimitBytes = limit

		accepted := fixture.ownerSync(t, pages, first)
		var response struct {
			AccountStorage AccountStorage `json:"account_storage"`
		}
		if accepted.Code != http.StatusOK || json.Unmarshal(accepted.Body.Bytes(), &response) != nil {
			t.Fatalf("sync within the limit failed (pages=%v): %d %s", pages, accepted.Code, accepted.Body.String())
		}
		if response.AccountStorage != (AccountStorage{UsedBytes: used, LimitBytes: limit}) {
			t.Fatalf("sync reported %#v, want %d of %d bytes", response.AccountStorage, used, limit)
		}

		second := accountStorageRecord("cell.diary.chunk.second", 400, "2026-10-10T00:00:00Z")
		expectStorageFull(t, fixture.ownerSync(t, pages, second), used, limit)
		if accountStorageStored(t, fixture.store, second.ID) {
			t.Fatal("a refused request still stored its record")
		}

		// A node may lower its limit below an account's data; the account can
		// still shrink it, but cannot grow it.
		fixture.server.Cfg.AccountStorageLimitBytes = 100
		smaller := first
		smaller.Ciphertext = strings.Repeat("y", 50)
		smaller.UpdatedAt = "2026-10-10T00:00:01Z"
		shrunk := fixture.ownerSync(t, pages, smaller)
		if shrunk.Code != http.StatusOK || json.Unmarshal(shrunk.Body.Bytes(), &response) != nil ||
			response.AccountStorage.UsedBytes != accountStorageBytes(smaller) {
			t.Fatalf("shrinking above the limit was refused: %d %s", shrunk.Code, shrunk.Body.String())
		}
		third := accountStorageRecord("cell.diary.chunk.third", 1, "2026-10-10T00:00:00Z")
		expectStorageFull(t, fixture.ownerSync(t, pages, third), accountStorageBytes(smaller), 100)

		// A node without a limit still reports usage and omits the limit.
		fixture.server.Cfg.AccountStorageLimitBytes = 0
		open := fixture.ownerSync(t, pages, second)
		response.AccountStorage = AccountStorage{}
		if open.Code != http.StatusOK || json.Unmarshal(open.Body.Bytes(), &response) != nil ||
			response.AccountStorage != (AccountStorage{UsedBytes: accountStorageBytes(smaller, second)}) {
			t.Fatalf("unlimited sync usage: %d %s", open.Code, open.Body.String())
		}
		if strings.Contains(open.Body.String(), "limit_bytes") {
			t.Fatalf("unlimited node reported a limit: %s", open.Body.String())
		}
	}
}

func TestAccountStorageLimitCoversDelegatedWrites(t *testing.T) {
	fixture := authorizationSetup(t)
	fixture.connect(t)
	input := fixture.syncInput()
	input.Read = false
	record := EncryptedRecord{Collection: input.Collection, ID: "cell.lumi.message.1", KeyID: "lumi-key-v2",
		Nonce: "nonce", Ciphertext: strings.Repeat("x", 200), UpdatedAt: "2026-10-08T00:00:00Z"}
	input.Sync.EncryptedRecords = []EncryptedRecord{record}
	limit := accountStorageBytes(record) - 1
	fixture.server.Cfg.AccountStorageLimitBytes = limit
	result := httptest.NewRecorder()
	fixture.handler.ServeHTTP(result, fixture.delegateRequest(t, input))
	expectStorageFull(t, result, 0, limit)
	if accountStorageStored(t, fixture.store, record.ID) {
		t.Fatal("a refused delegated write still stored its record")
	}
	fixture.server.Cfg.AccountStorageLimitBytes = accountStorageBytes(record)
	result = httptest.NewRecorder()
	fixture.handler.ServeHTTP(result, fixture.delegateRequest(t, input))
	var response DelegatedSyncResponse
	if result.Code != http.StatusOK || json.Unmarshal(result.Body.Bytes(), &response) != nil || response.Applied != 1 {
		t.Fatalf("delegated write within the limit failed: %d %s", result.Code, result.Body.String())
	}
}

func TestBasicTrackingWorksAboveEveryAccountStorageLimit(t *testing.T) {
	for _, pages := range []bool{false, true} {
		fixture := authorizationSetup(t)
		diary := accountStorageRecord("cell.diary.file.full", 400, "2026-10-10T00:00:00Z")
		if result := fixture.ownerSync(t, pages, diary); result.Code != http.StatusOK {
			t.Fatal(result.Body.String())
		}
		used := accountStorageBytes(diary)
		fixture.server.Cfg.AccountStorageLimitBytes = 1
		for _, collection := range []string{
			"private.inbe.v1.habits", "private.inbe.v1.habit-days",
			"private.inbe.v1.habit-settings", "private.inbe.v1.habit-changes",
			"private.inbe.v1.habit-rewards", "private.inbe.v1.habit-coins",
			"private.inbe.v1.achievements", "private.inbe.v1.app-preferences",
			"private.entity.v1.game-progress", "private.entity.v1.profile",
		} {
			record := accountStorageRecord("basic", 500, "2026-10-10T00:00:00Z")
			record.Collection = collection
			if result := fixture.ownerSync(t, pages, record); result.Code != http.StatusOK {
				t.Fatalf("free %s above quota: %d %s", collection, result.Code, result.Body.String())
			}
		}
		for _, collection := range []string{"private.inbe.v1.sessions", "private.inbe.v1.habit-entries"} {
			record := accountStorageRecord("tracking", 500, "2026-10-10T00:00:00Z")
			record.Collection = collection
			record.FreeBytes = accountStorageBytes(record)
			if result := fixture.ownerSync(t, pages, record); result.Code != http.StatusOK {
				t.Fatalf("free tracking above quota: %d %s", result.Code, result.Body.String())
			}
			// Only the note consumes bytes; growing the numeric portion is free.
			record.Ciphertext += "note"
			record.UpdatedAt = "2026-10-10T00:00:01Z"
			expectStorageFull(t, fixture.ownerSync(t, pages, record), used, 1)
			record.FreeBytes += 4
			if result := fixture.ownerSync(t, pages, record); result.Code != http.StatusOK {
				t.Fatalf("numeric growth was charged: %d %s", result.Code, result.Body.String())
			}
		}
		// The metadata is never an exemption for arbitrary documents or photos.
		for _, collection := range []string{"private.inbe.v1.cells", "private.inbe.v1.media", "private.inbe.v1.unknown"} {
			record := accountStorageRecord("content", 500, "2026-10-10T00:00:00Z")
			record.Collection = collection
			record.FreeBytes = accountStorageBytes(record)
			expectStorageFull(t, fixture.ownerSync(t, pages, record), used, 1)
		}
		assertStorageUsage(t, fixture.store, fixture.owner.UserID)
	}
}
