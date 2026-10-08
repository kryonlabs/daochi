package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func authorizationPaginationRecord(t *testing.T, fixture *authorizationFixture, record EncryptedRecord) {
	t.Helper()
	if !EncryptedRecord_ValidForProtocol(record, 6) {
		t.Fatal("pagination fixture does not satisfy the owner record grammar")
	}
	transaction, err := fixture.store.Database.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	written := SyncWrites_UpsertRecord(transaction, t.Context(), fixture.owner.UserID, record)
	if written.Error != nil {
		t.Fatal(written.Error)
	}
	if written.Applied != 1 {
		t.Fatalf("fixture write applied %d records", written.Applied)
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
}

func authorizationPaginationAnswer(t *testing.T, result *httptest.ResponseRecorder) DelegatedSyncResponse {
	t.Helper()
	if result.Code != http.StatusOK {
		t.Fatalf("delegated page status=%d", result.Code)
	}
	if result.Body.Len() > 1<<20 {
		t.Fatalf("delegated response exceeds the SDK byte bound: %d", result.Body.Len())
	}
	var answer DelegatedSyncResponse
	if err := json.Unmarshal(result.Body.Bytes(), &answer); err != nil {
		t.Fatalf("decode delegated page: %v", err)
	}
	return answer
}

func TestAuthorizationDelegatedPaginationByteBoundAndKeyGeneration(t *testing.T) {
	fixture := authorizationSetup(t)
	fixture.connect(t)
	input := fixture.syncInput()
	input.Limit = 512
	expected := make(map[string]EncryptedRecord)
	fixtureBytes := 0
	for index := 0; index < 7; index++ {
		// Interleaved versions outside the grant must affect neither the returned
		// records nor the cursor's ability to retrieve the approved generation.
		authorizationRecord(t, fixture, fmt.Sprintf("cell.lumi.photo.old-%02d", index), "lumi-key-v1")
		record := EncryptedRecord{
			Collection: input.Collection,
			ID:         fmt.Sprintf("cell.lumi.photo.approved-%02d", index),
			KeyID:      fixture.grant.Scopes[0].KeyID,
			Nonce:      "synthetic-photo-nonce",
			Ciphertext: strings.Repeat(fmt.Sprintf("%x", index), 220*1024),
			UpdatedAt:  "2026-10-08T00:00:00Z",
		}
		authorizationPaginationRecord(t, fixture, record)
		expected[record.ID] = record
		fixtureBytes += len(record.Ciphertext)
		authorizationRecord(t, fixture, fmt.Sprintf("cell.lumi.photo.rotated-%02d", index), "lumi-key-v3")
	}
	if fixtureBytes < 1200*1024 {
		t.Fatalf("pagination fixture is too small: %d", fixtureBytes)
	}

	seen := make(map[string]bool)
	pages := 0
	for pages < len(expected)+1 {
		result := authorizationServe(fixture, fixture.delegateRequest(t, input))
		answer := authorizationPaginationAnswer(t, result)
		pages++
		if answer.Collection != input.Collection || answer.Applied != 0 || len(answer.Records) == 0 {
			t.Fatalf("unexpected read page: records=%d applied=%d", len(answer.Records), answer.Applied)
		}
		if pages == 1 && (!answer.Truncated || len(answer.Records) == len(expected)) {
			t.Fatal("byte-limited first page did not report remaining approved records")
		}
		if answer.NextVersion <= input.SinceVersion {
			t.Fatal("nonempty page did not advance its scoped cursor")
		}
		var lastVersion int64
		for _, record := range answer.Records {
			original, exists := expected[record.ID]
			if !exists || record.Collection != input.Collection || record.KeyID != fixture.grant.Scopes[0].KeyID {
				t.Fatal("page delivered a record outside the approved collection/key generation")
			}
			if seen[record.ID] {
				t.Fatalf("record appeared on more than one page: %s", record.ID)
			}
			if record.Ciphertext != original.Ciphertext || record.Nonce != original.Nonce {
				t.Fatalf("page changed opaque photo data for %s", record.ID)
			}
			if err := fixture.store.Database.QueryRow(
				"SELECT server_version FROM server_encrypted_records WHERE user_id_hash=? AND collection=? AND id=?",
				fixture.owner.UserID, input.Collection, record.ID).Scan(&lastVersion); err != nil {
				t.Fatal(err)
			}
			if lastVersion <= input.SinceVersion {
				t.Fatal("page repeated a record at or before the requested cursor")
			}
			seen[record.ID] = true
		}
		if answer.NextVersion != lastVersion {
			t.Fatal("cursor advanced beyond the last record actually delivered")
		}
		input.SinceVersion = answer.NextVersion
		if !answer.Truncated {
			break
		}
	}
	if pages < 2 || len(seen) != len(expected) {
		t.Fatalf("pagination skipped approved records: pages=%d received=%d expected=%d", pages, len(seen), len(expected))
	}
	final := authorizationPaginationAnswer(t, authorizationServe(fixture, fixture.delegateRequest(t, input)))
	if len(final.Records) != 0 || final.Truncated || final.NextVersion != input.SinceVersion {
		t.Fatal("completed cursor returned duplicate records or leaked another generation")
	}
}

func TestAuthorizationDelegatedOversizedRecordRollsBackNonceAndWrites(t *testing.T) {
	fixture := authorizationSetup(t)
	fixture.connect(t)
	input := fixture.syncInput()
	oversized := EncryptedRecord{
		Collection: input.Collection,
		ID:         "cell.lumi.photo.escaped",
		KeyID:      fixture.grant.Scopes[0].KeyID,
		Nonce:      "synthetic-escaped-nonce",
		// JSON escapes expand opaque control bytes. The owner record grammar
		// permits this stored size, but its serialized record exceeds one MiB.
		Ciphertext: strings.Repeat("\x01", 200000),
		UpdatedAt:  "2026-10-08T00:00:00Z",
	}
	encoded, err := json.Marshal(oversized)
	if err != nil || len(encoded) <= 1<<20 {
		t.Fatal("oversized synthetic record does not exercise JSON expansion")
	}
	authorizationPaginationRecord(t, fixture, oversized)
	input.Sync.EncryptedRecords = []EncryptedRecord{{
		Collection: input.Collection, ID: "cell.lumi.message.rollback", KeyID: fixture.grant.Scopes[0].KeyID,
		Nonce: "synthetic-write-nonce", Ciphertext: "opaque-write", UpdatedAt: "2026-10-08T00:00:00Z",
	}}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request := fixture.delegateRequest(t, input)
	var proof RequestProof
	if err := json.Unmarshal([]byte(request.Header.Get("X-Daochi-Delegate")), &proof); err != nil {
		t.Fatal(err)
	}
	result := authorizationServe(fixture, request)
	if result.Code != http.StatusRequestEntityTooLarge || result.Body.Len() > 1<<20 {
		t.Fatalf("oversized record did not fail closed: status=%d bytes=%d", result.Code, result.Body.Len())
	}
	for name, query := range map[string]string{
		"record write": "SELECT COUNT(*) FROM server_encrypted_records WHERE id='cell.lumi.message.rollback'",
		"mesh write":   "SELECT COUNT(*) FROM server_mesh_changes WHERE record_id='cell.lumi.message.rollback'",
	} {
		var count int
		if err := fixture.store.Database.QueryRow(query).Scan(&count); err != nil || count != 0 {
			t.Fatalf("oversized response did not roll back %s: count=%d err=%v", name, count, err)
		}
	}
	var nonceCount int
	if err := fixture.store.Database.QueryRow(
		"SELECT COUNT(*) FROM server_authorization_nonces WHERE grant_id=? AND nonce=?",
		fixture.grant.GrantID, proof.Nonce).Scan(&nonceCount); err != nil || nonceCount != 0 {
		t.Fatalf("oversized response consumed the nonce: count=%d err=%v", nonceCount, err)
	}
	oversized.Ciphertext = "owner-repaired-opaque-record"
	authorizationPaginationRecord(t, fixture, oversized)
	retry := httptest.NewRequest(http.MethodPost, request.URL.String(), bytes.NewReader(raw))
	retry.Header = request.Header.Clone()
	answer := authorizationPaginationAnswer(t, authorizationServe(fixture, retry))
	if answer.Applied != 1 || len(answer.Records) != 2 || answer.Truncated {
		t.Fatal("the unchanged request proof could not complete after owner repair")
	}
	replay := httptest.NewRequest(http.MethodPost, request.URL.String(), bytes.NewReader(raw))
	replay.Header = request.Header.Clone()
	if result := authorizationServe(fixture, replay); result.Code != http.StatusConflict {
		t.Fatalf("successful retry did not consume its nonce: status=%d", result.Code)
	}
}

func TestAuthorizationDelegatedWriteAcknowledgesActualMutations(t *testing.T) {
	fixture := authorizationSetup(t)
	fixture.connect(t)
	input := fixture.syncInput()
	input.Read = false
	current := EncryptedRecord{
		Collection: input.Collection, ID: "cell.lumi.message.current", KeyID: fixture.grant.Scopes[0].KeyID,
		Nonce: "synthetic-current-nonce", Ciphertext: "current-opaque-record", UpdatedAt: "2026-10-08T00:00:00Z",
	}
	authorizationPaginationRecord(t, fixture, current)
	stale := current
	stale.Ciphertext = "stale-opaque-record"
	stale.UpdatedAt = "2026-10-07T00:00:00Z"
	input.Sync.EncryptedRecords = []EncryptedRecord{stale}
	answer := authorizationPaginationAnswer(t, authorizationServe(fixture, fixture.delegateRequest(t, input)))
	if answer.Applied != 0 || len(answer.Records) != 0 {
		t.Fatal("stale write was counted as a mutation")
	}
	fresh := current
	fresh.ID = "cell.lumi.message.fresh"
	input.Sync.EncryptedRecords = []EncryptedRecord{stale, fresh}
	answer = authorizationPaginationAnswer(t, authorizationServe(fixture, fixture.delegateRequest(t, input)))
	if answer.Applied != 1 || len(answer.Records) != 0 {
		t.Fatalf("mixed write acknowledgement count=%d", answer.Applied)
	}
	var stored string
	if err := fixture.store.Database.QueryRow(
		"SELECT ciphertext FROM server_encrypted_records WHERE user_id_hash=? AND collection=? AND id=?",
		fixture.owner.UserID, input.Collection, current.ID).Scan(&stored); err != nil || stored != current.Ciphertext {
		t.Fatal("stale write changed the current record")
	}
	var writes int
	if err := fixture.store.Database.QueryRow(
		"SELECT COUNT(*) FROM server_encrypted_records WHERE user_id_hash=? AND collection=? AND id IN (?,?)",
		fixture.owner.UserID, input.Collection, current.ID, fresh.ID).Scan(&writes); err != nil || writes != 2 {
		t.Fatalf("mixed writes produced unexpected storage: count=%d err=%v", writes, err)
	}
}

func TestAuthorizationDelegatedPaginationStopsReadingAtByteBudget(t *testing.T) {
	fixture := authorizationSetup(t)
	fixture.connect(t)
	input := fixture.syncInput()
	input.Limit = 512
	for index := 0; index < 6; index++ {
		authorizationPaginationRecord(t, fixture, EncryptedRecord{
			Collection: input.Collection,
			ID:         fmt.Sprintf("cell.lumi.photo.streaming-%02d", index),
			KeyID:      fixture.grant.Scopes[0].KeyID,
			Nonce:      "synthetic-streaming-nonce",
			Ciphertext: strings.Repeat("a", 220*1024),
			UpdatedAt:  "2026-10-08T00:00:00Z",
		})
	}
	// SQLite permits a stored type mismatch. A scan failure after the byte
	// boundary proves the first page does not materialize all selected rows.
	if _, err := fixture.store.Database.Exec(
		"UPDATE server_encrypted_records SET schema_version='synthetic-invalid-integer' WHERE id='cell.lumi.photo.streaming-05'"); err != nil {
		t.Fatal(err)
	}
	first := authorizationPaginationAnswer(t, authorizationServe(fixture, fixture.delegateRequest(t, input)))
	if len(first.Records) != 4 || !first.Truncated {
		t.Fatalf("streaming first page records=%d truncated=%v", len(first.Records), first.Truncated)
	}
	input.SinceVersion = first.NextVersion
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request := fixture.delegateRequest(t, input)
	if result := authorizationServe(fixture, request); result.Code != http.StatusServiceUnavailable {
		t.Fatalf("invalid later row did not fail its own page: status=%d", result.Code)
	}
	if _, err := fixture.store.Database.Exec(
		"UPDATE server_encrypted_records SET schema_version=0 WHERE id='cell.lumi.photo.streaming-05'"); err != nil {
		t.Fatal(err)
	}
	retry := httptest.NewRequest(http.MethodPost, request.URL.String(), bytes.NewReader(raw))
	retry.Header = request.Header.Clone()
	last := authorizationPaginationAnswer(t, authorizationServe(fixture, retry))
	if len(last.Records) != 2 || last.Truncated || last.NextVersion <= first.NextVersion {
		t.Fatal("repaired later page skipped records or consumed the failed proof")
	}
}
