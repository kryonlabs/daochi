package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

type stateHistoryReply struct {
	ServerVersion        int64  `json:"server_version"`
	ServerStateHash      string `json:"server_state_hash"`
	FullSnapshotRequired bool   `json:"full_snapshot_required"`
	Changes              struct {
		EncryptedRecords []EncryptedRecord `json:"encrypted_records"`
	} `json:"changes"`
	Data struct {
		EncryptedRecords []EncryptedRecord `json:"encrypted_records"`
	} `json:"data"`
	Diagnostics struct {
		SnapshotReason string `json:"snapshot_reason"`
	} `json:"diagnostics"`
}

func (fixture *authorizationFixture) stateSync(t *testing.T, since int64, hash string, records ...EncryptedRecord) stateHistoryReply {
	t.Helper()
	input := map[string]any{"protocol_version": 6, "app_id": "inbe", "user_id_hash": fixture.owner.UserID,
		"client_id": strings.Repeat("a", 64), "since_server_version": since, "client_clock": since}
	if hash != "" {
		input["last_server_state_hash"] = hash
	}
	if len(records) > 0 {
		input["encrypted_records"] = records
	}
	result := fixture.ownerCall(t, "/api/v1/sync", input)
	var value stateHistoryReply
	if result.Code != 200 || json.Unmarshal(result.Body.Bytes(), &value) != nil {
		t.Fatalf("sync: %d %s", result.Code, result.Body.String())
	}
	return value
}

func TestStateHistoryKeepsOtherDevicesOnChanges(t *testing.T) {
	fixture := authorizationSetup(t)
	first := fixture.stateSync(t, 0, "", accountStorageRecord("cell.diary.file.first", 64, "2026-10-10T00:00:00Z"))
	// Another device writes after this device's sync; the node's current
	// hash no longer matches the hash this device holds.
	second := fixture.stateSync(t, first.ServerVersion, first.ServerStateHash,
		accountStorageRecord("cell.diary.file.second", 64, "2026-10-10T00:00:01Z"))
	if second.FullSnapshotRequired {
		t.Fatalf("own upload forced a snapshot: %s", second.Diagnostics.SnapshotReason)
	}
	behind := fixture.stateSync(t, first.ServerVersion, first.ServerStateHash)
	if behind.FullSnapshotRequired {
		t.Fatalf("a device behind by one change took a full snapshot: %s", behind.Diagnostics.SnapshotReason)
	}
	if len(behind.Changes.EncryptedRecords) != 1 || behind.Changes.EncryptedRecords[0].ID != "cell.diary.file.second" {
		t.Fatalf("behind device did not get exactly the newer change: %+v", behind.Changes.EncryptedRecords)
	}
	if len(behind.Data.EncryptedRecords) != 0 {
		t.Fatalf("a normal sync repeated every record in its data: %d", len(behind.Data.EncryptedRecords))
	}
	current := fixture.stateSync(t, behind.ServerVersion, behind.ServerStateHash)
	if current.FullSnapshotRequired || len(current.Changes.EncryptedRecords) != 0 || len(current.Data.EncryptedRecords) != 0 {
		t.Fatalf("an up-to-date device downloaded records: %+v", current)
	}
}

func TestStateHistoryStillSnapshotsDivergedState(t *testing.T) {
	fixture := authorizationSetup(t)
	first := fixture.stateSync(t, 0, "", accountStorageRecord("cell.diary.file.first", 64, "2026-10-10T00:00:00Z"),
		accountStorageRecord("cell.diary.file.kept", 64, "2026-10-10T00:00:00Z"))
	unknown := fixture.stateSync(t, first.ServerVersion, strings.Repeat("f", 64))
	if !unknown.FullSnapshotRequired || unknown.Diagnostics.SnapshotReason != "state_hash_mismatch" {
		t.Fatalf("a hash this node never gave did not force a snapshot: %+v", unknown)
	}
	if len(unknown.Data.EncryptedRecords) != 2 {
		t.Fatalf("a full snapshot lost its records: %d", len(unknown.Data.EncryptedRecords))
	}
	// A hard delete does not reach devices as a change, so every device
	// that saw the record must compare the whole state again.
	lifecycleExecute(t, fixture.store, "DELETE FROM server_encrypted_records WHERE user_id_hash=?1 AND id='cell.diary.file.first'", fixture.owner.UserID)
	deleted := fixture.stateSync(t, first.ServerVersion, first.ServerStateHash)
	if !deleted.FullSnapshotRequired {
		t.Fatal("a hard delete was hidden behind an incremental sync")
	}
	// A write carrying an older version changes what a device already holds.
	recovered := fixture.stateSync(t, 0, "")
	lifecycleExecute(t, fixture.store, "UPDATE server_encrypted_records SET ciphertext='changed' WHERE user_id_hash=?1", fixture.owner.UserID)
	stale := fixture.stateSync(t, recovered.ServerVersion, recovered.ServerStateHash)
	if !stale.FullSnapshotRequired {
		t.Fatal("a write without a newer version was hidden behind an incremental sync")
	}
}

func TestStateHistoryKeepsNewestVersions(t *testing.T) {
	fixture := authorizationSetup(t)
	for index := 1; index <= HistoryLimit+10; index++ {
		if err := StateHistory_Record(fixture.store.Database, t.Context(), fixture.owner.UserID, int64(index), fmt.Sprintf("%064x", index)); err != nil {
			t.Fatal(err)
		}
	}
	var count, oldest int64
	if err := fixture.store.Database.QueryRow("SELECT COUNT(*), MIN(server_version) FROM server_state_hashes WHERE user_id_hash=?1", fixture.owner.UserID).Scan(&count, &oldest); err != nil {
		t.Fatal(err)
	}
	if count != HistoryLimit || oldest != 11 {
		t.Fatalf("history kept %d versions from %d", count, oldest)
	}
	if !StateHistory_Matches(fixture.store.Database, t.Context(), fixture.owner.UserID, 11, strings.ToUpper(fmt.Sprintf("%064x", 11))).Value {
		t.Fatal("a recorded hash in another letter case did not match")
	}
	if StateHistory_Matches(fixture.store.Database, t.Context(), fixture.owner.UserID, 10, fmt.Sprintf("%064x", 10)).Value {
		t.Fatal("a pruned version still matched")
	}
}
