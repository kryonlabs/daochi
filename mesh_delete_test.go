package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// Two independent stores act as mesh peers; delete tombstones must
// propagate so peers converge instead of silently keeping deleted rows.
func TestMeshDeletePropagationConverges(t *testing.T) {
	source, storeA, _ := testServer(t)
	target, storeB, _ := testServer(t)
	_ = source
	_ = target
	ctx := context.Background()
	policy := NodeSyncPolicy{
		Apps:        []string{"inbe"},
		Collections: []string{"inbe.*"},
		Data:        []string{"encrypted_records"},
	}

	publicKey := bytes.Repeat([]byte{0x6d}, mlDSA44PublicKeySize)
	userHash := sha256.Sum256(publicKey)
	userID := hex.EncodeToString(userHash[:])

	record := func(id, updatedAt string) EncryptedRecord {
		return EncryptedRecord{
			Collection: "inbe.habits", ID: id, KeyID: "main", Nonce: "n1",
			Ciphertext: "ct-" + id, UpdatedAt: updatedAt,
		}
	}
	syncA := func(req SyncRequest) {
		req.UserIDHash = userID
		if req.ProtocolVersion == 0 {
			req.ProtocolVersion = 5
		}
		if _, err := storeA.ApplySync(ctx, req, publicKey); err != nil {
			t.Fatal(err)
		}
	}
	rowAt := func(store *Store, id string) bool {
		var exists int
		if err := store.db.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM server_encrypted_records WHERE user_id_hash=?1 AND id=?2)`,
			userID, id).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		return exists != 0
	}
	syncPeers := func() {
		records, deletions, _, _, err := storeA.ExportMeshEncryptedRecords(ctx, policy, "", 100)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := storeB.ImportMeshEncryptedBatch(ctx, policy, records, deletions); err != nil {
			t.Fatal(err)
		}
	}

	// 1. Upsert on A, replicate to B.
	syncA(SyncRequest{EncryptedRecords: []EncryptedRecord{record("r1", "2026-09-04T12:00:00Z")}})
	syncPeers()
	if !rowAt(storeB, "r1") {
		t.Fatal("record missing on peer after initial replication")
	}

	// 2. A full client re-sync with no records wipes A's data
	// (replaceUserData); the deletion must reach B.
	syncA(SyncRequest{FullSyncRequested: true})
	syncPeers()
	if rowAt(storeB, "r1") {
		t.Fatal("deleted record still present on peer after full-sync wipe")
	}

	// 3. Direct single-record delete propagates too.
	syncA(SyncRequest{EncryptedRecords: []EncryptedRecord{record("r2", "2026-09-04T13:00:00Z")}})
	syncPeers()
	if !rowAt(storeB, "r2") {
		t.Fatal("r2 missing on peer before delete")
	}
	if _, err := storeA.db.ExecContext(ctx,
		`DELETE FROM server_encrypted_records WHERE user_id_hash=?1 AND id='r2'`, userID); err != nil {
		t.Fatal(err)
	}
	syncPeers()
	if rowAt(storeB, "r2") {
		t.Fatal("directly deleted record still present on peer")
	}

	// 4. Delete-then-recreate in one batch converges to the recreated row.
	syncA(SyncRequest{EncryptedRecords: []EncryptedRecord{record("r4", "2026-09-04T15:00:00Z")}})
	if _, err := storeA.db.ExecContext(ctx,
		`DELETE FROM server_encrypted_records WHERE user_id_hash=?1 AND id='r4'`, userID); err != nil {
		t.Fatal(err)
	}
	syncA(SyncRequest{EncryptedRecords: []EncryptedRecord{record("r4", "2026-09-04T16:00:00Z")}})
	syncPeers()
	var ciphertext string
	if err := storeB.db.QueryRowContext(ctx,
		`SELECT ciphertext FROM server_encrypted_records WHERE user_id_hash=?1 AND id='r4'`,
		userID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if ciphertext != "ct-r4" {
		t.Fatalf("delete-then-recreate converged to wrong row: ciphertext=%q", ciphertext)
	}

	// 5. Account deletion cascades to tombstones peers can apply.
	syncA(SyncRequest{EncryptedRecords: []EncryptedRecord{record("r3", "2026-09-04T14:00:00Z")}})
	syncPeers()
	if !rowAt(storeB, "r3") {
		t.Fatal("r3 missing on peer before account deletion")
	}
	if err := storeA.DeleteAccount(ctx, userID); err != nil {
		t.Fatal(err)
	}
	syncPeers()
	if rowAt(storeB, "r3") {
		t.Fatal("account-deleted record still present on peer")
	}
}
