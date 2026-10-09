package main

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestMeshBackfillLargeLibraryPreservesExistingHistory(t *testing.T) {
	_, store, _ := testServer(t)
	user := lifecycleAccounts[0]
	if err := store.RegisterUser(t.Context(), user, []byte("fixture-account")); err != nil {
		t.Fatal(err)
	}
	transaction, err := store.Database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	statement, err := transaction.Prepare(`INSERT INTO server_encrypted_records
		(user_id_hash,collection,id,key_id,nonce,ciphertext,updated_at)
		VALUES(?1,'private.fixture.v1.records.media',?2,'key','nonce','encrypted',?3)`)
	if err != nil {
		_ = transaction.Rollback()
		t.Fatal(err)
	}
	for index := 0; index < 25000; index++ {
		if _, err := statement.Exec(user, fmt.Sprintf("photo-%05d", index), lifecycleFixtureTime); err != nil {
			_ = statement.Close()
			_ = transaction.Rollback()
			t.Fatal(err)
		}
	}
	_ = statement.Close()
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
	lifecycleExecute(t, store, `DELETE FROM server_mesh_changes WHERE CAST(substr(record_id,7) AS INTEGER)%2=0`)
	lifecycleExecute(t, store, `INSERT INTO server_mesh_changes(user_id_hash,collection,record_id)
		SELECT user_id_hash,collection,record_id FROM server_mesh_changes`)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if _, err := store.Database.ExecContext(ctx, BackfillMesh); err != nil {
		t.Fatal("large-library startup backfill failed", err)
	}
	var records, changes, missing, duplicates int
	if err := store.Database.QueryRow(`SELECT COUNT(*) FROM server_encrypted_records`).Scan(&records); err != nil {
		t.Fatal(err)
	}
	if err := store.Database.QueryRow(`SELECT COUNT(*) FROM server_mesh_changes`).Scan(&changes); err != nil {
		t.Fatal(err)
	}
	if err := store.Database.QueryRow(`SELECT COUNT(*) FROM
		(SELECT record_id,COUNT(*) n FROM server_mesh_changes GROUP BY record_id)
		WHERE (CAST(substr(record_id,7) AS INTEGER)%2=0 AND n!=1)
		OR (CAST(substr(record_id,7) AS INTEGER)%2=1 AND n!=2)`).Scan(&duplicates); err != nil {
		t.Fatal(err)
	}
	if err := store.Database.QueryRow(`SELECT COUNT(*) FROM server_encrypted_records r
		LEFT JOIN (SELECT DISTINCT record_id FROM server_mesh_changes) c ON c.record_id=r.id
		WHERE c.record_id IS NULL`).Scan(&missing); err != nil {
		t.Fatal(err)
	}
	if records != 25000 || changes != 37500 || duplicates != 0 || missing != 0 {
		t.Fatalf("backfill changed history: %d records, %d changes, %d bad duplicates, %d missing", records, changes, duplicates, missing)
	}
	if _, err := store.Database.ExecContext(ctx, BackfillMesh); err != nil {
		t.Fatal(err)
	}
	var repeated int
	if err := store.Database.QueryRow(`SELECT COUNT(*) FROM server_mesh_changes`).Scan(&repeated); err != nil || repeated != changes {
		t.Fatal("restart duplicated change history", repeated, err)
	}
}
