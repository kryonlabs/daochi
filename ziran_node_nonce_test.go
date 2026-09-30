package main

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

// Preserve the original nonce operation as an independent regression oracle.
func baselineConsumeNodeNonce(database *sql.DB, context context.Context, nodeID, nonce string, expiresAt int64) error {
	transaction, err := database.BeginTx(context, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	if _, err := transaction.ExecContext(context,
		"DELETE FROM node_request_nonces WHERE expires_at<?1", time.Now().Unix()); err != nil {
		return err
	}
	if _, err := transaction.ExecContext(context, `
INSERT INTO node_request_nonces(node_id,nonce,expires_at)
VALUES(?1,?2,?3)`, nodeID, nonce, expiresAt); err != nil {
		return errors.New("node request replayed")
	}
	return transaction.Commit()
}

func nodeNonceFixture(t *testing.T) *sql.DB {
	t.Helper()
	database, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = database.Close() })
	if _, err := database.Exec(`
CREATE TABLE node_request_nonces (
node_id TEXT NOT NULL, nonce TEXT NOT NULL, expires_at INTEGER NOT NULL,
PRIMARY KEY(node_id, nonce));
INSERT INTO node_request_nonces VALUES('expired','old',0);
INSERT INTO node_request_nonces VALUES('peer','replay',9223372036854775807)`); err != nil {
		t.Fatal(err)
	}
	return database
}

type nodeNonceRow struct {
	nodeID    string
	nonce     string
	expiresAt int64
}

func nodeNonceSnapshot(t *testing.T, database *sql.DB) []nodeNonceRow {
	t.Helper()
	rows, err := database.Query("SELECT node_id,nonce,expires_at FROM node_request_nonces ORDER BY node_id,nonce")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var result []nodeNonceRow
	for rows.Next() {
		var row nodeNonceRow
		if err := rows.Scan(&row.nodeID, &row.nonce, &row.expiresAt); err != nil {
			t.Fatal(err)
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestZiranNodeNonceAgainstBaseline(t *testing.T) {
	actual, expected := nodeNonceFixture(t), nodeNonceFixture(t)
	future := time.Now().Add(time.Hour).Unix()
	for _, item := range []nodeNonceRow{
		{"peer", "replay", future},
		{"peer", "new", future},
		{"peer", "new", future},
		{"other", "new", future},
		{"", "", future},
		{"peer", "expired", -9223372036854775808},
		{"peer", "expired", future},
	} {
		got := NodeNonce_Consume(actual, context.Background(), item.nodeID, item.nonce, item.expiresAt)
		want := baselineConsumeNodeNonce(expected, context.Background(), item.nodeID, item.nonce, item.expiresAt)
		if (got == nil) != (want == nil) || got != nil && got.Error() != want.Error() {
			t.Fatalf("consume %#v: %v, want %v", item, got, want)
		}
		if got, want := nodeNonceSnapshot(t, actual), nodeNonceSnapshot(t, expected); !reflect.DeepEqual(got, want) {
			t.Fatalf("nonce state after %#v: %#v, want %#v", item, got, want)
		}
	}
}

func TestZiranNodeNonceFailureRollsBackExpiryCleanup(t *testing.T) {
	database := nodeNonceFixture(t)
	before := nodeNonceSnapshot(t, database)
	if _, err := database.Exec(`
CREATE TRIGGER reject_nonce BEFORE INSERT ON node_request_nonces
BEGIN SELECT RAISE(ABORT,'insert rejected'); END`); err != nil {
		t.Fatal(err)
	}
	err := NodeNonce_Consume(database, context.Background(), "peer", "new", time.Now().Add(time.Hour).Unix())
	if err == nil || err.Error() != "node request replayed" {
		t.Fatalf("insert failure contract: %v", err)
	}
	if got := nodeNonceSnapshot(t, database); !reflect.DeepEqual(got, before) {
		t.Fatalf("failed insertion committed expiry cleanup: %#v, want %#v", got, before)
	}
	if _, err := database.Exec("DROP TRIGGER reject_nonce"); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := NodeNonce_Consume(database, canceled, "peer", "new", 0); err != context.Canceled {
		t.Fatalf("cancellation identity: %v", err)
	}
	if got := nodeNonceSnapshot(t, database); !reflect.DeepEqual(got, before) {
		t.Fatalf("cancellation changed nonce state: %#v", got)
	}
	if err := NodeNonce_Consume(database, context.Background(), "peer", "new", time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatalf("transaction could not be reused after failure: %v", err)
	}
}

func TestZiranNodeNonceConcurrentReplay(t *testing.T) {
	database := nodeNonceFixture(t)
	const workers = 32
	results := make(chan error, workers)
	var group sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			results <- NodeNonce_Consume(database, context.Background(), "peer", "once", time.Now().Add(time.Hour).Unix())
		}()
	}
	group.Wait()
	close(results)
	successful := 0
	for err := range results {
		if err == nil {
			successful++
		} else if err.Error() != "node request replayed" {
			t.Fatalf("concurrent replay error: %v", err)
		}
	}
	if successful != 1 || database.Stats().InUse != 0 {
		t.Fatalf("successful consumes=%d, open transactions=%d", successful, database.Stats().InUse)
	}
}

func TestZiranNodeNonceRetainsNativeBeginAndDeletionErrors(t *testing.T) {
	database := nodeNonceFixture(t)
	if _, err := database.Exec(`
CREATE TRIGGER reject_expiry_cleanup BEFORE DELETE ON node_request_nonces
BEGIN SELECT RAISE(ABORT,'expiry cleanup rejected'); END`); err != nil {
		t.Fatal(err)
	}
	before := nodeNonceSnapshot(t, database)
	actual := NodeNonce_Consume(database, context.Background(), "peer", "new", 0)
	expected := baselineConsumeNodeNonce(database, context.Background(), "peer", "new", 0)
	if actual == nil || expected == nil || !reflect.DeepEqual(actual, expected) {
		t.Fatalf("deletion error = %#v, want native error %#v", actual, expected)
	}
	if got := nodeNonceSnapshot(t, database); !reflect.DeepEqual(got, before) {
		t.Fatalf("failed deletion changed nonce state: %#v", got)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	actual = NodeNonce_Consume(database, context.Background(), "peer", "new", 0)
	expected = baselineConsumeNodeNonce(database, context.Background(), "peer", "new", 0)
	if actual == nil || actual != expected {
		t.Fatalf("begin error = %v, want native error %v", actual, expected)
	}
}
