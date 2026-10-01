package main

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const lifecycleFixtureTime = "2026-01-01T00:00:00.000000000Z"

var lifecycleAccounts = []string{strings.Repeat("a", 64), strings.Repeat("b", 64)}

func lifecycleExecute(t *testing.T, store *Store, query string, values ...any) {
	t.Helper()
	if _, err := store.Database.Exec(query, values...); err != nil {
		t.Fatal(err)
	}
}

func lifecycleFixture(t *testing.T, now time.Time) *Store {
	t.Helper()
	_, store, _ := testServer(t)
	current := now.UTC().Format(CanonicalTimestampLayout)
	old := now.Add(-400 * 24 * time.Hour).UTC().Format(CanonicalTimestampLayout)
	for index, user := range lifecycleAccounts {
		if err := store.RegisterUser(context.Background(), user, []byte("public-key")); err != nil {
			t.Fatal(err)
		}
		lifecycleExecute(t, store, "UPDATE server_users SET created_at=?2,last_seen_at=?2 WHERE user_id_hash=?1", user, lifecycleFixtureTime)
		lifecycleExecute(t, store, "UPDATE server_sync_state SET server_version=10 WHERE user_id_hash=?1", user)
		for _, client := range []struct {
			id       string
			protocol int
			clock    int64
			seen     string
		}{
			{"floor", 2, 4, current}, {"current", 6, 8, current},
			{"old", 5, 1, old}, {"clockless", 2, 0, current}, {"legacy", 1, 1, current},
		} {
			lifecycleExecute(t, store, `INSERT INTO server_clients(user_id_hash,client_id,created_at,last_seen_at,last_sync_at,protocol_version,last_client_clock) VALUES(?1,?2,?3,?4,?4,?5,?6)`,
				user, client.id, lifecycleFixtureTime, client.seen, client.protocol, client.clock)
		}
		for version := 1; version <= 5; version++ {
			operation := "upsert"
			if version%2 == 0 {
				operation = "delete"
			}
			lifecycleExecute(t, store, `INSERT INTO server_sync_ops(user_id_hash,op_id,client_id,seq,entity_type,entity_id,local_date,op_type,payload_json,created_at,server_version) VALUES(?1,?2,'floor',?3,'habit',?2,20261001,?4,?5,?6,?3)`,
				user, fmt.Sprintf("op-%d", version), version, operation, fmt.Sprintf(`{"version":%d}`, version), lifecycleFixtureTime)
		}
		for version, payload := range []string{"null", `{"text":"日本語"}`, "arbitrary\x00\xff", ""} {
			created := current
			if version == 0 {
				created = now.Add(-48 * time.Hour).UTC().Format(CanonicalTimestampLayout)
			}
			lifecycleExecute(t, store, `INSERT INTO server_encrypted_payloads(user_id_hash,client_id,payload_json,server_version,created_at) VALUES(?1,'floor',?2,?3,?4)`,
				user, payload, version+1, created)
		}
		lifecycleExecute(t, store, `INSERT INTO server_sync_audit(user_id_hash,client_id,app_id,protocol_version,applied_json,full_snapshot_required,encrypted_payload,created_at) VALUES(?1,'floor','app',6,'{"habits":2,"sessions":"bad"}',-1,2,?2)`,
			user, lifecycleFixtureTime)
		lifecycleExecute(t, store, `INSERT INTO monero_account_addresses(account_id,address_index,address,allocation_id,created_at) VALUES(?1,?2,?3,?4,?5)`,
			user, index+1, fmt.Sprintf("address-%d", index), fmt.Sprintf("allocation-%d", index), lifecycleFixtureTime)
		lifecycleExecute(t, store, `INSERT INTO token_ledger(ledger_seq,receipt_id,issuer_id,asset_id,account_id,event_type,amount_delta,source_type,source_ref,previous_hash,event_hash,signature,created_at) VALUES(?1,?2,'issuer',(SELECT asset_id FROM token_assets ORDER BY asset_id LIMIT 1),?3,'credit',7,'payment',?2,'previous',?2,'signature',?4)`,
			index+1, fmt.Sprintf("receipt-%d", index), user, lifecycleFixtureTime)
		lifecycleExecute(t, store, `INSERT INTO token_processed_payments(provider,provider_payment_id,account_id,asset_id,amount,receipt_id,created_at) VALUES('fixture',?1,?2,'asset',7,?1,?3)`,
			fmt.Sprintf("receipt-%d", index), user, lifecycleFixtureTime)
	}
	return store
}

func lifecycleFixturePair(t *testing.T) (*Store, *Store) {
	t.Helper()
	now := time.Now()
	return lifecycleFixture(t, now), lifecycleFixture(t, now)
}

func lifecycleSnapshot(t *testing.T, store *Store) map[string]any {
	t.Helper()
	result := make(map[string]any)
	for _, table := range []string{"server_users", "server_clients", "server_sync_state", "server_sync_compaction", "server_sync_ops", "server_sync_audit", "server_encrypted_payloads", "server_account_tombstones", "monero_account_addresses", "token_ledger", "token_processed_payments"} {
		rows := AccountExport_QueryRows(store.Database, context.Background(), "SELECT * FROM "+table+" WHERE ?1='' ORDER BY rowid", "", nil)
		if rows.Error != nil {
			t.Fatal(rows.Error)
		}
		for _, row := range rows.Value {
			for column, value := range row {
				if !strings.HasSuffix(column, "_at") || value == nil || value == "" {
					continue
				}
				text, ok := value.(string)
				if !ok {
					t.Fatalf("timestamp %s.%s is %T", table, column, value)
				}
				if _, err := time.Parse(CanonicalTimestampLayout, text); err != nil {
					if _, err := time.Parse("2006-01-02 15:04:05", text); err != nil {
						t.Fatalf("timestamp %s.%s changed format: %q", table, column, text)
					}
				}
				// Separate calls legitimately observe different wall clocks.
				// Timestamp queries are compared before this state snapshot.
				row[column] = "<timestamp>"
			}
		}
		result[table] = rows.Value
	}
	return result
}

func lifecycleCompareState(t *testing.T, actual, expected *Store) {
	t.Helper()
	if !reflect.DeepEqual(lifecycleSnapshot(t, actual), lifecycleSnapshot(t, expected)) {
		t.Fatal("ported lifecycle changed stored state or account isolation")
	}
	for _, store := range []*Store{actual, expected} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		if err := store.Database.PingContext(ctx); err != nil {
			t.Fatal("lifecycle operation retained a database connection", err)
		}
		cancel()
	}
}

func TestZiranEncryptedPayloadReadsAgainstBaseline(t *testing.T) {
	actual, expected := lifecycleFixturePair(t)
	maximum := int(^uint(0) >> 1)
	for _, user := range []string{lifecycleAccounts[0], lifecycleAccounts[1], "missing", "' OR 1=1 --"} {
		for _, since := range []int64{-1, 0, 1, 3, 4, 10, 9223372036854775807} {
			for _, limit := range []int{-1, 0, 1, 2, 3, 4, 10, 50, 51, maximum} {
				got := EncryptedPayloads_Since(actual.Database, context.Background(), user, since, limit)
				want, truncated, err := expected.baselineLifecycleEncryptedPayloadsSince(context.Background(), user, since, limit)
				if !reflect.DeepEqual(got.Value, want) || got.Truncated != truncated || !sameIdentityError(got.Error, err) {
					t.Fatalf("payload read changed for %q/%d/%d: %#v, baseline %#v/%t/%v", user, since, limit, got, want, truncated, err)
				}
			}
		}
		for _, limit := range []int{-1, 0, 1, 2, 10, 50, 51, maximum} {
			got := EncryptedPayloads_Recent(actual.Database, context.Background(), user, limit)
			want, err := expected.baselineLifecycleRecentEncryptedPayloads(context.Background(), user, limit)
			if !reflect.DeepEqual(got.Value, want) || !sameIdentityError(got.Error, err) {
				t.Fatal("recent payloads changed")
			}
		}
		bytes := EncryptedPayloads_Bytes(actual.Database, context.Background(), user)
		want, err := expected.baselineLifecycleEncryptedPayloadBytes(context.Background(), user)
		if bytes.Value != want || !sameIdentityError(bytes.Error, err) {
			t.Fatal("SQLite payload length changed")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := EncryptedPayloads_Since(actual.Database, ctx, lifecycleAccounts[0], 0, 1)
	want, truncated, err := expected.baselineLifecycleEncryptedPayloadsSince(ctx, lifecycleAccounts[0], 0, 1)
	if !reflect.DeepEqual(got.Value, want) || got.Truncated != truncated || !errors.Is(got.Error, context.Canceled) || !sameIdentityError(got.Error, err) {
		t.Fatal("cancelled payload query changed")
	}
	lifecycleCompareState(t, actual, expected)
}

func TestZiranEncryptedPayloadWritesAndRollback(t *testing.T) {
	for _, mode := range []string{"normal", "missing user", "cancelled", "write failure", "version failure", "commit failure"} {
		t.Run(mode, func(t *testing.T) {
			actual, expected := lifecycleFixturePair(t)
			user := lifecycleAccounts[0]
			ctx := context.Background()
			query := ""
			switch mode {
			case "missing user":
				user = "missing"
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "write failure":
				query = "CREATE TRIGGER reject_payload BEFORE INSERT ON server_encrypted_payloads BEGIN SELECT RAISE(ABORT,'payload rejected'); END"
			case "version failure":
				query = "CREATE TRIGGER reject_version BEFORE UPDATE ON server_sync_state BEGIN SELECT RAISE(ABORT,'version rejected'); END"
			case "commit failure":
				query = "CREATE TABLE required(id INTEGER PRIMARY KEY); CREATE TABLE pending(id INTEGER REFERENCES required(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER reject_payload_commit AFTER INSERT ON server_encrypted_payloads BEGIN INSERT INTO pending VALUES(99); END"
			}
			if query != "" {
				for _, store := range []*Store{actual, expected} {
					lifecycleExecute(t, store, query)
				}
			}
			before := lifecycleSnapshot(t, actual)
			for _, payload := range [][]byte{nil, {}, []byte("null"), []byte(`{"v":2,"nonce":"n","ciphertext":"c"}`), {0, 0xff, '\n'}} {
				got := EncryptedPayloads_Store(actual.Database, ctx, user, "client\xff", payload, ErrSyncUserNotFound)
				want, err := expected.baselineLifecycleStoreEncryptedPayload(ctx, user, "client\xff", payload)
				if got.Version != want || !sameIdentityError(got.Error, err) {
					t.Fatalf("payload write changed: %#v, baseline %d/%v", got, want, err)
				}
				if mode == "commit failure" && (got.Error == nil || got.Version != 11) {
					t.Fatal("commit failure lost the tentative version")
				}
				if mode == "missing user" && !errors.Is(got.Error, ErrSyncUserNotFound) {
					t.Fatal("missing account lost error identity")
				}
				lifecycleCompareState(t, actual, expected)
				if mode != "normal" && !reflect.DeepEqual(before, lifecycleSnapshot(t, actual)) {
					t.Fatal("failed payload transaction changed stored state")
				}
			}
		})
	}
}

func TestZiranEncryptedPayloadPruningAgainstBaseline(t *testing.T) {
	for _, test := range []struct {
		mode     string
		age      time.Duration
		maximum  int64
		query    string
		rollback bool
	}{
		{"disabled", 0, 0, "", false},
		{"negative", -time.Hour, -1, "", false},
		{"age", time.Hour, 0, "", false},
		{"bytes", 0, 1, "", false},
		{"age and bytes", time.Hour, 1, "", false},
		{"enough bytes", 0, 9223372036854775807, "", false},
		{"first delete failure", time.Hour, 1, "CREATE TRIGGER reject_prune BEFORE DELETE ON server_encrypted_payloads BEGIN SELECT RAISE(ABORT,'prune rejected'); END", true},
		{"late delete failure", 0, 1, "CREATE TRIGGER reject_prune BEFORE DELETE ON server_encrypted_payloads WHEN OLD.server_version=3 BEGIN SELECT RAISE(ABORT,'late prune rejected'); END", true},
		{"commit failure", 0, 1, "CREATE TABLE required(id INTEGER PRIMARY KEY); CREATE TABLE pending(id INTEGER REFERENCES required(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER reject_prune_commit AFTER DELETE ON server_encrypted_payloads BEGIN INSERT INTO pending VALUES(99); END", true},
	} {
		t.Run(test.mode, func(t *testing.T) {
			actual, expected := lifecycleFixturePair(t)
			if test.query != "" {
				for _, store := range []*Store{actual, expected} {
					lifecycleExecute(t, store, test.query)
				}
			}
			before := lifecycleSnapshot(t, actual)
			got := EncryptedPayloads_Prune(actual.Database, context.Background(), lifecycleAccounts[0], test.age, test.maximum)
			want, err := expected.baselineLifecyclePruneEncryptedPayloads(context.Background(), lifecycleAccounts[0], test.age, test.maximum)
			if got.Value != want || !sameIdentityError(got.Error, err) {
				t.Fatalf("payload pruning changed: %#v, baseline %#v/%v", got, want, err)
			}
			if test.mode == "late delete failure" && (got.Error == nil || got.Value.Deleted != 2) {
				t.Fatal("late failure lost partial deletion count")
			}
			lifecycleCompareState(t, actual, expected)
			if test.rollback && !reflect.DeepEqual(before, lifecycleSnapshot(t, actual)) {
				t.Fatal("failed prune did not roll back")
			}
		})
	}
}

func TestZiranSyncClientCompactionAndPolicyAgainstBaseline(t *testing.T) {
	for _, mode := range []string{"normal", "no active clocks", "future floor", "empty version", "missing user", "delete failure", "checkpoint failure", "commit failure", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			actual, expected := lifecycleFixturePair(t)
			user := lifecycleAccounts[0]
			ctx := context.Background()
			query := ""
			switch mode {
			case "no active clocks":
				query = "UPDATE server_clients SET last_client_clock=0"
			case "future floor":
				query = "UPDATE server_clients SET last_client_clock=100"
			case "empty version":
				query = "UPDATE server_sync_state SET server_version=0"
			case "missing user":
				user = "missing"
			case "delete failure":
				query = "CREATE TRIGGER reject_compaction BEFORE DELETE ON server_sync_ops BEGIN SELECT RAISE(ABORT,'compaction rejected'); END"
			case "checkpoint failure":
				query = "CREATE TRIGGER reject_checkpoint BEFORE INSERT ON server_sync_compaction BEGIN SELECT RAISE(ABORT,'checkpoint rejected'); END"
			case "commit failure":
				query = "CREATE TABLE required(id INTEGER PRIMARY KEY); CREATE TABLE pending(id INTEGER REFERENCES required(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER reject_compaction_commit AFTER DELETE ON server_sync_ops BEGIN INSERT INTO pending VALUES(99); END"
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if query != "" {
				for _, store := range []*Store{actual, expected} {
					lifecycleExecute(t, store, query)
				}
			}
			before := lifecycleSnapshot(t, actual)
			got := SyncClients_Compact(actual.Database, ctx, user)
			want := expected.baselineLifecycleCompactSyncOps(ctx, user)
			if !sameIdentityError(got, want) {
				t.Fatalf("compaction changed: %v, baseline %v", got, want)
			}
			lifecycleCompareState(t, actual, expected)
			if got != nil && !reflect.DeepEqual(before, lifecycleSnapshot(t, actual)) {
				t.Fatal("failed compaction changed stored operations or checkpoint")
			}
			for _, clock := range []int64{-1, 0, 1, 3, 4, 5, 10, 100} {
				got := SyncClients_Compacted(actual.Database, context.Background(), user, clock)
				want, through, err := expected.baselineLifecycleSyncOpsCompacted(context.Background(), user, clock)
				if got.Compacted != want || got.Through != through || !sameIdentityError(got.Error, err) {
					t.Fatal("compacted clock boundary changed")
				}
			}
			if mode == "normal" {
				got := SyncClients_Compacted(actual.Database, context.Background(), user, 0)
				if got.Through != 4 {
					t.Fatal("compaction ignored the oldest active client clock")
				}
			}
		})
	}
	actual, expected := lifecycleFixturePair(t)
	for _, user := range []string{lifecycleAccounts[0], lifecycleAccounts[1], "missing", "' OR 1=1 --"} {
		for _, protocol := range []int{-1, 0, 1, 2, 3, 6, 7} {
			got := SyncClients_Legacy(actual.Database, context.Background(), user, protocol)
			want, err := expected.baselineLifecycleLegacyClients(context.Background(), user, protocol)
			if !reflect.DeepEqual(got.Value, want) || !sameIdentityError(got.Error, err) {
				t.Fatal("legacy client ordering or filtering changed")
			}
		}
		got := SyncClients_LegacyWritePolicy(actual.Database, context.Background(), user)
		want, epoch, err := expected.baselineLifecycleLegacyWritePolicy(context.Background(), user)
		if got.Required != want || got.Epoch != epoch || !sameIdentityError(got.Error, err) {
			t.Fatal("legacy write window changed")
		}
	}
}

func TestZiranAccountDeletionAgainstBaseline(t *testing.T) {
	for _, mode := range []string{"normal", "already disabled", "missing user", "cancelled", "tombstone failure", "address failure", "user failure", "commit failure"} {
		t.Run(mode, func(t *testing.T) {
			actual, expected := lifecycleFixturePair(t)
			user := lifecycleAccounts[0]
			ctx := context.Background()
			query := ""
			switch mode {
			case "already disabled":
				query = "UPDATE monero_account_addresses SET disabled_at='2026-01-01T00:00:00.000000000Z'"
			case "missing user":
				user = "missing"
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "tombstone failure":
				query = "CREATE TRIGGER reject_tombstone BEFORE INSERT ON server_account_tombstones BEGIN SELECT RAISE(ABORT,'tombstone rejected'); END"
			case "address failure":
				query = "CREATE TRIGGER reject_disable BEFORE UPDATE ON monero_account_addresses BEGIN SELECT RAISE(ABORT,'disable rejected'); END"
			case "user failure":
				query = "CREATE TRIGGER reject_user_delete BEFORE DELETE ON server_users BEGIN SELECT RAISE(ABORT,'delete rejected'); END"
			case "commit failure":
				query = "CREATE TABLE required(id INTEGER PRIMARY KEY); CREATE TABLE pending(id INTEGER REFERENCES required(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER reject_delete_commit AFTER DELETE ON server_users BEGIN INSERT INTO pending VALUES(99); END"
			}
			if query != "" {
				for _, store := range []*Store{actual, expected} {
					lifecycleExecute(t, store, query)
				}
			}
			before := lifecycleSnapshot(t, actual)
			for repeat := 0; repeat < 2; repeat++ {
				got := AccountState_Delete(actual.Database, ctx, user)
				want := expected.baselineLifecycleDeleteAccount(ctx, user)
				if !sameIdentityError(got, want) {
					t.Fatalf("account deletion changed: %v, baseline %v", got, want)
				}
				lifecycleCompareState(t, actual, expected)
				if got != nil && !reflect.DeepEqual(before, lifecycleSnapshot(t, actual)) {
					t.Fatal("failed deletion changed the account, address, or tombstone")
				}
			}
			for _, table := range []string{"token_ledger", "token_processed_payments", "monero_account_addresses"} {
				var count int
				if err := actual.Database.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 2 {
					t.Fatalf("account deletion removed retained payment/address rows from %s: %d/%v", table, count, err)
				}
			}
			if mode == "already disabled" {
				var disabled string
				if err := actual.Database.QueryRow("SELECT disabled_at FROM monero_account_addresses WHERE account_id=?1", user).Scan(&disabled); err != nil || disabled != lifecycleFixtureTime {
					t.Fatal("deletion rewrote an already-disabled address")
				}
			}
		})
	}
}

func TestZiranEncryptedPayloadConcurrentVersions(t *testing.T) {
	store := lifecycleFixture(t, time.Now())
	var workers sync.WaitGroup
	results := make(chan PayloadWriteResult, 16)
	for index := 0; index < cap(results); index++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			results <- EncryptedPayloads_Store(store.Database, context.Background(), lifecycleAccounts[0], fmt.Sprintf("client-%d", index), []byte("payload"), ErrSyncUserNotFound)
		}(index)
	}
	workers.Wait()
	close(results)
	seen := make(map[int64]bool)
	for result := range results {
		if result.Error != nil || result.Version < 11 || result.Version > 26 || seen[result.Version] {
			t.Fatalf("concurrent payload write lost atomic version allocation: %#v", result)
		}
		seen[result.Version] = true
	}
	if len(seen) != 16 {
		t.Fatal("concurrent writes lost payloads")
	}
	other := AccountState_CurrentVersion(store.Database, context.Background(), lifecycleAccounts[1])
	if other.Error != nil || other.Value != 10 {
		t.Fatal("payload writes changed another account's version")
	}
}

func TestZiranSyncAuditAndClientWritesAgainstBaseline(t *testing.T) {
	actual, expected := lifecycleFixturePair(t)
	user := lifecycleAccounts[0]
	ctx := context.Background()
	for _, client := range []string{"floor", "new", "", "\xff", "日本語"} {
		if got, want := SyncClients_RecordLogin(actual.Database, ctx, user, client), expected.baselineLifecycleRecordClientLogin(ctx, user, client); !sameIdentityError(got, want) {
			t.Fatal("client login changed")
		}
		if got, want := SyncClients_RecordSync(actual.Database, ctx, user, client, -1, 9223372036854775807, 6, 42), expected.baselineLifecycleRecordClientSync(ctx, user, client, -1, 9223372036854775807, 6, 42); !sameIdentityError(got, want) {
			t.Fatal("client sync changed")
		}
		entry := SyncAuditEntry{UserIDHash: user, ClientID: client, ProtocolVersion: 6, Applied: SyncResult{Habits: 2}, FullSnapshotRequired: true, EncryptedPayload: true, EncryptedPayloadBytes: 100}
		if got, want := SyncAudit_Record(actual.Database, ctx, entry), expected.baselineLifecycleRecordSyncAudit(ctx, entry); !sameIdentityError(got, want) {
			t.Fatal("audit record changed")
		}
	}
	for _, account := range []string{user, lifecycleAccounts[1], "missing", "' OR 1=1 --"} {
		for _, limit := range []int{-1, 0, 1, 2, 10, 50, 51} {
			got := SyncAudit_Recent(actual.Database, ctx, account, limit)
			want, err := expected.baselineLifecycleRecentSyncAudit(ctx, account, limit)
			for _, items := range [][]SyncAuditEntry{got.Value, want} {
				for index := range items {
					if items[index].ID > 2 {
						if _, err := time.Parse("2006-01-02 15:04:05", items[index].CreatedAt); err != nil {
							t.Fatal("audit lost the SQLite creation timestamp")
						}
						items[index].CreatedAt = "<timestamp>"
					}
				}
			}
			if !reflect.DeepEqual(got.Value, want) || !sameIdentityError(got.Error, err) {
				t.Fatal("audit ordering, flags or partial JSON decoding changed")
			}
		}
		for _, since := range []int64{-1, 0, 2, 5, 10} {
			got := SyncAudit_Logs(actual.Database, ctx, account, since)
			want, err := expected.baselineLifecycleSyncLogs(ctx, account, since)
			if !reflect.DeepEqual(got.Value, want) || !sameIdentityError(got.Error, err) {
				t.Fatal("sync operation ordering or payload changed")
			}
			deletes := SyncAudit_Deletes(actual.Database, ctx, account, since)
			want, err = expected.baselineLifecycleDeleteLogs(ctx, account, since)
			if !reflect.DeepEqual(deletes.Value, want) || !sameIdentityError(deletes.Error, err) {
				t.Fatal("delete log filtering or kind changed")
			}
		}
	}
	lifecycleCompareState(t, actual, expected)
}
