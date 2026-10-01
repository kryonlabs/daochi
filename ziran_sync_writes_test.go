package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"reflect"
	"testing"
)

type writesCall func(context.Context, *sql.Tx, string) SyncWriteResult

type writesCase struct {
	name     string
	actual   writesCall
	baseline writesCall
}

func writesCases(updated string, rounds []SessionRound) []writesCase {
	session := Session{
		ID: "z-last", StartedAt: lifecycleFixtureTime, LocalDate: 20261001,
		Topic: "日本語\x00\xff", Activity: -1, Source: "source", RoundsHash: "hash",
		MoodBefore: -2, MoodAfter: 3, Energy: 4, Stress: 5,
		Note: "arbitrary\n\t\x00\xff", Tags: "[]", UpdatedAt: updated, Rounds: rounds,
	}
	record := EncryptedRecord{
		Collection: "a.collection", ID: "record-1", KeyID: "key", Nonce: "nonce",
		Ciphertext: "arbitrary\x00\xff", UpdatedAt: updated, DeletedAt: -1,
		ContentHash: "hash", SchemaVersion: -2, ParentID: "parent",
	}
	habit := Habit{ID: "z-last", UpdatedAt: updated}
	day := HabitDay{HabitID: "z-last", LocalDate: 20261001, UpdatedAt: updated}
	return []writesCase{
		{"session", func(ctx context.Context, tx *sql.Tx, user string) SyncWriteResult {
			return SyncWrites_UpsertSession(tx, ctx, user, session)
		}, func(ctx context.Context, tx *sql.Tx, user string) SyncWriteResult {
			applied, err := baselineWritesUpsertSession(ctx, tx, user, session)
			return SyncWriteResult{applied, err}
		}},
		{"record", func(ctx context.Context, tx *sql.Tx, user string) SyncWriteResult {
			return SyncWrites_UpsertRecord(tx, ctx, user, record)
		}, func(ctx context.Context, tx *sql.Tx, user string) SyncWriteResult {
			applied, err := baselineWritesUpsertEncryptedRecord(ctx, tx, user, record)
			return SyncWriteResult{applied, err}
		}},
		{"delete habit", func(ctx context.Context, tx *sql.Tx, user string) SyncWriteResult {
			return SyncWrites_DeleteHabit(tx, ctx, user, habit)
		}, func(ctx context.Context, tx *sql.Tx, user string) SyncWriteResult {
			applied, err := baselineWritesDeleteHabit(ctx, tx, user, habit)
			return SyncWriteResult{applied, err}
		}},
		{"delete day", func(ctx context.Context, tx *sql.Tx, user string) SyncWriteResult {
			return SyncWrites_DeleteHabitDay(tx, ctx, user, day)
		}, func(ctx context.Context, tx *sql.Tx, user string) SyncWriteResult {
			applied, err := baselineWritesDeleteHabitDay(ctx, tx, user, day)
			return SyncWriteResult{applied, err}
		}},
		{"delete session", func(ctx context.Context, tx *sql.Tx, user string) SyncWriteResult {
			return SyncWrites_DeleteSession(tx, ctx, user, session)
		}, func(ctx context.Context, tx *sql.Tx, user string) SyncWriteResult {
			applied, err := baselineWritesDeleteSession(ctx, tx, user, session)
			return SyncWriteResult{applied, err}
		}},
		{"replace data", func(ctx context.Context, tx *sql.Tx, user string) SyncWriteResult {
			return SyncWriteResult{Error: SyncWrites_ReplaceData(tx, ctx, user)}
		}, func(ctx context.Context, tx *sql.Tx, user string) SyncWriteResult {
			return SyncWriteResult{Error: baselineWritesReplaceUserData(ctx, tx, user)}
		}},
	}
}

func writesInTransaction(store *Store, ctx context.Context, user string, call writesCall) SyncWriteResult {
	transaction, err := store.Database.BeginTx(ctx, nil)
	if err != nil {
		return SyncWriteResult{Error: err}
	}
	defer transaction.Rollback()
	result := call(ctx, transaction, user)
	if result.Error == nil {
		result.Error = transaction.Commit()
	}
	return result
}

func writesFixture(t *testing.T) *Store {
	t.Helper()
	store := viewsFixture(t)
	for _, user := range lifecycleAccounts {
		lifecycleExecute(t, store, "UPDATE server_users SET created_at=?2,last_seen_at=?2 WHERE user_id_hash=?1", user, lifecycleFixtureTime)
		lifecycleExecute(t, store, `INSERT INTO server_clients(user_id_hash,client_id,created_at,last_seen_at) VALUES(?1,'client',?2,?2)`, user, lifecycleFixtureTime)
		lifecycleExecute(t, store, `INSERT INTO server_encrypted_payloads(user_id_hash,client_id,payload_json,created_at,server_version) VALUES(?1,'client','payload',?2,20)`, user, lifecycleFixtureTime)
		lifecycleExecute(t, store, `INSERT INTO server_sync_audit(user_id_hash,client_id,created_at) VALUES(?1,'client',?2)`, user, lifecycleFixtureTime)
	}
	return store
}

func writesSnapshot(t *testing.T, store *Store) map[string]any {
	t.Helper()
	value := make(map[string]any)
	for _, table := range []string{
		"server_users", "server_clients", "server_sync_state", "server_habits", "server_habit_days",
		"server_sessions", "server_session_rounds", "server_meditation_logs", "server_social_snapshots",
		"server_encrypted_records", "server_encrypted_payloads", "server_sync_ops", "server_sync_audit",
	} {
		rows := AccountExport_QueryRows(store.Database, t.Context(), "SELECT * FROM "+table+" WHERE ?1='' ORDER BY rowid", "", nil)
		if rows.Error != nil {
			t.Fatal(rows.Error)
		}
		value[table] = rows.Value
	}
	return value
}

func TestZiranSyncWritesStateAgainstBaseline(t *testing.T) {
	for _, stamp := range []string{"2025-01-01T00:00:00.000000000Z", lifecycleFixtureTime, "2027-01-01T00:00:00.000000000Z"} {
		for _, rounds := range [][]SessionRound{nil, {}, {{RoundIndex: 3, Breaths: -2, HoldSeconds: 4}, {RoundIndex: 1, Breaths: 7}}} {
			for _, test := range writesCases(stamp, rounds) {
				t.Run(test.name+"/"+stamp, func(t *testing.T) {
					for _, user := range []string{lifecycleAccounts[0], "missing", "' OR 1=1 --"} {
						actual := writesFixture(t)
						expected := writesFixture(t)
						got := writesInTransaction(actual, t.Context(), user, test.actual)
						want := writesInTransaction(expected, t.Context(), user, test.baseline)
						if got.Applied != want.Applied || !sameIdentityError(got.Error, want.Error) {
							t.Fatalf("write result changed: %#v; original %#v", got, want)
						}
						if !reflect.DeepEqual(writesSnapshot(t, actual), writesSnapshot(t, expected)) {
							t.Fatal("write changed database state, version allocation or account isolation")
						}
						viewsConnectionReleased(t, actual)
						viewsConnectionReleased(t, expected)
					}
				})
			}
		}
	}
}

func TestZiranSyncWriteRollbackAgainstBaseline(t *testing.T) {
	rounds := []SessionRound{{RoundIndex: 1}, {RoundIndex: 3}}
	triggers := map[string]string{
		"session":        `CREATE TRIGGER reject_round BEFORE INSERT ON server_session_rounds WHEN NEW.round_index=3 BEGIN SELECT RAISE(ABORT,'round rejected'); END`,
		"record":         `CREATE TRIGGER reject_record BEFORE INSERT ON server_encrypted_records BEGIN SELECT RAISE(ABORT,'record rejected'); END`,
		"delete habit":   `CREATE TRIGGER reject_days BEFORE DELETE ON server_habit_days BEGIN SELECT RAISE(ABORT,'days rejected'); END`,
		"delete day":     `CREATE TRIGGER reject_day BEFORE DELETE ON server_habit_days BEGIN SELECT RAISE(ABORT,'day rejected'); END`,
		"delete session": `CREATE TRIGGER reject_rounds BEFORE DELETE ON server_session_rounds BEGIN SELECT RAISE(ABORT,'rounds rejected'); END`,
		"replace data":   `CREATE TRIGGER reject_social BEFORE DELETE ON server_social_snapshots BEGIN SELECT RAISE(ABORT,'social rejected'); END`,
	}
	for _, test := range writesCases(lifecycleFixtureTime, rounds) {
		t.Run(test.name, func(t *testing.T) {
			actual, expected := writesFixture(t), writesFixture(t)
			before := writesSnapshot(t, actual)
			for _, store := range []*Store{actual, expected} {
				lifecycleExecute(t, store, triggers[test.name])
			}
			got := writesInTransaction(actual, t.Context(), lifecycleAccounts[0], test.actual)
			want := writesInTransaction(expected, t.Context(), lifecycleAccounts[0], test.baseline)
			if got.Error == nil || got.Applied != 0 || got.Applied != want.Applied || !sameIdentityError(got.Error, want.Error) {
				t.Fatal("write failure changed", got, want)
			}
			if !reflect.DeepEqual(before, writesSnapshot(t, actual)) || !reflect.DeepEqual(before, writesSnapshot(t, expected)) {
				t.Fatal("failed write left partial changes or advanced the account version")
			}
			viewsConnectionReleased(t, actual)
		})
	}
}

func TestZiranSyncWriteVersionsAndOmittedRounds(t *testing.T) {
	store := writesFixture(t)
	user := lifecycleAccounts[0]
	originalRounds := SyncViews_SessionRounds(store.Database, t.Context(), user, "z-last")
	if originalRounds.Error != nil || len(originalRounds.Value) != 2 {
		t.Fatal("invalid round fixture", originalRounds)
	}
	for _, test := range writesCases("2025-01-01T00:00:00.000000000Z", nil)[:2] {
		result := writesInTransaction(store, t.Context(), user, test.actual)
		if result.Error != nil || result.Applied != 0 {
			t.Fatal("stale upsert should be rejected", result)
		}
	}
	version := AccountState_CurrentVersion(store.Database, t.Context(), user)
	if version.Error != nil || version.Value != 22 {
		t.Fatal("rejected upserts must retain released version allocation", version)
	}
	for _, test := range writesCases("2025-01-01T00:00:00.000000000Z", nil)[2:5] {
		result := writesInTransaction(store, t.Context(), user, test.actual)
		if result.Error != nil || result.Applied != 0 {
			t.Fatal("stale delete should be rejected", result)
		}
	}
	version = AccountState_CurrentVersion(store.Database, t.Context(), user)
	if version.Error != nil || version.Value != 22 {
		t.Fatal("rejected deletions must not advance the version", version)
	}
	result := writesInTransaction(store, t.Context(), user, writesCases(lifecycleFixtureTime, nil)[0].actual)
	if result.Error != nil || result.Applied != 1 {
		t.Fatal("equal timestamp should update the session", result)
	}
	rounds := SyncViews_SessionRounds(store.Database, t.Context(), user, "z-last")
	if rounds.Error != nil || !reflect.DeepEqual(rounds.Value, originalRounds.Value) {
		t.Fatal("omitting rounds must preserve stored rounds", rounds)
	}
}

func TestZiranSyncWritesCancelledInsideTransaction(t *testing.T) {
	store := writesFixture(t)
	before := writesSnapshot(t, store)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, test := range writesCases(lifecycleFixtureTime, []SessionRound{{RoundIndex: 1}}) {
		t.Run(test.name, func(t *testing.T) {
			for _, call := range []writesCall{test.actual, test.baseline} {
				transaction, err := store.Database.BeginTx(t.Context(), nil)
				if err != nil {
					t.Fatal(err)
				}
				result := call(ctx, transaction, lifecycleAccounts[0])
				if err := transaction.Rollback(); err != nil {
					t.Fatal(err)
				}
				if result.Applied != 0 || result.Error != context.Canceled {
					t.Fatal("cancelled write changed error identity or result", result)
				}
				viewsConnectionReleased(t, store)
			}
		})
	}
	if !reflect.DeepEqual(before, writesSnapshot(t, store)) {
		t.Fatal("cancelled write changed account data or versions")
	}
}

func TestZiranSyncWritesNativeFailuresAgainstBaseline(t *testing.T) {
	sentinel := errors.New("native sync write failure")
	panicValue := errors.New("native sync write panic")
	rounds := []SessionRound{{RoundIndex: 3, Breaths: -2}, {RoundIndex: 1, HoldSeconds: 4}}
	for _, test := range writesCases(lifecycleFixtureTime, rounds) {
		t.Run(test.name, func(t *testing.T) {
			for _, mode := range []string{"normal", "error", "panic", "scan panic", "affected error", "zero affected", "negative affected"} {
				for step := 1; step <= 16; step++ {
					var plans [2]*lifecycleDriverPlan
					var results [2]SyncWriteResult
					var panics [2]any
					for index, call := range []writesCall{test.actual, test.baseline} {
						plan := &lifecycleDriverPlan{
							columns: []string{"version"}, rows: [][]driver.Value{{int64(10)}},
							affected: 1, failure: sentinel, panicValue: panicValue,
						}
						switch mode {
						case "error":
							plan.failAt = step
						case "panic":
							plan.panicAt = step
						case "scan panic":
							plan.rowsPanic = panicValue
						case "affected error":
							plan.affectedErr = sentinel
						case "zero affected":
							plan.affected = 0
						case "negative affected":
							plan.affected = -1
						}
						plans[index] = plan
						store := lifecycleDriverStore(t, plan)
						panics[index] = boundaryRecover(func() {
							results[index] = writesInTransaction(store, t.Context(), "account\x00\xff", call)
						})
						viewsConnectionReleased(t, store)
					}
					if results[0].Applied != results[1].Applied || results[0].Error != results[1].Error || panics[0] != panics[1] {
						t.Fatalf("%s at step %d changed native result/error/panic: %#v/%v; original %#v/%v", mode, step, results[0], panics[0], results[1], panics[1])
					}
					if !reflect.DeepEqual(plans[0].trace, plans[1].trace) || plans[0].committed != plans[1].committed || plans[0].rolledBack != plans[1].rolledBack || plans[0].closed != plans[1].closed {
						t.Fatalf("%s at step %d changed native SQL trace or cleanup: %#v; original %#v", mode, step, plans[0].trace, plans[1].trace)
					}
				}
			}
		})
	}
}
