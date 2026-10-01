package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type lifecycleTrace struct {
	Operation string
	Query     string
	Arguments []driver.Value
}

type lifecycleDriverPlan struct {
	trace       []lifecycleTrace
	rows        [][]driver.Value
	columns     []string
	queryError  error
	nextError   error
	closeError  error
	rowsPanic   any
	failAt      int
	panicAt     int
	failure     error
	panicValue  any
	steps       int
	closed      int
	rolledBack  int
	committed   int
	affected    int64
	affectedErr error
}

func (plan *lifecycleDriverPlan) step(operation, query string, arguments []driver.NamedValue) error {
	values := make([]driver.Value, len(arguments))
	for index, argument := range arguments {
		value := argument.Value
		if text, ok := value.(string); ok {
			if parsed, err := time.Parse(CanonicalTimestampLayout, text); err == nil {
				if parsed.Location() != time.UTC {
					return errors.New("timestamp is not UTC")
				}
				value = "<canonical timestamp>"
			}
		}
		values[index] = value
	}
	plan.trace = append(plan.trace, lifecycleTrace{operation, query, values})
	plan.steps++
	if plan.steps == plan.panicAt && operation == "exec" {
		panic(plan.panicValue)
	}
	if plan.steps == plan.failAt {
		return plan.failure
	}
	return nil
}

type lifecycleDriver struct{ plan *lifecycleDriverPlan }
type lifecycleConnection struct{ plan *lifecycleDriverPlan }
type lifecycleTransaction struct{ plan *lifecycleDriverPlan }
type lifecycleRows struct {
	plan  *lifecycleDriverPlan
	index int
}
type lifecycleResult struct{ plan *lifecycleDriverPlan }

func (driver lifecycleDriver) Open(string) (driver.Conn, error) {
	return lifecycleConnection{driver.plan}, nil
}

func (lifecycleConnection) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}

func (lifecycleConnection) Close() error { return nil }

func (connection lifecycleConnection) Begin() (driver.Tx, error) {
	return connection.BeginTx(context.Background(), driver.TxOptions{})
}

func (connection lifecycleConnection) BeginTx(_ context.Context, _ driver.TxOptions) (driver.Tx, error) {
	if err := connection.plan.step("begin", "", nil); err != nil {
		return nil, err
	}
	return lifecycleTransaction{connection.plan}, nil
}

func (connection lifecycleConnection) ExecContext(_ context.Context, query string, arguments []driver.NamedValue) (driver.Result, error) {
	if err := connection.plan.step("exec", query, arguments); err != nil {
		return nil, err
	}
	return lifecycleResult{connection.plan}, nil
}

func (connection lifecycleConnection) QueryContext(_ context.Context, query string, arguments []driver.NamedValue) (driver.Rows, error) {
	if err := connection.plan.step("query", query, arguments); err != nil {
		return nil, err
	}
	if connection.plan.queryError != nil {
		return nil, connection.plan.queryError
	}
	return &lifecycleRows{plan: connection.plan}, nil
}

func (transaction lifecycleTransaction) Commit() error {
	transaction.plan.committed++
	return transaction.plan.step("commit", "", nil)
}

func (transaction lifecycleTransaction) Rollback() error {
	transaction.plan.rolledBack++
	return transaction.plan.step("rollback", "", nil)
}

func (result lifecycleResult) LastInsertId() (int64, error) { return 0, nil }

func (result lifecycleResult) RowsAffected() (int64, error) {
	return result.plan.affected, result.plan.affectedErr
}

func (rows *lifecycleRows) Columns() []string { return rows.plan.columns }

func (rows *lifecycleRows) Close() error {
	rows.plan.closed++
	return rows.plan.closeError
}

func (rows *lifecycleRows) Next(values []driver.Value) error {
	if rows.plan.rowsPanic != nil {
		panic(rows.plan.rowsPanic)
	}
	if rows.index >= len(rows.plan.rows) {
		if rows.plan.nextError != nil {
			return rows.plan.nextError
		}
		return io.EOF
	}
	copy(values, rows.plan.rows[rows.index])
	rows.index++
	return nil
}

var lifecycleDriverSequence atomic.Uint64

func lifecycleDriverStore(t *testing.T, plan *lifecycleDriverPlan) *Store {
	t.Helper()
	name := fmt.Sprintf("sync-lifecycle-%d", lifecycleDriverSequence.Add(1))
	sql.Register(name, lifecycleDriver{plan})
	database, err := sql.Open(name, "")
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = database.Close() })
	return &Store{Database: database}
}

type lifecycleReadResult struct {
	Value any
	Extra any
	Error error
}

func TestZiranSyncStorageNativeReadsAgainstBaseline(t *testing.T) {
	type readCase struct {
		name     string
		columns  []string
		rows     [][]driver.Value
		actual   func(*Store) lifecycleReadResult
		baseline func(*Store) lifecycleReadResult
	}
	cases := []readCase{
		{"payload since", []string{"id", "client", "payload", "created", "version"}, [][]driver.Value{{int64(1), "client", "{arbitrary\xff", "created", int64(2)}},
			func(store *Store) lifecycleReadResult {
				value := EncryptedPayloads_Since(store.Database, context.Background(), "account", 0, 2)
				return lifecycleReadResult{value.Value, value.Truncated, value.Error}
			}, func(store *Store) lifecycleReadResult {
				value, truncated, err := store.baselineLifecycleEncryptedPayloadsSince(context.Background(), "account", 0, 2)
				return lifecycleReadResult{value, truncated, err}
			}},
		{"payload recent", []string{"id", "client", "payload", "created", "version"}, [][]driver.Value{{int64(1), "client", "", "created", int64(2)}},
			func(store *Store) lifecycleReadResult {
				value := EncryptedPayloads_Recent(store.Database, context.Background(), "account", 4)
				return lifecycleReadResult{value.Value, nil, value.Error}
			}, func(store *Store) lifecycleReadResult {
				value, err := store.baselineLifecycleRecentEncryptedPayloads(context.Background(), "account", 4)
				return lifecycleReadResult{value, nil, err}
			}},
		{"payload bytes", []string{"bytes"}, [][]driver.Value{{int64(42)}},
			func(store *Store) lifecycleReadResult {
				value := EncryptedPayloads_Bytes(store.Database, context.Background(), "account")
				return lifecycleReadResult{value.Value, nil, value.Error}
			}, func(store *Store) lifecycleReadResult {
				value, err := store.baselineLifecycleEncryptedPayloadBytes(context.Background(), "account")
				return lifecycleReadResult{value, nil, err}
			}},
		{"audit", []string{"id", "user", "client", "app", "protocol", "since", "clock", "version", "applied", "remote", "snapshot", "reason", "encrypted", "bytes", "created"},
			[][]driver.Value{{int64(1), "account", "client", "app", int64(6), int64(2), int64(3), int64(4), `{"habits":2,"sessions":"bad"}`, int64(5), int64(-1), "reason", int64(2), int64(6), "created"}},
			func(store *Store) lifecycleReadResult {
				value := SyncAudit_Recent(store.Database, context.Background(), "account", 10)
				return lifecycleReadResult{value.Value, nil, value.Error}
			}, func(store *Store) lifecycleReadResult {
				value, err := store.baselineLifecycleRecentSyncAudit(context.Background(), "account", 10)
				return lifecycleReadResult{value, nil, err}
			}},
		{"logs", []string{"version", "entity", "id", "date", "op", "payload", "created"}, [][]driver.Value{{int64(1), "habit", "id", int64(20261001), "delete", "", "created"}},
			func(store *Store) lifecycleReadResult {
				value := SyncAudit_Logs(store.Database, context.Background(), "account", 0)
				return lifecycleReadResult{value.Value, nil, value.Error}
			}, func(store *Store) lifecycleReadResult {
				value, err := store.baselineLifecycleSyncLogs(context.Background(), "account", 0)
				return lifecycleReadResult{value, nil, err}
			}},
		{"deletes", []string{"version", "entity", "id", "date", "op", "payload", "created"}, [][]driver.Value{{int64(1), "habit", "id", int64(20261001), "delete", "{invalid\xff", "created"}},
			func(store *Store) lifecycleReadResult {
				value := SyncAudit_Deletes(store.Database, context.Background(), "account", 0)
				return lifecycleReadResult{value.Value, nil, value.Error}
			}, func(store *Store) lifecycleReadResult {
				value, err := store.baselineLifecycleDeleteLogs(context.Background(), "account", 0)
				return lifecycleReadResult{value, nil, err}
			}},
		{"legacy clients", []string{"client"}, [][]driver.Value{{"client\xff"}},
			func(store *Store) lifecycleReadResult {
				value := SyncClients_Legacy(store.Database, context.Background(), "account", 3)
				return lifecycleReadResult{value.Value, nil, value.Error}
			}, func(store *Store) lifecycleReadResult {
				value, err := store.baselineLifecycleLegacyClients(context.Background(), "account", 3)
				return lifecycleReadResult{value, nil, err}
			}},
		{"legacy policy", []string{"latest"}, [][]driver.Value{{"2026-10-01T00:00:00.000000000Z"}},
			func(store *Store) lifecycleReadResult {
				value := SyncClients_LegacyWritePolicy(store.Database, context.Background(), "account")
				return lifecycleReadResult{value.Required, value.Epoch, value.Error}
			}, func(store *Store) lifecycleReadResult {
				value, epoch, err := store.baselineLifecycleLegacyWritePolicy(context.Background(), "account")
				return lifecycleReadResult{value, epoch, err}
			}},
		{"compaction", []string{"through"}, [][]driver.Value{{int64(10)}},
			func(store *Store) lifecycleReadResult {
				value := SyncClients_Compacted(store.Database, context.Background(), "account", 5)
				return lifecycleReadResult{value.Compacted, value.Through, value.Error}
			}, func(store *Store) lifecycleReadResult {
				value, through, err := store.baselineLifecycleSyncOpsCompacted(context.Background(), "account", 5)
				return lifecycleReadResult{value, through, err}
			}},
		{"version", []string{"version"}, [][]driver.Value{{int64(10)}},
			func(store *Store) lifecycleReadResult {
				value := AccountState_CurrentVersion(store.Database, context.Background(), "account")
				return lifecycleReadResult{value.Value, nil, value.Error}
			}, func(store *Store) lifecycleReadResult {
				value, err := store.baselineLifecycleCurrentUserVersion(context.Background(), "account")
				return lifecycleReadResult{value, nil, err}
			}},
	}
	sentinel := errors.New("native SQL error")
	panicValue := errors.New("native rows panic")
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			for _, mode := range []string{"normal", "empty", "query error", "next error", "close error", "panic", "scan error", "null"} {
				var plans [2]*lifecycleDriverPlan
				var results [2]lifecycleReadResult
				var panics [2]any
				for index, call := range []func(*Store) lifecycleReadResult{test.actual, test.baseline} {
					plan := &lifecycleDriverPlan{columns: test.columns, rows: test.rows}
					switch mode {
					case "empty":
						plan.rows = nil
					case "query error":
						plan.queryError = sentinel
					case "next error":
						plan.nextError = sentinel
					case "close error":
						plan.closeError = sentinel
					case "panic":
						plan.rowsPanic = panicValue
					case "scan error":
						plan.rows = [][]driver.Value{make([]driver.Value, len(test.columns))}
						plan.rows[0][0] = struct{ invalid bool }{true}
					case "null":
						plan.rows = [][]driver.Value{make([]driver.Value, len(test.columns))}
					}
					plans[index] = plan
					store := lifecycleDriverStore(t, plan)
					panics[index] = boundaryRecover(func() { results[index] = call(store) })
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					if err := store.Database.PingContext(ctx); err != nil {
						t.Fatalf("%s retained the database connection: %v", mode, err)
					}
					cancel()
				}
				if panics[0] != panics[1] || !reflect.DeepEqual(results[0].Value, results[1].Value) ||
					!reflect.DeepEqual(results[0].Extra, results[1].Extra) || !sameIdentityError(results[0].Error, results[1].Error) {
					t.Fatalf("%s differs: %#v/%v, baseline %#v/%v", mode, results[0], panics[0], results[1], panics[1])
				}
				if !reflect.DeepEqual(plans[0].trace, plans[1].trace) || plans[0].closed != plans[1].closed {
					t.Fatalf("%s changed SQL arguments or resource cleanup", mode)
				}
				if mode == "panic" && plans[0].closed != 1 {
					t.Fatal("panic did not close rows exactly once")
				}
			}
		})
	}
}

func TestZiranSyncStorageTransactionFailuresAgainstBaseline(t *testing.T) {
	type transactionCase struct {
		name     string
		actual   func(*Store) lifecycleReadResult
		baseline func(*Store) lifecycleReadResult
	}
	cases := []transactionCase{
		{"registration", func(store *Store) lifecycleReadResult {
			return lifecycleReadResult{nil, nil, AccountState_Register(store.Database, context.Background(), "account", []byte("key"))}
		}, func(store *Store) lifecycleReadResult {
			return lifecycleReadResult{nil, nil, store.baselineSocialRegisterUser(context.Background(), "account", []byte("key"))}
		}},
		{"payload", func(store *Store) lifecycleReadResult {
			value := EncryptedPayloads_Store(store.Database, context.Background(), "account", "client", []byte("arbitrary\x00\xff"), ErrSyncUserNotFound)
			return lifecycleReadResult{value.Version, nil, value.Error}
		}, func(store *Store) lifecycleReadResult {
			value, err := store.baselineLifecycleStoreEncryptedPayload(context.Background(), "account", "client", []byte("arbitrary\x00\xff"))
			return lifecycleReadResult{value, nil, err}
		}},
		{"account deletion", func(store *Store) lifecycleReadResult {
			return lifecycleReadResult{nil, nil, AccountState_Delete(store.Database, context.Background(), "account")}
		}, func(store *Store) lifecycleReadResult {
			return lifecycleReadResult{nil, nil, store.baselineLifecycleDeleteAccount(context.Background(), "account")}
		}},
		{"compaction", func(store *Store) lifecycleReadResult {
			return lifecycleReadResult{nil, nil, SyncClients_Compact(store.Database, context.Background(), "account")}
		}, func(store *Store) lifecycleReadResult {
			return lifecycleReadResult{nil, nil, store.baselineLifecycleCompactSyncOps(context.Background(), "account")}
		}},
		{"prune by age", func(store *Store) lifecycleReadResult {
			value := EncryptedPayloads_Prune(store.Database, context.Background(), "account", time.Hour, 0)
			return lifecycleReadResult{value.Value, nil, value.Error}
		}, func(store *Store) lifecycleReadResult {
			value, err := store.baselineLifecyclePruneEncryptedPayloads(context.Background(), "account", time.Hour, 0)
			return lifecycleReadResult{value, nil, err}
		}},
	}
	sentinel := errors.New("transaction failure")
	panicValue := errors.New("transaction panic")
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			for _, mode := range []string{"normal", "error", "panic", "row scan panic", "affected rows error"} {
				for step := 1; step <= 8; step++ {
					var results [2]lifecycleReadResult
					var plans [2]*lifecycleDriverPlan
					var panics [2]any
					for index, call := range []func(*Store) lifecycleReadResult{test.actual, test.baseline} {
						plan := &lifecycleDriverPlan{columns: []string{"integer"}, rows: [][]driver.Value{{int64(10)}}, affected: 1, failure: sentinel, panicValue: panicValue}
						switch mode {
						case "error":
							plan.failAt = step
						case "panic":
							plan.panicAt = step
						case "row scan panic":
							plan.rowsPanic = panicValue
						case "affected rows error":
							plan.affectedErr = sentinel
						}
						plans[index] = plan
						store := lifecycleDriverStore(t, plan)
						panics[index] = boundaryRecover(func() { results[index] = call(store) })
						ctx, cancel := context.WithTimeout(context.Background(), time.Second)
						if err := store.Database.PingContext(ctx); err != nil {
							t.Fatalf("%s at step %d retained the connection: %v", mode, step, err)
						}
						cancel()
					}
					if panics[0] != panics[1] || !reflect.DeepEqual(results[0].Value, results[1].Value) || !sameIdentityError(results[0].Error, results[1].Error) {
						t.Fatalf("%s at step %d differs: %#v/%v, baseline %#v/%v", mode, step, results[0], panics[0], results[1], panics[1])
					}
					if test.name == "registration" {
						// Previously ported registration queries differ only in
						// whitespace; preserve operation order and native arguments.
						for _, plan := range plans {
							for index := range plan.trace {
								plan.trace[index].Query = strings.Join(strings.Fields(plan.trace[index].Query), " ")
							}
						}
					}
					if !reflect.DeepEqual(plans[0].trace, plans[1].trace) || plans[0].rolledBack != plans[1].rolledBack || plans[0].committed != plans[1].committed {
						t.Fatalf("%s at step %d changed SQL or cleanup: %#v, baseline %#v", mode, step, plans[0].trace, plans[1].trace)
					}
				}
			}
		})
	}
}

func TestZiranSyncStorageNativeWritesAgainstBaseline(t *testing.T) {
	entry := SyncAuditEntry{
		UserIDHash: "account\xff", ClientID: "client\x00", AppID: "App日本語", ProtocolVersion: 6,
		SinceServerVersion: -9223372036854775808, ClientClock: 9223372036854775807,
		ServerVersion: 42, Applied: SyncResult{Habits: -1, EncryptedRecords: 2},
		RemoteOps: -1, FullSnapshotRequired: true, SnapshotReason: "reason\xff",
		EncryptedPayload: true, EncryptedPayloadBytes: 9223372036854775807,
	}
	cases := []struct {
		name     string
		actual   func(*Store, context.Context) error
		baseline func(*Store, context.Context) error
	}{
		{"login", func(store *Store, ctx context.Context) error {
			return SyncClients_RecordLogin(store.Database, ctx, "account\xff", "client\x00")
		}, func(store *Store, ctx context.Context) error {
			return store.baselineLifecycleRecordClientLogin(ctx, "account\xff", "client\x00")
		}},
		{"sync", func(store *Store, ctx context.Context) error {
			return SyncClients_RecordSync(store.Database, ctx, "account\xff", "client\x00", -9223372036854775808, 9223372036854775807, -1, 42)
		}, func(store *Store, ctx context.Context) error {
			return store.baselineLifecycleRecordClientSync(ctx, "account\xff", "client\x00", -9223372036854775808, 9223372036854775807, -1, 42)
		}},
		{"audit", func(store *Store, ctx context.Context) error {
			return SyncAudit_Record(store.Database, ctx, entry)
		}, func(store *Store, ctx context.Context) error {
			return store.baselineLifecycleRecordSyncAudit(ctx, entry)
		}},
	}
	sentinel := errors.New("native write error")
	panicValue := errors.New("native write panic")
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			for _, mode := range []string{"normal", "error", "panic", "cancelled"} {
				var plans [2]*lifecycleDriverPlan
				var results [2]error
				var panics [2]any
				for index, call := range []func(*Store, context.Context) error{test.actual, test.baseline} {
					plan := &lifecycleDriverPlan{failure: sentinel, panicValue: panicValue}
					ctx := context.Background()
					switch mode {
					case "error":
						plan.failAt = 1
					case "panic":
						plan.panicAt = 1
					case "cancelled":
						var cancel context.CancelFunc
						ctx, cancel = context.WithCancel(ctx)
						cancel()
					}
					plans[index] = plan
					store := lifecycleDriverStore(t, plan)
					panics[index] = boundaryRecover(func() { results[index] = call(store, ctx) })
				}
				if !sameIdentityError(results[0], results[1]) || panics[0] != panics[1] || !reflect.DeepEqual(plans[0].trace, plans[1].trace) {
					t.Fatalf("%s changed native write arguments or error identity", mode)
				}
			}
		})
	}
}
