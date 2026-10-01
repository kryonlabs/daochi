package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func migrationFixture(t *testing.T) *Store {
	t.Helper()
	store := applicationFixture(t)
	for _, user := range lifecycleAccounts {
		for index, id := range []string{"z-last", "a-first", "deleted", "orphan"} {
			canonical := fmt.Sprintf("12345678-1234-4567-89ab-%012d", index)
			lifecycleExecute(t, store, `INSERT INTO server_habit_id_migrations(user_id_hash,old_id,new_id,source) VALUES(?1,?2,?3,'fixture')`, user, id, canonical)
			if index == 0 {
				// A canonical keeper and its legacy duplicate have overlapping days.
				lifecycleExecute(t, store, `INSERT INTO server_habits(user_id_hash,id,name,color_r,color_g,color_b,sync_mode,sync_activity,counter_enabled,sort_order,deleted_at,updated_at,server_version) VALUES(?1,?2,'',0,0,0,0,4,0,9,0,?3,9)`, user, canonical, lifecycleFixtureTime)
				lifecycleExecute(t, store, `INSERT INTO server_habit_days(user_id_hash,habit_id,local_date,completed,count,updated_at,server_version) VALUES(?1,?2,20261001,1,10,?3,9)`, user, canonical, lifecycleFixtureTime)
			}
		}
	}
	return store
}

func TestZiranHabitAccountMigrationAgainstBaseline(t *testing.T) {
	for _, mode := range []string{"protocol 1", "protocol 2", "protocol 3", "protocol 6", "all accounts", "cleanup", "missing account", "cancelled", "update failure", "commit failure"} {
		t.Run(mode, func(t *testing.T) {
			actual, expected := migrationFixture(t), migrationFixture(t)
			user := lifecycleAccounts[0]
			protocol := 3
			ctx := t.Context()
			query := ""
			switch mode {
			case "protocol 1":
				protocol = 1
			case "protocol 2":
				protocol = 2
			case "protocol 6":
				protocol = 6
			case "missing account":
				user = "missing"
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "update failure":
				query = "CREATE TRIGGER reject_migration BEFORE UPDATE ON server_habits BEGIN SELECT RAISE(ABORT,'migration rejected'); END"
			case "commit failure":
				query = "CREATE TABLE required(id INTEGER PRIMARY KEY); CREATE TABLE pending(id INTEGER REFERENCES required(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER reject_commit AFTER UPDATE ON server_sync_state BEGIN INSERT INTO pending VALUES(99); END"
			}
			if query != "" {
				for _, store := range []*Store{actual, expected} {
					lifecycleExecute(t, store, query)
				}
			}
			before := applicationSnapshot(t, actual)
			for repetition := 0; repetition < 2; repetition++ {
				var got, want error
				switch mode {
				case "all accounts":
					got = HabitMigration_AllAccounts(actual.db, ctx)
					want = expected.baselineMigrationAutoMigrateAllAccounts(ctx)
				case "cleanup":
					got = HabitMigration_Cleanup(actual.db, ctx, user)
					want = expected.baselineMigrationCleanupOrphanHabitDays(ctx, user)
				default:
					got = HabitMigration_ForProtocol(actual.db, ctx, user, protocol)
					want = expected.baselineMigrationAutoMigrateAccountForProtocol(ctx, user, protocol)
				}
				if !sameIdentityError(got, want) {
					t.Fatalf("migration failure changed: %v; original %v", got, want)
				}
				state := applicationSnapshot(t, actual)
				if !reflect.DeepEqual(state, applicationSnapshot(t, expected)) {
					t.Fatal("migration changed merged rows, day recovery, operation payloads, versions or account isolation")
				}
				if got != nil || protocol < 3 || repetition > 0 {
					if !reflect.DeepEqual(before, state) {
						t.Fatal("failed, skipped or repeated migration changed account data")
					}
				}
				before = state
				viewsConnectionReleased(t, actual)
				viewsConnectionReleased(t, expected)
			}
		})
	}
	// Old protocols return before touching storage, even with a cancelled context.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := HabitMigration_ForProtocol(nil, ctx, "user", 2); err != nil {
		t.Fatal("old protocol attempted a migration", err)
	}
}

func migrationInTransaction(t *testing.T, store *Store, call func(*sql.Tx) MigrationResult) MigrationResult {
	t.Helper()
	transaction, err := store.db.BeginTx(t.Context(), nil)
	if err != nil {
		return MigrationResult{Error: err}
	}
	defer transaction.Rollback()
	result := call(transaction)
	if result.Error == nil {
		result.Error = transaction.Commit()
	}
	return result
}

func TestZiranSunSalutationMigrationAgainstBaseline(t *testing.T) {
	for _, mode := range []string{"absent", "inactive", "deleted", "rename", "merge", "already migrated"} {
		t.Run(mode, func(t *testing.T) {
			actual, expected := migrationFixture(t), migrationFixture(t)
			for _, store := range []*Store{actual, expected} {
				if mode != "absent" {
					activity, deleted := 4, 0
					if mode == "inactive" {
						activity = 2
					}
					if mode == "deleted" {
						deleted = 123
					}
					lifecycleExecute(t, store, `INSERT INTO server_habits(user_id_hash,id,name,sync_activity,deleted_at,updated_at) VALUES(?1,'yoga','Yoga',?2,?3,?4)`, lifecycleAccounts[0], activity, deleted, lifecycleFixtureTime)
					lifecycleExecute(t, store, `INSERT INTO server_habit_days(user_id_hash,habit_id,local_date,completed,count,updated_at) VALUES(?1,'yoga',20261001,1,3,?2)`, lifecycleAccounts[0], lifecycleFixtureTime)
				}
				if mode == "merge" {
					lifecycleExecute(t, store, `INSERT INTO server_habits(user_id_hash,id,name,updated_at) VALUES(?1,'sun-salutation','keeper',?2)`, lifecycleAccounts[0], lifecycleFixtureTime)
					lifecycleExecute(t, store, `INSERT INTO server_habit_days(user_id_hash,habit_id,local_date,completed,count,updated_at) VALUES(?1,'sun-salutation',20261001,0,9,?2)`, lifecycleAccounts[0], lifecycleFixtureTime)
				}
				if mode == "already migrated" {
					lifecycleExecute(t, store, `INSERT INTO server_habit_id_migrations(user_id_hash,old_id,new_id,source) VALUES(?1,'yoga','sun-salutation','fixture')`, lifecycleAccounts[0])
				}
			}
			got := migrationInTransaction(t, actual, func(tx *sql.Tx) MigrationResult {
				return HabitMigration_SunSalutation(tx, t.Context(), lifecycleAccounts[0])
			})
			want := migrationInTransaction(t, expected, func(tx *sql.Tx) MigrationResult {
				changed, err := baselineMigrationMigrateSunSalutationHabitID(t.Context(), tx, lifecycleAccounts[0])
				return MigrationResult{changed, err}
			})
			if got.Changed != want.Changed || !sameIdentityError(got.Error, want.Error) || !reflect.DeepEqual(applicationSnapshot(t, actual), applicationSnapshot(t, expected)) {
				t.Fatal("sun salutation migration changed", got, want)
			}
		})
	}
}

type migrationDriver struct{ plan *lifecycleDriverPlan }
type migrationConnection struct{ lifecycleConnection }

func (driver migrationDriver) Open(string) (driver.Conn, error) {
	return migrationConnection{lifecycleConnection{driver.plan}}, nil
}

func (connection migrationConnection) QueryContext(ctx context.Context, query string, arguments []driver.NamedValue) (driver.Rows, error) {
	if err := connection.plan.step("query", query, arguments); err != nil {
		return nil, err
	}
	if connection.plan.queryError != nil {
		return nil, connection.plan.queryError
	}
	snapshot := *connection.plan
	query = strings.TrimSpace(query)
	snapshot.columns = []string{"value"}
	snapshot.rows = [][]driver.Value{{int64(1)}}
	switch {
	case strings.HasPrefix(query, "SELECT user_id_hash"):
		snapshot.rows = [][]driver.Value{{"user"}}
	case strings.HasPrefix(query, "SELECT id"):
		snapshot.rows = [][]driver.Value{{"legacy-habit"}, {applicationHabitID}}
	case strings.HasPrefix(query, "SELECT op_id"):
		snapshot.columns = []string{"op_id", "entity_id", "payload"}
		snapshot.rows = [][]driver.Value{{"operation", "legacy-habit", `{"id":"legacy-habit"}`}}
	case strings.HasPrefix(query, "SELECT hd.habit_id"):
		snapshot.columns = []string{"id", "updated_at", "version"}
		snapshot.rows = [][]driver.Value{{"legacy-orphan", lifecycleFixtureTime, int64(5)}}
	case strings.HasPrefix(query, "SELECT new_id"):
		snapshot.rows = [][]driver.Value{{applicationHabitID}}
	case strings.HasPrefix(query, "SELECT server_version"):
		snapshot.rows = [][]driver.Value{{int64(10)}}
	}
	if connection.plan.rows != nil {
		snapshot.rows = connection.plan.rows
	}
	return &viewsDriverRows{lifecycleRows{plan: &snapshot}, connection.plan}, nil
}

func migrationDriverStore(t *testing.T, plan *lifecycleDriverPlan) *Store {
	t.Helper()
	name := fmt.Sprintf("habit-migration-%d", lifecycleDriverSequence.Add(1))
	sql.Register(name, migrationDriver{plan})
	database, err := sql.Open(name, "")
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = database.Close() })
	return &Store{db: database}
}

func TestZiranHabitMigrationNativeFailures(t *testing.T) {
	sentinel := errors.New("migration SQL failure")
	panicValue := errors.New("migration SQL panic")
	for _, mode := range []string{"normal", "error", "panic", "scan error", "close error", "next error", "affected error", "zero affected"} {
		steps := 1
		if mode == "error" || mode == "panic" {
			steps = 40
		}
		for step := 1; step <= steps; step++ {
			var plans [2]*lifecycleDriverPlan
			var failures [2]error
			var panics [2]any
			for index := range plans {
				plan := &lifecycleDriverPlan{affected: 1, failure: sentinel, panicValue: panicValue}
				switch mode {
				case "error":
					plan.failAt = step
				case "panic":
					plan.panicAt = step
				case "scan error":
					plan.rows = [][]driver.Value{{nil}}
				case "close error":
					plan.closeError = sentinel
				case "next error":
					plan.nextError = sentinel
				case "affected error":
					plan.affectedErr = sentinel
				case "zero affected":
					plan.affected = 0
				}
				plans[index] = plan
				store := migrationDriverStore(t, plan)
				panics[index] = boundaryRecover(func() {
					if index == 0 {
						failures[index] = HabitMigration_AllAccounts(store.db, t.Context())
					} else {
						failures[index] = store.baselineMigrationAutoMigrateAllAccounts(t.Context())
					}
				})
				viewsConnectionReleased(t, store)
			}
			failuresMatch := failures[0] == failures[1]
			if mode == "scan error" {
				failuresMatch = sameIdentityError(failures[0], failures[1])
			}
			if !failuresMatch || panics[0] != panics[1] || !reflect.DeepEqual(plans[0].trace, plans[1].trace) || plans[0].closed != plans[1].closed || plans[0].committed != plans[1].committed || plans[0].rolledBack != plans[1].rolledBack {
				t.Fatalf("%s/step %d changed SQL, failure or cleanup:\n%v/%v versus %v/%v\n%#v\n%#v", mode, step, failures[0], panics[0], failures[1], panics[1], plans[0].trace, plans[1].trace)
			}
		}
	}
}

func TestZiranHabitMigrationClosesRowsOnPanic(t *testing.T) {
	panicValue := errors.New("migration row panic")
	for _, allAccounts := range []bool{false, true} {
		plan := &lifecycleDriverPlan{rowsPanic: panicValue}
		store := migrationDriverStore(t, plan)
		got := boundaryRecover(func() {
			if allAccounts {
				_ = HabitMigration_AllAccounts(store.db, t.Context())
			} else {
				_ = HabitMigration_Account(store.db, t.Context(), "user")
			}
		})
		if got != panicValue || plan.closed != 1 || (!allAccounts && plan.rolledBack != 1) {
			t.Fatal("row panic lost its identity or retained migration resources", got, plan)
		}
		viewsConnectionReleased(t, store)
	}
}

func TestZiranLegacyHabitDisplayNames(t *testing.T) {
	for _, id := range []string{"", "sun-salutation", "whm", "meditation", "yoga", "\t---\u2003", "my--habit", "élan-日 本", "a\x00\xff-b", "\xff\xfe-x"} {
		if got, want := HabitMigration_DisplayName(id), baselineMigrationLegacyHabitDisplayName(id); got != want {
			t.Fatalf("display name changed for %q: %q; original %q", id, got, want)
		}
	}
}
