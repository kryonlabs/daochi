package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

const applicationHabitID = "12345678-1234-4567-89ab-123456789abc"

func applicationFixture(t *testing.T) *Store {
	t.Helper()
	store := writesFixture(t)
	for _, user := range lifecycleAccounts {
		for _, id := range []string{"legacy-habit", "payload-only"} {
			lifecycleExecute(t, store, `INSERT INTO server_habit_id_migrations(user_id_hash,old_id,new_id,source) VALUES(?1,?2,?3,'fixture')`, user, id, applicationHabitID)
		}
	}
	return store
}

func applicationSnapshot(t *testing.T, store *Store) map[string]any {
	t.Helper()
	value := writesSnapshot(t, store)
	rows := AccountExport_QueryRows(store.Database, t.Context(), "SELECT * FROM server_habit_id_migrations WHERE ?1='' ORDER BY rowid", "", nil)
	if rows.Error != nil {
		t.Fatal(rows.Error)
	}
	value["server_habit_id_migrations"] = rows.Value
	for _, table := range []string{"server_users", "server_meditation_logs", "server_habit_id_migrations"} {
		for _, row := range value[table].([]map[string]any) {
			for _, column := range []string{"created_at", "last_seen_at", "migrated_at"} {
				if stamp, ok := row[column].(string); ok && stamp != "" {
					if _, err := time.Parse(CanonicalTimestampLayout, stamp); err != nil {
						if _, err := time.Parse("2006-01-02 15:04:05", stamp); err != nil {
							t.Fatalf("%s.%s changed timestamp format: %q", table, column, stamp)
						}
					}
					row[column] = "<wall clock>"
				}
			}
		}
	}
	return value
}

func applicationOperation(kind, id, action, payload string) SyncOp {
	return SyncOp{OpID: "operation-" + kind, ClientID: "client", Seq: 1,
		EntityType: kind, EntityID: id, LocalDate: 20261001, OpType: action,
		Payload: json.RawMessage(payload), CreatedAt: lifecycleFixtureTime}
}

func applicationRequest() SyncRequest {
	return SyncRequest{
		UserIDHash: lifecycleAccounts[0], ProtocolVersion: 4,
		MeditationLogs: []MeditationLog{{ID: "new-meditation", SessionID: "z-last", DurationSeconds: -4, CompletedAt: lifecycleFixtureTime}},
		Habits:         []Habit{{ID: "legacy-habit", Name: "日本語\n\t\x00\xff", UpdatedAt: lifecycleFixtureTime}},
		HabitDays:      []HabitDay{{HabitID: "legacy-habit", LocalDate: 20261001, Completed: true, Count: -2, UpdatedAt: lifecycleFixtureTime}},
		Sessions: []Session{{ID: "z-last", StartedAt: lifecycleFixtureTime, UpdatedAt: lifecycleFixtureTime,
			Rounds: []SessionRound{{RoundIndex: 2, Breaths: -3}, {RoundIndex: 1, HoldSeconds: 7}}}},
		EncryptedRecords: []EncryptedRecord{{Collection: "private.test", ID: "new-record", Ciphertext: "opaque\x00\xff", UpdatedAt: lifecycleFixtureTime}},
		Ops: []SyncOp{
			applicationOperation("habit", "payload-only", "upsert", `{"name":"operation","updated_at":"2026-01-01T00:00:00Z"}`),
			applicationOperation("habit_day", "payload-only", "upsert", `{"completed":false,"count":7,"updated_at":"2026-01-01T00:00:00Z"}`),
			applicationOperation("session", "op-session", "upsert", `{"started_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","rounds":[]}`),
			applicationOperation("unknown", "opaque", "upsert", "invalid JSON\x00\xff"),
		},
	}
}

func compareApplication(t *testing.T, actual, expected *Store, ctx context.Context, request SyncRequest, key []byte) SyncApplicationResult {
	t.Helper()
	got := SyncApplication_Apply(actual.Database, ctx, request, key, ErrSyncUserNotFound)
	value, accepted, err := expected.baselineApplicationApplySyncDetailed(ctx, request, key)
	if got.Value != value || !reflect.DeepEqual(got.Accepted, accepted) || !sameIdentityError(got.Error, err) {
		t.Fatalf("sync result changed: %#v; original %#v/%#v/%v", got, value, accepted, err)
	}
	actualState, expectedState := applicationSnapshot(t, actual), applicationSnapshot(t, expected)
	for table, rows := range actualState {
		if !reflect.DeepEqual(rows, expectedState[table]) {
			t.Fatalf("sync changed table %s: %#v; original %#v", table, rows, expectedState[table])
		}
	}
	viewsConnectionReleased(t, actual)
	viewsConnectionReleased(t, expected)
	return got
}

func TestZiranSyncApplicationAgainstBaseline(t *testing.T) {
	for _, mode := range []string{"normal", "empty", "full replacement", "bootstrap", "tombstones", "nil rounds", "older timestamps", "new account", "empty key", "missing account", "social rejected", "record rejected", "invalid identity", "malformed payload", "missing payload", "social operation", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			actual, expected := applicationFixture(t), applicationFixture(t)
			request := applicationRequest()
			key := []byte(nil)
			ctx := t.Context()
			switch mode {
			case "empty":
				request = SyncRequest{UserIDHash: lifecycleAccounts[0]}
			case "full replacement":
				request.FullSyncRequested = true
			case "bootstrap", "tombstones":
				request.Bootstrap = mode == "bootstrap"
				request.Habits[0].DeletedAt = 123
				request.Sessions[0].DeletedAt = 123
			case "nil rounds":
				request.Sessions[0].Rounds = nil
			case "older timestamps":
				request.Sessions[0].UpdatedAt = "2020-01-01T00:00:00Z"
			case "new account", "empty key":
				request.UserIDHash = "new-account"
				request.Habits[0].ID = applicationHabitID
				request.HabitDays[0].HabitID = applicationHabitID
				for index := range request.Ops {
					request.Ops[index].EntityID = applicationHabitID
				}
				key = []byte("key\x00\xff")
				if mode == "empty key" {
					key = []byte{}
				}
			case "missing account":
				request.UserIDHash = "missing"
			case "social rejected":
				request.FullSyncRequested = true
				request.SocialCache = []SocialSnapshot{{Kind: "friends"}}
			case "record rejected":
				request.FullSyncRequested = true
				request.EncryptedRecords[0].Ciphertext = ""
			case "invalid identity":
				request.Ops[3].Seq = 0
			case "malformed payload":
				request.Ops[2].Payload = json.RawMessage(`{"note":1}`)
			case "missing payload":
				request.Ops[0].Payload = nil
			case "social operation":
				request.Ops = append(request.Ops, applicationOperation("social_snapshots", "friends", "upsert", "{}"))
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			before := applicationSnapshot(t, actual)
			result := compareApplication(t, actual, expected, ctx, request, key)
			if result.Error != nil {
				if !reflect.DeepEqual(before, applicationSnapshot(t, actual)) || result.Value != (SyncResult{}) || result.Accepted != nil {
					t.Fatal("failed sync exposed tentative counts or persisted partial data")
				}
			} else {
				// A replay accepts the same operations without materializing them again.
				replay := SyncRequest{UserIDHash: request.UserIDHash, Ops: request.Ops}
				result = compareApplication(t, actual, expected, t.Context(), replay, nil)
				if result.Value != (SyncResult{}) || result.Error != nil || len(result.Accepted) != len(request.Ops) {
					t.Fatal("operation replay was not idempotent", result)
				}
			}
			if mode == "missing account" && result.Error != ErrSyncUserNotFound {
				t.Fatal("missing account lost error identity")
			}
		})
	}
}

func TestZiranSyncApplicationDatabaseRollback(t *testing.T) {
	for _, query := range []string{
		"CREATE TRIGGER reject_write BEFORE INSERT ON server_habit_days BEGIN SELECT RAISE(ABORT,'day rejected'); END",
		"CREATE TRIGGER reject_write BEFORE INSERT ON server_sync_ops BEGIN SELECT RAISE(ABORT,'operation rejected'); END",
		"CREATE TABLE required(id INTEGER PRIMARY KEY); CREATE TABLE pending(id INTEGER REFERENCES required(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER reject_commit AFTER INSERT ON server_sync_ops BEGIN INSERT INTO pending VALUES(99); END",
	} {
		actual, expected := applicationFixture(t), applicationFixture(t)
		for _, store := range []*Store{actual, expected} {
			lifecycleExecute(t, store, query)
		}
		before := applicationSnapshot(t, actual)
		result := compareApplication(t, actual, expected, t.Context(), applicationRequest(), nil)
		if result.Error == nil || !reflect.DeepEqual(before, applicationSnapshot(t, actual)) {
			t.Fatal("write or deferred commit failure did not roll back the entire sync")
		}
	}
}

func TestZiranSyncApplicationNativeFailures(t *testing.T) {
	sentinel := errors.New("application SQL failure")
	panicValue := errors.New("application SQL panic")
	requests := []SyncRequest{
		{UserIDHash: "user"},
		{UserIDHash: "user", FullSyncRequested: true},
		{UserIDHash: "user", Habits: []Habit{{ID: applicationHabitID, UpdatedAt: lifecycleFixtureTime}},
			HabitDays:      []HabitDay{{HabitID: applicationHabitID, Completed: true, Count: -1, UpdatedAt: lifecycleFixtureTime}},
			MeditationLogs: []MeditationLog{{ID: "meditation", CompletedAt: lifecycleFixtureTime}}},
		{UserIDHash: "user", Ops: []SyncOp{applicationOperation("unknown", "id", "upsert", "[]")}},
		{UserIDHash: "user", Ops: []SyncOp{applicationOperation("habit", applicationHabitID, "upsert", `{"name":"habit","updated_at":"2026-01-01T00:00:00Z"}`)}},
	}
	for caseIndex, request := range requests {
		for _, key := range [][]byte{nil, {}, []byte("key\xff")} {
			for _, mode := range []string{"normal", "error", "panic", "scan panic", "query error", "no rows", "close error", "zero affected", "affected error"} {
				steps := 1
				if mode == "error" || mode == "panic" {
					steps = 25
				}
				for step := 1; step <= steps; step++ {
					var plans [2]*lifecycleDriverPlan
					var results [2]SyncApplicationResult
					var panics [2]any
					for index := range plans {
						plan := &lifecycleDriverPlan{columns: []string{"value"}, rows: [][]driver.Value{{int64(0)}}, affected: 1, failure: sentinel, panicValue: panicValue}
						switch mode {
						case "error":
							plan.failAt = step
						case "panic":
							plan.panicAt = step
						case "scan panic":
							plan.rowsPanic = panicValue
						case "query error":
							plan.queryError = sentinel
						case "no rows":
							plan.rows = nil
						case "close error":
							plan.closeError = sentinel
						case "zero affected":
							plan.affected = 0
						case "affected error":
							plan.affectedErr = sentinel
						}
						plans[index] = plan
						store := lifecycleDriverStore(t, plan)
						panics[index] = boundaryRecover(func() {
							if index == 0 {
								results[index] = SyncApplication_Apply(store.Database, t.Context(), request, key, ErrSyncUserNotFound)
							} else {
								value, accepted, err := store.baselineApplicationApplySyncDetailed(t.Context(), request, key)
								results[index] = SyncApplicationResult{value, accepted, err}
							}
						})
						viewsConnectionReleased(t, store)
					}
					if !reflect.DeepEqual(results[0], results[1]) || panics[0] != panics[1] || !reflect.DeepEqual(plans[0].trace, plans[1].trace) || plans[0].committed != plans[1].committed || plans[0].rolledBack != plans[1].rolledBack || plans[0].closed != plans[1].closed {
						t.Fatalf("case %d/%s/step %d changed native SQL, result or cleanup:\n%#v / %#v\n%#v / %#v", caseIndex, mode, step, results[0], results[1], plans[0].trace, plans[1].trace)
					}
				}
			}
		}
	}
}

func TestZiranHabitIdentifiersAndPayloads(t *testing.T) {
	for _, id := range []string{"", "legacy", applicationHabitID, strings.ToUpper(applicationHabitID), "12345678-1234-4567-89ab-123456789ab日", strings.Repeat("a", 36)} {
		if HabitId_IsCanonical(id) != baselineApplicationIsCanonicalHabitID(id) {
			t.Fatalf("identifier grammar changed for %q", id)
		}
	}
	for _, payload := range []string{"", "null", "[]", "{}", `{"id":1,"habit_id":null,"extra":"日本語"}`, `{"id":"first","id":"last"}`, `{"id":`, `{"id":"<tag>","number":1e20}`} {
		got := HabitId_RewritePayload(json.RawMessage(payload), applicationHabitID)
		want := baselineApplicationRewriteHabitPayloadID(json.RawMessage(payload), applicationHabitID)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("payload rewrite changed: %q; original %q", got, want)
		}
	}
	store := applicationFixture(t)
	transaction, err := store.Database.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	for _, user := range []string{lifecycleAccounts[0], lifecycleAccounts[1], "missing"} {
		for _, id := range []string{"", "\u2003legacy-habit\u00a0", "unmapped", strings.ToUpper(applicationHabitID)} {
			got := HabitId_ForRead(transaction, t.Context(), user, id)
			want, mapped, err := baselineApplicationCanonicalHabitIDForRead(t.Context(), transaction, user, id)
			if got.Value != want || got.Mapped != mapped || !sameIdentityError(got.Error, err) {
				t.Fatal("identifier lookup changed", got, want, mapped, err)
			}
		}
	}
	for index := 0; index < 32; index++ {
		value := HabitId_New()
		if value.Error != nil || !baselineApplicationIsCanonicalHabitID(value.Value) || value.Value[14] != '4' || !strings.ContainsRune("89ab", rune(value.Value[19])) {
			t.Fatal("generated identifier is not a version-4 UUID", value)
		}
		id := fmt.Sprintf("new-%d", index)
		created := HabitId_ForWrite(transaction, t.Context(), lifecycleAccounts[0], id, "test")
		read := HabitId_ForRead(transaction, t.Context(), lifecycleAccounts[0], id)
		if created.Error != nil || !created.Mapped || !baselineApplicationIsCanonicalHabitID(created.Value) || read.Value != created.Value || !read.Mapped {
			t.Fatal("legacy identifier was not persisted and reused", created, read)
		}
	}
	if got := HabitId_ForWrite(transaction, t.Context(), lifecycleAccounts[0], "\t ", "test"); got.Error == nil || got.Error.Error() != "empty habit id" {
		t.Fatal("empty identifier was accepted", got)
	}
	if err := transaction.Rollback(); err != nil && err != sql.ErrTxDone {
		t.Fatal(err)
	}
}
