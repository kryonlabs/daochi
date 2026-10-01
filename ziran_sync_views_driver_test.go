package main

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Reuse the native SQL trace oracle, with a separate row set for nested rounds.
type viewsDriver struct{ plan *lifecycleDriverPlan }
type viewsConnection struct{ lifecycleConnection }
type viewsDriverRows struct {
	lifecycleRows
	owner *lifecycleDriverPlan
}

func (driver viewsDriver) Open(string) (driver.Conn, error) {
	return viewsConnection{lifecycleConnection{driver.plan}}, nil
}

func (connection viewsConnection) QueryContext(ctx context.Context, query string, arguments []driver.NamedValue) (driver.Rows, error) {
	_, err := connection.lifecycleConnection.QueryContext(ctx, query, arguments)
	if err != nil {
		return nil, err
	}
	snapshot := *connection.plan
	if strings.Contains(query, "FROM server_session_rounds") {
		snapshot.columns = []string{"round", "breaths", "hold"}
		snapshot.rows = [][]driver.Value{{int64(2), int64(7), int64(-3)}}
	}
	return &viewsDriverRows{lifecycleRows{plan: &snapshot}, connection.plan}, nil
}

func (rows *viewsDriverRows) Close() error {
	rows.owner.closed++
	return rows.plan.closeError
}

func viewsDriverStore(t *testing.T, plan *lifecycleDriverPlan) *Store {
	t.Helper()
	name := fmt.Sprintf("sync-views-%d", lifecycleDriverSequence.Add(1))
	sql.Register(name, viewsDriver{plan})
	database, err := sql.Open(name, "")
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = database.Close() })
	return &Store{db: database}
}

func viewsFailurePlan(columns []string, values []driver.Value, mode string, sentinel error, panicValue any) *lifecycleDriverPlan {
	plan := &lifecycleDriverPlan{columns: columns, rows: [][]driver.Value{values}}
	switch mode {
	case "empty":
		plan.rows = nil
	case "query error":
		plan.queryError = sentinel
	case "next error":
		plan.nextError = sentinel
	case "close error":
		plan.closeError = sentinel
	case "rows panic":
		plan.rowsPanic = panicValue
	case "scan error":
		plan.rows = [][]driver.Value{make([]driver.Value, len(columns))}
		plan.rows[0][0] = struct{ invalid bool }{true}
	case "null":
		plan.rows = [][]driver.Value{make([]driver.Value, len(columns))}
	case "round query error":
		plan.failAt = 2
		plan.failure = sentinel
	}
	return plan
}

func viewsConnectionReleased(t *testing.T, store *Store) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := store.db.PingContext(ctx); err != nil {
		t.Fatal("operation retained the database connection", err)
	}
}

func TestZiranSyncViewsNativeFailuresAgainstBaseline(t *testing.T) {
	type fixture struct {
		columns []string
		values  []driver.Value
	}
	fixtures := map[string]fixture{
		"habits":            {[]string{"column-0", "column-1", "column-2", "column-3", "column-4", "column-5", "column-6", "column-7", "column-8", "column-9", "column-10", "column-11"}, []driver.Value{"id", "name", int64(-1), int64(2), int64(3), int64(4), int64(5), int64(6), int64(-7), int64(-8), "updated", int64(9)}},
		"days":              {[]string{"column-0", "column-1", "column-2", "column-3", "column-4"}, []driver.Value{"habit", int64(20261001), int64(-2), int64(-3), "updated"}},
		"sessions":          {[]string{"column-0", "column-1", "column-2", "column-3", "column-4", "column-5", "column-6", "column-7", "column-8", "column-9", "column-10", "column-11", "column-12", "column-13", "column-14"}, []driver.Value{"session", "started", int64(20261001), "topic", int64(-1), "source", "hash", int64(-2), int64(3), int64(4), int64(5), "note\t\n\x00\xff", "tags", int64(-6), "updated"}},
		"rounds":            {[]string{"column-0", "column-1", "column-2"}, []driver.Value{int64(2), int64(7), int64(-3)}},
		"meditations":       {[]string{"column-0", "column-1", "column-2", "column-3"}, []driver.Value{"log", "session", int64(-3), "completed"}},
		"social":            {[]string{"column-0", "column-1", "column-2"}, []driver.Value{"kind", "arbitrary\x00\xff", "updated"}},
		"records":           {[]string{"column-0", "column-1", "column-2", "column-3", "column-4", "column-5", "column-6", "column-7", "column-8", "column-9"}, []driver.Value{"collection", "id", "key", "nonce", "cipher\x00\xff", "updated", int64(-3), "hash", int64(-4), "parent"}},
		"operations":        {[]string{"column-0", "column-1", "column-2", "column-3", "column-4", "column-5", "column-6", "column-7", "column-8"}, []driver.Value{"op", "client", int64(9), "habit", "id", int64(20261001), "upsert", "arbitrary\x00\xff", "created"}},
		"clean habits":      {[]string{"column-0", "column-1", "column-2", "column-3", "column-4", "column-5", "column-6", "column-7", "column-8", "column-9", "column-10"}, []driver.Value{"id", "name", int64(-1), int64(2), int64(3), int64(4), int64(5), int64(6), int64(-7), int64(-8), "updated"}},
		"clean days":        {[]string{"column-0", "column-1", "column-2", "column-3", "column-4", "column-5"}, []driver.Value{"habit", "name", int64(20261001), int64(-2), int64(-3), "updated"}},
		"clean sessions":    {[]string{"column-0", "column-1", "column-2", "column-3", "column-4", "column-5", "column-6", "column-7", "column-8", "column-9", "column-10", "column-11", "column-12", "column-13", "column-14"}, []driver.Value{"session", "started", int64(20261001), "topic", int64(-1), "source", "hash", int64(-2), int64(3), int64(4), int64(5), "note\t\n\x00\xff", "tags", int64(-6), "updated"}},
		"clean meditations": {[]string{"column-0", "column-1", "column-2", "column-3"}, []driver.Value{"log", "session", int64(-3), "completed"}},
	}
	sentinel := errors.New("native view read failure")
	panicValue := errors.New("native view row panic")
	for _, test := range viewsReadCases() {
		fixture, found := fixtures[test.name]
		if !found {
			continue
		}
		t.Run(test.name, func(t *testing.T) {
			modes := []string{"normal", "empty", "query error", "next error", "close error", "rows panic", "scan error", "null"}
			if strings.Contains(test.name, "sessions") {
				modes = append(modes, "round query error")
			}
			for _, mode := range modes {
				var plans [2]*lifecycleDriverPlan
				var results [2]lifecycleReadResult
				var panics [2]any
				for index, call := range []func(*Store, context.Context, string, int64) lifecycleReadResult{test.actual, test.baseline} {
					plans[index] = viewsFailurePlan(fixture.columns, fixture.values, mode, sentinel, panicValue)
					store := viewsDriverStore(t, plans[index])
					panics[index] = boundaryRecover(func() { results[index] = call(store, t.Context(), "account", 5) })
					viewsConnectionReleased(t, store)
				}
				if panics[0] != panics[1] {
					t.Fatalf("%s changed native panic identity: %v, original %v", mode, panics[0], panics[1])
				}
				compareViewsRead(t, results[0], results[1])
				if (mode == "query error" || mode == "next error" || mode == "close error" || mode == "round query error") && results[0].Error != sentinel {
					t.Fatalf("%s changed native error identity", mode)
				}
				if !reflect.DeepEqual(plans[0].trace, plans[1].trace) || plans[0].closed != plans[1].closed {
					t.Fatalf("%s changed SQL query, arguments or row cleanup: %#v/%d, original %#v/%d", mode, plans[0].trace, plans[0].closed, plans[1].trace, plans[1].closed)
				}
				if mode == "rows panic" && plans[0].closed != 1 {
					t.Fatal("panic did not close the rows exactly once")
				}
			}
		})
	}
}

type viewsFailureWriter struct {
	error      error
	panicValue any
}

func (writer viewsFailureWriter) Write([]byte) (int, error) {
	if writer.panicValue != nil {
		panic(writer.panicValue)
	}
	return 0, writer.error
}

func TestZiranStateHashNativeBytesAgainstBaseline(t *testing.T) {
	type hashCase struct {
		name     string
		values   []driver.Value
		actual   func(*Store, io.Writer) error
		baseline func(*Store, io.Writer) error
	}
	cases := []hashCase{
		{"habits", []driver.Value{"id", "name", int64(-1), int64(2), int64(3), int64(4), int64(5), int64(6), int64(-7), int64(-8), "updated"},
			func(s *Store, writer io.Writer) error {
				return StateHash_Habits(s.db, context.Background(), writer, "account")
			},
			func(s *Store, writer io.Writer) error {
				return s.baselineViewsHashHabits(context.Background(), writer, "account")
			},
		},
		{"days", []driver.Value{"habit", int64(20261001), int64(-2), int64(-3), "updated"},
			func(s *Store, writer io.Writer) error {
				return StateHash_HabitDays(s.db, context.Background(), writer, "account")
			},
			func(s *Store, writer io.Writer) error {
				return s.baselineViewsHashHabitDays(context.Background(), writer, "account")
			},
		},
		{"sessions", []driver.Value{"session", "started", int64(20261001), "topic", int64(-1), "source", "hash", int64(-2), int64(3), int64(4), int64(5), "note\t\n\x00\xff", "tags", int64(-6), "updated"},
			func(s *Store, writer io.Writer) error {
				return StateHash_Sessions(s.db, context.Background(), writer, "account")
			},
			func(s *Store, writer io.Writer) error {
				return s.baselineViewsHashSessions(context.Background(), writer, "account")
			},
		},
		{"rounds", []driver.Value{int64(2), int64(7), int64(-3)},
			func(s *Store, writer io.Writer) error {
				return StateHash_Rounds(s.db, context.Background(), writer, "account", "session")
			},
			func(s *Store, writer io.Writer) error {
				return s.baselineViewsHashSessionRounds(context.Background(), writer, "account", "session")
			},
		},
		{"meditations", []driver.Value{"log", "session", int64(-3), "completed"},
			func(s *Store, writer io.Writer) error {
				return StateHash_Meditations(s.db, context.Background(), writer, "account")
			},
			func(s *Store, writer io.Writer) error {
				return s.baselineViewsHashMeditationLogs(context.Background(), writer, "account")
			},
		},
		{"social", []driver.Value{"kind", "arbitrary\x00\xff", "updated"},
			func(s *Store, writer io.Writer) error {
				return StateHash_Social(s.db, context.Background(), writer, "account")
			},
			func(s *Store, writer io.Writer) error {
				return s.baselineViewsHashSocialCache(context.Background(), writer, "account")
			},
		},
		{"records", []driver.Value{"collection", "id", "key", "nonce", "cipher\x00\xff", "updated", int64(-3), "hash", int64(-4), "parent"},
			func(s *Store, writer io.Writer) error {
				return StateHash_Records(s.db, context.Background(), writer, "account")
			},
			func(s *Store, writer io.Writer) error {
				return s.baselineViewsHashEncryptedRecords(context.Background(), writer, "account")
			},
		},
	}
	sentinel := errors.New("native hash read or write failure")
	panicValue := errors.New("native hash panic")
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			columns := make([]string, len(test.values))
			for index := range columns {
				columns[index] = fmt.Sprintf("column-%d", index)
			}
			modes := []string{"normal", "empty", "query error", "next error", "close error", "rows panic", "scan error", "null", "write error", "write panic", "nil writer"}
			if test.name == "sessions" {
				modes = append(modes, "round query error")
			}
			for _, mode := range modes {
				var plans [2]*lifecycleDriverPlan
				var outputs [2]bytes.Buffer
				var failures [2]error
				var panics [2]any
				for index, call := range []func(*Store, io.Writer) error{test.actual, test.baseline} {
					plans[index] = viewsFailurePlan(columns, test.values, mode, sentinel, panicValue)
					store := viewsDriverStore(t, plans[index])
					var writer io.Writer = &outputs[index]
					switch mode {
					case "write error":
						writer = viewsFailureWriter{error: sentinel}
					case "write panic":
						writer = viewsFailureWriter{panicValue: panicValue}
					case "nil writer":
						writer = (*bytes.Buffer)(nil)
					}
					panics[index] = boundaryRecover(func() { failures[index] = call(store, writer) })
					viewsConnectionReleased(t, store)
				}
				if !reflect.DeepEqual(panics[0], panics[1]) || !sameIdentityError(failures[0], failures[1]) || outputs[0].String() != outputs[1].String() {
					t.Fatalf("%s changed hash bytes or failures: %q/%v/%v, original %q/%v/%v", mode, outputs[0].String(), failures[0], panics[0], outputs[1].String(), failures[1], panics[1])
				}
				if !reflect.DeepEqual(plans[0].trace, plans[1].trace) || plans[0].closed != plans[1].closed {
					t.Fatalf("%s changed hash SQL query, arguments or cleanup", mode)
				}
				if (mode == "query error" || mode == "next error" || mode == "close error" || mode == "round query error") && failures[0] != sentinel {
					t.Fatalf("%s changed native error identity", mode)
				}
				if mode == "write error" && failures[0] != nil {
					t.Fatal("released hash formatting ignores writer errors")
				}
				if (mode == "rows panic" || mode == "write panic") && panics[0] != panicValue {
					t.Fatal("native panic identity was lost")
				}
			}
		})
	}
}
