package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func statsFixture(t *testing.T) *Store {
	t.Helper()
	store := viewsFixture(t)
	for _, app := range []struct{ id, name, prefix string }{
		{"a", "Exact 日本語", "a.collection"},
		{"b", "Wildcard", "a.*"},
		{"c", "Empty", "no.records.*"},
		{"d", "No collections", ""},
		{"z", "Tie", "a.collection"},
	} {
		lifecycleExecute(t, store, "INSERT INTO server_apps(app_id,display_name) VALUES(?1,?2)", app.id, app.name)
		if app.prefix != "" {
			lifecycleExecute(t, store, "INSERT INTO server_app_collections(app_id,collection_prefix) VALUES(?1,?2)", app.id, app.prefix)
		}
	}
	now := time.Date(2026, 10, 1, 23, 4, 5, 999, time.FixedZone("fixture", -3*60*60))
	for index, user := range lifecycleAccounts {
		for client, age := range []time.Duration{0, 30 * 24 * time.Hour, 31 * 24 * time.Hour} {
			stamp := now.Add(-age).UTC().Format("2006-01-02 15:04:05")
			lifecycleExecute(t, store, "INSERT INTO server_clients(user_id_hash,client_id,last_seen_at,protocol_version) VALUES(?1,?2,?3,?4)", user, fmt.Sprintf("client-%d", client), stamp, client+1)
		}
		lifecycleExecute(t, store, "INSERT INTO server_sync_compaction(user_id_hash,compacted_through_version) VALUES(?1,7)", user)
		for item := 0; item < 12; item++ {
			lifecycleExecute(t, store, "INSERT INTO server_sync_audit(user_id_hash,client_id,protocol_version,applied_json,created_at) VALUES(?1,?2,6,'{\"habits\":3}',?3)", user, fmt.Sprintf("client-%d-%d", index, item), lifecycleFixtureTime)
			lifecycleExecute(t, store, "INSERT INTO server_encrypted_payloads(user_id_hash,client_id,payload_json,server_version,created_at) VALUES(?1,?2,?3,?4,?5)", user, fmt.Sprintf("client-%d", index), []string{"日本語", "arbitrary\x00\xff", ""}[item%3], item+1, lifecycleFixtureTime)
		}
	}
	return store
}

func TestZiranStoreStatisticsAgainstBaseline(t *testing.T) {
	store := statsFixture(t)
	for _, now := range []time.Time{
		{}, time.Date(2026, 10, 1, 23, 4, 5, 999, time.FixedZone("fixture", -3*60*60)),
		time.Date(2026, 11, 1, 2, 4, 5, 0, time.UTC),
	} {
		got := StoreStats_Usage(store.db, t.Context(), now)
		want, err := store.baselineStatsNodeUsage(t.Context(), now)
		if got.Value != want || !sameIdentityError(got.Error, err) {
			t.Fatal("recent account/client counts or time window changed", got, want, err)
		}
	}
	apps := StoreStats_Apps(store.db, t.Context())
	wantApps, err := store.baselineStatsAppStorageUsage(t.Context())
	if !reflect.DeepEqual(apps.Value, wantApps) || !sameIdentityError(apps.Error, err) {
		t.Fatal("app attribution, counts, names, bytes or ordering changed", apps, wantApps, err)
	}
	for _, path := range []string{store.path, "", ":memory:", filepath.Join(t.TempDir(), "missing"), strings.Repeat("x", 4096)} {
		store.path = path
		got := StoreStats_Storage(store.db, t.Context(), path)
		want, err := store.baselineStatsNodeStorageUsage(t.Context())
		if !reflect.DeepEqual(got.Value, want) || !sameIdentityError(got.Error, err) {
			t.Fatal("file/page totals or unassigned payload/record accounting changed", path, got, want, err)
		}
		gotJSON, _ := json.Marshal(got.Value)
		wantJSON, _ := json.Marshal(want)
		if string(gotJSON) != string(wantJSON) {
			t.Fatal("storage wire shape changed", string(gotJSON), string(wantJSON))
		}
	}
	if got, want := StoreDiagnostics_Health(store.db, t.Context()), store.baselineStatsHealth(t.Context()); !sameIdentityError(got, want) {
		t.Fatal("database health changed", got, want)
	}
	for _, user := range []string{lifecycleAccounts[0], lifecycleAccounts[1], "missing", "' OR 1=1 --", "\x00\xff"} {
		got := StoreDiagnostics_Report(store.db, t.Context(), user)
		want, err := store.baselineStatsSyncDiagnosticReport(t.Context(), user)
		if !reflect.DeepEqual(got.Value, want) || !sameIdentityError(got.Error, err) {
			t.Fatal("diagnostic report changed account scope, counts, limits or data", user, got, want, err)
		}
		gotJSON, _ := json.Marshal(got.Value)
		wantJSON, _ := json.Marshal(want)
		if string(gotJSON) != string(wantJSON) {
			t.Fatal("diagnostics wire bytes changed", user, string(gotJSON), string(wantJSON))
		}
	}
	viewsConnectionReleased(t, store)
}

func TestZiranStoreStatisticsEmptyAndCancelled(t *testing.T) {
	_, store, _ := testServer(t)
	lifecycleExecute(t, store, "DELETE FROM server_app_collections")
	apps := StoreStats_Apps(store.db, t.Context())
	want, err := store.baselineStatsAppStorageUsage(t.Context())
	if apps.Error != nil || err != nil || apps.Value == nil || !reflect.DeepEqual(apps.Value, want) {
		t.Fatal("empty app storage lost its allocated list", apps, want, err)
	}
	for _, test := range statsReadCases() {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		actual := test.actual(store, ctx)
		expected := test.baseline(store, ctx)
		if !reflect.DeepEqual(actual.Value, expected.Value) || actual.Error != context.Canceled || expected.Error != context.Canceled {
			t.Fatal("cancelled storage read changed zero/nil output or error", test.name, actual, expected)
		}
	}
	viewsConnectionReleased(t, store)
}

func TestZiranStoreFileStatisticsAgainstBaseline(t *testing.T) {
	for _, value := range []int64{-9223372036854775808, -1, 0, 1, (1 << 30) - 1, 1 << 30, (1 << 30) + 1, 9223372036854775807} {
		if got, want := StoreStats_FloorGB(value), baselineStatsBytesToFloorGB(value); got != want {
			t.Fatal("GB flooring changed", value, got, want)
		}
		if got, want := StoreStats_UsedText(value), baselineStatsStorageUsedText(value); got != want {
			t.Fatal("public storage text changed", value, got, want)
		}
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "database")
	for _, suffix := range []string{"", "-wal", "-shm"} {
		file, err := os.Create(path + suffix)
		if err != nil {
			t.Fatal(err)
		}
		// Sparse sizes cover GB boundaries without allocating a GB of test data.
		if err := file.Truncate((1 << 30) + int64(len(suffix))); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	loop := filepath.Join(directory, "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{path, link, loop, directory, filepath.Join(directory, "missing"), filepath.Join(path, "not-a-directory"), strings.Repeat("x", 4096), ""} {
		got := StoreStats_FileSetSize(value)
		want, err := baselineStatsSqliteFileSetSize(value)
		if got.Value != want || !sameIdentityError(got.Error, err) || StoreStats_FileSizeOrZero(value) != baselineStatsFileSizeOrZero(value) {
			t.Fatal("file set changed symlink, missing-file or native error behavior", value, got, want, err)
		}
	}
	for _, value := range []string{path, "", ":memory:", filepath.Join(path, "invalid"), filepath.Join(directory, "missing", "db")} {
		before, beforeError := baselineStatsDiskAvailableBytes(value)
		got := StoreStats_AvailableBytes(value)
		after, afterError := baselineStatsDiskAvailableBytes(value)
		if !sameIdentityError(got.Error, beforeError) || !sameIdentityError(got.Error, afterError) {
			t.Fatal("filesystem error changed", value, got, beforeError, afterError)
		}
		if got.Error == nil {
			assertAvailableRange(t, got.Value, before, after)
		}
	}
	_, store, _ := testServer(t)
	before, _ := baselineStatsDiskAvailableBytes(path)
	got := StoreStats_Public(store.db, t.Context(), path)
	after, _ := baselineStatsDiskAvailableBytes(path)
	want, err := store.baselineStatsPublicStats(t.Context(), path)
	if got.Error != nil || err != nil {
		t.Fatal("public statistics failed", got, err)
	}
	assertAvailableRange(t, got.Value.AvailableBytes, max(before-(1<<30), 0), max(after-(1<<30), 0))
	if got.Value.AvailableGB != baselineStatsBytesToFloorGB(got.Value.AvailableBytes) {
		t.Fatal("public available GB changed", got)
	}
	want.AvailableBytes, want.AvailableGB = got.Value.AvailableBytes, got.Value.AvailableGB
	if got.Value != want {
		t.Fatal("public counts, file bytes or GB display changed", got, want)
	}
	for _, value := range []string{loop, filepath.Join(path, "invalid"), filepath.Join(directory, "missing", "db")} {
		got := StoreStats_Public(store.db, t.Context(), value)
		want, err := store.baselineStatsPublicStats(t.Context(), value)
		if got.Value != want || !sameIdentityError(got.Error, err) || got.Value != (PublicStats{}) || err == nil {
			t.Fatal("failed public statistics returned partial data or changed error", value, got, want, err)
		}
	}
}

func assertAvailableRange(t *testing.T, value, before, after int64) {
	t.Helper()
	// Other processes can allocate or release filesystem blocks between samples.
	const slack = 64 << 20
	if value < 0 || value < min(before, after)-slack || value > max(before, after)+slack {
		t.Fatal("available bytes changed the native block calculation", value, before, after)
	}
}

type statsReadCase struct {
	name     string
	actual   func(*Store, context.Context) lifecycleReadResult
	baseline func(*Store, context.Context) lifecycleReadResult
}

func statsReadCases() []statsReadCase {
	now := time.Date(2026, 10, 1, 4, 5, 6, 7, time.FixedZone("fixture", 4*60*60))
	return []statsReadCase{
		{"usage", func(s *Store, ctx context.Context) lifecycleReadResult {
			r := StoreStats_Usage(s.db, ctx, now)
			return lifecycleReadResult{Value: r.Value, Error: r.Error}
		}, func(s *Store, ctx context.Context) lifecycleReadResult {
			v, err := s.baselineStatsNodeUsage(ctx, now)
			return lifecycleReadResult{Value: v, Error: err}
		}},
		{"apps", func(s *Store, ctx context.Context) lifecycleReadResult {
			r := StoreStats_Apps(s.db, ctx)
			return lifecycleReadResult{Value: r.Value, Error: r.Error}
		}, func(s *Store, ctx context.Context) lifecycleReadResult {
			v, err := s.baselineStatsAppStorageUsage(ctx)
			return lifecycleReadResult{Value: v, Error: err}
		}},
		{"storage", func(s *Store, ctx context.Context) lifecycleReadResult {
			r := StoreStats_Storage(s.db, ctx, s.path)
			return lifecycleReadResult{Value: r.Value, Error: r.Error}
		}, func(s *Store, ctx context.Context) lifecycleReadResult {
			v, err := s.baselineStatsNodeStorageUsage(ctx)
			return lifecycleReadResult{Value: v, Error: err}
		}},
		{"counts", func(s *Store, ctx context.Context) lifecycleReadResult {
			r := StoreDiagnostics_TableCounts(s.db, ctx, "user\x00\xff")
			return lifecycleReadResult{Value: r.Value, Error: r.Error}
		}, func(s *Store, ctx context.Context) lifecycleReadResult {
			v, err := s.baselineStatsAccountTableCounts(ctx, "user\x00\xff")
			return lifecycleReadResult{Value: v, Error: err}
		}},
		{"report", func(s *Store, ctx context.Context) lifecycleReadResult {
			r := StoreDiagnostics_Report(s.db, ctx, "user\x00\xff")
			return lifecycleReadResult{Value: r.Value, Error: r.Error}
		}, func(s *Store, ctx context.Context) lifecycleReadResult {
			v, err := s.baselineStatsSyncDiagnosticReport(ctx, "user\x00\xff")
			return lifecycleReadResult{Value: v, Error: err}
		}},
		{"health", func(s *Store, ctx context.Context) lifecycleReadResult {
			return lifecycleReadResult{Error: StoreDiagnostics_Health(s.db, ctx)}
		}, func(s *Store, ctx context.Context) lifecycleReadResult {
			return lifecycleReadResult{Error: s.baselineStatsHealth(ctx)}
		}},
	}
}

type statsDriverPlan struct {
	lifecycleDriverPlan
	rowFailureAt int
	rowMode      string
	quickCheck   string
	schemaExists int64
	emptyApps    bool
}
type statsDriver struct{ plan *statsDriverPlan }
type statsConnection struct {
	lifecycleConnection
	plan *statsDriverPlan
}

func (d statsDriver) Open(string) (driver.Conn, error) {
	return statsConnection{lifecycleConnection{&d.plan.lifecycleDriverPlan}, d.plan}, nil
}

func (c statsConnection) Ping(context.Context) error {
	return c.step("ping", "", nil)
}

func (c statsConnection) step(operation, query string, arguments []driver.NamedValue) error {
	err := c.plan.lifecycleDriverPlan.step(operation, query, arguments)
	if c.plan.steps == c.plan.panicAt {
		panic(c.plan.panicValue)
	}
	return err
}

func (c statsConnection) QueryContext(_ context.Context, query string, arguments []driver.NamedValue) (driver.Rows, error) {
	if err := c.step("query", query, arguments); err != nil {
		return nil, err
	}
	snapshot := c.plan.lifecycleDriverPlan
	snapshot.columns = []string{"value"}
	snapshot.rows = [][]driver.Value{{int64(3)}}
	switch {
	case query == "PRAGMA quick_check":
		snapshot.rows = [][]driver.Value{{c.plan.quickCheck}}
	case strings.Contains(query, "SELECT EXISTS(SELECT 1 FROM sqlite_master"):
		snapshot.rows = [][]driver.Value{{c.plan.schemaExists}}
	case strings.Contains(query, "FROM server_apps a"):
		snapshot.columns = []string{"id", "name", "prefix"}
		snapshot.rows = [][]driver.Value{{"a", "First", "private.*"}, {"a", "Other name", "a"}, {"", "Empty identifier", "empty.*"}, {"z", "Exact", "private.exact"}, {"unused", "No records", "unused.*"}}
		if c.plan.emptyApps {
			snapshot.rows = nil
		}
	case strings.Contains(query, "GROUP BY collection"):
		snapshot.columns = []string{"collection", "count", "bytes"}
		// Intentionally unordered so collection sorting is exercised independently.
		snapshot.rows = [][]driver.Value{{"private.z", int64(2), int64(50)}, {"private.a", int64(3), int64(49)}, {"private.exact", int64(1), int64(99)}, {"empty.value", int64(-1), int64(-7)}, {"unknown\x00\xff", int64(4), int64(0)}}
		if c.plan.emptyApps {
			snapshot.rows = nil
		}
	case strings.Contains(query, "COUNT(*), COALESCE(SUM(LENGTH(client_id)"):
		snapshot.columns = []string{"count", "bytes"}
		snapshot.rows = [][]driver.Value{{int64(3), int64(101)}}
	case strings.Contains(query, "SELECT COUNT(*)"), strings.Contains(query, "SELECT server_version"), strings.Contains(query, "SELECT compacted_through_version"), strings.Contains(query, "SELECT SUM(LENGTH(payload_json))"), strings.Contains(query, "SELECT page_count"):
		// Single scalar queries use the default row.
	default:
		// State hashing and recent client/audit/payload queries see empty lists.
		snapshot.rows = nil
	}
	if c.plan.steps == c.plan.rowFailureAt {
		switch c.plan.rowMode {
		case "empty":
			snapshot.rows = nil
		case "next error":
			snapshot.nextError = c.plan.failure
		case "close error":
			snapshot.closeError = c.plan.failure
		case "rows panic":
			snapshot.rowsPanic = c.plan.panicValue
		case "scan error":
			snapshot.rows = [][]driver.Value{make([]driver.Value, len(snapshot.columns))}
			snapshot.rows[0][0] = struct{ invalid bool }{true}
		case "null":
			snapshot.rows = [][]driver.Value{make([]driver.Value, len(snapshot.columns))}
		}
	}
	return &viewsDriverRows{lifecycleRows{plan: &snapshot}, &c.plan.lifecycleDriverPlan}, nil
}

func statsDriverStore(t *testing.T, plan *statsDriverPlan) *Store {
	t.Helper()
	name := fmt.Sprintf("store-stats-%d", lifecycleDriverSequence.Add(1))
	sql.Register(name, statsDriver{plan})
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return &Store{db: db}
}

func TestZiranStoreStatisticsNativeTraceAndFailures(t *testing.T) {
	sentinel := errors.New("statistics SQL failure")
	panicValue := errors.New("statistics native panic")
	for _, test := range statsReadCases() {
		t.Run(test.name, func(t *testing.T) {
			normal := &statsDriverPlan{quickCheck: "ok", schemaExists: 1}
			store := statsDriverStore(t, normal)
			if r := test.baseline(store, t.Context()); r.Error != nil {
				t.Fatal("invalid native baseline fixture", r)
			}
			steps := normal.steps
			for _, mode := range []string{"normal", "error", "panic", "empty", "next error", "close error", "rows panic", "scan error", "null"} {
				limit := steps
				if mode == "normal" {
					limit = 1
				}
				for step := 1; step <= limit; step++ {
					var plans [2]*statsDriverPlan
					var results [2]lifecycleReadResult
					var panics [2]any
					var inUse [2]int
					for index := range plans {
						plan := &statsDriverPlan{quickCheck: "ok", schemaExists: 1}
						plan.failure, plan.panicValue = sentinel, panicValue
						switch mode {
						case "error":
							plan.failAt = step
						case "panic":
							plan.panicAt = step
						default:
							plan.rowFailureAt, plan.rowMode = step, mode
						}
						plans[index] = plan
						store := statsDriverStore(t, plan)
						panics[index] = boundaryRecover(func() {
							if index == 0 {
								results[index] = test.actual(store, t.Context())
							} else {
								results[index] = test.baseline(store, t.Context())
							}
						})
						inUse[index] = store.db.Stats().InUse
						// A driver panic inside QueryContext or Ping occurs before the
						// application receives a row handle. database/sql itself retains
						// that connection in the original and generated implementations.
						if mode != "panic" && inUse[index] != 0 {
							t.Fatal("statistics retained a database connection", mode, step, index)
						}
					}
					if !reflect.DeepEqual(results[0].Value, results[1].Value) || !sameIdentityError(results[0].Error, results[1].Error) || panics[0] != panics[1] || inUse[0] != inUse[1] || !reflect.DeepEqual(plans[0].trace, plans[1].trace) || plans[0].closed != plans[1].closed {
						t.Fatalf("%s/step %d changed value, error/panic, SQL/arguments or cleanup:\n%#v/%v versus %#v/%v\n%#v\n%#v", mode, step, results[0], panics[0], results[1], panics[1], plans[0].trace, plans[1].trace)
					}
				}
			}
		})
	}
}

func TestZiranStoreHealthAndEmptyNativeApps(t *testing.T) {
	for _, status := range []string{"ok", "corrupt\n日本語\x00\xff", ""} {
		for _, exists := range []int64{0, 1, -1} {
			store := statsDriverStore(t, &statsDriverPlan{quickCheck: status, schemaExists: exists})
			if got, want := StoreDiagnostics_Health(store.db, t.Context()), store.baselineStatsHealth(t.Context()); !sameIdentityError(got, want) {
				t.Fatal("health status or schema-presence error changed", status, exists, got, want)
			}
		}
	}
	store := statsDriverStore(t, &statsDriverPlan{emptyApps: true})
	got := StoreStats_Apps(store.db, t.Context())
	want, err := store.baselineStatsAppStorageUsage(t.Context())
	if got.Error != nil || err != nil || got.Value == nil || !reflect.DeepEqual(got.Value, want) {
		t.Fatal("empty native app list changed", got, want, err)
	}
}
