package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const schemaLegacyUsers = `
CREATE TABLE server_users(user_id_hash TEXT PRIMARY KEY,public_key BLOB NOT NULL,
created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
INSERT INTO server_users(user_id_hash,public_key,created_at,last_seen_at) VALUES('user',x'00','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z');`

func schemaFixture(t *testing.T, setup string) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "schema.db")
	database, err := sql.Open("sqlite3", path+"?_busy_timeout=5000&_foreign_keys=on")
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = database.Close() })
	store := &Store{Database: database, Path: path}
	if setup != "" {
		lifecycleExecute(t, store, setup)
	}
	return store
}

func schemaCatalog(t *testing.T, store *Store) []map[string]any {
	t.Helper()
	result := AccountExport_QueryRows(store.Database, t.Context(), "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE ?1='' ORDER BY type,name", "", nil)
	if result.Error != nil {
		t.Fatal(result.Error)
	}
	// These tables extend the schema; existing-table equivalence remains
	// checked against the released migration below. Their constraints and
	// transactional behavior are exercised by the authorization tests.
	legacy := result.Value[:0]
	for _, entry := range result.Value {
		name := entry["tbl_name"].(string)
		if strings.HasPrefix(name, "server_authorization_") || strings.HasPrefix(name, "server_telegram_") {
			continue
		}
		legacy = append(legacy, entry)
	}
	return legacy
}

func schemaData(t *testing.T, store *Store) map[string]any {
	t.Helper()
	value := make(map[string]any)
	for _, entry := range schemaCatalog(t, store) {
		if entry["type"] != "table" {
			continue
		}
		name := entry["name"].(string)
		// Catalog names come from SQLite; quote even unusual legacy identifiers.
		query := `SELECT * FROM "` + strings.ReplaceAll(name, `"`, `""`) + `" WHERE ?1='' ORDER BY rowid`
		result := AccountExport_QueryRows(store.Database, t.Context(), query, "", nil)
		if result.Error != nil {
			t.Fatal(result.Error)
		}
		value[name] = result.Value
	}
	return value
}

func schemaCompare(t *testing.T, actual, expected *Store) {
	t.Helper()
	if !reflect.DeepEqual(schemaCatalog(t, actual), schemaCatalog(t, expected)) {
		t.Fatal("schema changed table, index, trigger, key or constraint definitions")
	}
	if !reflect.DeepEqual(schemaData(t, actual), schemaData(t, expected)) {
		t.Fatal("schema upgrade changed existing data or backfill values")
	}
	for _, store := range []*Store{actual, expected} {
		viewsConnectionReleased(t, store)
		var foreignKeys int
		if err := store.Database.QueryRow("PRAGMA foreign_keys").Scan(&foreignKeys); err != nil || foreignKeys != 1 {
			t.Fatal("schema migration left foreign keys disabled", foreignKeys, err)
		}
	}
}

func TestZiranStoreSchemaAgainstBaseline(t *testing.T) {
	fixtures := []struct {
		name  string
		setup string
	}{
		{"empty", ""},
		{"legacy users", schemaLegacyUsers},
		{"legacy meditation", schemaLegacyUsers + `
CREATE TABLE server_meditation_logs(id TEXT PRIMARY KEY,user_id_hash TEXT NOT NULL,session_id TEXT NOT NULL,duration_seconds INTEGER NOT NULL DEFAULT 0,completed_at TEXT NOT NULL,server_version INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
INSERT INTO server_meditation_logs VALUES('same-id','user','session',7,'2026-01-01T00:00:00Z',9,'2026-01-01T00:00:00Z');`},
		{"composite meditation", schemaLegacyUsers + `
CREATE TABLE server_meditation_logs(user_id_hash TEXT NOT NULL,id TEXT NOT NULL,session_id TEXT NOT NULL,duration_seconds INTEGER NOT NULL DEFAULT 0,completed_at TEXT NOT NULL,server_version INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(user_id_hash,id));
INSERT INTO server_meditation_logs VALUES('user','same-id','session',7,'2026-01-01T00:00:00Z',9,'2026-01-01T00:00:00Z');`},
		{"legacy social cache", schemaLegacyUsers + `
CREATE TABLE server_social_cache(user_id_hash TEXT NOT NULL,kind TEXT NOT NULL,json TEXT NOT NULL,updated_at TEXT NOT NULL,server_version INTEGER NOT NULL,PRIMARY KEY(user_id_hash,kind));
INSERT INTO server_social_cache VALUES('user','friends','{"names":["日本語"]}','2026-01-01T00:00:00Z',7);`},
		{"legacy mesh", schemaLegacyUsers + `
CREATE TABLE server_mesh_changes(seq INTEGER PRIMARY KEY AUTOINCREMENT,user_id_hash TEXT NOT NULL,collection TEXT NOT NULL,record_id TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
INSERT INTO server_mesh_changes(user_id_hash,collection,record_id,created_at) VALUES('user','private.test','record','2026-01-01T00:00:00Z');`},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			actual, expected := schemaFixture(t, fixture.setup), schemaFixture(t, fixture.setup)
			for repetition := 0; repetition < 2; repetition++ {
				got := StoreSchema_Ensure(actual.Database, t.Context())
				want := expected.baselineSchemaMigrate(t.Context())
				if got != nil || want != nil {
					t.Fatal("schema upgrade failed", got, want)
				}
				schemaCompare(t, actual, expected)
			}
		})
	}
}

func TestZiranStoreSchemaMeditationFailureRollback(t *testing.T) {
	setup := schemaLegacyUsers + `
CREATE TABLE server_meditation_logs(id TEXT PRIMARY KEY,user_id_hash TEXT NOT NULL,session_id TEXT NOT NULL,duration_seconds INTEGER NOT NULL DEFAULT 0,completed_at TEXT NOT NULL,server_version INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
INSERT INTO server_meditation_logs VALUES('id','user','session',7,'fixed',9,'fixed');
CREATE TABLE server_meditation_logs_new(unrelated TEXT);`
	actual, expected := schemaFixture(t, setup), schemaFixture(t, setup)
	before := schemaData(t, actual)
	got := StoreSchema_MeditationKey(actual.Database, t.Context())
	want := expected.baselineSchemaMigrateMeditationLogPrimaryKey(t.Context())
	if got == nil || !sameIdentityError(got, want) {
		t.Fatal("meditation migration failure changed", got, want)
	}
	schemaCompare(t, actual, expected)
	if !reflect.DeepEqual(before, schemaData(t, actual)) {
		t.Fatal("failed primary-key migration did not roll back existing data")
	}
}

func TestZiranStoreSchemaCancellationAndBoundColumnNames(t *testing.T) {
	actual, expected := schemaFixture(t, ""), schemaFixture(t, "")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	got, want := StoreSchema_Ensure(actual.Database, ctx), expected.baselineSchemaMigrate(ctx)
	if got != context.Canceled || got != want || !reflect.DeepEqual(schemaCatalog(t, actual), schemaCatalog(t, expected)) {
		t.Fatal("cancelled schema migration changed failure identity or created objects", got, want)
	}
	lifecycleExecute(t, actual, "CREATE TABLE target(id INTEGER)")
	lifecycleExecute(t, expected, "CREATE TABLE target(id INTEGER)")
	for _, name := range []string{"target", "target'); DROP TABLE target; --", "missing", "\x00\xff"} {
		got = StoreSchema_AddColumn(actual.Database, t.Context(), name, "id", "ALTER TABLE target ADD COLUMN added INTEGER")
		want = expected.baselineSchemaAddColumnIfMissing(t.Context(), name, "id", "ALTER TABLE target ADD COLUMN added INTEGER")
		if !sameIdentityError(got, want) || !reflect.DeepEqual(schemaCatalog(t, actual), schemaCatalog(t, expected)) {
			t.Fatal("column lookup changed bound-name behavior", name, got, want)
		}
	}
}

func TestZiranStoreOpenAgainstBaseline(t *testing.T) {
	for _, mode := range []string{"empty", "missing directory", "directory", "read only"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "open.db")
			baselinePath := filepath.Join(t.TempDir(), "open.db")
			switch mode {
			case "missing directory":
				path = filepath.Join(t.TempDir(), "missing", "open.db")
				baselinePath = path
			case "directory":
				path = t.TempDir()
				baselinePath = path
			case "read only":
				store := schemaFixture(t, "")
				lifecycleExecute(t, store, "CREATE TABLE preserved(value TEXT)")
				path = "file:" + store.Path + "?mode=ro&unused="
				baselinePath = path
			}
			got := StoreOpen_Open(path)
			want, err := baselineSchemaOpenStore(baselinePath)
			if !sameIdentityError(got.Error, err) || (got.Value == nil) != (want == nil) {
				t.Fatal("database startup changed error or nil result", got, want, err)
			}
			if got.Value == nil {
				return
			}
			t.Cleanup(func() { _ = got.Value.Close() })
			t.Cleanup(func() { _ = want.Close() })
			if got.Value.Stats().MaxOpenConnections != 1 {
				t.Fatal("startup changed connection limit")
			}
			actual := &Store{Database: got.Value}
			if !reflect.DeepEqual(schemaCatalog(t, actual), schemaCatalog(t, want)) || !reflect.DeepEqual(schemaOpenSnapshot(t, actual), schemaOpenSnapshot(t, want)) {
				t.Fatal("startup changed initialized schema or seeded data")
			}
			viewsConnectionReleased(t, actual)
			viewsConnectionReleased(t, want)
		})
	}
}

func schemaOpenSnapshot(t *testing.T, store *Store) map[string]any {
	t.Helper()
	value := schemaData(t, store)
	for _, table := range value {
		for _, row := range table.([]map[string]any) {
			for _, column := range []string{"created_at", "updated_at"} {
				if stamp, ok := row[column].(string); ok && stamp != "" {
					if _, err := time.Parse(CanonicalTimestampLayout, stamp); err != nil {
						if _, err := time.Parse("2006-01-02 15:04:05", stamp); err != nil {
							t.Fatalf("startup timestamp %s changed format: %q", column, stamp)
						}
					}
					row[column] = "<wall clock>"
				}
			}
		}
	}
	return value
}

type schemaDriver struct {
	plan      *lifecycleDriverPlan
	composite bool
	duplicate bool
}
type schemaConnection struct {
	lifecycleConnection
	composite bool
	duplicate bool
}

func (driver schemaDriver) Open(string) (driver.Conn, error) {
	return schemaConnection{lifecycleConnection{driver.plan}, driver.composite, driver.duplicate}, nil
}

func (connection schemaConnection) ExecContext(ctx context.Context, query string, arguments []driver.NamedValue) (driver.Result, error) {
	if err := connection.plan.step("exec", query, arguments); err != nil {
		return nil, err
	}
	if connection.duplicate && strings.HasPrefix(query, "ALTER TABLE") {
		return nil, errors.New("duplicate column name: existing")
	}
	return lifecycleResult{connection.plan}, nil
}

func (connection schemaConnection) QueryContext(ctx context.Context, query string, arguments []driver.NamedValue) (driver.Rows, error) {
	if err := connection.plan.step("query", query, arguments); err != nil {
		return nil, err
	}
	snapshot := *connection.plan
	snapshot.columns = []string{"value"}
	snapshot.rows = [][]driver.Value{{int64(1)}}
	if query == "PRAGMA table_info(server_meditation_logs)" {
		userKey, idKey := int64(0), int64(1)
		if connection.composite {
			userKey, idKey = 1, 2
		}
		snapshot.columns = []string{"cid", "name", "type", "notnull", "default", "pk"}
		snapshot.rows = [][]driver.Value{
			{int64(0), "user_id_hash", "TEXT", int64(1), nil, userKey},
			{int64(1), "id", "TEXT", int64(1), "'default'", idKey},
		}
	}
	return &viewsDriverRows{lifecycleRows{plan: &snapshot}, connection.plan}, nil
}

func schemaDriverStore(t *testing.T, plan *lifecycleDriverPlan, composite, duplicate bool) *Store {
	t.Helper()
	name := fmt.Sprintf("store-schema-%d", lifecycleDriverSequence.Add(1))
	sql.Register(name, schemaDriver{plan, composite, duplicate})
	database, err := sql.Open(name, "")
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = database.Close() })
	return &Store{Database: database}
}

func TestZiranStoreSchemaNativeTraceAndFailures(t *testing.T) {
	sentinel := errors.New("schema SQL failure")
	panicValue := errors.New("schema SQL panic")
	for _, composite := range []bool{false, true} {
		for _, mode := range []string{"normal", "error", "panic", "duplicate column", "next error", "close error"} {
			steps := 1
			if mode == "error" || mode == "panic" {
				steps = 65
			}
			for step := 1; step <= steps; step++ {
				var plans [2]*lifecycleDriverPlan
				var failures [2]error
				var panics [2]any
				for index := range plans {
					plan := &lifecycleDriverPlan{failure: sentinel, panicValue: panicValue}
					switch mode {
					case "error":
						plan.failAt = step
					case "panic":
						plan.panicAt = step
					case "next error":
						plan.nextError = sentinel
					case "close error":
						plan.closeError = sentinel
					}
					plans[index] = plan
					store := schemaDriverStore(t, plan, composite, mode == "duplicate column")
					panics[index] = boundaryRecover(func() {
						if index == 0 {
							failures[index] = StoreSchema_Ensure(store.Database, t.Context())
						} else {
							failures[index] = store.baselineSchemaMigrate(t.Context())
						}
					})
					viewsConnectionReleased(t, store)
				}
				if failures[0] != failures[1] || panics[0] != panics[1] || !reflect.DeepEqual(schemaLegacyTrace(plans[0].trace), schemaLegacyTrace(plans[1].trace)) || plans[0].closed != plans[1].closed {
					t.Fatalf("composite %t/%s/step %d changed SQL, failure or cursor cleanup:\n%v/%v versus %v/%v\n%#v\n%#v", composite, mode, step, failures[0], panics[0], failures[1], panics[1], plans[0].trace, plans[1].trace)
				}
			}
		}
	}
}

func TestZiranStoreSchemaClosesMeditationRowsOnPanic(t *testing.T) {
	panicValue := errors.New("schema row panic")
	plan := &lifecycleDriverPlan{rowsPanic: panicValue}
	store := schemaDriverStore(t, plan, true, false)
	got := boundaryRecover(func() { _ = StoreSchema_MeditationKey(store.Database, t.Context()) })
	if got != panicValue || plan.closed != 1 {
		t.Fatal("schema row panic changed identity or retained its cursor", got, plan)
	}
	viewsConnectionReleased(t, store)
}

// Ignore only the appended authorization DDL when comparing released SQL
// behavior. Keep every original statement, ordering, binding and failure.
func schemaLegacyTrace(trace []lifecycleTrace) []lifecycleTrace {
	result := append([]lifecycleTrace(nil), trace...)
	for index := range result {
		if result[index].Operation == "exec" {
			before, _, _ := strings.Cut(result[index].Query, "CREATE TABLE IF NOT EXISTS server_authorization_requests")
			result[index].Query = strings.TrimSpace(before)
		}
	}
	return result
}
