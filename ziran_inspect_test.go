package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func inspectFixture(t *testing.T) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "inspect.db")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	userID := strings.Repeat("a", 64)
	statements := []struct {
		query string
		args  []any
	}{
		{"INSERT INTO server_users(user_id_hash,public_key,created_at,last_seen_at) VALUES(?,?,?,?)", []any{userID, bytes.Repeat([]byte{0xab}, 1312), "2026-01-02", "2026-09-30"}},
		{"INSERT INTO server_users(user_id_hash,public_key,created_at,last_seen_at) VALUES(?,?,?,?)", []any{strings.Repeat("b", 64), []byte{1, 2}, "2026-01-01", "2026-09-29"}},
		{"INSERT INTO server_sync_state VALUES(?,?)", []any{userID, int64(9223372036854775807)}},
		{"INSERT INTO server_sync_compaction(user_id_hash,compacted_through_version) VALUES(?,?)", []any{userID, int64(41)}},
		{"INSERT INTO server_encrypted_payloads(user_id_hash,payload_json) VALUES(?,?)", []any{userID, `{"nonce":"secret","ciphertext":"private"}`}},
	}
	for _, statement := range statements {
		if _, err := store.Database.Exec(statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	for index := 0; index < 55; index++ {
		if _, err := store.Database.Exec(`INSERT INTO server_habits(user_id_hash,id,name,sync_mode,sync_activity,sort_order,deleted_at,updated_at)
VALUES(?,?,?,?,?,?,?,?)`, userID, fmt.Sprintf("habit-%02d", index), "Meditate\n\"日本語\"\\\x00", index%3, index%4, 54-index, index%2, "2026-09-30T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}
	for index := 0; index < 28; index++ {
		if _, err := store.Database.Exec(`INSERT INTO server_sessions(user_id_hash,id,started_at,local_date,topic,activity,deleted_at,updated_at)
VALUES(?,?,?,?,?,?,?,?)`, userID, fmt.Sprintf("session-%02d", index), fmt.Sprintf("2026-09-%02d", index+1), 20260901+index, "topic=日本語", index%3, index%2, "2026-09-30"); err != nil {
			t.Fatal(err)
		}
	}
	for index := 0; index < 14; index++ {
		var login any
		var synced any
		if index%3 == 1 {
			login, synced = "", ""
		} else if index%3 == 2 {
			login, synced = "2026-09-29", "2026-09-30"
		}
		if _, err := store.Database.Exec(`INSERT INTO server_clients(user_id_hash,client_id,last_seen_at,last_login_at,last_sync_at,protocol_version,last_seen_server_version,last_client_clock)
VALUES(?,?,?,?,?,?,?,?)`, userID, fmt.Sprintf("client-%02d", index), "2026-09-30", login, synced, index, int64(index), -int64(index)); err != nil {
			t.Fatal(err)
		}
	}
	for index := 0; index < 10; index++ {
		reason := ""
		if index%2 != 0 {
			reason = "changed"
		}
		if _, err := store.Database.Exec(`INSERT INTO server_sync_audit(user_id_hash,client_id,protocol_version,server_version,remote_ops,full_snapshot_required,snapshot_reason,encrypted_payload,encrypted_payload_bytes,created_at)
VALUES(?,?,?,?,?,?,?,?,?,?)`, userID, fmt.Sprintf("audit-%02d", index), index, int64(index), index+1, index%2, reason, index%2, int64(index*10), "2026-09-30"); err != nil {
			t.Fatal(err)
		}
	}
	return path, userID
}

func compareInspectRun(t *testing.T, ctx context.Context, path string, args []string, full bool) {
	t.Helper()
	var actual, expected bytes.Buffer
	got := Inspect_Run(ctx, args, InspectOptions{DBPath: path, Full: full, Out: &actual})
	want := baselineRunInspect(ctx, args, InspectOptions{DBPath: path, Full: full, Out: &expected})
	if actual.String() != expected.String() || !sameIdentityError(got, want) || reflect.TypeOf(got) != reflect.TypeOf(want) {
		t.Fatalf("inspect %q full=%v\nactual error: %v\nbaseline error: %v\nactual:\n%s\nbaseline:\n%s", args, full, got, want, actual.String(), expected.String())
	}
	for _, sentinel := range []error{context.Canceled, context.DeadlineExceeded, sql.ErrNoRows} {
		if errors.Is(got, sentinel) != errors.Is(want, sentinel) {
			t.Fatalf("inspect %q changed native error identity for %v", args, sentinel)
		}
	}
}

func TestZiranInspectCommandsAgainstBaseline(t *testing.T) {
	path, userID := inspectFixture(t)
	for _, full := range []bool{false, true} {
		for _, args := range [][]string{
			nil,
			{},
			{"summary"},
			{"summary", "ignored"},
			{"users"},
			{"users", "ignored"},
			{"user", userID},
			{"doctor", userID},
			{"--full", "user", userID},
			{"--full=false", "doctor", userID},
			{"user", " \u2003" + strings.ToUpper(userID) + "\t"},
			{"doctor", " \u2003" + strings.ToUpper(userID) + "\t"},
			{"user", strings.Repeat("c", 64)},
			{"doctor", strings.Repeat("c", 64)},
			{"user", "invalid"},
			{"doctor", "\xff\x00"},
			{"user"},
			{"doctor"},
			{"user", userID, "extra"},
			{"doctor", userID, "extra"},
			{"unknown"},
			{"\xff\x00"},
			{"--unknown"},
			{"--db"},
			{"--full=invalid"},
			{"--help"},
			{"--db", path, "users"},
			{"--", "users"},
		} {
			compareInspectRun(t, context.Background(), path, args, full)
		}
	}
	for _, args := range [][]string{{"summary"}, {"users"}, {"user", userID}, {"doctor", userID}} {
		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		compareInspectRun(t, cancelled, path, args, false)
		expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		compareInspectRun(t, expired, path, args, false)
		stop()
	}
	var out bytes.Buffer
	if err := Inspect_Run(context.Background(), []string{"user", userID}, InspectOptions{DBPath: path, Out: &out}); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), "habit-") != 50 || strings.Count(out.String(), "session-") != 25 || strings.Contains(out.String(), userID) {
		t.Fatal("inspection changed row limits or leaked the full account ID")
	}
	out.Reset()
	if err := Inspect_Run(context.Background(), []string{"doctor", userID}, InspectOptions{DBPath: path, Out: &out}); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), "client-") != 12 || strings.Count(out.String(), "audit-") != 8 || strings.Contains(out.String(), "ciphertext") || strings.Contains(out.String(), "private") {
		t.Fatal("doctor changed row limits or exposed an encrypted payload")
	}
}

func TestZiranInspectOpenReadOnlyAndErrorsAgainstBaseline(t *testing.T) {
	path, _ := inspectFixture(t)
	directory := t.TempDir()
	missing := filepath.Join(directory, "missing.db")
	for _, name := range []string{path, missing, directory, "\x00", "file:invalid?mode=invalid"} {
		got := Inspect_Open(name)
		want, err := baselineOpenInspectDB(name)
		if !sameIdentityError(got.Error, err) || (got.Value == nil) != (want == nil) || reflect.TypeOf(got.Error) != reflect.TypeOf(err) {
			t.Fatalf("open %q = %#v, baseline %v, %v", name, got, want, err)
		}
		if got.Value == nil {
			continue
		}
		if got.Value.Stats().MaxOpenConnections != 1 {
			t.Fatal("inspection permits concurrent open connections")
		}
		_, actual := got.Value.Exec("DELETE FROM server_users")
		_, expected := want.Exec("DELETE FROM server_users")
		if actual == nil || !sameIdentityError(actual, expected) {
			t.Fatal("inspection database is not read-only", actual, expected)
		}
		_ = got.Value.Close()
		_ = want.Close()
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("inspection created a missing database", err)
	}
	t.Setenv("DAOCHI_DB", path)
	compareInspectRun(t, context.Background(), "", nil, false)
	t.Setenv("DAOCHI_DB", " \u2003"+path+"\t")
	compareInspectRun(t, context.Background(), "", nil, false)
	compareInspectRun(t, context.Background(), missing, []string{"unknown"}, false)
}

func TestZiranInspectNativeWriterAndOptionsAgainstBaseline(t *testing.T) {
	actual := reflect.TypeOf(InspectOptions{})
	expected := reflect.TypeOf(struct {
		DBPath string
		Full   bool
		Out    io.Writer
	}{})
	if actual.NumField() != expected.NumField() {
		t.Fatal("inspection options field count changed")
	}
	for index := 0; index < expected.NumField(); index++ {
		got, want := actual.Field(index), expected.Field(index)
		if got.Name != want.Name || got.Type != want.Type || got.Tag != want.Tag {
			t.Fatal("inspection options native layout changed", got, want)
		}
	}
	path, _ := inspectFixture(t)
	functions := []func(context.Context, []string, InspectOptions) error{Inspect_Run, baselineRunInspect}
	var outputs [2]string
	for implementation, function := range functions {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		func() {
			original := os.Stdout
			os.Stdout = writer
			defer func() { os.Stdout = original }()
			err = function(context.Background(), nil, InspectOptions{DBPath: path})
		}()
		_ = writer.Close()
		data, readError := io.ReadAll(reader)
		_ = reader.Close()
		if err != nil || readError != nil {
			t.Fatal(err, readError)
		}
		outputs[implementation] = string(data)
	}
	if outputs[0] != outputs[1] || !strings.HasPrefix(outputs[0], "Daochi data summary\n") {
		t.Fatal("default standard output changed", outputs)
	}
	var panics [2]any
	for implementation, function := range functions {
		func() {
			defer func() { panics[implementation] = recover() }()
			var typedNil *bytes.Buffer
			_ = function(context.Background(), nil, InspectOptions{DBPath: path, Out: typedNil})
		}()
	}
	if panics[0] == nil || reflect.TypeOf(panics[0]) != reflect.TypeOf(panics[1]) || fmt.Sprint(panics[0]) != fmt.Sprint(panics[1]) {
		t.Fatal("typed nil writer was treated as a nil interface", panics)
	}
}

func TestZiranInspectHelpersAgainstBaseline(t *testing.T) {
	values := []string{"", "0123456789abcdef", "0123456789abcdefg", strings.Repeat("a", 64), "日本語の識別子は長い文字列です", "\xff\x00"}
	random := rand.New(rand.NewSource(930))
	for index := 0; index < 1000; index++ {
		data := make([]byte, random.Intn(120))
		_, _ = random.Read(data)
		values = append(values, string(data))
	}
	for _, value := range values {
		for _, full := range []bool{false, true} {
			if got, want := Inspect_RedactID(value, full), baselineRedactID(value, full); got != want {
				t.Fatalf("redaction %q full=%v = %q, baseline %q", value, full, got, want)
			}
			for _, valid := range []bool{false, true} {
				nullable := sql.NullString{String: value, Valid: valid}
				if got, want := Inspect_NullText(nullable), baselineNullText(nullable); got != want {
					t.Fatal("nullable text changed", got, want)
				}
			}
		}
		for _, fallback := range []string{"", "-", "日本語"} {
			if got, want := Inspect_EmptyText(value, fallback), baselineEmptyText(value, fallback); got != want {
				t.Fatal("empty text changed", got, want)
			}
		}
	}
}

func TestZiranInspectWarningBoundariesAgainstBaseline(t *testing.T) {
	for _, fixture := range []struct {
		name      string
		clients   int
		payloads  int
		bytes     int64
		snapshots int
		warnings  int
	}{
		{"none", 0, 0, 0, 0, 0},
		{"below limits", 0, 1000, 64 << 20, 2, 0},
		{"legacy", 2, 0, 0, 0, 1},
		{"payload count", 0, 1001, 0, 0, 1},
		{"payload bytes", 0, 1, (64 << 20) + 1, 0, 1},
		{"snapshots", 0, 0, 0, 3, 1},
		{"all warnings", 2, 1001, (64 << 20) + 1, 12, 4},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			database, err := sql.Open("sqlite3", ":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			// LENGTH(zeroblob) supplies the boundary without allocating a 64 MiB fixture.
			queries := []string{
				fmt.Sprintf(`CREATE VIEW server_clients AS WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<%d)
SELECT 'user' AS user_id_hash, 4 AS protocol_version FROM n WHERE x<=%d`, fixture.clients, fixture.clients),
				fmt.Sprintf(`CREATE VIEW server_encrypted_payloads AS WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<%d)
SELECT 'user' AS user_id_hash, CASE WHEN x=1 THEN zeroblob(%d) ELSE '' END AS payload_json FROM n WHERE x<=%d`, fixture.payloads, fixture.bytes, fixture.payloads),
				fmt.Sprintf(`CREATE VIEW server_sync_audit AS WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<%d)
SELECT 'user' AS user_id_hash, x AS id, 1 AS full_snapshot_required FROM n WHERE x<=%d`, fixture.snapshots, fixture.snapshots),
			}
			for _, query := range queries {
				if _, err := database.Exec(query); err != nil {
					t.Fatal(err)
				}
			}
			var actual, expected bytes.Buffer
			got := Inspect_DoctorWarnings(context.Background(), database, &actual, "user")
			want := baselineInspectDoctorWarnings(context.Background(), database, &expected, "user")
			if got != nil || want != nil || actual.String() != expected.String() {
				t.Fatalf("warning output changed: %v, %v\n%s\n%s", got, want, actual.String(), expected.String())
			}
			if fixture.warnings == 0 {
				if actual.String() != "\nWarnings\n- none\n" {
					t.Fatal("empty warning output changed")
				}
			} else if strings.Count(actual.String(), "- ") != fixture.warnings {
				t.Fatal("warning boundary changed", actual.String())
			}
		})
	}
}

type inspectFunction func(context.Context, *sql.DB, io.Writer, string) error

func inspectFunctions(full bool) [][2]inspectFunction {
	return [][2]inspectFunction{
		{func(ctx context.Context, db *sql.DB, out io.Writer, _ string) error {
			return Inspect_Summary(ctx, db, out)
		}, func(ctx context.Context, db *sql.DB, out io.Writer, _ string) error {
			return baselineInspectSummary(ctx, db, out)
		}},
		{func(ctx context.Context, db *sql.DB, out io.Writer, _ string) error {
			return Inspect_Users(ctx, db, out, full)
		}, func(ctx context.Context, db *sql.DB, out io.Writer, _ string) error {
			return baselineInspectUsers(ctx, db, out, full)
		}},
		{func(ctx context.Context, db *sql.DB, out io.Writer, user string) error {
			return Inspect_User(ctx, db, out, user, full)
		}, func(ctx context.Context, db *sql.DB, out io.Writer, user string) error {
			return baselineInspectUser(ctx, db, out, user, full)
		}},
		{func(ctx context.Context, db *sql.DB, out io.Writer, user string) error {
			return Inspect_Doctor(ctx, db, out, user, full)
		}, func(ctx context.Context, db *sql.DB, out io.Writer, user string) error {
			return baselineInspectDoctor(ctx, db, out, user, full)
		}},
		{Inspect_DoctorWarnings, baselineInspectDoctorWarnings},
		{Inspect_DoctorClients, baselineInspectDoctorClients},
		{Inspect_DoctorAudit, baselineInspectDoctorAudit},
		{Inspect_UserHabits, baselineInspectUserHabits},
		{Inspect_UserSessions, baselineInspectUserSessions},
	}
}

func TestZiranInspectQueryFailuresAgainstBaseline(t *testing.T) {
	for _, mode := range []string{"empty schema", "closed database", "scan failure", "ignored version errors"} {
		t.Run(mode, func(t *testing.T) {
			path, userID := inspectFixture(t)
			opened := Inspect_Open(path)
			if opened.Error != nil {
				t.Fatal(opened.Error)
			}
			database := opened.Value
			defer database.Close()
			if mode == "empty schema" || mode == "scan failure" {
				_ = database.Close()
				var err error
				database, err = sql.Open("sqlite3", ":memory:")
				if err != nil {
					t.Fatal(err)
				}
				defer database.Close()
				database.SetMaxOpenConns(1)
			}
			if mode == "scan failure" {
				for _, query := range []string{
					"CREATE TABLE server_users(user_id_hash,public_key,created_at,last_seen_at)",
					"INSERT INTO server_users VALUES('" + userID + "',x'0102',NULL,NULL)",
					"CREATE TABLE server_clients(user_id_hash,client_id,protocol_version,last_login_at,last_sync_at,last_seen_server_version,last_client_clock,last_seen_at)",
					"INSERT INTO server_clients VALUES('" + userID + "','client','invalid',NULL,NULL,0,0,'date')",
				} {
					if _, err := database.Exec(query); err != nil {
						t.Fatal(err)
					}
				}
			}
			if mode == "ignored version errors" {
				writable, err := sql.Open("sqlite3", path)
				if err != nil {
					t.Fatal(err)
				}
				for _, query := range []string{"DROP TABLE server_sync_state", "DROP TABLE server_sync_compaction"} {
					if _, err := writable.Exec(query); err != nil {
						t.Fatal(err)
					}
				}
				_ = writable.Close()
			}
			if mode == "closed database" {
				_ = database.Close()
			}
			for index, pair := range inspectFunctions(false) {
				var actual, expected bytes.Buffer
				got := pair[0](context.Background(), database, &actual, userID)
				want := pair[1](context.Background(), database, &expected, userID)
				if actual.String() != expected.String() || !sameIdentityError(got, want) || reflect.TypeOf(got) != reflect.TypeOf(want) {
					t.Fatalf("function %d changed error/output: %v, %v\n%s\n%s", index, got, want, actual.String(), expected.String())
				}
				if database.Stats().InUse != 0 {
					t.Fatal("query failure left a connection in use")
				}
			}
		})
	}
}

type inspectFailingWriter struct {
	buffer bytes.Buffer
	error  error
	panic  bool
	writes int
	after  int
}

func (writer *inspectFailingWriter) Write(data []byte) (int, error) {
	writer.writes++
	if writer.writes > writer.after {
		if writer.panic {
			panic(writer.error)
		}
		return 0, writer.error
	}
	return writer.buffer.Write(data)
}

func TestZiranInspectWriterCleanupAgainstBaseline(t *testing.T) {
	path, userID := inspectFixture(t)
	opened := Inspect_Open(path)
	if opened.Error != nil {
		t.Fatal(opened.Error)
	}
	database := opened.Value
	defer database.Close()
	sentinel := errors.New("inspection output failure")
	for index, pair := range inspectFunctions(false) {
		for _, panicking := range []bool{false, true} {
			for _, after := range []int{0, 1, 2} {
				var results [2]error
				var panics [2]any
				var buffers [2]string
				for implementation, function := range pair {
					writer := &inspectFailingWriter{error: sentinel, panic: panicking, after: after}
					func() {
						defer func() { panics[implementation] = recover() }()
						results[implementation] = function(context.Background(), database, writer, userID)
					}()
					buffers[implementation] = writer.buffer.String()
					if database.Stats().InUse != 0 {
						t.Fatalf("function %d left its connection in use after writer failure", index)
					}
				}
				if !sameIdentityError(results[0], results[1]) || panics[0] != panics[1] || buffers[0] != buffers[1] {
					t.Fatalf("function %d writer panic=%v after=%d changed result or cleanup", index, panicking, after)
				}
			}
		}
	}
}
