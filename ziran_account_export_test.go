package main

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func compareAccountExport(t *testing.T, store *Store, ctx context.Context, user string) AccountExportResult {
	t.Helper()
	got := AccountExport_Export(store.Database, ctx, user)
	want, err := store.baselineExportAccount(ctx, user)
	if !reflect.DeepEqual(got.Value, want) || !sameIdentityError(got.Error, err) {
		t.Fatalf("account export = %#v, baseline = %#v, %v", got, want, err)
	}
	actualJSON, actualError := json.Marshal(got.Value)
	expectedJSON, expectedError := json.Marshal(want)
	if !bytes.Equal(actualJSON, expectedJSON) || !sameIdentityError(actualError, expectedError) {
		t.Fatal("account export JSON changed")
	}
	return got
}

func TestZiranAccountExportAgainstBaseline(t *testing.T) {
	path, account := inspectFixture(t)
	database, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	database.SetMaxOpenConns(1)
	store := &Store{Database: database}
	for _, user := range []string{account, strings.Repeat("b", 64), "missing", "", "' OR 1=1 --"} {
		result := compareAccountExport(t, store, context.Background(), user)
		if result.Error == nil && len(result.Value.Tables) != 19 {
			t.Fatalf("account export omitted tables: %d", len(result.Value.Tables))
		}
	}
	for _, alias := range []any{nil, "", "日本語 <>&\x00\xff", "alias"} {
		if _, err := database.Exec("UPDATE server_users SET alias=?,profile_icon=? WHERE user_id_hash=?", alias, 13, account); err != nil {
			t.Fatal(err)
		}
		compareAccountExport(t, store, context.Background(), account)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if result := compareAccountExport(t, store, cancelled, account); !errors.Is(result.Error, context.Canceled) {
		t.Fatal("cancelled export lost native context error")
	}
	expired, finish := context.WithDeadline(context.Background(), time.Now().Add(-time.Hour))
	defer finish()
	compareAccountExport(t, store, expired, account)
	if _, err := database.Exec("DROP TABLE server_app_grants"); err != nil {
		t.Fatal(err)
	}
	if result := compareAccountExport(t, store, context.Background(), account); result.Error == nil || result.Value.Tables != nil {
		t.Fatal("late export error exposed an incomplete response")
	}
	if err := database.Ping(); err != nil {
		t.Fatal("failed export retained the database connection", err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	compareAccountExport(t, store, context.Background(), account)
}

func TestZiranAccountExportRowValuesAgainstBaseline(t *testing.T) {
	var typedNil []byte
	var pointer *int
	values := []any{
		nil, typedNil, []byte{}, []byte("null"), []byte("true"), []byte("42"),
		[]byte("[1,2]"), []byte(`{"text":"日本語 <>&"}`), []byte("{malformed"),
		[]byte{0, 0xff, '\n'}, json.RawMessage(`{"raw":true}`), pointer,
		"text", int64(-9223372036854775808), int64(9223372036854775807),
		float64(1.25), true, map[string]any{"native": 42},
	}
	random := rand.New(rand.NewSource(20261001))
	for index := 0; index < 200; index++ {
		value := make([]byte, random.Intn(120))
		_, _ = random.Read(value)
		values = append(values, value)
	}
	for _, fields := range []map[string]bool{nil, {}, {"payload": false}, {"payload": true}} {
		for _, value := range values {
			got := AccountExport_RowValue("payload", value, fields)
			want := baselineExportRowValue("payload", value, fields)
			if !reflect.DeepEqual(got, want) || reflect.TypeOf(got) != reflect.TypeOf(want) {
				t.Fatalf("row value changed for %T %#v: %#v, baseline %#v", value, value, got, want)
			}
		}
	}
}

func TestZiranAccountExportDynamicRowsAgainstBaseline(t *testing.T) {
	_, store, _ := testServer(t)
	if _, err := store.Database.Exec("CREATE TABLE account_export_fixture(owner TEXT, rank INTEGER, payload BLOB, nullable BLOB, value REAL, text TEXT)"); err != nil {
		t.Fatal(err)
	}
	for index, value := range [][]byte{nil, {}, []byte("null"), []byte(`{"value":42}`), []byte("[true,false]"), []byte("not json"), {0xff, 0}} {
		if _, err := store.Database.Exec("INSERT INTO account_export_fixture VALUES(?,?,?,?,?,?)", "account", index, value, nil, 1.25, "日本語"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Database.Exec("INSERT INTO account_export_fixture VALUES('other',0,X'42',NULL,0,'private')"); err != nil {
		t.Fatal(err)
	}
	for _, user := range []string{"account", "missing", "other", "' OR 1=1 --"} {
		for _, fields := range []map[string]bool{nil, {"payload": true}} {
			query := "SELECT payload,nullable,rank,value,text FROM account_export_fixture WHERE owner=?1 ORDER BY rank DESC"
			got := AccountExport_QueryRows(store.Database, context.Background(), query, user, fields)
			want, err := store.baselineQueryAccountRows(context.Background(), query, user, fields)
			if !reflect.DeepEqual(got.Value, want) || !sameIdentityError(got.Error, err) {
				t.Fatalf("dynamic rows changed: %#v, baseline %#v, %v", got, want, err)
			}
			if user == "missing" && got.Value == nil {
				t.Fatal("empty rows became a nil slice")
			}
		}
	}
	got := AccountExport_QueryRows(store.Database, context.Background(), "SELECT missing FROM account_export_fixture WHERE owner=?1", "account", nil)
	if got.Error == nil || got.Value != nil {
		t.Fatal("query error exposed rows")
	}
}

type accountExportRowsPlan struct {
	columns    []string
	values     []driver.Value
	nextErr    error
	closeErr   error
	panicValue any
	closed     atomic.Int64
}

type accountExportDriver struct{ plan *accountExportRowsPlan }
type accountExportConnection struct{ plan *accountExportRowsPlan }
type accountExportRows struct {
	plan *accountExportRowsPlan
	read bool
}

var accountExportDriverSequence atomic.Uint64

func (d accountExportDriver) Open(string) (driver.Conn, error) {
	return accountExportConnection{d.plan}, nil
}
func (accountExportConnection) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (accountExportConnection) Close() error { return nil }
func (accountExportConnection) Begin() (driver.Tx, error) {
	return nil, errors.New("unexpected transaction")
}
func (c accountExportConnection) QueryContext(_ context.Context, query string, values []driver.NamedValue) (driver.Rows, error) {
	if query != "fixture" || len(values) != 1 || values[0].Value != "account" {
		return nil, errors.New("SQL argument slice changed")
	}
	return &accountExportRows{plan: c.plan}, nil
}
func (r *accountExportRows) Columns() []string { return r.plan.columns }
func (r *accountExportRows) Close() error {
	r.plan.closed.Add(1)
	return r.plan.closeErr
}
func (r *accountExportRows) Next(values []driver.Value) error {
	if r.read {
		if r.plan.nextErr != nil {
			return r.plan.nextErr
		}
		return io.EOF
	}
	r.read = true
	if r.plan.panicValue != nil {
		panic(r.plan.panicValue)
	}
	copy(values, r.plan.values)
	return nil
}

func accountExportDriverStore(t *testing.T, plan *accountExportRowsPlan) *Store {
	t.Helper()
	name := fmt.Sprintf("account-export-%d", accountExportDriverSequence.Add(1))
	sql.Register(name, accountExportDriver{plan})
	database, err := sql.Open(name, "")
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = database.Close() })
	return &Store{Database: database}
}

func TestZiranAccountExportDriverErrorsAndWideRows(t *testing.T) {
	sentinel := errors.New("driver sentinel")
	for _, mode := range []string{"wide", "iteration error", "close error"} {
		t.Run(mode, func(t *testing.T) {
			plan := &accountExportRowsPlan{}
			for index := 0; index < 96; index++ {
				plan.columns = append(plan.columns, fmt.Sprintf("column_%d", index))
				plan.values = append(plan.values, int64(index))
			}
			if mode == "iteration error" {
				plan.nextErr = sentinel
			}
			if mode == "close error" {
				plan.closeErr = sentinel
			}
			store := accountExportDriverStore(t, plan)
			got := AccountExport_QueryRows(store.Database, context.Background(), "fixture", "account", nil)
			want, err := store.baselineQueryAccountRows(context.Background(), "fixture", "account", nil)
			if !reflect.DeepEqual(got.Value, want) || got.Error != err || plan.closed.Load() != 2 {
				t.Fatalf("driver boundary changed: %#v, baseline %#v, %v; closes %d", got, want, err, plan.closed.Load())
			}
			if got.Error != nil && got.Error != sentinel {
				t.Fatal("driver error identity changed")
			}
			if len(got.Value) != 1 || len(got.Value[0]) != 96 {
				t.Fatal("dynamic row scan lost columns or partial output")
			}
		})
	}
}

func TestZiranAccountExportRowsCloseDuringPanic(t *testing.T) {
	sentinel := errors.New("driver panic")
	for _, generated := range []bool{false, true} {
		plan := &accountExportRowsPlan{columns: []string{"value"}, panicValue: sentinel}
		store := accountExportDriverStore(t, plan)
		func() {
			defer func() {
				if recovered := recover(); recovered != sentinel {
					t.Fatalf("driver panic identity changed: %v", recovered)
				}
			}()
			if generated {
				AccountExport_QueryRows(store.Database, context.Background(), "fixture", "account", nil)
			} else {
				store.baselineQueryAccountRows(context.Background(), "fixture", "account", nil)
			}
		}()
		if plan.closed.Load() != 1 {
			t.Fatal("panic retained a live rows iterator")
		}
		if err := store.Database.Ping(); err != nil {
			t.Fatal("panic retained the only connection", err)
		}
	}
}

func TestZiranAccountExportHTTPMatchesBaseline(t *testing.T) {
	for _, mode := range []string{"normal", "missing bearer", "missing account", "mismatched account", "cancelled", "late SQL failure", "response panic"} {
		t.Run(mode, func(t *testing.T) {
			server, store, _ := testServer(t)
			account := newTestIdentity(t, server.Routes(), 0x65)
			request := httptest.NewRequest(http.MethodGet, "/api/v1/account/export", nil)
			request.Header.Set("Authorization", "Bearer "+account.Token)
			switch mode {
			case "missing bearer":
				request.Header.Del("Authorization")
			case "missing account":
				if _, err := store.Database.Exec("DELETE FROM server_users WHERE user_id_hash=?", account.UserID); err != nil {
					t.Fatal(err)
				}
			case "mismatched account":
				request.Header.Set("X-Daochi-User", strings.Repeat("a", 64))
			case "cancelled":
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				request = request.WithContext(ctx)
			case "late SQL failure":
				if _, err := store.Database.Exec("DROP TABLE server_app_grants"); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "response panic" {
				sentinel := errors.New("response panic")
				for _, generated := range []bool{false, true} {
					func() {
						defer func() {
							if recovered := recover(); recovered != sentinel {
								t.Fatalf("response panic identity changed: %v", recovered)
							}
						}()
						writer := accountExportPanickingWriter{sentinel}
						if generated {
							AccountHttp_Export(server.accounts(), writer, request)
						} else {
							server.baselineHandleAccountExport(writer, request)
						}
					}()
				}
				return
			}
			actual, expected := httptest.NewRecorder(), httptest.NewRecorder()
			AccountHttp_Export(server.accounts(), actual, request)
			server.baselineHandleAccountExport(expected, request)
			compareHTTPResponse(t, actual, expected)
		})
	}
}

type accountExportPanickingWriter struct{ failure error }

func (accountExportPanickingWriter) Header() http.Header         { return make(http.Header) }
func (w accountExportPanickingWriter) WriteHeader(int)           { panic(w.failure) }
func (w accountExportPanickingWriter) Write([]byte) (int, error) { panic(w.failure) }
