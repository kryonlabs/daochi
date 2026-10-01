package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mattn/go-sqlite3"
)

// Exercise the real SQLite schema while failing an individual native SQL call.
type syncHTTPDriver struct{ plan *lifecycleDriverPlan }
type syncHTTPConnection struct {
	driver.Conn
	plan *lifecycleDriverPlan
}
type syncHTTPTransaction struct {
	driver.Tx
	plan *lifecycleDriverPlan
}

func (wrapper syncHTTPDriver) Open(source string) (driver.Conn, error) {
	connection, err := (&sqlite3.SQLiteDriver{}).Open(source)
	if err != nil {
		return nil, err
	}
	return syncHTTPConnection{connection, wrapper.plan}, nil
}

func (connection syncHTTPConnection) QueryContext(ctx context.Context, query string, arguments []driver.NamedValue) (driver.Rows, error) {
	if err := connection.plan.step("query", query, arguments); err != nil {
		return nil, err
	}
	return connection.Conn.(driver.QueryerContext).QueryContext(ctx, query, arguments)
}

func (connection syncHTTPConnection) ExecContext(ctx context.Context, query string, arguments []driver.NamedValue) (driver.Result, error) {
	if err := connection.plan.step("exec", query, arguments); err != nil {
		return nil, err
	}
	return connection.Conn.(driver.ExecerContext).ExecContext(ctx, query, arguments)
}

func (connection syncHTTPConnection) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	if err := connection.plan.step("begin", "", nil); err != nil {
		return nil, err
	}
	transaction, err := connection.Conn.(driver.ConnBeginTx).BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return syncHTTPTransaction{transaction, connection.plan}, nil
}

func (transaction syncHTTPTransaction) Commit() error {
	if err := transaction.plan.step("commit", "", nil); err != nil {
		// database/sql considers a failed commit terminal. Model a driver that
		// rolls back its native transaction before returning the commit error.
		_ = transaction.Tx.Rollback()
		return err
	}
	return transaction.Tx.Commit()
}

func (transaction syncHTTPTransaction) Rollback() error {
	_ = transaction.plan.step("rollback", "", nil)
	return transaction.Tx.Rollback()
}

func syncHTTPTrackStore(t *testing.T, store *Store, plan *lifecycleDriverPlan) {
	t.Helper()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("sync-http-%d", lifecycleDriverSequence.Add(1))
	sql.Register(name, syncHTTPDriver{plan})
	database, err := sql.Open(name, store.Path+"?_busy_timeout=5000&_foreign_keys=on")
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	store.Database = database
}

func syncHTTPState(t *testing.T, store *Store) map[string]any {
	t.Helper()
	names := AccountExport_QueryRows(store.Database, t.Context(), "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND ?1='' ORDER BY name", "", nil)
	if names.Error != nil {
		t.Fatal(names.Error)
	}
	result := map[string]any{}
	for _, table := range names.Value {
		name := table["name"].(string)
		rows := AccountExport_QueryRows(store.Database, t.Context(), "SELECT * FROM "+name+" WHERE ?1='' ORDER BY rowid", "", nil)
		if rows.Error != nil {
			t.Fatal(rows.Error)
		}
		for _, row := range rows.Value {
			for column, value := range row {
				if !strings.HasSuffix(column, "_at") {
					continue
				}
				if stamp, ok := value.(string); ok && stamp != "" {
					validateSyncHTTPTime(t, stamp)
					row[column] = "<validated timestamp>"
				}
			}
		}
		result[name] = rows.Value
	}
	return result
}

func validateSyncHTTPTime(t *testing.T, stamp string) {
	t.Helper()
	if _, err := time.Parse(CanonicalTimestampLayout, stamp); err != nil {
		if _, err := time.Parse("2006-01-02 15:04:05", stamp); err != nil {
			t.Fatal("sync changed timestamp format", stamp)
		}
	}
}

func normalizeSyncHTTPResponse(t *testing.T, recorder *httptest.ResponseRecorder, before, after time.Time, bootstrap bool) {
	t.Helper()
	if recorder.Body.Len() == 0 {
		return
	}
	var value any
	if err := json.Unmarshal(recorder.Body.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	data := recorder.Body.Bytes()
	var visit func(any)
	visit = func(value any) {
		switch value := value.(type) {
		case map[string]any:
			for key, child := range value {
				dynamicSocial := (value["kind"] == "friends.list" || value["kind"] == "friends.requests") && key == "updated_at"
				if key == "created_at" || dynamicSocial {
					if stamp, ok := child.(string); ok && stamp != "" {
						validateSyncHTTPTime(t, stamp)
						if dynamicSocial {
							parsed, _ := time.Parse(CanonicalTimestampLayout, stamp)
							if parsed.Before(before) || parsed.After(after) {
								t.Fatal("authoritative social timestamp is outside the request", stamp)
							}
						}
						data = bytes.ReplaceAll(data, []byte(stamp), []byte("<validated timestamp>"))
					}
				}
				visit(child)
			}
		case []any:
			for _, child := range value {
				visit(child)
			}
		}
	}
	visit(value)
	if bootstrap && recorder.Code == http.StatusOK {
		epoch := int64(value.(map[string]any)["legacy_projection_epoch"].(float64))
		if epoch < before.Unix() || epoch > after.Unix() {
			t.Fatal("bootstrap legacy projection timestamp is outside the request", epoch)
		}
		data = bytes.ReplaceAll(data, []byte(fmt.Sprintf(`"legacy_projection_epoch":%d`, epoch)), []byte(`"legacy_projection_epoch":0`))
	}
	recorder.Body.Reset()
	_, _ = recorder.Body.Write(data)
}

type syncHTTPCase struct {
	version  int
	envelope bool
	mode     string
	expiry   int64
}

type syncHTTPObservation struct {
	response      *httptest.ResponseRecorder
	trace         []lifecycleTrace
	state         map[string]any
	logs          []string
	counters      string
	events        []SyncEvent
	verifications []signatureObservation
	panicValue    any
	bodyClosed    int
	replayCount   int
	failures      uint64
}

func syncHTTPRun(t *testing.T, test syncHTTPCase, original bool, failAt int, sentinel error) syncHTTPObservation {
	t.Helper()
	logger, logWriter, logFlags := slog.Default(), log.Writer(), log.Flags()
	defer func() {
		slog.SetDefault(logger)
		log.SetOutput(logWriter)
		log.SetFlags(logFlags)
	}()
	server, store, _ := testServer(t)
	user, key, signature := accessIdentity()
	verifier := &accessVerifier{transactionVerifier: transactionVerifier{accept: test.mode != "rejected"}}
	server.verifier = verifier
	if test.mode == "callback panic" {
		verifier.panicValue = sentinel
	}
	if test.mode != "bootstrap" && test.mode != "missing account" {
		if err := store.RegisterUser(t.Context(), user, key); err != nil {
			t.Fatal(err)
		}
		lifecycleExecute(t, store, "UPDATE server_users SET alias='Sync 日本語',profile_icon=4 WHERE user_id_hash=?1", user)
		lifecycleExecute(t, store, "INSERT INTO server_clients(user_id_hash,client_id,last_seen_at,last_sync_at,protocol_version) VALUES(?1,'legacy-client','2100-01-01T00:00:00.000000000Z','2100-01-01T00:00:00.000000000Z',1)", user)
		if _, err := store.ApplySync(t.Context(), SyncRequest{ProtocolVersion: 2, UserIDHash: user, ClientID: "remote-client",
			Ops: []SyncOp{{OpID: "remote-op-1", ClientID: "remote-client", Seq: 1, EntityType: "habit", EntityID: applicationHabitID, OpType: "upsert",
				Payload: json.RawMessage(`{"name":"remote habit","updated_at":"2026-01-01T00:00:00Z"}`), CreatedAt: lifecycleFixtureTime}}}, nil); err != nil {
			t.Fatal(err)
		}
		if test.envelope {
			for index := 0; index < 3; index++ {
				lifecycleExecute(t, store, "INSERT INTO server_encrypted_payloads(user_id_hash,client_id,payload_json,server_version,created_at) VALUES(?1,'remote-client',?2,?3,?4)",
					user, `{"v":1,"nonce":"old","ciphertext":"opaque"}`, index+1, lifecycleFixtureTime)
			}
			lifecycleExecute(t, store, "UPDATE server_sync_state SET server_version=3 WHERE user_id_hash=?1", user)
		}
	}
	other := strings.Repeat("b", 64)
	if err := store.RegisterUser(t.Context(), other, []byte("unrelated public key")); err != nil {
		t.Fatal(err)
	}
	device := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x57}, ed25519.SeedSize))
	if err := AppStore_Upsert(store.Database, t.Context(), AppRegistration{AppID: "syncapp", DisplayName: "Sync App", CompatibilityUntil: "2100-01-01",
		ManifestExpiresAt: 4_000_000_000, Collections: []AppCollection{{CollectionPrefix: "private.syncapp.v1.*", Visibility: "private"}}}); err != nil {
		t.Fatal(err)
	}
	if test.version >= 6 {
		lifecycleExecute(t, store, `INSERT INTO server_app_manifests(app_id,manifest_version,manifest_json,manifest_hash,manifest_signature,approval_signature,expires_at) VALUES('syncapp',1,'{"compatibility_until":"2100-01-01"}','fixture-hash','fixture-signature','fixture-approval',4000000000)`)
	}
	if test.version >= 6 && !test.envelope && test.mode != "missing account" && test.mode != "bootstrap" {
		if err := DeviceKeys_Register(store.Database, t.Context(), DeviceKey{AccountID: user, AppID: "syncapp", KeyID: "device-key", ClientID: "test-client", PublicKey: hex.EncodeToString(device.Public().(ed25519.PublicKey))}, "register-device", errSignedTxReplay); err != nil {
			t.Fatal(err)
		}
	}
	input := SyncRequest{ProtocolVersion: test.version, UserIDHash: user, ClientID: "test-client", PublicKey: hex.EncodeToString(key),
		Habits:         []Habit{{ID: applicationHabitID, Name: "changed habit", UpdatedAt: "2026-02-01T00:00:00Z"}},
		HabitDays:      []HabitDay{{HabitID: applicationHabitID, LocalDate: 20261001, Completed: true, Count: 3, UpdatedAt: lifecycleFixtureTime}},
		MeditationLogs: []MeditationLog{{ID: "meditation", Duration: 42, CompletedAt: lifecycleFixtureTime}}}
	if test.version >= 5 {
		input.AppID = "syncapp"
		input.EncryptedRecords = []EncryptedRecord{{Collection: "private.syncapp.v1.notes", ID: "note", KeyID: "main", Nonce: "nonce", Ciphertext: "opaque", UpdatedAt: lifecycleFixtureTime}}
	}
	if test.mode == "ops" {
		input.Ops = []SyncOp{{OpID: "new-op-1", ClientID: input.ClientID, Seq: 2, EntityType: "habit_day", EntityID: applicationHabitID,
			LocalDate: 20261001, OpType: "upsert", Payload: json.RawMessage(`{"completed":true,"count":4,"updated_at":"2026-02-01T00:00:00Z"}`), CreatedAt: lifecycleFixtureTime}}
	}
	if test.mode == "stale hash" || test.mode == "stale upload" {
		input.LastServerStateHash = strings.Repeat("0", 64)
		input.SinceServerVersion = 99
		if test.mode == "stale hash" {
			input.Habits, input.HabitDays, input.MeditationLogs, input.EncryptedRecords = nil, nil, nil, nil
		}
	}
	if test.mode == "compacted" {
		lifecycleExecute(t, store, "INSERT INTO server_sync_compaction(user_id_hash,compacted_through_version) VALUES(?1,1)", user)
		input.Habits, input.HabitDays, input.MeditationLogs, input.EncryptedRecords = nil, nil, nil, nil
	}
	if test.mode == "full sync" {
		input.FullSyncRequested = true
	}
	if test.mode == "legacy projection" {
		input.IncludeLegacyData = true
	}
	if test.mode == "missing app" {
		input.AppID = ""
	}
	if test.mode == "unknown app" {
		input.AppID = "unknown"
	}
	if test.mode == "invalid app" {
		input.AppID = "!"
	}
	if test.mode == "invalid record" {
		input.EncryptedRecords[0].Ciphertext = ""
	}
	if test.mode == "legacy denied" {
		lifecycleExecute(t, store, "UPDATE server_apps SET compatibility_until='1970-01-01' WHERE app_id='syncapp'")
	}
	if test.mode == "inactive app" {
		lifecycleExecute(t, store, "UPDATE server_apps SET status='suspended' WHERE app_id='syncapp'")
	}
	if test.mode == "expired app" {
		lifecycleExecute(t, store, "UPDATE server_app_manifests SET expires_at=1 WHERE app_id='syncapp'")
	}
	if test.mode == "unregistered collection" {
		input.EncryptedRecords[0].Collection = "private.unregistered.v1.notes"
	}
	if test.mode == "client failure" || test.mode == "log panic" {
		lifecycleExecute(t, store, "CREATE TRIGGER reject_client BEFORE INSERT ON server_clients BEGIN SELECT RAISE(ABORT,'client rejected'); END")
	}
	if test.mode == "audit failure" {
		lifecycleExecute(t, store, "CREATE TRIGGER reject_audit BEFORE INSERT ON server_sync_audit BEGIN SELECT RAISE(ABORT,'audit rejected'); END")
	}
	if test.mode == "prune" || test.mode == "prune failure" {
		server.cfg.EncryptedPayloadRetention = time.Hour
		server.cfg.EncryptedPayloadMaxAccountBytes = 1_000_000
		if test.mode == "prune failure" {
			lifecycleExecute(t, store, "CREATE TRIGGER reject_prune BEFORE DELETE ON server_encrypted_payloads BEGIN SELECT RAISE(ABORT,'prune rejected'); END")
		}
	}
	if test.mode == "tombstoned" {
		if err := store.DeleteAccount(t.Context(), user); err != nil {
			t.Fatal(err)
		}
	}
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if test.envelope {
		data = []byte(`{"v":2,"nonce":"nonce","ciphertext":"opaque","extra":{"unchanged":true}}`)
	}
	if test.mode == "malformed body" {
		data = []byte("{bad")
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/sync", bytes.NewReader(data))
	request.Header.Set("X-Daochi-User", user)
	request.Header.Set("X-Daochi-Client", input.ClientID)
	request.Header.Set("X-Daochi-Limit", "1")
	request.Header.Set("Authorization", "Bearer "+Token_IssueAuthToken(server.cfg.TokenSecret, user, 4_000_000_000).Value)
	if test.version >= 6 && !test.envelope {
		tx := SignedTxEnvelope{ProtocolVersion: 6, TxID: "transaction-1", AccountID: user, AppID: input.AppID, DeviceKeyID: "device-key",
			Method: request.Method, Path: request.URL.Path, BodySHA256: Signing_SHA256Hex(data), Nonce: "transaction-nonce", ExpiresAt: test.expiry,
			SignatureContext: TransactionContext, Signature: signature}
		signDeviceTransaction(&tx, device)
		raw, err := json.Marshal(tx)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("X-Daochi-Tx", string(raw))
		if test.mode == "replay" {
			lifecycleExecute(t, store, "INSERT INTO server_signed_transactions(account_id,tx_id,app_id,nonce,expires_at) VALUES(?1,?2,?3,?4,?5)", user, tx.TxID, tx.AppID, tx.Nonce, tx.ExpiresAt)
		}
	}
	if test.mode == "missing bearer" {
		request.Header.Del("Authorization")
	}
	if test.mode == "unsigned" {
		request.Header.Del("X-Daochi-Tx")
	}
	if test.mode == "token mismatch" {
		request.Header.Set("Authorization", "Bearer "+Token_IssueAuthToken(server.cfg.TokenSecret, other, 4_000_000_000).Value)
	}
	if test.mode == "missing header" {
		request.Header.Del("X-Daochi-User")
	}
	if test.mode == "legacy header" {
		request.Header.Del("X-Daochi-User")
		request.Header.Set("X-Inbe-User", user)
	}
	if test.mode == "invalid client" {
		if test.envelope {
			request.Header.Set("X-Daochi-Client", "!")
		} else {
			input.ClientID = "!"
			data, _ = json.Marshal(input)
		}
	}
	if test.mode == "invalid since" {
		request.Header.Set("X-Daochi-Since-Version", "-1")
	}
	if test.mode == "quota" {
		server.cfg.EncryptedPayloadMaxAccountBytes = int64(len(data) - 1)
	}
	if test.mode == "oversized" {
		server.cfg.MaxBodyBytes = 3
	}
	if test.mode == "cancelled" {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		request = request.WithContext(ctx)
	}
	if test.mode == "closed" {
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}
	reader := &httpPortBody{Reader: bytes.NewReader(data)}
	request.Body = reader
	if test.mode == "body panic" {
		reader.panicValue = sentinel
	}
	subscription := SyncHub_Subscribe(server.syncHub, user)
	foreign := SyncHub_Subscribe(server.syncHub, other)
	defer SyncHub_Unsubscribe(server.syncHub, user, subscription)
	defer SyncHub_Unsubscribe(server.syncHub, other, foreign)
	plan := &lifecycleDriverPlan{failAt: failAt, failure: sentinel}
	if test.mode != "closed" {
		syncHTTPTrackStore(t, store, plan)
	}
	result := syncHTTPObservation{response: httptest.NewRecorder()}
	slog.SetDefault(slog.New(discoveryLogHandler{record: func(record slog.Record) {
		event := record.Level.String() + ":" + record.Message
		record.Attrs(func(attribute slog.Attr) bool {
			event += "|" + attribute.Key + "=" + attribute.Value.String()
			return true
		})
		result.logs = append(result.logs, event)
		if test.mode == "log panic" {
			panic(sentinel)
		}
	}}))
	var writer http.ResponseWriter = result.response
	if test.mode == "response panic" {
		writer = &httpPortWriter{header: make(http.Header), panicValue: sentinel}
	}
	before := time.Now()
	result.panicValue = boundaryRecover(func() {
		if original {
			server.baselineSyncHTTPHandleSync(writer, request)
		} else {
			server.handleSync(writer, request)
		}
	})
	after := time.Now()
	result.trace = append([]lifecycleTrace(nil), plan.trace...)
	for _, call := range result.trace {
		if call.Query == "DELETE FROM server_signed_transactions WHERE expires_at<?1" {
			epoch, ok := call.Arguments[0].(int64)
			if !ok || epoch < before.Unix() || epoch > after.Unix() {
				t.Fatal("transaction cleanup timestamp changed", call.Arguments)
			}
			call.Arguments[0] = "<validated Unix timestamp>"
		}
	}
	plan.failAt = 0
	result.bodyClosed = reader.closed
	result.verifications = verifier.calls
	result.failures = server.metrics.SyncFailures.Load()
	metrics := httptest.NewRecorder()
	Metrics_Prometheus(server.metrics, metrics, NodeUsage{}, NodeStorageUsage{}, "fixture")
	result.counters = metrics.Body.String()
	for subscription.Channel.Len() > 0 {
		value, _ := subscription.Channel.Recv()
		result.events = append(result.events, value.Interface().(SyncEvent))
	}
	if foreign.Channel.Len() != 0 {
		t.Fatal("sync notification escaped its account")
	}
	if store.Database.Stats().InUse != 0 {
		t.Fatal("sync handler retained a native SQL connection")
	}
	if test.mode != "closed" {
		result.state = syncHTTPState(t, store)
		result.replayCount = len(result.state["server_signed_transactions"].([]map[string]any))
	}
	normalizeSyncHTTPResponse(t, result.response, before, after, test.mode == "bootstrap")
	return result
}

func compareSyncHTTP(t *testing.T, test syncHTTPCase, failAt int, sentinel error) syncHTTPObservation {
	t.Helper()
	actual := syncHTTPRun(t, test, false, failAt, sentinel)
	expected := syncHTTPRun(t, test, true, failAt, sentinel)
	compareHTTPResponse(t, actual.response, expected.response)
	recorder := actual.response
	actual.response, expected.response = nil, nil
	if !reflect.DeepEqual(actual, expected) {
		for table, rows := range actual.state {
			if !reflect.DeepEqual(rows, expected.state[table]) {
				t.Fatalf("sync changed table %s: %#v / %#v", table, rows, expected.state[table])
			}
		}
		t.Fatalf("sync response, SQL order, logs, counters, notification, callback, cleanup or state changed:\n%#v\n%#v", actual, expected)
	}
	actual.response = recorder
	return actual
}

func TestZiranSyncHTTPAgainstBaseline(t *testing.T) {
	sentinel := errors.New("sync HTTP injected failure")
	expiry := time.Now().Add(5 * time.Minute).Unix()
	for _, version := range []int{1, 2, 3, 4, 5, 6} {
		modes := []string{"valid", "stale hash", "stale upload", "full sync", "legacy projection", "malformed body", "oversized", "missing header", "missing bearer", "token mismatch", "legacy header", "invalid client", "client failure", "audit failure", "cancelled", "closed", "body panic", "response panic", "log panic"}
		if version >= 2 {
			modes = append(modes, "ops", "compacted")
		}
		if version >= 5 {
			modes = append(modes, "unknown app", "invalid app", "inactive app", "invalid record", "unregistered collection")
		}
		if version == 5 {
			modes = append(modes, "legacy denied")
		}
		if version == 1 {
			modes = append(modes, "bootstrap")
		}
		if version == 6 {
			modes = append(modes, "missing app", "expired app", "unsigned", "rejected", "callback panic", "replay")
		}
		for _, mode := range modes {
			t.Run(fmt.Sprintf("v%d/%s", version, mode), func(t *testing.T) {
				test := syncHTTPCase{version: version, mode: mode, expiry: expiry}
				actual := compareSyncHTTP(t, test, 0, sentinel)
				if strings.Contains(mode, "panic") && actual.panicValue != sentinel {
					t.Fatal("sync panic lost identity", actual.panicValue)
				}
				if actual.bodyClosed != 1 {
					t.Fatal("sync body was not closed exactly once", actual.bodyClosed)
				}
				if (mode == "valid" || mode == "bootstrap" || mode == "audit failure") && actual.response.Code != http.StatusOK {
					t.Fatal("valid sync was rejected", actual.response.Body.String())
				}
				if mode == "response panic" && (actual.failures != 0 || (version == 6 && actual.replayCount != 1)) {
					t.Fatal("structured sync marked a completed request failed or forgot its replay entry")
				}
				if version == 6 && (mode == "client failure" || mode == "log panic") && actual.replayCount != 0 {
					t.Fatal("failed signed sync kept its replay entry")
				}
			})
		}
	}
	for _, mode := range []string{"valid", "prune", "prune failure", "missing header", "missing bearer", "token mismatch", "invalid client", "invalid since", "quota", "oversized", "legacy header", "missing account", "tombstoned", "client failure", "audit failure", "cancelled", "closed", "body panic", "response panic", "log panic"} {
		t.Run("envelope/"+mode, func(t *testing.T) {
			actual := compareSyncHTTP(t, syncHTTPCase{version: 6, envelope: true, mode: mode, expiry: expiry}, 0, sentinel)
			if mode == "response panic" && actual.failures != 1 {
				t.Fatal("envelope writer panic did not mark the request failed")
			}
			if mode == "valid" || mode == "prune" || mode == "prune failure" || mode == "audit failure" || mode == "client failure" {
				if actual.response.Code != http.StatusOK || actual.failures != 0 || len(actual.events) != 1 {
					t.Fatal("valid envelope or optional storage failure changed success/notification", actual.response.Body.String())
				}
			}
			if mode == "valid" {
				var response SyncResponse
				if err := json.Unmarshal(actual.response.Body.Bytes(), &response); err != nil || !response.EncryptedPayloadsTruncated || len(response.EncryptedPayloads) != 1 || response.EncryptedPayloadsNextSinceVersion != 1 {
					t.Fatal("opaque envelope pagination changed", response, err)
				}
			}
		})
	}
}

func TestZiranSyncHTTPNativeFailuresAgainstBaseline(t *testing.T) {
	sentinel := errors.New("sync SQL injected failure")
	expiry := time.Now().Add(5 * time.Minute).Unix()
	for _, test := range []syncHTTPCase{{version: 2, mode: "ops", expiry: expiry}, {version: 6, mode: "valid", expiry: expiry}, {version: 6, envelope: true, mode: "prune", expiry: expiry}} {
		normal := syncHTTPRun(t, test, true, 0, sentinel)
		for step := 1; step <= len(normal.trace); step++ {
			t.Run(fmt.Sprintf("v%d/envelope-%t/step-%d", test.version, test.envelope, step), func(t *testing.T) {
				compareSyncHTTP(t, test, step, sentinel)
			})
		}
	}
}
