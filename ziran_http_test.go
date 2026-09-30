package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

type httpPortBody struct {
	io.Reader
	closed     int
	panicValue any
}

func (body *httpPortBody) Read(output []byte) (int, error) {
	if body.panicValue != nil {
		panic(body.panicValue)
	}
	return body.Reader.Read(output)
}

func (body *httpPortBody) Close() error {
	body.closed++
	return errors.New("ignored close failure")
}

type httpPortWriter struct {
	header     http.Header
	status     int
	data       []byte
	failure    error
	panicValue any
}

func (writer *httpPortWriter) Header() http.Header {
	return writer.header
}

func (writer *httpPortWriter) WriteHeader(status int) {
	writer.status = status
}

func (writer *httpPortWriter) Write(data []byte) (int, error) {
	if writer.panicValue != nil {
		panic(writer.panicValue)
	}
	writer.data = append(writer.data, data...)
	return len(data), writer.failure
}

func TestZiranHTTPBodiesAgainstBaseline(t *testing.T) {
	for _, input := range []string{"{}", "null", " true \n", "[]", "", "{}[]", "{", "\xff", `{"value":"日本語"}`} {
		for _, limit := range []int64{-1, 0, int64(len(input) - 1), int64(len(input)), 1000} {
			actual := &httpPortBody{Reader: strings.NewReader(input)}
			expected := &httpPortBody{Reader: strings.NewReader(input)}
			got := HttpBody_ReadJSON(httptest.NewRecorder(), httptest.NewRequest("POST", "/", actual), limit)
			want, err := baselineReadJSONBody(httptest.NewRecorder(), httptest.NewRequest("POST", "/", expected), limit)
			if !sameIdentityError(got.Error, err) || !reflect.DeepEqual(got.Value, want) || actual.closed != 1 || expected.closed != 1 {
				t.Fatalf("body %q, limit %d = %#v, baseline = %q, %v; close counts %d/%d", input, limit, got, want, err, actual.closed, expected.closed)
			}
		}
	}
	sentinel := errors.New("body read panicked")
	for _, baseline := range []bool{false, true} {
		body := &httpPortBody{panicValue: sentinel}
		func() {
			defer func() {
				if recover() != sentinel || body.closed != 1 {
					t.Fatal("request-body panic identity or cleanup changed")
				}
			}()
			request := httptest.NewRequest("POST", "/", body)
			if baseline {
				_, _ = baselineReadJSONBody(httptest.NewRecorder(), request, 100)
			} else {
				_ = HttpBody_ReadJSON(httptest.NewRecorder(), request, 100)
			}
		}()
	}
}

func TestZiranHTTPResponsesAgainstBaseline(t *testing.T) {
	for _, value := range []any{nil, "<>&\u2028\xff", map[string]any{"nil": []int(nil), "empty": []int{}}, AppGrantsResponse{Grants: []AppGrant{}}, func() {}, math.NaN()} {
		for _, failure := range []error{nil, errors.New("writer failed")} {
			actual := &httpPortWriter{header: make(http.Header), failure: failure}
			expected := &httpPortWriter{header: make(http.Header), failure: failure}
			Response_JSON(actual, 201, value)
			baselineWriteJSON(expected, 201, value)
			if actual.status != expected.status || !reflect.DeepEqual(actual.header, expected.header) || !bytes.Equal(actual.data, expected.data) {
				t.Fatalf("response for %T changed: %#v, baseline %#v", value, actual, expected)
			}
		}
	}
	for _, message := range []string{"", "<>&", "\xff\n", "failed"} {
		actual, expected := httptest.NewRecorder(), httptest.NewRecorder()
		Response_Error(actual, 400, message)
		baselineWriteError(expected, 400, message)
		compareHTTPResponse(t, actual, expected)
	}
}

func compareHTTPResponse(t *testing.T, actual, expected *httptest.ResponseRecorder) {
	t.Helper()
	if actual.Code != expected.Code || !reflect.DeepEqual(actual.Header(), expected.Header()) || actual.Body.String() != expected.Body.String() {
		t.Fatalf("HTTP response = %d %v %s; baseline = %d %v %s", actual.Code, actual.Header(), actual.Body.String(), expected.Code, expected.Header(), expected.Body.String())
	}
}

func registryHTTPFixture(t *testing.T) (*Server, string, ed25519.PrivateKey) {
	t.Helper()
	server, store, _ := testServer(t)
	server.cfg.AdminToken = "registry-admin"
	user := strings.Repeat("a", 64)
	if _, err := store.db.Exec("INSERT INTO server_users(user_id_hash,public_key) VALUES(?1,?2)", user, bytes.Repeat([]byte{0x35}, mlDSA44PublicKeySize)); err != nil {
		t.Fatal(err)
	}
	for _, app := range []AppRegistration{
		{AppID: "source", DisplayName: "Source", Collections: []AppCollection{
			{CollectionPrefix: "shared.source.v1.*", Visibility: "shared"},
			{CollectionPrefix: "private.source.v1.*", Visibility: "private"},
		}},
		{AppID: "target", DisplayName: "Target"},
	} {
		if err := AppStore_Upsert(store.db, t.Context(), app); err != nil {
			t.Fatal(err)
		}
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize))
	device := DeviceKey{AccountID: user, AppID: "target", KeyID: "device-key", ClientID: "client-test", PublicKey: hex.EncodeToString(key.Public().(ed25519.PublicKey))}
	if err := DeviceKeys_Register(store.db, t.Context(), device, "registered-device", errSignedTxReplay); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`
UPDATE server_apps SET created_at='fixture',updated_at='fixture';
CREATE TRIGGER app_clock_insert AFTER INSERT ON server_apps BEGIN
 UPDATE server_apps SET created_at='fixture',updated_at='fixture' WHERE app_id=NEW.app_id;
END;
CREATE TRIGGER app_clock_update AFTER UPDATE ON server_apps BEGIN
 UPDATE server_apps SET updated_at='fixture' WHERE app_id=NEW.app_id;
END;
CREATE TRIGGER key_clock_insert AFTER INSERT ON server_app_keys BEGIN
 UPDATE server_app_keys SET created_at='fixture' WHERE app_id=NEW.app_id AND key_id=NEW.key_id;
END;
CREATE TRIGGER grant_clock_insert AFTER INSERT ON server_app_grants BEGIN
 UPDATE server_app_grants SET created_at='fixture',updated_at='fixture' WHERE id=NEW.id;
END;
CREATE TRIGGER grant_clock_update AFTER UPDATE ON server_app_grants BEGIN
 UPDATE server_app_grants SET updated_at='fixture',revoked_at=CASE WHEN NEW.status='revoked' THEN 'revoked' ELSE NEW.revoked_at END WHERE id=NEW.id;
END;`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`INSERT INTO server_app_grants(id,user_id_hash,source_app_id,target_app_id,collection_prefix,permission,status)
 VALUES('seed-grant',?1,'source','target','shared.source.v1.*','read','active')`, user); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`INSERT INTO server_encrypted_records(user_id_hash,collection,id,updated_at,ciphertext)
 VALUES(?1,'shared.source.v1.items','record','2026-09-30T00:00:00Z','encrypted')`, user); err != nil {
		t.Fatal(err)
	}
	return server, user, key
}

func TestZiranHTTPAuthenticationAgainstBaseline(t *testing.T) {
	for _, mode := range []string{"valid", "missing", "invalid", "empty", "wrong scheme", "whitespace", "header mismatch", "legacy user", "header precedence", "missing account", "bootstrap", "deleted bootstrap", "query error", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			server, user, _ := registryHTTPFixture(t)
			token := Token_IssueAuthToken(server.cfg.TokenSecret, user, time.Now().Add(time.Hour).Unix()).Value
			request := httptest.NewRequest("GET", "/api/v1/account/app-grants", nil)
			request.Header.Set("Authorization", "Bearer "+token)
			switch mode {
			case "missing":
				request.Header.Del("Authorization")
			case "invalid":
				request.Header.Set("Authorization", "Bearer broken")
			case "empty":
				request.Header.Set("Authorization", "Bearer \t")
			case "wrong scheme":
				request.Header.Set("Authorization", "bearer "+token)
			case "whitespace":
				request.Header.Set("Authorization", "\u2003Bearer \t"+token+"\u2003")
			case "header mismatch":
				request.Header.Set("X-Daochi-User", strings.Repeat("b", 64))
			case "legacy user":
				request.Header.Set("X-Inbe-User", "\u2003"+strings.ToUpper(user)+"\t")
			case "header precedence":
				request.Header.Set("X-Daochi-User", user)
				request.Header.Set("X-Ksync-User", strings.Repeat("b", 64))
			case "missing account", "bootstrap", "deleted bootstrap":
				if _, err := server.store.db.Exec("DELETE FROM server_users WHERE user_id_hash=?1", user); err != nil {
					t.Fatal(err)
				}
				if mode != "missing account" {
					request.URL.Path = "/api/v1/sync"
				}
				if mode == "deleted bootstrap" {
					if _, err := server.store.db.Exec("INSERT INTO server_account_tombstones(user_id_hash) VALUES(?1)", user); err != nil {
						t.Fatal(err)
					}
				}
			case "query error":
				if err := server.store.db.Close(); err != nil {
					t.Fatal(err)
				}
			case "cancelled":
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				request = request.WithContext(ctx)
			}
			got := HttpAuth_AuthenticateToken(server.store.db, request, server.cfg.TokenSecret)
			want, err := server.baselineAuthenticateToken(request)
			if got.Value != want || !equalAuthenticationError(authenticationError(got.Authentication), err) {
				t.Fatalf("token authentication = %#v, baseline = %q, %v", got, want, err)
			}
			actual, expected := httptest.NewRecorder(), httptest.NewRecorder()
			value, allowed := server.bearerUser(actual, request)
			want, ok := server.baselineBearerUser(expected, request)
			if value != want || allowed != ok {
				t.Fatal("bearer/header authentication changed", value, allowed, want, ok)
			}
			compareHTTPResponse(t, actual, expected)
		})
	}
}

func TestZiranRegistryHTTPAgainstBaseline(t *testing.T) {
	tests := []struct{ name, method, path, body, handler, mutation string }{
		{"list", "GET", "/api/v1/apps", "", "list", ""},
		{"detail", "GET", "/api/v1/apps/source", "", "route", ""},
		{"missing", "GET", "/api/v1/apps/missing", "", "route", ""},
		{"bad ID", "GET", "/api/v1/apps/!", "", "route", ""},
		{"collections", "GET", "/api/v1/apps/source/collections", "", "route", ""},
		{"empty collections", "GET", "/api/v1/apps/target/collections", "", "route", ""},
		{"missing collections", "GET", "/api/v1/apps/missing/collections", "", "route", ""},
		{"register", "POST", "/api/v1/apps", `{"app_id":"newapp","display_name":"New App"}`, "list", ""},
		{"path mismatch", "PUT", "/api/v1/apps/other", `{"app_id":"newapp","display_name":"New App"}`, "route", ""},
		{"bad JSON", "POST", "/api/v1/apps", "{", "list", ""},
		{"admin disabled", "POST", "/api/v1/apps", "{", "list", "admin disabled"},
		{"admin rejected", "POST", "/api/v1/apps", "{", "list", "admin rejected"},
		{"body limit", "POST", "/api/v1/apps", "{}", "list", "body limit"},
		{"grants", "GET", "/api/v1/account/app-grants", "", "grants", ""},
		{"create grant", "POST", "/api/v1/account/app-grants", `{"source_app_id":"source","target_app_id":"target","collection_prefix":"shared.source.v1.*"}`, "grants", ""},
		{"private grant", "POST", "/api/v1/account/app-grants", `{"source_app_id":"source","target_app_id":"target","collection_prefix":"private.source.v1.*"}`, "grants", ""},
		{"missing app grant", "POST", "/api/v1/account/app-grants", `{"source_app_id":"source","target_app_id":"missing","collection_prefix":"shared.source.v1.*"}`, "grants", ""},
		{"revoke", "DELETE", "/api/v1/account/app-grants/seed-grant", "", "grant route", ""},
		{"missing revoke", "DELETE", "/api/v1/account/app-grants/missing", "", "grant route", ""},
		{"empty revoke", "DELETE", "/api/v1/account/app-grants/", "", "grant route", ""},
		{"unsigned records", "GET", "/api/v1/account/app-records?source_app_id=source&target_app_id=target&collection_prefix=shared.source.v1.*", "", "records", ""},
		{"invalid query", "GET", "/api/v1/account/app-records?source_app_id=!", "", "records", ""},
		{"unsigned manifest", "POST", "/api/v1/apps/register-signed", "{}", "signed register", ""},
		{"unsigned grant", "POST", "/api/v1/account/app-grants/signed", "{}", "signed grant", ""},
		{"query error", "GET", "/api/v1/apps", "", "list", "closed"},
		{"cancelled", "GET", "/api/v1/apps/source", "", "route", "cancelled"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, user, _ := registryHTTPFixture(t)
			expected, _, _ := registryHTTPFixture(t)
			var responses []*httptest.ResponseRecorder
			original := rand.Reader
			defer func() { rand.Reader = original }()
			for index, server := range []*Server{actual, expected} {
				if test.name == "create grant" {
					if _, err := server.store.db.Exec("DELETE FROM server_app_grants"); err != nil {
						t.Fatal(err)
					}
				}
				request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
				token := Token_IssueAuthToken(server.cfg.TokenSecret, user, time.Now().Add(time.Hour).Unix()).Value
				request.Header.Set("Authorization", "Bearer "+token)
				request.Header.Set("X-Ksync-Admin", server.cfg.AdminToken)
				switch test.mutation {
				case "admin disabled":
					server.cfg.AdminToken = ""
				case "admin rejected":
					request.Header.Set("X-Daochi-Admin", "wrong")
				case "body limit":
					server.cfg.MaxBodyBytes = 1
				case "closed":
					_ = server.store.db.Close()
				case "cancelled":
					ctx, cancel := context.WithCancel(t.Context())
					cancel()
					request = request.WithContext(ctx)
				}
				rand.Reader = bytes.NewReader(bytes.Repeat([]byte{0x42}, 16))
				writer := httptest.NewRecorder()
				if index == 0 {
					registry := server.appRegistry()
					switch test.handler {
					case "list":
						AppHttp_List(registry, writer, request)
					case "route":
						AppHttp_Route(registry, writer, request)
					case "grants":
						AppHttp_Grants(registry, writer, request)
					case "grant route":
						AppHttp_GrantRoute(registry, writer, request)
					case "records":
						AppHttp_Records(registry, writer, request)
					case "signed register":
						AppHttp_RegisterSigned(registry, writer, request)
					case "signed grant":
						AppHttp_GrantSigned(registry, writer, request)
					}
				} else {
					switch test.handler {
					case "list":
						server.baselineHandleAppList(writer, request)
					case "route":
						server.baselineHandleAppRoute(writer, request)
					case "grants":
						server.baselineHandleAppGrants(writer, request)
					case "grant route":
						server.baselineHandleAppGrantRoute(writer, request)
					case "records":
						server.baselineHandleAppRecords(writer, request)
					case "signed register":
						server.baselineHandleSignedAppRegister(writer, request)
					case "signed grant":
						server.baselineHandleSignedAppGrant(writer, request)
					}
				}
				responses = append(responses, writer)
			}
			compareHTTPResponse(t, responses[0], responses[1])
			if actual.metrics.AuthFailures.Load() != expected.metrics.AuthFailures.Load() || !reflect.DeepEqual(actual.metrics.AuthFailuresBy, expected.metrics.AuthFailuresBy) {
				t.Fatal("HTTP authentication metrics changed")
			}
			if test.mutation != "closed" {
				compareGrantState(t, actual.store, expected.store)
				compareAppStores(t, actual.store, expected.store)
			}
		})
	}
}

func TestZiranRegistrySignedRegistrationAgainstBaseline(t *testing.T) {
	for _, mode := range []string{"valid", "missing node key", "manifest signature", "approval signature", "bad JSON", "body limit", "failed write", "closed", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			actual, _, _ := registryHTTPFixture(t)
			expected, _, _ := registryHTTPFixture(t)
			registration, nodeKey, _ := signedRegistrationFixture(t)
			status := http.StatusOK
			switch mode {
			case "missing node key":
				nodeKey = nil
				status = http.StatusForbidden
			case "manifest signature":
				registration.ManifestSignature = strings.Repeat("0", 128)
				status = http.StatusUnauthorized
			case "approval signature":
				registration.ApprovalSignature = strings.Repeat("0", 128)
				status = http.StatusUnauthorized
			case "bad JSON", "body limit":
				status = http.StatusBadRequest
			case "failed write", "closed", "cancelled":
				status = http.StatusInternalServerError
			}
			body, err := json.Marshal(registration)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "bad JSON" {
				body = []byte("{")
			}
			var responses []*httptest.ResponseRecorder
			for index, server := range []*Server{actual, expected} {
				server.cfg.NodeRegistryPublicKey = nodeKey
				request := httptest.NewRequest("POST", "/api/v1/apps/register-signed", bytes.NewReader(body))
				switch mode {
				case "body limit":
					server.cfg.MaxBodyBytes = 1
				case "failed write":
					if _, err := server.store.db.Exec("CREATE TRIGGER reject_http_manifest BEFORE INSERT ON server_app_manifests BEGIN SELECT RAISE(ABORT,'manifest rejected'); END"); err != nil {
						t.Fatal(err)
					}
				case "closed":
					if err := server.store.db.Close(); err != nil {
						t.Fatal(err)
					}
				case "cancelled":
					ctx, cancel := context.WithCancel(t.Context())
					cancel()
					request = request.WithContext(ctx)
				}
				writer := httptest.NewRecorder()
				if index == 0 {
					AppHttp_RegisterSigned(server.appRegistry(), writer, request)
				} else {
					server.baselineHandleSignedAppRegister(writer, request)
				}
				responses = append(responses, writer)
			}
			compareHTTPResponse(t, responses[0], responses[1])
			if responses[0].Code != status {
				t.Fatalf("signed registration status = %d, expected %d", responses[0].Code, status)
			}
			if actual.metrics.AuthFailures.Load() != expected.metrics.AuthFailures.Load() || !reflect.DeepEqual(actual.metrics.AuthFailuresBy, expected.metrics.AuthFailuresBy) {
				t.Fatal("signed registration authentication metrics changed")
			}
			if mode != "closed" {
				compareAppStores(t, actual.store, expected.store, registration.Manifest.AppID)
				stored := AppStore_Exists(actual.store.db, t.Context(), registration.Manifest.AppID)
				if stored.Error != nil || stored.Value != (mode == "valid") {
					t.Fatal("signed registration persistence or rollback changed", stored)
				}
			}
		})
	}
}

type httpPortPanickingLog struct {
	value any
}

func (handler httpPortPanickingLog) Enabled(context.Context, slog.Level) bool {
	return true
}

func (handler httpPortPanickingLog) Handle(context.Context, slog.Record) error {
	panic(handler.value)
}

func (handler httpPortPanickingLog) WithAttrs([]slog.Attr) slog.Handler {
	return handler
}

func (handler httpPortPanickingLog) WithGroup(string) slog.Handler {
	return handler
}

func TestZiranRegistrySignedRequestCleanupAgainstBaseline(t *testing.T) {
	for _, mode := range []string{"grant", "empty hash", "wrong hash", "grant failure", "grant log panic", "grant response panic", "records", "grant required", "unowned scope", "record log panic", "record response panic"} {
		t.Run(mode, func(t *testing.T) {
			actual, user, key := registryHTTPFixture(t)
			expected, _, _ := registryHTTPFixture(t)
			grant := AppGrantRequest{SourceAppID: "source", TargetAppID: "target", CollectionPrefix: "shared.source.v1.*", Permission: "read"}
			payload, err := json.Marshal(grant)
			if err != nil {
				t.Fatal(err)
			}
			method, path := "POST", "/api/v1/account/app-grants/signed"
			records := mode == "records" || mode == "grant required" || mode == "unowned scope" || strings.HasPrefix(mode, "record ")
			if records {
				method, path = "GET", "/api/v1/account/app-records?source_app_id=source&target_app_id=target&collection_prefix=shared.source.v1.*"
				payload = nil
				if mode == "unowned scope" {
					path = strings.ReplaceAll(path, "shared.source.v1.*", "shared.source.v1.unowned")
				}
			}
			template := httptest.NewRequest(method, path, nil)
			tx := SignedTxEnvelope{
				ProtocolVersion: 6, TxID: "transaction", AccountID: user, AppID: "target",
				DeviceKeyID: "device-key", Method: method, Path: template.URL.Path,
				BodySHA256: Signing_SHA256Hex(payload), Nonce: "nonce-http-port",
				ExpiresAt: time.Now().Add(time.Minute).Unix(), SignatureContext: baselineTxContext,
				Signature: hex.EncodeToString(bytes.Repeat([]byte{0x33}, mlDSA44SignatureSize)),
			}
			signDeviceTransaction(&tx, key)
			wire := tx
			if mode == "empty hash" {
				wire.BodySHA256 = ""
			}
			if mode == "wrong hash" {
				wire.BodySHA256 = strings.Repeat("0", 64)
			}
			originalRandom, originalLogger := rand.Reader, slog.Default()
			originalLogWriter, originalLogFlags := log.Writer(), log.Flags()
			restoreLogger := func() {
				slog.SetDefault(originalLogger)
				log.SetOutput(originalLogWriter)
				log.SetFlags(originalLogFlags)
			}
			defer func() {
				rand.Reader = originalRandom
				restoreLogger()
			}()
			panicValue := errors.New("HTTP boundary panicked")
			var responses []*httptest.ResponseRecorder
			for index, server := range []*Server{actual, expected} {
				if !records {
					if _, err := server.store.db.Exec("DELETE FROM server_app_grants"); err != nil {
						t.Fatal(err)
					}
				}
				query := ""
				switch mode {
				case "grant failure", "grant log panic":
					query = "CREATE TRIGGER reject_http_grant BEFORE INSERT ON server_app_grant_audit BEGIN SELECT RAISE(ABORT,'audit rejected'); END"
				case "grant required":
					query = "DELETE FROM server_app_grants"
				case "record log panic":
					query = "UPDATE server_encrypted_records SET schema_version='broken'"
				}
				if query != "" {
					if _, err := server.store.db.Exec(query); err != nil {
						t.Fatal(err)
					}
				}
				body, err := json.Marshal(SignedAppGrantRequest{Tx: wire, Grant: grant})
				if err != nil {
					t.Fatal(err)
				}
				request := httptest.NewRequest(method, path, bytes.NewReader(body))
				token := Token_IssueAuthToken(server.cfg.TokenSecret, user, time.Now().Add(time.Hour).Unix()).Value
				request.Header.Set("Authorization", "Bearer "+token)
				if records {
					header, err := json.Marshal(wire)
					if err != nil {
						t.Fatal(err)
					}
					request.Header.Set("X-Daochi-Tx", string(header))
				}
				rand.Reader = bytes.NewReader(bytes.Repeat([]byte{0x42}, 16))
				writer := httptest.NewRecorder()
				var output http.ResponseWriter = writer
				if strings.Contains(mode, "response panic") {
					output = &httpPortWriter{header: make(http.Header), panicValue: panicValue}
				}
				if strings.Contains(mode, "log panic") {
					slog.SetDefault(slog.New(httpPortPanickingLog{value: panicValue}))
				}
				func() {
					defer func() {
						caught := recover()
						if strings.Contains(mode, "panic") {
							if caught != panicValue {
								t.Fatalf("HTTP panic = %v, expected sentinel", caught)
							}
						} else if caught != nil {
							t.Fatalf("unexpected HTTP panic: %v", caught)
						}
					}()
					if index == 0 {
						if records {
							AppHttp_Records(server.appRegistry(), output, request)
						} else {
							AppHttp_GrantSigned(server.appRegistry(), output, request)
						}
					} else if records {
						server.baselineHandleAppRecords(output, request)
					} else {
						server.baselineHandleSignedAppGrant(output, request)
					}
				}()
				restoreLogger()
				responses = append(responses, writer)
			}
			compareHTTPResponse(t, responses[0], responses[1])
			got, want := signedTransactionRows(t, actual.store), signedTransactionRows(t, expected.store)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("HTTP replay state = %#v, baseline = %#v", got, want)
			}
			retain := mode == "grant" || mode == "empty hash" || mode == "records" || strings.Contains(mode, "response panic")
			if (len(got) == 1) != retain {
				t.Fatalf("HTTP replay retained incorrectly for %s: %#v", mode, got)
			}
			compareGrantState(t, actual.store, expected.store)
		})
	}
}
