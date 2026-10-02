package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

type operationalHandlerCase struct {
	name     string
	path     string
	actual   func(*Server, http.ResponseWriter, *http.Request)
	baseline func(*Server, http.ResponseWriter, *http.Request)
}

func operationalHandlerCases() []operationalHandlerCase {
	return []operationalHandlerCase{
		{"health", "/healthz", (*Server).handleHealth, (*Server).baselineOpsHandleHealth},
		{"ready", "/readyz", (*Server).handleReady, (*Server).baselineOpsHandleReady},
		{"node", "/api/v1/node", (*Server).handleNodeInfo, (*Server).baselineOpsHandleNodeInfo},
		{"metrics", "/metrics", (*Server).handleMetrics, (*Server).baselineOpsHandleMetrics},
		{"diagnostics", "/api/v1/sync/diagnostics", (*Server).handleSyncDiagnostics, (*Server).baselineOpsHandleSyncDiagnostics},
	}
}

func TestZiranOperationalHTTPAgainstBaseline(t *testing.T) {
	logger := slog.Default()
	logWriter, logFlags := log.Writer(), log.Flags()
	restoreLogging := func() {
		slog.SetDefault(logger)
		log.SetOutput(logWriter)
		log.SetFlags(logFlags)
	}
	t.Cleanup(restoreLogging)
	for _, test := range operationalHandlerCases() {
		for _, mode := range []string{"normal", "nil peers", "empty peers", "public metrics", "admin missing", "admin wrong", "admin legacy", "token missing", "token wrong", "missing account", "user mismatch", "closed", "cancelled", "usage failure", "storage failure", "diagnostic failure", "response panic", "log panic"} {
			t.Run(test.name+"/"+mode, func(t *testing.T) {
				t.Cleanup(restoreLogging)
				server, store, _ := testServer(t)
				user := strings.Repeat("a", 64)
				if err := store.RegisterUser(t.Context(), user, []byte("key")); err != nil {
					t.Fatal(err)
				}
				lifecycleExecute(t, store, "UPDATE server_users SET created_at=?2,last_seen_at=?2 WHERE user_id_hash=?1", user, lifecycleFixtureTime)
				server.Cfg.NodeDisplayName = "Home 日本語\n\x00\xff"
				server.Cfg.BaseURL = " \u2003 https://node.example/base/ \t"
				server.Cfg.KnownNodes = []NodePeer{{Name: "Neighbor\xff", URL: "https://peer.example"}}
				server.Cfg.AdminToken = "admin-secret"
				server.Node = NodeIdentity{ID: "id\x00\xff", PublicKey: []byte{0, 1, 254, 255}}
				for _, id := range []string{user, user, "other"} {
					subscription := SyncHub_Subscribe(server.SyncHub, id)
					t.Cleanup(func() { SyncHub_Unsubscribe(server.SyncHub, id, subscription) })
				}
				switch mode {
				case "nil peers":
					server.Cfg.KnownNodes = nil
				case "empty peers":
					server.Cfg.KnownNodes = []NodePeer{}
				case "public metrics":
					server.Cfg.AdminToken = ""
				case "closed", "log panic":
					if err := store.Close(); err != nil {
						t.Fatal(err)
					}
				case "usage failure":
					lifecycleExecute(t, store, "DROP TABLE server_clients")
				case "storage failure":
					lifecycleExecute(t, store, "DROP TABLE server_encrypted_records")
				case "diagnostic failure":
					lifecycleExecute(t, store, "DROP TABLE server_social_snapshots")
				}
				token := Token_IssueAuthToken(server.Cfg.TokenSecret, user, time.Now().Add(time.Hour).Unix())
				if token.Error != "" {
					t.Fatal(token.Error)
				}
				if mode == "missing account" {
					token = Token_IssueAuthToken(server.Cfg.TokenSecret, strings.Repeat("b", 64), time.Now().Add(time.Hour).Unix())
				}
				sentinel := errors.New("operational HTTP panic")
				var responses [2]*httptest.ResponseRecorder
				var events [2][]string
				var panics [2]any
				var counters [2]string
				for index := range responses {
					server.Metrics = &ServerMetrics{}
					server.Metrics.SyncRequests.Add(17)
					server.Metrics.WebSocketAccepted.Add(3)
					slog.SetDefault(slog.New(discoveryLogHandler{record: func(record slog.Record) {
						event := record.Level.String() + ":" + record.Message
						record.Attrs(func(attribute slog.Attr) bool {
							event += "|" + attribute.Key + "=" + attribute.Value.String()
							return true
						})
						events[index] = append(events[index], event)
						if mode == "log panic" {
							panic(sentinel)
						}
					}}))
					request := httptest.NewRequest(http.MethodGet, test.path, nil)
					request.Header.Set("X-Daochi-Admin", server.Cfg.AdminToken)
					request.Header.Set("Authorization", "Bearer "+token.Value)
					request.Header.Set("X-Daochi-User", user)
					switch mode {
					case "admin missing":
						request.Header.Del("X-Daochi-Admin")
					case "admin wrong":
						request.Header.Set("X-Daochi-Admin", "wrong")
					case "admin legacy":
						request.Header.Del("X-Daochi-Admin")
						request.Header.Set("X-Ksync-Admin", server.Cfg.AdminToken)
					case "token missing":
						request.Header.Del("Authorization")
					case "token wrong":
						request.Header.Set("Authorization", "Bearer invalid")
					case "user mismatch":
						request.Header.Set("X-Daochi-User", strings.Repeat("b", 64))
					case "cancelled":
						ctx, cancel := context.WithCancel(t.Context())
						cancel()
						request = request.WithContext(ctx)
					}
					writer := httptest.NewRecorder()
					responses[index] = writer
					var output http.ResponseWriter = writer
					if mode == "response panic" {
						output = &httpPortWriter{header: make(http.Header), panicValue: sentinel}
					}
					panics[index] = boundaryRecover(func() {
						if index == 0 {
							test.actual(server, output, request)
						} else {
							test.baseline(server, output, request)
						}
					})
					metricOutput := httptest.NewRecorder()
					Metrics_Prometheus(server.Metrics, metricOutput, NodeUsage{}, NodeStorageUsage{}, "fixture")
					counters[index] = metricOutput.Body.String()
				}
				compareHTTPResponse(t, responses[0], responses[1])
				if !reflect.DeepEqual(events[0], events[1]) || panics[0] != panics[1] || counters[0] != counters[1] {
					t.Fatal("operational logs, panic identity or counters changed", events, panics, counters)
				}
				if mode == "response panic" && panics[0] != sentinel {
					t.Fatal("response panic was swallowed", panics)
				}
				if store.Database.Stats().InUse != 0 {
					t.Fatal("operational HTTP retained a database connection")
				}
			})
		}
	}
}

func TestZiranReadinessConfigurationAgainstBaseline(t *testing.T) {
	for _, mode := range []string{"ready", "ephemeral", "short secret", "missing verifier", "typed nil verifier", "issuer disabled", "issuer read only", "issuer malformed", "rate missing", "rate only", "product only", "wallet missing", "wallet blank", "multiple failures"} {
		t.Run(mode, func(t *testing.T) {
			server, store, _ := testServer(t)
			server.Cfg.TokenDirectPurchasesEnabled = true
			server.Cfg.WaoziIssuerPrivateKey = ed25519.PrivateKey(bytes.Repeat([]byte{3}, 64))
			server.Cfg.MoneroRateAtomicAmount, server.Cfg.MoneroRateTokenUnits = 7, 5
			server.Cfg.MoneroWalletRPCURL = " https://wallet.example \u2003 "
			switch mode {
			case "ready":
				server.Cfg.TokenDirectPurchasesEnabled = false
			case "ephemeral":
				server.Cfg.TokenSecretEphemeral = true
			case "short secret":
				server.Cfg.TokenSecret = []byte{1}
			case "missing verifier":
				server.Verifier = testVerifier(nil)
			case "typed nil verifier":
				server.Verifier = testVerifier((*recordingVerifier)(nil))
			case "issuer disabled":
				server.Cfg.WaoziIssuerPrivateKey = nil
			case "issuer read only":
				server.Cfg.WaoziIssuerPrivateKey = nil
				server.Cfg.WaoziIssuerPublicKey = bytes.Repeat([]byte{3}, 32)
			case "issuer malformed":
				server.Cfg.WaoziIssuerPrivateKey = []byte{1}
			case "rate missing":
				server.Cfg.MoneroRateAtomicAmount = 0
			case "product only":
				server.Cfg.MoneroRateAtomicAmount = 0
				server.Cfg.TokenProducts = map[string]TokenProduct{"product": {MoneroAtomicAmount: 3, TokenUnits: 7}}
			case "wallet missing":
				server.Cfg.MoneroWalletRPCURL = ""
			case "wallet blank":
				server.Cfg.MoneroWalletRPCURL = " \u2003\t"
			case "multiple failures":
				server.Verifier = testVerifier(nil)
				server.Cfg.TokenSecretEphemeral = true
				server.Cfg.WaoziIssuerPrivateKey = nil
				server.Cfg.MoneroRateAtomicAmount = 0
				server.Cfg.MoneroWalletRPCURL = ""
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
			}
			actual, expected := httptest.NewRecorder(), httptest.NewRecorder()
			server.handleReady(actual, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			server.baselineOpsHandleReady(expected, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			compareHTTPResponse(t, actual, expected)
		})
	}
}

func TestZiranNodeCapabilitiesAndLiveUsageAgainstBaseline(t *testing.T) {
	if !reflect.DeepEqual(NodeInfo_Capabilities(), baselineOpsCapabilities) {
		t.Fatal("capability contents or order changed")
	}
	server, _, _ := testServer(t)
	for _, user := range []string{"a", "a", "b"} {
		_ = SyncHub_Subscribe(server.SyncHub, user)
	}
	actual, expectedError := server.nodeUsage(t.Context())
	expected, err := server.baselineOpsNodeUsage(t.Context())
	if actual != expected || expectedError != err || actual.ConnectedUsers != 2 || actual.ConnectedWebSocketClients != 3 {
		t.Fatal("live usage connection counts or policy changed", actual, expected, expectedError, err)
	}
}
