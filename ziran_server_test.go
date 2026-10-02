package main

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"
)

func serverConfiguration(store *Store) Config {
	return Config{
		DBPath: store.Path, MaxBodyBytes: 1 << 20,
		ChallengeTTL: time.Minute, TokenTTL: time.Hour,
		TokenSecret:            []byte("server wiring token secret"),
		NodeIdentityPrivateKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize)),
	}
}

func serverWiringFixture(t *testing.T) (*Server, *baselineServer, *Store) {
	t.Helper()
	opened := Store_Open(t.TempDir() + "/server.sqlite")
	if opened.Error != nil {
		t.Fatal("open wiring store", opened.Error)
	}
	store := opened.Value
	t.Cleanup(func() { _ = store.Close() })
	configuration := serverConfiguration(store)
	actualVerifier, expectedVerifier := &transactionVerifier{accept: true}, &transactionVerifier{accept: true}
	actual := Server_New(configuration, store, Verifier_New(actualVerifier.Verify), signAccountProof)
	expected := baselineNewServer(configuration, store, expectedVerifier)
	return actual, expected, store
}

func TestZiranServerConstructionAndDependencies(t *testing.T) {
	actual, expected, store := serverWiringFixture(t)
	if !reflect.DeepEqual(actual.Cfg, expected.cfg) || actual.Store != store || expected.store != store ||
		!reflect.DeepEqual(actual.Node, expected.node) || actual.Challenges == nil || actual.SyncHub == nil ||
		actual.Limiter == nil || actual.Metrics == nil {
		t.Fatal("server construction changed configuration, identity or dependencies")
	}
	configuration := serverConfiguration(store)
	configuration.NodeIdentityPrivateKey = []byte{42}
	var failures [2]string
	for index := range failures {
		func() {
			defer func() {
				if value := recover(); value != nil {
					failures[index] = fmt.Sprint(value)
				}
			}()
			if index == 0 {
				Server_New(configuration, store, nil, signAccountProof)
			} else {
				baselineNewServer(configuration, store, nil)
			}
		}()
	}
	if failures[0] == "" || failures[0] != failures[1] {
		t.Fatal("invalid node identity changed constructor panic", failures)
	}

	access := actual.access()
	if access.Database != store.Database || access.Configuration != &actual.Cfg || access.Challenges != actual.Challenges ||
		access.Limiter != actual.Limiter || access.Counters != actual.Metrics || access.Verify == nil || access.Sign == nil {
		t.Fatal("account access changed dependency identity")
	}
	operations := actual.operations()
	if operations.Database != store.Database || operations.Configuration != &actual.Cfg || operations.Identity != &actual.Node ||
		operations.Notifications != actual.SyncHub || operations.Counters != actual.Metrics || !operations.VerifierAvailable ||
		operations.Path != store.Path || unsafe.StringData(operations.Path) != unsafe.StringData(store.Path) {
		t.Fatal("operations changed native storage or dependency identity")
	}
	accounts := actual.accounts()
	if accounts.Database != store.Database || accounts.Configuration != &actual.Cfg || accounts.Counters != actual.Metrics || accounts.MissingUser != ErrSyncUserNotFound {
		t.Fatal("account dependency identity")
	}
	social := actual.social()
	if social.Accounts != accounts || social.Notifications != actual.SyncHub {
		t.Fatal("social dependency identity")
	}
	monero := actual.monero()
	if monero.AddressLocks != &actual.MoneroAddressLocks || monero.StuckNotified != &actual.MoneroStuckNotified ||
		monero.Database != store.Database || monero.Configuration != &actual.Cfg || monero.Counters != actual.Metrics ||
		monero.ReplayError != errSignedTxReplay || monero.Unavailable != errPaymentUnavailable ||
		monero.IssuerUnavailable != errTokenIssuerReadOnly || monero.MissingUser != ErrSyncUserNotFound {
		t.Fatal("Monero lock, dependency or error identity")
	}
	tokens := actual.tokens()
	if tokens.Database != store.Database || tokens.Configuration != &actual.Cfg || tokens.Counters != actual.Metrics ||
		tokens.Limiter != actual.Limiter || tokens.ReplayError != errSignedTxReplay || tokens.IssuerUnavailable != errTokenIssuerReadOnly {
		t.Fatal("token dependency identity")
	}
	registry := actual.appRegistry()
	if registry.Database != store.Database || registry.Configuration != &actual.Cfg || registry.Counters != actual.Metrics ||
		registry.ReplayError != errSignedTxReplay || registry.MissingUser != ErrSyncUserNotFound || registry.ScopeNotOwned != errAppScopeNotOwned {
		t.Fatal("registry dependency identity")
	}
	devices := actual.devices()
	if devices.Database != store.Database || devices.Configuration != &actual.Cfg || devices.Counters != actual.Metrics || devices.ReplayError != errSignedTxReplay {
		t.Fatal("device dependency identity")
	}
	trust := actual.trust()
	if trust.Database != store.Database || trust.Configuration != &actual.Cfg || !reflect.DeepEqual(trust.Identity, actual.Node) ||
		unsafe.StringData(trust.Identity.ID) != unsafe.StringData(actual.Node.ID) ||
		&trust.Identity.PrivateKey[0] != &actual.Node.PrivateKey[0] {
		t.Fatal("trust identity copy changed native backing storage")
	}
	mesh := actual.mesh()
	if mesh.Database != store.Database || mesh.Configuration != &actual.Cfg || mesh.Identity != &actual.Node ||
		mesh.ConvertError(AuthenticationResult{}) != nil {
		t.Fatal("mesh dependency identity")
	}
	sync := actual.synchronization()
	if sync.Database != store.Database || sync.Configuration != &actual.Cfg || sync.Counters != actual.Metrics ||
		sync.Notifications != actual.SyncHub || sync.Verify == nil || sync.ReplayError != errSignedTxReplay || sync.MissingUser != ErrSyncUserNotFound {
		t.Fatal("sync dependency identity")
	}
	socket := actual.syncSocket()
	if socket.Database != store.Database || socket.Configuration != &actual.Cfg || socket.Counters != actual.Metrics || socket.Limiter != actual.Limiter || socket.Hub != actual.SyncHub {
		t.Fatal("socket dependency identity")
	}
}

func TestZiranServerVerifierCaptureTiming(t *testing.T) {
	actual, expected, _ := serverWiringFixture(t)
	oldActual, oldExpected := &transactionVerifier{accept: true}, &transactionVerifier{accept: true}
	newActual, newExpected := &transactionVerifier{}, &transactionVerifier{}
	actual.Verifier, expected.verifier = Verifier_New(oldActual.Verify), oldExpected
	actualCallbacks := []VerifySignature{actual.access().Verify, actual.synchronization().Verify,
		actual.tokens().Verify, actual.monero().Verify, actual.appRegistry().Verify, actual.devices().Verify}
	expectedCallbacks := []func([]byte, []byte, []byte) bool{expected.access().Verify, expected.synchronization().Verify,
		expected.tokens().Verify, expected.monero().Verify, expected.appRegistry().Verify, expected.devices().Verify}
	actual.Verifier, expected.verifier = Verifier_New(newActual.Verify), newExpected
	for index := range actualCallbacks {
		key, message, signature := []byte{0, 1, 255}, []byte("message"), []byte{42}
		got, want := actualCallbacks[index](key, message, signature), expectedCallbacks[index](key, message, signature)
		if got != want || got != (index >= 2) {
			t.Fatal("verifier capture moved from invocation to getter or back", index, got, want)
		}
	}
	if !reflect.DeepEqual(oldActual.calls, oldExpected.calls) || !reflect.DeepEqual(newActual.calls, newExpected.calls) {
		t.Fatal("verifier callback arguments changed")
	}
	actual.Verifier, expected.verifier = nil, nil
	if actual.operations().VerifierAvailable || expected.operations().VerifierAvailable {
		t.Fatal("nil verifier availability")
	}
	// Creating access and sync dependencies must not evaluate a nil verifier.
	_ = actual.access()
	_ = actual.synchronization()
	for _, method := range []string{"access", "synchronization", "tokens", "monero", "appRegistry", "devices"} {
		var panics [2]string
		for index := range panics {
			func() {
				defer func() {
					if value := recover(); value != nil {
						panics[index] = fmt.Sprint(value)
					}
				}()
				if index == 0 {
					switch method {
					case "access":
						actual.access().Verify(nil, nil, nil)
					case "synchronization":
						actual.synchronization().Verify(nil, nil, nil)
					case "tokens":
						_ = actual.tokens()
					case "monero":
						_ = actual.monero()
					case "appRegistry":
						_ = actual.appRegistry()
					case "devices":
						_ = actual.devices()
					}
				} else {
					switch method {
					case "access":
						expected.access().Verify(nil, nil, nil)
					case "synchronization":
						expected.synchronization().Verify(nil, nil, nil)
					case "tokens":
						_ = expected.tokens()
					case "monero":
						_ = expected.monero()
					case "appRegistry":
						_ = expected.appRegistry()
					case "devices":
						_ = expected.devices()
					}
				}
			}()
		}
		if panics[0] == "" || panics[0] != panics[1] {
			t.Fatal("nil verifier changed panic timing or value", method, panics)
		}
	}
}

func baselineRoutePatterns(t *testing.T) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "ziran_server_baseline_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var patterns []string
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "HandleFunc" {
			return true
		}
		literal := call.Args[0].(*ast.BasicLit)
		pattern, err := strconv.Unquote(literal.Value)
		if err != nil {
			t.Fatal(err)
		}
		patterns = append(patterns, pattern)
		return true
	})
	if len(patterns) != 62 {
		t.Fatal("original server route fixture changed", len(patterns))
	}
	return patterns
}

func TestZiranServerRoutesAgainstBaseline(t *testing.T) {
	actual, expected, _ := serverWiringFixture(t)
	actualHandler, expectedHandler := actual.Routes(), expected.Routes()
	actualMux := actualHandler.(*Middleware).Next.(*http.ServeMux)
	expectedMux := expectedHandler.(*Middleware).Next.(*http.ServeMux)
	paths := []string{"/missing", "/api/v1", "/api/v1/apps", "/api/v1/apps/demo", "/api/v1/apps//demo", "/api/v1/apps/../node", "/api/v1/account/devices/", "/api/v1/friends/requests/42/action"}
	patterns := baselineRoutePatterns(t)
	for _, pattern := range patterns {
		path := strings.SplitN(pattern, " ", 2)[1]
		paths = append(paths, path)
		if len(path) > 1 && strings.HasSuffix(path, "/") {
			paths = append(paths, path+"example", strings.TrimSuffix(path, "/"))
		}
	}
	for _, path := range paths {
		for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"} {
			request := httptest.NewRequest(method, path, nil)
			_, got := actualMux.Handler(request)
			_, want := expectedMux.Handler(request)
			if got != want {
				t.Fatal("native route matching changed", method, path, got, want)
			}
		}
	}
	for _, pattern := range patterns {
		parts := strings.SplitN(pattern, " ", 2)
		method, path := parts[0], parts[1]
		if path == "/api/v1/node" {
			continue // Its runtime memory statistics are checked by the operational HTTP fixtures.
		}
		t.Run(pattern, func(t *testing.T) {
			actual, expected, _ := serverWiringFixture(t)
			actualHandler, expectedHandler := actual.Routes(), expected.Routes()
			// Mutation after route registration must be observed at request time.
			actual.Cfg.AdminToken, expected.cfg.AdminToken = "updated administrator", "updated administrator"
			actual.Metrics, expected.metrics = &ServerMetrics{}, &ServerMetrics{}
			actualRecorder, expectedRecorder := httptest.NewRecorder(), httptest.NewRecorder()
			actualHandler.ServeHTTP(actualRecorder, httptest.NewRequest(method, path, strings.NewReader("{")))
			expectedHandler.ServeHTTP(expectedRecorder, httptest.NewRequest(method, path, strings.NewReader("{")))
			if actualRecorder.Code != expectedRecorder.Code || actualRecorder.Body.String() != expectedRecorder.Body.String() ||
				!reflect.DeepEqual(actualRecorder.Header(), expectedRecorder.Header()) ||
				!reflect.DeepEqual(actual.Metrics.HttpRequests, expected.metrics.HttpRequests) ||
				actual.Metrics.AuthFailures.Load() != expected.metrics.AuthFailures.Load() ||
				!reflect.DeepEqual(actual.Metrics.AuthFailuresBy, expected.metrics.AuthFailuresBy) {
				t.Fatal("route dispatch, response or counters changed", actualRecorder, expectedRecorder)
			}
		})
	}
}
