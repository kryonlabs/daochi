package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func meshHTTPFixture(t *testing.T) *Server {
	t.Helper()
	store := meshPortFixture(t)
	if err := TrustStore_EnsureSchema(store.db, t.Context()); err != nil {
		t.Fatal(err)
	}
	identity := NodeIdentity_New(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize)))
	if identity.Error != nil {
		t.Fatal(identity.Error)
	}
	return &Server{
		store: store,
		node:  identity.Value,
		cfg: Config{
			NodeSyncToken:      "mesh-secret",
			NodeSyncBatchLimit: 1,
			MaxBodyBytes:       1 << 20,
		},
	}
}

func meshHTTPPolicy() NodeSyncPolicy {
	return NodeSyncPolicy{
		Direction: "bidirectional", Apps: []string{"source", "demo"},
		Collections: []string{"shared.source.*"}, Spaces: []string{"space"},
		Data: []string{"encrypted_records", "app_registry", "names"},
	}
}

func meshHTTPPeer(t *testing.T, server *Server, identity NodeIdentity, approved NodeSyncPolicy) {
	t.Helper()
	encoded, err := json.Marshal(approved)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.store.db.Exec(`INSERT INTO trusted_node_peers(node_id,public_key,display_name,addresses_json,policy_json,trusted_at)
VALUES(?1,?2,'peer','[]',?3,'fixture')`, identity.ID, identity.PublicKey, string(encoded)); err != nil {
		t.Fatal(err)
	}
}

func TestZiranMeshBearerTokenAgainstBaseline(t *testing.T) {
	values := []string{"", "Bearer", "Bearer token", "bearer\ttoken", "BEARER  token\u2003", "\u2003beAreR \xff\t", "Basic token", "Bearer \x00"}
	random := rand.New(rand.NewSource(914))
	for index := 0; index < 1000; index++ {
		data := make([]byte, random.Intn(100))
		_, _ = random.Read(data)
		values = append(values, string(data), "Bearer "+string(data))
	}
	for _, value := range values {
		if got, want := Mesh_BearerToken(value), baselineBearerToken(value); got != want {
			t.Fatalf("bearer %q = %q; baseline %q", value, got, want)
		}
	}
}

func TestZiranMeshTokenAuthenticationAgainstBaseline(t *testing.T) {
	for _, token := range []string{"", "\u2003\t", "mesh-secret", " \u2003mesh-secret\t", "\xff\x00"} {
		for _, headers := range []http.Header{
			{}, {"Authorization": {"Bearer mesh-secret"}}, {"Authorization": {"bEaReR  mesh-secret\u2003"}},
			{"X-Daochi-Node-Token": {"wrong"}, "Authorization": {"Bearer mesh-secret"}},
			{"X-Daochi-Node-Token": {"\u2003\t"}, "X-Ksync-Node-Token": {" mesh-secret "}},
			{"X-Daochi-Node-Token": {"\xff\x00"}}, {"X-Daochi-Node-ID": {"invalid"}, "X-Daochi-Node-Token": {"mesh-secret"}},
		} {
			server := meshHTTPFixture(t)
			server.cfg.NodeSyncToken = token
			request := httptest.NewRequest("POST", "/api/v1/node/mesh/export", nil)
			request.Header = headers.Clone()
			actual, expected := httptest.NewRecorder(), httptest.NewRecorder()
			got := Mesh_Authorize(server.mesh(), actual, request, []byte("body"))
			want := server.baselineMeshAuthorizeNodeSync(expected, request, []byte("body"))
			if got != want {
				t.Fatalf("authentication changed for token %q and headers %v", token, headers)
			}
			compareHTTPResponse(t, actual, expected)
		}
	}
}

func TestZiranMeshHTTPAgainstBaseline(t *testing.T) {
	registration, registryKey := meshAppRegistration(t, "demo", 1)
	identity := NodeIdentity_New(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x45}, ed25519.SeedSize))).Value
	for _, operation := range []string{"export", "import"} {
		for _, mode := range []string{
			"valid", "empty", "null", "wrong shape", "invalid JSON", "read failure", "body limit",
			"no token", "disabled", "unscoped", "signed", "replayed", "unpaired", "expired", "bad signature",
			"denied scope", "policy query failure", "cancelled", "closed", "apps query failure", "record query failure",
			"name query failure", "invalid app", "invalid record", "invalid name", "record write failure", "response panic",
		} {
			t.Run(operation+"/"+mode, func(t *testing.T) {
				actual, expected := meshHTTPFixture(t), meshHTTPFixture(t)
				approved := meshHTTPPolicy()
				requested := meshHTTPPolicy()
				if mode == "unscoped" {
					requested = NodeSyncPolicy{}
				}
				if mode == "denied scope" {
					approved.Apps = []string{"source"}
				}
				input := NodeMeshImportRequest{
					Policy: requested, Apps: []SignedAppRegistrationRequest{registration},
					Records: []MeshEncryptedRecord{meshPortRecord("http-new", 20)},
				}
				switch mode {
				case "invalid app":
					input.Apps[0].ManifestSignature = "bad signature"
				case "invalid record":
					input.Records[0].UserIDHash = "invalid"
				case "invalid name":
					input.Names = []NameClaim{{SpaceID: "space", Name: "invalid!"}}
				}
				payload := any(input)
				if operation == "export" {
					payload = NodeMeshExportRequest{Policy: requested, Limit: 1}
				}
				encoded, err := json.Marshal(payload)
				if err != nil {
					t.Fatal(err)
				}
				switch mode {
				case "empty":
					encoded = nil
				case "null":
					encoded = []byte("null")
				case "wrong shape":
					encoded = []byte("[]")
				case "invalid JSON":
					encoded = []byte("{")
				}
				signed := mode == "signed" || mode == "replayed" || mode == "unpaired" || mode == "expired" || mode == "bad signature" || mode == "denied scope" || mode == "policy query failure"
				request := httptest.NewRequest("POST", "/api/v1/node/mesh/"+operation, bytes.NewReader(encoded))
				request.Header.Set("Authorization", "Bearer mesh-secret")
				if mode == "no token" {
					request.Header.Del("Authorization")
				}
				if signed {
					NodeAuth_Sign(identity.ID, identity.PrivateKey, request, encoded)
				}
				if mode == "bad signature" {
					request.Header.Set("X-Daochi-Node-Signature", "bad")
				}
				if mode == "expired" {
					request.Header.Set("X-Daochi-Node-Time", "1")
				}
				panicValue := errors.New("mesh response panic")
				var results []*httptest.ResponseRecorder
				for index, server := range []*Server{actual, expected} {
					server.cfg.NodeRegistryPublicKey = registryKey
					if signed && mode != "unpaired" {
						meshHTTPPeer(t, server, identity, approved)
					}
					if mode == "replayed" {
						if err := NodeAuth_Verify(server.store.db, t.Context(), request, encoded); err != nil {
							t.Fatal(err)
						}
					}
					query := ""
					switch mode {
					case "disabled":
						server.cfg.NodeSyncToken = ""
					case "body limit":
						server.cfg.MaxBodyBytes = 1
					case "apps query failure":
						query = "ALTER TABLE server_app_manifests RENAME TO broken_manifests"
					case "record query failure":
						query = "ALTER TABLE server_encrypted_records RENAME TO broken_records"
					case "name query failure":
						query = "ALTER TABLE trust_spaces RENAME TO broken_spaces"
					case "policy query failure":
						query = "UPDATE trusted_node_peers SET policy_json='{'"
					case "record write failure":
						query = "CREATE TRIGGER reject_mesh_http BEFORE INSERT ON server_encrypted_records BEGIN SELECT RAISE(ABORT,'record rejected'); END"
					}
					if query != "" {
						if _, err := server.store.db.Exec(query); err != nil {
							t.Fatal(err)
						}
					}
					body := &httpPortBody{Reader: bytes.NewReader(encoded)}
					if mode == "read failure" {
						body.Reader = deviceHTTPReadFailure{failure: errors.New("read failed")}
					}
					local := request.Clone(t.Context())
					local.Body = body
					if mode == "cancelled" {
						cancelled, cancel := context.WithCancel(t.Context())
						cancel()
						local = local.WithContext(cancelled)
					}
					if mode == "closed" {
						server.store.db.Close()
					}
					writer := httptest.NewRecorder()
					var destination http.ResponseWriter = writer
					if mode == "response panic" {
						destination = &httpPortWriter{header: make(http.Header), panicValue: panicValue}
					}
					func() {
						defer func() {
							got := recover()
							if mode == "response panic" && got != panicValue {
								t.Fatalf("response panic = %v", got)
							}
							if mode != "response panic" && got != nil {
								panic(got)
							}
						}()
						if operation == "export" {
							if index == 0 {
								Mesh_Export(server.mesh(), destination, local)
							} else {
								server.baselineMeshHandleNodeMeshExport(destination, local)
							}
						} else if index == 0 {
							Mesh_Import(server.mesh(), destination, local)
						} else {
							server.baselineMeshHandleNodeMeshImport(destination, local)
						}
					}()
					if body.closed != 1 {
						t.Fatalf("request body closed %d times", body.closed)
					}
					results = append(results, writer)
				}
				compareHTTPResponse(t, results[0], results[1])
				if mode == "valid" || mode == "signed" {
					if results[0].Code != http.StatusOK {
						t.Fatalf("valid request failed: %s", results[0].Body.String())
					}
				}
				if mode != "closed" && mode != "apps query failure" && mode != "record query failure" && mode != "name query failure" {
					compareMeshState(t, actual.store, expected.store)
					if got, want := appStoreSnapshot(t, actual.store), appStoreSnapshot(t, expected.store); !reflect.DeepEqual(got, want) {
						t.Fatal("mesh HTTP changed app registry state", got, want)
					}
					if got, want := trustSnapshot(t, actual.store), trustSnapshot(t, expected.store); !reflect.DeepEqual(got, want) {
						t.Fatal("mesh HTTP changed trust state", got, want)
					}
				}
			})
		}
	}
}

func TestZiranMeshPostJSONAgainstBaseline(t *testing.T) {
	previous := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previous })
	sentinel := errors.New("mesh transport or read failure")
	for _, signed := range []bool{false, true} {
		for _, mode := range []string{"success", "trailing JSON", "invalid JSON", "EOF", "HTTP failure", "redirect status", "read failure", "failure read", "transport failure", "invalid URL", "nil context", "cancelled", "marshal failure", "read panic"} {
			t.Run(mode+map[bool]string{false: "/token", true: "/signed"}[signed], func(t *testing.T) {
				server := meshHTTPFixture(t)
				server.cfg.NodeSyncToken = " raw mesh-secret "
				contextValue := t.Context()
				if mode == "nil context" {
					contextValue = nil
				}
				if mode == "cancelled" {
					cancelled, cancel := context.WithCancel(contextValue)
					cancel()
					contextValue = cancelled
				}
				target := "http://peer.test/api/v1/node/mesh/export"
				if mode == "invalid URL" {
					target = "http://%zz"
				}
				input := any(NodeMeshExportRequest{Policy: meshHTTPPolicy(), Limit: 1})
				if mode == "marshal failure" {
					input = func() {}
				}
				var outcomes []error
				var replies []NodeMeshExportResponse
				var requestLogs [][]string
				for implementation := 0; implementation < 2; implementation++ {
					var logs []string
					var body *httpPortBody
					http.DefaultTransport = trustHTTPTransport(func(request *http.Request) (*http.Response, error) {
						data, err := io.ReadAll(request.Body)
						request.Body.Close()
						if err != nil {
							t.Fatal(err)
						}
						logs = append(logs, request.Method, request.URL.String(), string(data), request.Header.Get("Content-Type"), request.Header.Get("Authorization"))
						deadline, exists := request.Context().Deadline()
						if !exists || time.Until(deadline) > 20*time.Second || time.Until(deadline) < 19*time.Second || request.GetBody == nil {
							t.Fatalf("mesh timeout or request replay changed: %v, %v", deadline, exists)
						}
						if signed {
							signature, err := base64.RawURLEncoding.DecodeString(request.Header.Get("X-Daochi-Node-Signature"))
							message := baselineNodeMessage("daochi-node-request-v1", server.node.ID, request.Header.Get("X-Daochi-Node-Time"), request.Header.Get("X-Daochi-Node-Nonce"), request.Method, request.URL.EscapedPath(), data)
							if err != nil || !ed25519.Verify(server.node.PublicKey, []byte(message), signature) || request.Header.Get("X-Daochi-Node-ID") != server.node.ID || request.Header.Get("Authorization") != "" {
								t.Fatal("mesh request lost node authentication")
							}
						} else if request.Header.Get("Authorization") != "Bearer "+server.cfg.NodeSyncToken {
							t.Fatal("mesh request token was normalized")
						}
						if mode == "transport failure" {
							return nil, sentinel
						}
						if mode == "cancelled" {
							return nil, context.Canceled
						}
						status := http.StatusOK
						payload := `{"status":"ok","records":[]}`
						switch mode {
						case "trailing JSON":
							payload += `{"ignored":true}`
						case "invalid JSON":
							payload = `{"status":false}`
						case "EOF":
							payload = ""
						case "HTTP failure", "failure read":
							status = http.StatusServiceUnavailable
							payload = "\u2003" + strings.Repeat("failed <peer> ", 300)
						case "redirect status":
							status = http.StatusMultipleChoices
						}
						body = &httpPortBody{Reader: strings.NewReader(payload)}
						if mode == "read failure" || mode == "failure read" {
							body.Reader = deviceHTTPReadFailure{failure: sentinel}
						}
						if mode == "read panic" {
							body.panicValue = sentinel
						}
						return &http.Response{StatusCode: status, Status: http.StatusText(status), Header: make(http.Header), Body: body, Request: request}, nil
					})
					peerID := ""
					if signed {
						peerID = "remote-node"
					}
					var reply NodeMeshExportResponse
					var result error
					func() {
						defer func() {
							value := recover()
							if mode == "read panic" && value != sentinel {
								t.Fatalf("mesh read panic = %v", value)
							}
							if mode != "read panic" && value != nil {
								panic(value)
							}
						}()
						if implementation == 0 {
							result = Mesh_PostJSON(server.mesh(), contextValue, peerID, target, input, &reply)
						} else {
							result = server.baselineMeshPostNodeMeshJSON(contextValue, peerID, target, input, &reply)
						}
					}()
					if body != nil && body.closed != 1 {
						t.Fatalf("mesh response body closed %d times", body.closed)
					}
					outcomes = append(outcomes, result)
					replies = append(replies, reply)
					requestLogs = append(requestLogs, logs)
				}
				if !sameIdentityError(outcomes[0], outcomes[1]) || !reflect.DeepEqual(replies[0], replies[1]) || !reflect.DeepEqual(requestLogs[0], requestLogs[1]) {
					t.Fatal("mesh POST changed", outcomes, replies, requestLogs)
				}
				if (mode == "read failure" || mode == "transport failure") && !errors.Is(outcomes[0], sentinel) {
					t.Fatal("mesh native failure lost its identity", outcomes[0])
				}
			})
		}
	}
}

func TestZiranMeshConcurrentReplayAtHTTPBoundary(t *testing.T) {
	server := meshHTTPFixture(t)
	identity := NodeIdentity_New(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x47}, ed25519.SeedSize))).Value
	meshHTTPPeer(t, server, identity, meshHTTPPolicy())
	body, err := json.Marshal(NodeMeshExportRequest{Policy: meshHTTPPolicy()})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("POST", "/api/v1/node/mesh/export", bytes.NewReader(body))
	NodeAuth_Sign(identity.ID, identity.PrivateKey, request, body)
	statuses := make(chan int, 12)
	var workers sync.WaitGroup
	for index := 0; index < cap(statuses); index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			local := request.Clone(t.Context())
			local.Body = io.NopCloser(bytes.NewReader(body))
			writer := httptest.NewRecorder()
			Mesh_Export(server.mesh(), writer, local)
			statuses <- writer.Code
		}()
	}
	workers.Wait()
	close(statuses)
	accepted := 0
	for status := range statuses {
		switch status {
		case http.StatusOK:
			accepted++
		case http.StatusUnauthorized:
		default:
			t.Fatalf("concurrent mesh replay status = %d", status)
		}
	}
	if accepted != 1 {
		t.Fatalf("mesh request accepted %d times", accepted)
	}
}
