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
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

type trustHTTPTransport func(*http.Request) (*http.Response, error)

func (transport trustHTTPTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func trustHTTPFixture(t *testing.T) *Server {
	t.Helper()
	identity := NodeIdentity_New(ed25519.NewKeyFromSeed(bytesOf(0x41, ed25519.SeedSize)))
	if identity.Error != nil {
		t.Fatal(identity.Error)
	}
	return &Server{
		Store: trustStoreFixture(t),
		Node:  identity.Value,
		Cfg: Config{
			AdminToken:      "operator-secret",
			BaseURL:         "http://local.test/",
			NodeDisplayName: "Local <node>",
			MaxBodyBytes:    1 << 20,
		},
		Signer: signAccountProof}
}

func TestZiranPairingPolicyAgainstBaseline(t *testing.T) {
	for _, direction := range []string{"", "pull", "push", "bidirectional", "\u2003PULL\t", "receive", "off", "\xff"} {
		for _, data := range [][]string{nil, {}, {"names"}, {"encrypted_records"}, {"app_registry"}, {"\u2003NAMES\t", "ENCRYPTED_RECORDS"}, {"*"}} {
			for flags := 0; flags < 8; flags++ {
				policy := NodeSyncPolicy{Direction: direction, Data: data}
				if flags&1 != 0 {
					policy.Apps = []string{"notes"}
				}
				if flags&2 != 0 {
					policy.Collections = []string{"private.notes.*"}
				}
				if flags&4 != 0 {
					policy.Spaces = []string{"space"}
				}
				if got, want := MeshPolicy_ValidInbound(policy), baselineTrustInboundPolicy(policy); got != want {
					t.Fatalf("inbound policy %#v = %v, baseline %v", policy, got, want)
				}
				if got, want := TrustHttp_ValidPairingPolicy(policy), baselineTrustPairingPolicy(policy); got != want {
					t.Fatalf("pairing policy %#v = %v, baseline %v", policy, got, want)
				}
			}
		}
	}
}

func TestZiranRemotePairingAgainstBaseline(t *testing.T) {
	previous := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previous })
	sentinel := errors.New("pairing transport or read failed")
	for _, mode := range []string{"success", "last success", "redirect status", "HTTP failure", "transport failure", "read failure", "empty addresses", "nil context", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			invite := PairingInvite{InviteID: "fixture", Addresses: []string{"http://first.test///", "http://second.test"}}
			acceptance := PairingAcceptance{InviteID: invite.InviteID, NodeID: "acceptor"}
			if mode == "last success" {
				invite.Addresses = append([]string{"http://%zz"}, invite.Addresses...)
			}
			if mode == "empty addresses" {
				invite.Addresses = nil
			}
			ctx := t.Context()
			if mode == "nil context" {
				ctx = nil
			}
			if mode == "cancelled" {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			payload, err := json.Marshal(completePairingRequest{Invite: invite, Acceptance: acceptance})
			if err != nil {
				t.Fatal(err)
			}
			var outcomes []error
			var requestLogs [][]string
			var closeLogs [][]int
			for implementation := 0; implementation < 2; implementation++ {
				var requests []string
				var bodies []*httpPortBody
				http.DefaultTransport = trustHTTPTransport(func(request *http.Request) (*http.Response, error) {
					requests = append(requests, request.URL.String())
					data, err := io.ReadAll(request.Body)
					request.Body.Close()
					if err != nil || !bytes.Equal(data, payload) || request.Method != "POST" || request.Header.Get("Content-Type") != "application/json" || request.GetBody == nil {
						t.Fatalf("pairing request changed: %#v, body %q, error %v", request, data, err)
					}
					deadline, exists := request.Context().Deadline()
					if !exists || time.Until(deadline) > 10*time.Second || time.Until(deadline) < 9*time.Second {
						t.Fatalf("pairing deadline = %v, exists %v", deadline, exists)
					}
					if mode == "cancelled" {
						return nil, context.Canceled
					}
					if mode == "transport failure" {
						return nil, sentinel
					}
					body := &httpPortBody{Reader: strings.NewReader("\u2003" + strings.Repeat("failed <peer> ", 200))}
					status := http.StatusNoContent
					if mode == "read failure" {
						body.Reader = deviceHTTPReadFailure{failure: sentinel}
					}
					if mode == "HTTP failure" || (mode == "last success" && len(requests) == 1) {
						status = http.StatusServiceUnavailable
					}
					if mode == "redirect status" {
						status = http.StatusMultipleChoices
					}
					bodies = append(bodies, body)
					return &http.Response{StatusCode: status, Status: http.StatusText(status), Header: make(http.Header), Body: body, Request: request}, nil
				})
				var result error
				if implementation == 0 {
					result = TrustHttp_CompleteRemote(ctx, invite, acceptance)
				} else {
					result = baselineTrustCompleteRemote(ctx, invite, acceptance)
				}
				outcomes = append(outcomes, result)
				requestLogs = append(requestLogs, requests)
				var closes []int
				for _, body := range bodies {
					closes = append(closes, body.closed)
					if body.closed != 1 {
						t.Fatalf("response body closed %d times", body.closed)
					}
				}
				closeLogs = append(closeLogs, closes)
			}
			if !sameIdentityError(outcomes[0], outcomes[1]) || !reflect.DeepEqual(requestLogs[0], requestLogs[1]) || !reflect.DeepEqual(closeLogs[0], closeLogs[1]) {
				t.Fatalf("remote pairing outcomes = %v/%v; requests = %v/%v; closes = %v/%v", outcomes[0], outcomes[1], requestLogs[0], requestLogs[1], closeLogs[0], closeLogs[1])
			}
			if (mode == "transport failure" || mode == "read failure") && !errors.Is(outcomes[0], sentinel) {
				t.Fatalf("pairing failure lost error identity: %v", outcomes[0])
			}
			if mode == "cancelled" && !errors.Is(outcomes[0], context.Canceled) {
				t.Fatalf("pairing cancellation lost error identity: %v", outcomes[0])
			}
			if mode == "last success" && len(requestLogs[0]) != 2 {
				t.Fatalf("pairing did not retry the failed peer: %v", requestLogs[0])
			}
		})
	}
}

func TestZiranPairingAcceptanceAgainstBaseline(t *testing.T) {
	previous := rand.Reader
	t.Cleanup(func() { rand.Reader = previous })
	inviter := NodeIdentity_New(ed25519.NewKeyFromSeed(bytesOf(0x43, ed25519.SeedSize))).Value
	invite := PairingInvite{
		Version: 1, InviteID: "acceptance-fixture", NodeID: inviter.ID,
		PublicKey: hex.EncodeToString(inviter.PublicKey), Nonce: "invite-nonce",
		Addresses: []string{"http://inviter.test"}, ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	NodeIdentity_SignInvite(inviter, &invite)
	for _, address := range []string{"http://local.test///", "\u2003https://local.test/path/\t", "", "\u2003\t", "ftp://local.test", "http://%zz"} {
		t.Run(address, func(t *testing.T) {
			server := trustHTTPFixture(t)
			server.Cfg.BaseURL = address
			rand.Reader = identityEntropyReader{}
			got := TrustHttp_NewAcceptance(server.trust(), invite)
			rand.Reader = identityEntropyReader{}
			want, err := server.baselineTrustAcceptance(invite)
			if !sameIdentityError(got.Error, err) {
				t.Fatalf("acceptance errors = %v/%v", got.Error, err)
			}
			if got.Error == nil {
				if checked := NodeIdentity_ValidateAcceptance(invite, got.Value, time.Now()); checked.Error != nil {
					t.Fatal(checked.Error)
				}
				if difference := got.Value.AcceptedAt - want.AcceptedAt; difference < -1 || difference > 1 {
					t.Fatalf("acceptance time changed: %d/%d", got.Value.AcceptedAt, want.AcceptedAt)
				}
				got.Value.AcceptedAt, got.Value.Signature = want.AcceptedAt, want.Signature
			}
			if !reflect.DeepEqual(got.Value, want) {
				t.Fatalf("acceptance fields = %#v, baseline %#v", got.Value, want)
			}
		})
	}
}

func trustHTTPPayload(t *testing.T, server *Server, handler, mode string, now time.Time) ([]byte, string) {
	t.Helper()
	privateKey, authority, spaceID := trustKeyFixture()
	if handler == "claim" || handler == "resolve" {
		if _, err := server.Store.Database.Exec(`INSERT INTO trust_spaces(space_id,display_name,authority_public_key,authority_private_key,created_at)
VALUES(?1,'Fixture',?2,?3,?4)`, spaceID, []byte(authority), []byte(privateKey), Timestamp_CanonicalNow()); err != nil {
			t.Fatal(err)
		}
	}
	remote := NodeIdentity_New(ed25519.NewKeyFromSeed(bytesOf(0x43, ed25519.SeedSize))).Value
	inviter := remote
	if handler == "complete" || mode == "self" {
		inviter = server.Node
	}
	invite := PairingInvite{
		Version: 1, InviteID: "http-fixture", NodeID: inviter.ID, PublicKey: hex.EncodeToString(inviter.PublicKey),
		Addresses: []string{"http://remote.test"}, ExpiresAt: now.Add(time.Hour).Unix(), Nonce: "invite-nonce",
		Policy: NodeSyncPolicy{Direction: "pull", Apps: []string{"notes"}, Data: []string{"encrypted_records"}},
	}
	if mode == "expired" {
		invite.ExpiresAt = 1
	}
	NodeIdentity_SignInvite(inviter, &invite)
	acceptance := PairingAcceptance{
		Version: 1, InviteID: invite.InviteID, NodeID: remote.ID, PublicKey: hex.EncodeToString(remote.PublicKey),
		Addresses: []string{"http://remote.test"}, AcceptedAt: now.Unix(), Nonce: "acceptance-nonce",
	}
	if mode == "self" {
		acceptance.NodeID, acceptance.PublicKey = server.Node.ID, hex.EncodeToString(server.Node.PublicKey)
		NodeIdentity_SignAcceptance(server.Node, invite, &acceptance)
	} else {
		NodeIdentity_SignAcceptance(remote, invite, &acceptance)
	}
	if handler == "complete" && mode != "unissued" {
		if err := TrustStore_RecordIssuedPairingInvite(server.Store.Database, t.Context(), invite); err != nil {
			t.Fatal(err)
		}
	}
	if mode == "bad signature" {
		if handler == "complete" {
			acceptance.Signature = "!"
		} else {
			invite.Signature = "!"
		}
	}
	claim := NameClaim{
		SpaceID: spaceID, Name: "\u2003HOME\t", NodeID: server.Node.ID,
		ExpiresAt: now.Add(time.Hour).Unix(),
		Services:  []ServiceRecord{{Service: "sync", Endpoints: []string{"http://local.test"}}},
	}
	if mode == "expired" {
		claim.ExpiresAt = 1
	}
	if mode == "far future" {
		claim.ExpiresAt = now.Add(367 * 24 * time.Hour).Unix()
	}
	if mode == "invalid services" {
		claim.Services[0].Endpoints = []string{"javascript:evil"}
	}
	if mode == "invalid name" {
		claim.Name = "bad/name"
	}
	path := "/"
	var value any
	switch handler {
	case "invite":
		value = createInviteRequest{DisplayName: "\u2003Home <node>\t", SpaceID: " space ", Policy: invite.Policy}
		if mode == "no policy" {
			value = createInviteRequest{}
		}
		if mode == "far future" {
			value = createInviteRequest{ExpiresIn: MaximumInviteLifetimeSeconds + 1, Policy: invite.Policy}
		}
	case "accept":
		value = invite
		if mode == "replay" {
			if err := TrustStore_TrustPeer(server.Store.Database, t.Context(), invite, inviter.PublicKey); err != nil {
				t.Fatal(err)
			}
		}
	case "complete":
		value = completePairingRequest{Invite: invite, Acceptance: acceptance}
		if mode == "replay" {
			if err := TrustStore_CompleteIssuedPairing(server.Store.Database, t.Context(), invite, acceptance, remote.PublicKey); err != nil {
				t.Fatal(err)
			}
		}
	case "peers":
		if mode == "populated" {
			if err := TrustStore_TrustPeer(server.Store.Database, t.Context(), invite, inviter.PublicKey); err != nil {
				t.Fatal(err)
			}
			if _, err := server.Store.Database.Exec("UPDATE trusted_node_peers SET trusted_at=?1", Timestamp_CanonicalTimestamp(now)); err != nil {
				t.Fatal(err)
			}
		}
	case "space":
		value = map[string]any{"display_name": "\u2003Neighbors <name>\t"}
		if mode == "blank name" {
			value = map[string]any{"display_name": "\u2003\t"}
		}
	case "claim":
		value = claim
	case "resolve":
		claim.Name = "home"
		if mode != "missing" {
			if result := TrustStore_SignAndStoreNameClaim(server.Store.Database, t.Context(), claim); result.Error != nil {
				t.Fatal(result.Error)
			}
		}
		path = "/?space_id=" + spaceID + "&name=%E2%80%83HOME%09"
		if mode == "invalid name" {
			path = "/?space_id=!&name=bad/name"
		}
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded, path
}

func TestZiranTrustHTTPAgainstBaseline(t *testing.T) {
	previousTransport, previousEntropy := http.DefaultTransport, rand.Reader
	t.Cleanup(func() { http.DefaultTransport, rand.Reader = previousTransport, previousEntropy })
	http.DefaultTransport = trustHTTPTransport(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 204, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
	})
	type handlerPair struct {
		name       string
		actual     func(Trust, http.ResponseWriter, *http.Request)
		baseline   func(*Server, http.ResponseWriter, *http.Request)
		additional []string
	}
	handlers := []handlerPair{
		{"invite", TrustHttp_CreateInvite, (*Server).baselineTrustCreateInvite, []string{"no policy", "far future", "storage failure"}},
		{"accept", TrustHttp_AcceptInvite, (*Server).baselineTrustAcceptInvite, []string{"expired", "bad signature", "self", "unreachable local", "partition", "storage failure", "replay"}},
		{"complete", TrustHttp_CompletePairing, (*Server).baselineTrustCompletePairing, []string{"expired", "bad signature", "self", "unissued", "storage failure", "replay"}},
		{"peers", TrustHttp_ListPeers, (*Server).baselineTrustListPeers, []string{"populated"}},
		{"space", TrustHttp_CreateSpace, (*Server).baselineTrustCreateSpace, []string{"blank name", "storage failure"}},
		{"claim", TrustHttp_RegisterName, (*Server).baselineTrustRegisterName, []string{"expired", "far future", "invalid name", "invalid services", "storage failure"}},
		{"resolve", TrustHttp_ResolveName, (*Server).baselineTrustResolveName, []string{"missing", "invalid name"}},
	}
	for _, handler := range handlers {
		modes := []string{"valid", "unauthorized", "closed", "cancelled", "response panic"}
		if handler.name != "peers" && handler.name != "resolve" {
			modes = append(modes, "bad JSON", "wrong shape", "body limit", "read failure", "body panic")
		}
		modes = append(modes, handler.additional...)
		for _, mode := range modes {
			t.Run(handler.name+"/"+mode, func(t *testing.T) {
				http.DefaultTransport = trustHTTPTransport(func(request *http.Request) (*http.Response, error) {
					if mode == "partition" {
						return nil, errors.New("peer unavailable")
					}
					return &http.Response{StatusCode: 204, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
				})
				actual, expected := trustHTTPFixture(t), trustHTTPFixture(t)
				now := time.Now()
				payload, path := trustHTTPPayload(t, actual, handler.name, mode, now)
				_, _ = trustHTTPPayload(t, expected, handler.name, mode, now)
				var responses []*httptest.ResponseRecorder
				var closes []int
				panicValue := errors.New("trust HTTP panic")
				for index, server := range []*Server{actual, expected} {
					if mode == "storage failure" {
						table := map[string]string{
							"invite": "issued_pairing_invites", "accept": "trusted_node_peers",
							"complete": "trusted_node_peers", "space": "trust_spaces", "claim": "name_claims",
						}[handler.name]
						query := "CREATE TRIGGER reject_trust_http BEFORE INSERT ON " + table + " BEGIN SELECT RAISE(ABORT,'trust write failed'); END"
						if _, err := server.Store.Database.Exec(query); err != nil {
							t.Fatal(err)
						}
					}
					data := payload
					if mode == "bad JSON" {
						data = []byte("{")
					}
					if mode == "wrong shape" {
						data = []byte("[]")
					}
					body := &httpPortBody{Reader: bytes.NewReader(data)}
					if mode == "read failure" {
						body.Reader = deviceHTTPReadFailure{failure: errors.New("trust body read failed")}
					}
					if mode == "body panic" {
						body.panicValue = panicValue
					}
					request := httptest.NewRequest("POST", path, body)
					request.Header.Set("X-Daochi-Admin", "operator-secret")
					if mode == "unauthorized" {
						request.Header.Del("X-Daochi-Admin")
					}
					if mode == "body limit" {
						server.Cfg.MaxBodyBytes = 1
					}
					if mode == "unreachable local" {
						server.Cfg.BaseURL = ""
					}
					if mode == "closed" {
						_ = server.Store.Database.Close()
					}
					if mode == "cancelled" {
						ctx, cancel := context.WithCancel(t.Context())
						cancel()
						request = request.WithContext(ctx)
					}
					writer := httptest.NewRecorder()
					var output http.ResponseWriter = writer
					if mode == "response panic" {
						output = &httpPortWriter{header: make(http.Header), panicValue: panicValue}
					}
					rand.Reader = identityEntropyReader{}
					func() {
						defer func() {
							caught := recover()
							if mode == "response panic" || mode == "body panic" {
								if caught != panicValue {
									t.Fatalf("panic = %v, expected original %v", caught, panicValue)
								}
							} else if caught != nil {
								panic(caught)
							}
						}()
						if index == 0 {
							handler.actual(server.trust(), output, request)
						} else {
							handler.baseline(server, output, request)
						}
					}()
					responses = append(responses, writer)
					closes = append(closes, body.closed)
				}
				got, want := responses[0], responses[1]
				if got.Code != want.Code || !reflect.DeepEqual(got.Header(), want.Header()) || closes[0] != closes[1] {
					t.Fatalf("HTTP contract changed: %d/%d, headers %v/%v, closes %v", got.Code, want.Code, got.Header(), want.Header(), closes)
				}
				if mode == "valid" && handler.name == "space" && got.Code != http.StatusCreated {
					t.Fatalf("space success path not reached: %d, %s", got.Code, got.Body.String())
				}
				if mode == "valid" && handler.name != "space" && got.Code != http.StatusOK {
					t.Fatalf("success path not reached: %d, %s", got.Code, got.Body.String())
				}
				if got.Code == 200 && handler.name == "invite" && mode != "response panic" && mode != "body panic" {
					var invites [2]PairingInvite
					for index, response := range responses {
						if err := json.Unmarshal(response.Body.Bytes(), &invites[index]); err != nil {
							t.Fatal(err)
						}
						if checked := NodeIdentity_ValidateInvite(invites[index], time.Now()); checked.Error != nil {
							t.Fatal(checked.Error)
						}
						if remaining := invites[index].ExpiresAt - now.Unix(); remaining < 600 || remaining > 601 {
							t.Fatalf("default invite lifetime changed: %d seconds", remaining)
						}
						server := []*Server{actual, expected}[index]
						var signature string
						var expiry int64
						if err := server.Store.Database.QueryRow("SELECT signature,expires_at FROM issued_pairing_invites WHERE invite_id=?1", invites[index].InviteID).Scan(&signature, &expiry); err != nil {
							t.Fatal(err)
						}
						if signature != invites[index].Signature || expiry != invites[index].ExpiresAt {
							t.Fatal("issued invite does not match its HTTP response")
						}
					}
					if difference := invites[0].ExpiresAt - invites[1].ExpiresAt; difference < -1 || difference > 1 {
						t.Fatalf("invite expiry changed: %v", invites)
					}
					invites[0].ExpiresAt = invites[1].ExpiresAt
					invites[0].Signature = invites[1].Signature
					if !reflect.DeepEqual(invites[0], invites[1]) {
						t.Fatalf("invite fields changed: %#v/%#v", invites[0], invites[1])
					}
				} else if handler.name == "resolve" && got.Code == 200 && mode != "response panic" {
					var results [2]map[string]json.RawMessage
					var lifetimes [2]int64
					for index, response := range responses {
						if err := json.Unmarshal(response.Body.Bytes(), &results[index]); err != nil {
							t.Fatal(err)
						}
						if err := json.Unmarshal(results[index]["ttl_seconds"], &lifetimes[index]); err != nil {
							t.Fatal(err)
						}
						if lifetimes[index] < 3598 || lifetimes[index] > 3600 {
							t.Fatalf("name TTL changed: %d", lifetimes[index])
						}
						delete(results[index], "ttl_seconds")
					}
					if difference := lifetimes[0] - lifetimes[1]; difference < -1 || difference > 1 {
						t.Fatalf("name TTL differs from baseline: %v", lifetimes)
					}
					if !reflect.DeepEqual(results[0], results[1]) {
						t.Fatalf("resolved name changed: %s/%s", got.Body.String(), want.Body.String())
					}
				} else if !bytes.Equal(got.Body.Bytes(), want.Body.Bytes()) {
					t.Fatalf("response bytes changed: %s/%s", got.Body.String(), want.Body.String())
				}
				if mode != "closed" {
					actualState, expectedState := trustSnapshot(t, actual.Store), trustSnapshot(t, expected.Store)
					if handler.name == "invite" {
						for _, state := range []map[string][][]any{actualState, expectedState} {
							for _, issued := range state["issued"] {
								issued[1], issued[2] = "checked above", int64(0)
							}
						}
					}
					if !reflect.DeepEqual(actualState, expectedState) {
						t.Fatalf("trust writes changed: %#v/%#v", actualState, expectedState)
					}
				}
			})
		}
	}
}
