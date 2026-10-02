package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestZiranMeshPullPaginationAndFailuresAgainstBaseline(t *testing.T) {
	previous := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previous })
	registration, registryKey := meshAppRegistration(t, "demo", 1)
	first := meshPortRecord("pull-first", 12)
	second := meshPortRecord("pull-second", 14)
	deletion := MeshEncryptedRecordDeletion{
		UserIDHash: first.UserIDHash, Collection: first.Record.Collection, ID: first.Record.ID,
		DeletedAt: "2026-10-01T00:00:00Z", MeshVersion: 16,
	}
	sentinel := errors.New("mesh interrupted")
	for _, mode := range []string{
		"pagination", "legacy cursor", "truncated legacy", "empty", "spaces only", "nil policy", "empty URL",
		"invalid URL", "resume", "reconnect", "transport", "cancelled", "cursor load", "cursor save",
		"invalid app", "invalid record", "invalid name", "late record failure",
	} {
		t.Run(mode, func(t *testing.T) {
			actual, expected := meshHTTPFixture(t), meshHTTPFixture(t)
			policy := meshHTTPPolicy()
			peer := NodePeer{Name: "Peer <one>\n", URL: "\u2003http://peer.test///\t", Sync: &policy}
			if mode == "empty URL" {
				peer.URL = "\u2003///\t"
			}
			if mode == "invalid URL" {
				peer.URL = "http://%zz"
			}
			if mode == "nil policy" {
				peer.Sync = nil
			}
			firstCursor := MeshCursor_Encode(MeshCursor{Seq: 12}).Value
			lastCursor := MeshCursor_Encode(MeshCursor{Seq: 16}).Value
			pages := []NodeMeshExportResponse{
				{Status: "ok", Apps: []SignedAppRegistrationRequest{registration}, Records: []MeshEncryptedRecord{first}, NextCursor: firstCursor, Truncated: true},
				{Status: "ok", Records: []MeshEncryptedRecord{second}, Deletions: []MeshEncryptedRecordDeletion{deletion}, NextCursor: lastCursor},
			}
			switch mode {
			case "legacy cursor", "truncated legacy":
				pages = []NodeMeshExportResponse{{Records: []MeshEncryptedRecord{first, second}, Deletions: []MeshEncryptedRecordDeletion{deletion}, Truncated: mode == "truncated legacy"}}
			case "empty":
				pages = []NodeMeshExportResponse{{NextCursor: firstCursor, Truncated: true}}
			case "spaces only":
				pages = []NodeMeshExportResponse{{Spaces: []MeshTrustSpace{{SpaceID: "invalid"}}, NextCursor: firstCursor}}
			case "nil policy":
				pages = []NodeMeshExportResponse{{Records: []MeshEncryptedRecord{first}, NextCursor: firstCursor}}
			case "invalid app":
				pages[0].Apps[0].ManifestSignature = "bad signature"
			case "invalid record":
				pages[0].Records[0].UserIDHash = "invalid"
			case "invalid name":
				pages[0].Names = []NameClaim{{SpaceID: "space", Name: "invalid!"}}
			}
			var outcomes []error
			var allRequests [][]NodeMeshExportRequest
			for implementation, server := range []*Server{actual, expected} {
				server.Cfg.NodeRegistryPublicKey = registryKey
				ctx := t.Context()
				if mode == "cancelled" {
					cancelled, cancel := context.WithCancel(ctx)
					cancel()
					ctx = cancelled
				}
				query := ""
				switch mode {
				case "cursor load":
					query = "ALTER TABLE node_sync_cursors RENAME TO broken_cursors"
				case "cursor save":
					query = "CREATE TRIGGER reject_cursor BEFORE INSERT ON node_sync_cursors BEGIN SELECT RAISE(ABORT,'cursor rejected'); END"
				case "late record failure":
					query = "CREATE TRIGGER reject_record BEFORE INSERT ON server_encrypted_records WHEN NEW.id='pull-second' BEGIN SELECT RAISE(ABORT,'record rejected'); END"
				}
				if query != "" {
					if _, err := server.Store.Database.Exec(query); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "resume" {
					key := MeshCursor_PeerKey("http://peer.test", policy)
					if err := MeshStore_SaveCursor(server.Store.Database, ctx, key, " raw saved cursor "); err != nil {
						t.Fatal(err)
					}
				}
				var requests []NodeMeshExportRequest
				var bodies []*httpPortBody
				interrupted := mode == "reconnect"
				http.DefaultTransport = trustHTTPTransport(func(request *http.Request) (*http.Response, error) {
					var input NodeMeshExportRequest
					if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
						t.Fatal(err)
					}
					request.Body.Close()
					requests = append(requests, input)
					if mode == "transport" || (interrupted && len(requests) == 2) {
						return nil, sentinel
					}
					page := 0
					if input.Cursor == firstCursor {
						page = 1
					}
					if page >= len(pages) {
						t.Fatal("unexpected mesh page request", input)
					}
					encoded, err := json.Marshal(pages[page])
					if err != nil {
						t.Fatal(err)
					}
					body := &httpPortBody{Reader: strings.NewReader(string(encoded))}
					bodies = append(bodies, body)
					return &http.Response{StatusCode: 200, Status: "200 OK", Header: make(http.Header), Body: body, Request: request}, nil
				})
				pull := func() error {
					if implementation == 0 {
						return Mesh_PullPeer(server.mesh(), ctx, peer)
					}
					return server.baselineMeshPullNodePeer(ctx, peer)
				}
				result := pull()
				if mode == "reconnect" {
					if !errors.Is(result, sentinel) {
						t.Fatal("mesh interruption lost error identity", result)
					}
					interrupted = false
					result = pull()
					if len(requests) != 3 || requests[2].Cursor != firstCursor {
						t.Fatal("mesh reconnect failed to resume its completed page", requests)
					}
				}
				for _, body := range bodies {
					if body.closed != 1 {
						t.Fatalf("pull response closed %d times", body.closed)
					}
				}
				outcomes = append(outcomes, result)
				allRequests = append(allRequests, requests)
			}
			if !sameIdentityError(outcomes[0], outcomes[1]) || !reflect.DeepEqual(allRequests[0], allRequests[1]) {
				t.Fatal("mesh pull changed", outcomes, allRequests)
			}
			if mode == "pagination" || mode == "reconnect" || mode == "legacy cursor" || mode == "truncated legacy" || mode == "resume" {
				if outcomes[0] != nil {
					t.Fatal("valid mesh pull failed", outcomes[0])
				}
			}
			if mode != "cursor load" {
				compareMeshState(t, actual.Store, expected.Store)
			}
			if got, want := appStoreSnapshot(t, actual.Store), appStoreSnapshot(t, expected.Store); !reflect.DeepEqual(got, want) {
				t.Fatal("mesh pull changed app transactions", got, want)
			}
			if got, want := trustSnapshot(t, actual.Store), trustSnapshot(t, expected.Store); !reflect.DeepEqual(got, want) {
				t.Fatal("mesh pull changed trust transactions", got, want)
			}
		})
	}
}

func TestZiranMeshConfiguredPeersAgainstBaseline(t *testing.T) {
	previous := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previous })
	for _, mode := range []string{"ordered", "missing trust table", "invalid stored policy"} {
		t.Run(mode, func(t *testing.T) {
			var traces [][]string
			for implementation := 0; implementation < 2; implementation++ {
				server := meshHTTPFixture(t)
				pull := NodeSyncPolicy{Direction: " PULL ", Data: []string{"encrypted_records"}, Apps: []string{"source"}}
				push := NodeSyncPolicy{Direction: "push", Data: []string{"encrypted_records"}}
				server.Cfg.KnownNodes = []NodePeer{
					{Name: "failed", URL: "http://failed.test", Sync: &pull},
					{Name: "configured", URL: "http://configured.test", Sync: &pull},
					{Name: "disabled", URL: "http://disabled.test"},
				}
				encodedPull, _ := json.Marshal(pull)
				encodedPush, _ := json.Marshal(push)
				for _, peer := range []struct{ name, addresses, policy string }{
					{"z-last", `["http://z.test","http://unused.test"]`, string(encodedPull)},
					{"a-first", `["http://a.test"]`, string(encodedPull)},
					{"push", `["http://push.test"]`, string(encodedPush)},
					{"no addresses", `[]`, string(encodedPull)},
				} {
					if _, err := server.Store.Database.Exec(`INSERT INTO trusted_node_peers(node_id,public_key,display_name,addresses_json,policy_json,trusted_at)
VALUES(?1,?2,?1,?3,?4,'fixture')`, peer.name, server.Node.PublicKey, peer.addresses, peer.policy); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "missing trust table" {
					if _, err := server.Store.Database.Exec("DROP TABLE trusted_node_peers"); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "invalid stored policy" {
					if _, err := server.Store.Database.Exec("UPDATE trusted_node_peers SET policy_json='{' WHERE display_name='z-last'"); err != nil {
						t.Fatal(err)
					}
				}
				var requests []string
				http.DefaultTransport = trustHTTPTransport(func(request *http.Request) (*http.Response, error) {
					data, err := io.ReadAll(request.Body)
					request.Body.Close()
					if err != nil {
						t.Fatal(err)
					}
					requests = append(requests, request.URL.Host, string(data))
					// The original worker snapshots configured peers before I/O.
					server.Cfg.KnownNodes[1].URL = "http://mutated.test"
					if request.URL.Host == "failed.test" {
						return nil, errors.New("first peer unavailable")
					}
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"records":[]}`)), Request: request}, nil
				})
				if implementation == 0 {
					Mesh_PullPeers(server.mesh(), t.Context())
				} else {
					server.baselineMeshPullConfiguredNodePeers(t.Context())
				}
				traces = append(traces, requests)
			}
			if !reflect.DeepEqual(traces[0], traces[1]) {
				t.Fatal("configured and paired peer ordering changed", traces)
			}
			if mode == "ordered" && (len(traces[0]) != 8 || traces[0][0] != "failed.test" || traces[0][2] != "configured.test" || traces[0][4] != "a.test" || traces[0][6] != "z.test") {
				t.Fatal("configured and trusted peers were not pulled in released order", traces[0])
			}
		})
	}
}
