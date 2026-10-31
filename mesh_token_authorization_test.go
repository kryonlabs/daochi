package main

import (
	"bytes"
	"crypto/ed25519"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func meshTokenCredential(nodeID string) string {
	return nodeID + ":mesh-secret"
}

func TestMeshTokenUsesStoredIdentityBoundPolicy(t *testing.T) {
	server := meshHTTPFixture(t)
	peer := NodeIdentity_New(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x47}, ed25519.SeedSize))).Value
	approved := meshHTTPPolicy()
	meshHTTPPeer(t, server, peer, approved)
	server.Cfg.NodeSyncToken = meshTokenCredential(peer.ID)

	for _, testCase := range []struct {
		name         string
		credential   string
		requested    NodeSyncPolicy
		operation    string
		authorized   bool
		authStatus   int
		policyStatus int
	}{
		{
			name: "bound credential and exact policy", credential: meshTokenCredential(peer.ID),
			requested: approved, operation: "import", authorized: true,
		},
		{
			name: "claimed foreign node", credential: meshTokenCredential(strings.Repeat("c", 64)),
			requested: approved, operation: "import", authStatus: http.StatusUnauthorized,
		},
		{
			name: "legacy raw secret", credential: "mesh-secret", requested: approved,
			operation: "import", authStatus: http.StatusUnauthorized,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			request := httptest.NewRequest("POST", "/api/v1/node/mesh/import", nil)
			request.Header.Set("Authorization", "Bearer "+testCase.credential)
			writer := httptest.NewRecorder()
			authorized := Mesh_Authorize(server.mesh(), writer, request, []byte("body"))
			if authorized != testCase.authorized {
				t.Fatalf("authentication = %v, want %v; status=%d body=%s", authorized, testCase.authorized, writer.Code, writer.Body.String())
			}
			if authorized {
				writer = httptest.NewRecorder()
				allowed := Mesh_AuthorizePolicy(server.mesh(), writer, request, testCase.requested, testCase.operation)
				if allowed {
					return
				}
				if writer.Code != testCase.policyStatus {
					t.Fatalf("policy status = %d, want %d", writer.Code, testCase.policyStatus)
				}
				return
			}
			if writer.Code != testCase.authStatus {
				t.Fatalf("authentication status = %d, want %d", writer.Code, testCase.authStatus)
			}
		})
	}
}

func TestMeshTokenUnknownPeerHasNoImplicitAuthority(t *testing.T) {
	server := meshHTTPFixture(t)
	server.Cfg.NodeSyncToken = meshTokenCredential(server.Node.ID)
	request := httptest.NewRequest("POST", "/api/v1/node/mesh/import", nil)
	request.Header.Set("Authorization", "Bearer "+server.Cfg.NodeSyncToken)
	if !Mesh_Authorize(server.mesh(), httptest.NewRecorder(), request, []byte("body")) {
		t.Fatal("credential authentication failed")
	}
	writer := httptest.NewRecorder()
	if Mesh_AuthorizePolicy(server.mesh(), writer, request, meshHTTPPolicy(), "import") {
		t.Fatal("unknown peer gained implicit mesh authority")
	}
	if writer.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", writer.Code, http.StatusForbidden)
	}
}

func TestMeshTokenMalformedStoredPolicyHasNoAuthority(t *testing.T) {
	server := meshHTTPFixture(t)
	server.Cfg.NodeSyncToken = meshTokenCredential(server.Node.ID)
	if _, err := server.Store.Database.Exec(
		`INSERT INTO trusted_node_peers(node_id,public_key,display_name,addresses_json,policy_json,trusted_at)
		 VALUES(?1,?2,'peer','[]','{}','fixture')`,
		server.Node.ID, server.Node.PublicKey,
	); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("POST", "/api/v1/node/mesh/import", nil)
	request.Header.Set("Authorization", "Bearer "+server.Cfg.NodeSyncToken)
	if !Mesh_Authorize(server.mesh(), httptest.NewRecorder(), request, []byte("body")) {
		t.Fatal("credential authentication failed")
	}
	writer := httptest.NewRecorder()
	if Mesh_AuthorizePolicy(server.mesh(), writer, request, meshHTTPPolicy(), "import") {
		t.Fatal("empty stored policy gained mesh authority")
	}
	if writer.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", writer.Code, http.StatusForbidden)
	}
}

func TestMeshTokenCannotClaimSignedNodeIdentity(t *testing.T) {
	server := meshHTTPFixture(t)
	server.Cfg.NodeSyncToken = meshTokenCredential(server.Node.ID)
	request := httptest.NewRequest("POST", "/api/v1/node/mesh/import", nil)
	request.Header.Set("X-Daochi-Node-ID", strings.Repeat("d", 64))
	request.Header.Set("Authorization", "Bearer "+server.Cfg.NodeSyncToken)
	writer := httptest.NewRecorder()
	if Mesh_Authorize(server.mesh(), writer, request, []byte("body")) {
		t.Fatal("shared token impersonated a signed node identity")
	}
	if writer.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", writer.Code, http.StatusUnauthorized)
	}
}

func TestMeshLegacySharedTokenConfigurationIsDisabled(t *testing.T) {
	server := meshHTTPFixture(t)
	server.Cfg.NodeSyncToken = "mesh-secret"
	request := httptest.NewRequest("POST", "/api/v1/node/mesh/import", nil)
	request.Header.Set("Authorization", "Bearer mesh-secret")
	writer := httptest.NewRecorder()
	if Mesh_Authorize(server.mesh(), writer, request, []byte("body")) {
		t.Fatal("raw shared token retained implicit authority")
	}
	if writer.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", writer.Code, http.StatusServiceUnavailable)
	}
}

func TestMeshPublicBootstrapSendsIdentityBoundCredential(t *testing.T) {
	previous := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previous })
	server := meshHTTPFixture(t)
	credential := meshTokenCredential(server.Node.ID)
	server.Cfg.NodeSyncToken = credential
	var sentAuthorization string
	http.DefaultTransport = trustHTTPTransport(func(request *http.Request) (*http.Response, error) {
		sentAuthorization = request.Header.Get("Authorization")
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     http.StatusText(http.StatusOK),
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"status":"ok","records":[]}`)),
			Request:    request,
		}, nil
	})
	var reply NodeMeshExportResponse
	if err := Mesh_PostJSON(server.mesh(), t.Context(), "", "http://public.test/api/v1/node/mesh/export", NodeMeshExportRequest{}, &reply); err != nil {
		t.Fatal(err)
	}
	if sentAuthorization != "Bearer "+credential || reply.Status != "ok" {
		t.Fatalf("public bootstrap credential = %q, reply = %#v", sentAuthorization, reply)
	}
}

func TestMeshTokenPolicyCannotWidenStoredGrant(t *testing.T) {
	server := meshHTTPFixture(t)
	peer := NodeIdentity_New(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x48}, ed25519.SeedSize))).Value
	account := strings.Repeat("1", 64)
	approved := NodeSyncPolicy{
		Direction: "bidirectional", Accounts: []string{account}, Apps: []string{"source"},
		Collections: []string{"shared.source.*"}, Spaces: []string{"space"},
		Data: []string{"encrypted_records"},
	}
	meshHTTPPeer(t, server, peer, approved)
	server.Cfg.NodeSyncToken = meshTokenCredential(peer.ID)
	request := httptest.NewRequest("POST", "/api/v1/node/mesh/import", nil)
	request.Header.Set("Authorization", "Bearer "+server.Cfg.NodeSyncToken)

	for _, operation := range []string{"import", "export"} {
		if !Mesh_Authorize(server.mesh(), httptest.NewRecorder(), request, []byte("body")) {
			t.Fatal("bound token authentication failed")
		}
		if !Mesh_AuthorizePolicy(server.mesh(), httptest.NewRecorder(), request, approved, operation) {
			t.Fatalf("approved %s policy rejected", operation)
		}
	}
	for _, requested := range []NodeSyncPolicy{
		{Direction: approved.Direction, Apps: approved.Apps, Collections: approved.Collections, Spaces: approved.Spaces, Data: approved.Data},
		{Direction: approved.Direction, Accounts: approved.Accounts, Collections: approved.Collections, Spaces: approved.Spaces, Data: approved.Data},
		{Direction: approved.Direction, Accounts: approved.Accounts, Apps: approved.Apps, Spaces: approved.Spaces, Data: approved.Data},
		{Direction: approved.Direction, Accounts: approved.Accounts, Apps: approved.Apps, Collections: approved.Collections, Data: approved.Data},
		{Direction: approved.Direction, Accounts: approved.Accounts, Apps: approved.Apps, Collections: approved.Collections, Spaces: approved.Spaces},
	} {
		if Mesh_AuthorizePolicy(server.mesh(), httptest.NewRecorder(), request, requested, "import") {
			t.Fatalf("omitted filter widened policy: %#v", requested)
		}
	}
	for _, requested := range []NodeSyncPolicy{
		func() NodeSyncPolicy {
			value := approved
			value.Accounts = []string{strings.Repeat("2", 64)}
			return value
		}(),
		func() NodeSyncPolicy { value := approved; value.Apps = []string{"foreign"}; return value }(),
		func() NodeSyncPolicy { value := approved; value.Collections = []string{"foreign.*"}; return value }(),
		func() NodeSyncPolicy { value := approved; value.Spaces = []string{"foreign"}; return value }(),
		func() NodeSyncPolicy { value := approved; value.Data = []string{"names"}; return value }(),
	} {
		if Mesh_AuthorizePolicy(server.mesh(), httptest.NewRecorder(), request, requested, "import") {
			t.Fatalf("foreign scope widened policy: %#v", requested)
		}
	}
	pullOnly := approved
	pullOnly.Direction = "pull"
	pullServer := meshHTTPFixture(t)
	meshHTTPPeer(t, pullServer, peer, pullOnly)
	pullServer.Cfg.NodeSyncToken = meshTokenCredential(peer.ID)
	pullRequest := httptest.NewRequest("POST", "/api/v1/node/mesh/import", nil)
	pullRequest.Header.Set("Authorization", "Bearer "+pullServer.Cfg.NodeSyncToken)
	if Mesh_AuthorizePolicy(pullServer.mesh(), httptest.NewRecorder(), pullRequest, approved, "export") {
		t.Fatal("pull-only policy authorized export")
	}
	if !Mesh_AuthorizePolicy(pullServer.mesh(), httptest.NewRecorder(), pullRequest, approved, "import") {
		t.Fatal("pull-only policy rejected import")
	}
	pushOnly := approved
	pushOnly.Direction = "push"
	pushServer := meshHTTPFixture(t)
	meshHTTPPeer(t, pushServer, peer, pushOnly)
	pushServer.Cfg.NodeSyncToken = meshTokenCredential(peer.ID)
	pushRequest := httptest.NewRequest("POST", "/api/v1/node/mesh/import", nil)
	pushRequest.Header.Set("Authorization", "Bearer "+pushServer.Cfg.NodeSyncToken)
	if Mesh_AuthorizePolicy(pushServer.mesh(), httptest.NewRecorder(), pushRequest, approved, "import") {
		t.Fatal("push-only policy authorized import")
	}
	if !Mesh_AuthorizePolicy(pushServer.mesh(), httptest.NewRecorder(), pushRequest, approved, "export") {
		t.Fatal("push-only policy rejected export")
	}
}

func TestMeshSignedAuthenticationSurvivesReconnectionWithoutReplay(t *testing.T) {
	server := meshHTTPFixture(t)
	peer := NodeIdentity_New(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x49}, ed25519.SeedSize))).Value
	meshHTTPPeer(t, server, peer, meshHTTPPolicy())
	body := []byte(`{"policy":{}}`)
	signed := func() *http.Request {
		request := httptest.NewRequest("POST", "/api/v1/node/mesh/import", nil)
		NodeAuth_Sign(peer.ID, peer.PrivateKey, request, body)
		return request
	}
	if !Mesh_Authorize(server.mesh(), httptest.NewRecorder(), signed(), body) {
		t.Fatal("valid signed request rejected")
	}
	reconnected := signed()
	reconnected.Header.Set("X-Daochi-Node-Time", "1")
	if Mesh_Authorize(server.mesh(), httptest.NewRecorder(), reconnected, body) {
		t.Fatal("expired reconnection accepted")
	}
	malformed := signed()
	malformed.Header.Set("X-Daochi-Node-Signature", "malformed")
	if Mesh_Authorize(server.mesh(), httptest.NewRecorder(), malformed, body) {
		t.Fatal("malformed signature accepted")
	}
}

func TestMeshSignedReplayIsRejectedAfterReconnection(t *testing.T) {
	server := meshHTTPFixture(t)
	peer := NodeIdentity_New(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x50}, ed25519.SeedSize))).Value
	meshHTTPPeer(t, server, peer, meshHTTPPolicy())
	body := []byte(`{"policy":{}}`)
	first := httptest.NewRequest("POST", "/api/v1/node/mesh/import", nil)
	NodeAuth_Sign(peer.ID, peer.PrivateKey, first, body)
	if !Mesh_Authorize(server.mesh(), httptest.NewRecorder(), first, body) {
		t.Fatal("first signed request rejected")
	}
	second := first.Clone(t.Context())
	if Mesh_Authorize(server.mesh(), httptest.NewRecorder(), second, body) {
		t.Fatal("signed replay accepted after reconnection")
	}
}
