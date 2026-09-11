package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNodeIdentityPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.key")
	first, err := loadOrCreateNodeIdentityKey(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateNodeIdentityKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("node identity changed after reload")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("node key permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestPairingInviteSignatureAndTampering(t *testing.T) {
	identity, err := newNodeIdentity(nil)
	if err != nil {
		t.Fatal(err)
	}
	invite := PairingInvite{
		Version:     1,
		InviteID:    randomHex(16),
		NodeID:      identity.ID,
		PublicKey:   encodeHex(identity.PublicKey),
		DisplayName: "Home",
		Addresses:   []string{"http://192.168.1.10:8080"},
		ExpiresAt:   time.Now().Add(time.Minute).Unix(),
		Nonce:       randomHex(16),
		Policy: NodeSyncPolicy{
			Direction:   "bidirectional",
			Apps:        []string{"inbe"},
			Collections: []string{"private.inbe.v1.*"},
			Data:        []string{"encrypted_records"},
		},
	}
	identity.signInvite(&invite)
	if _, err := validatePairingInvite(invite, time.Now()); err != nil {
		t.Fatalf("valid invite rejected: %v", err)
	}
	invite.DisplayName = "Attacker"
	if _, err := validatePairingInvite(invite, time.Now()); err == nil {
		t.Fatal("tampered invite accepted")
	}
}

func TestPairingAcceptanceSignatureAndTampering(t *testing.T) {
	inviter, err := newNodeIdentity(nil)
	if err != nil {
		t.Fatal(err)
	}
	acceptor, err := newNodeIdentity(nil)
	if err != nil {
		t.Fatal(err)
	}
	invite := PairingInvite{
		Version:   1,
		InviteID:  randomHex(16),
		NodeID:    inviter.ID,
		PublicKey: encodeHex(inviter.PublicKey),
		Addresses: []string{"http://192.168.1.10:8080"},
		ExpiresAt: time.Now().Add(time.Minute).Unix(),
		Nonce:     randomHex(16),
		Policy: NodeSyncPolicy{
			Direction: "bidirectional",
			Apps:      []string{"inbe"},
			Data:      []string{"encrypted_records"},
		},
	}
	inviter.signInvite(&invite)
	acceptance := PairingAcceptance{
		Version:     1,
		InviteID:    invite.InviteID,
		NodeID:      acceptor.ID,
		PublicKey:   encodeHex(acceptor.PublicKey),
		DisplayName: "Neighbor",
		Addresses:   []string{"http://192.168.1.11:8080"},
		AcceptedAt:  time.Now().Unix(),
		Nonce:       randomHex(16),
	}
	acceptor.signAcceptance(invite, &acceptance)
	if _, err := validatePairingAcceptance(invite, acceptance, time.Now()); err != nil {
		t.Fatalf("valid acceptance rejected: %v", err)
	}
	acceptance.DisplayName = "Attacker"
	if _, err := validatePairingAcceptance(invite, acceptance, time.Now()); err == nil {
		t.Fatal("tampered acceptance accepted")
	}
}

func TestSignedNodeRequestRejectsReplay(t *testing.T) {
	source, _, _ := testServer(t)
	target, targetStore, _ := testServer(t)
	trustServer(t, targetStore, source)

	body := []byte(`{"policy":{"apps":["inbe"],"data":["encrypted_records"]}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/node/mesh/export", bytes.NewReader(body))
	source.signNodeRequest(req, body)
	if err := target.verifyNodeRequest(req.Context(), req, body); err != nil {
		t.Fatalf("signed request rejected: %v", err)
	}
	if err := target.verifyNodeRequest(req.Context(), req, body); err == nil {
		t.Fatal("replayed request accepted")
	}
}

func TestPairedPolicyCannotBeExpanded(t *testing.T) {
	approved := NodeSyncPolicy{
		Direction:   "bidirectional",
		Apps:        []string{"inbe"},
		Collections: []string{"private.inbe.v1.*"},
		Data:        []string{"encrypted_records"},
	}
	if !policyAllowsOperation(approved, approved, "export") {
		t.Fatal("approved policy was rejected")
	}
	expanded := approved
	expanded.Apps = []string{"inbe", "other"}
	if policyAllowsOperation(approved, expanded, "export") {
		t.Fatal("expanded app scope was accepted")
	}
	expanded = approved
	expanded.Collections = []string{"public.other.v1.*"}
	if policyAllowsOperation(approved, expanded, "import") {
		t.Fatal("expanded collection scope was accepted")
	}
	pullOnly := approved
	pullOnly.Direction = "pull"
	if policyAllowsOperation(pullOnly, approved, "export") {
		t.Fatal("pull-only peer was allowed to export data")
	}
	if inverseNodeSyncPolicy(pullOnly).Direction != "push" {
		t.Fatal("reciprocal policy did not invert pull to push")
	}
}

func TestTrustSpaceNameRegistrationAndResolution(t *testing.T) {
	server, store, _ := testServer(t)
	spaceID, err := store.CreateTrustSpace(t.Context(), "Neighborhood")
	if err != nil {
		t.Fatal(err)
	}
	claim := NameClaim{
		SpaceID: spaceID,
		Name:    "home",
		NodeID:  server.node.ID,
		Services: []ServiceRecord{{
			Service:   "sync",
			Endpoints: []string{"http://192.168.1.10:8080"},
		}},
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	stored, err := store.SignAndStoreNameClaim(t.Context(), claim)
	if err != nil {
		t.Fatal(err)
	}
	resolved, found, err := store.ResolveNameClaim(t.Context(), spaceID, "home")
	if err != nil {
		t.Fatal(err)
	}
	if !found || resolved.NodeID != server.node.ID || resolved.Sequence != 1 {
		t.Fatalf("unexpected resolved claim: %#v", resolved)
	}
	if stored.Signature == "" || resolved.Signature != stored.Signature {
		t.Fatal("name claim signature was not preserved")
	}
}

func TestTrustSpaceNamesReplicateWithoutAuthorityPrivateKey(t *testing.T) {
	source, sourceStore, _ := testServer(t)
	_, targetStore, _ := testServer(t)
	spaceID, err := sourceStore.CreateTrustSpace(t.Context(), "Neighborhood")
	if err != nil {
		t.Fatal(err)
	}
	claim := NameClaim{
		SpaceID:   spaceID,
		Name:      "home",
		NodeID:    source.node.ID,
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Services: []ServiceRecord{{
			Service:   "sync",
			Endpoints: []string{"http://192.168.1.10:8080"},
		}},
	}
	if _, err := sourceStore.SignAndStoreNameClaim(t.Context(), claim); err != nil {
		t.Fatal(err)
	}
	policy := NodeSyncPolicy{
		Direction: "bidirectional",
		Spaces:    []string{spaceID},
		Data:      []string{"names"},
	}
	spaces, claims, err := sourceStore.ExportMeshNames(t.Context(), policy)
	if err != nil {
		t.Fatal(err)
	}
	if len(spaces) != 1 || len(claims) != 1 {
		t.Fatalf("exported spaces=%d names=%d", len(spaces), len(claims))
	}
	applied, err := targetStore.ImportMeshNames(t.Context(), policy, spaces, claims)
	if err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("applied names = %d, want 1", applied)
	}
	resolved, found, err := targetStore.ResolveNameClaim(t.Context(), spaceID, "home")
	if err != nil || !found || resolved.NodeID != source.node.ID {
		t.Fatalf("replicated name resolution = %#v, %v, %v", resolved, found, err)
	}
	var privateKey []byte
	if err := targetStore.db.QueryRow(`
SELECT authority_private_key FROM trust_spaces
WHERE space_id=?1`, spaceID).Scan(&privateKey); err != nil {
		t.Fatal(err)
	}
	if len(privateKey) != 0 {
		t.Fatal("namespace authority private key was replicated")
	}
}

func TestSignedAppManifestReplicatesBeforeOfflineRecords(t *testing.T) {
	source, sourceStore, _ := testServer(t)
	target, targetStore, _ := testServer(t)
	registryPublicKey, registryPrivateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	appPublicKey, appPrivateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	source.cfg.NodeRegistryPublicKey = registryPublicKey
	target.cfg.NodeRegistryPublicKey = registryPublicKey

	manifest := AppManifest{
		ManifestVersion: 1,
		AppID:           "notes",
		DisplayName:     "Notes",
		Keys: []AppKey{{
			KeyID:     "key-main1",
			Algorithm: "Ed25519",
			PublicKey: encodeHex(appPublicKey),
		}},
		Collections: []AppCollection{{
			CollectionPrefix: "private.notes.v1.*",
			Visibility:       "private",
			SchemaVersion:    1,
		}},
	}
	manifestBytes, manifestHash, err := formatAppManifestForTest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	registration := SignedAppRegistrationRequest{
		Manifest: manifest,
		ManifestSignature: encodeHex(ed25519.Sign(
			appPrivateKey,
			append([]byte(daochiAppManifestContext+"\n"), manifestBytes...),
		)),
		ApprovalSignature: encodeHex(ed25519.Sign(
			registryPrivateKey,
			appApprovalMessage(manifest.AppID, manifestHash),
		)),
	}
	if err := sourceStore.UpsertSignedAppManifest(
		t.Context(),
		manifest,
		manifestBytes,
		manifestHash,
		registration.ManifestSignature,
		registration.ApprovalSignature,
	); err != nil {
		t.Fatal(err)
	}

	policy := NodeSyncPolicy{
		Direction: "bidirectional",
		Apps:      []string{"notes"},
		Data:      []string{"app_registry", "encrypted_records"},
	}
	registrations, err := sourceStore.ExportMeshApps(t.Context(), policy)
	if err != nil {
		t.Fatal(err)
	}
	if len(registrations) != 1 {
		t.Fatalf("exported apps = %d, want 1", len(registrations))
	}
	applied, err := target.ImportMeshApps(t.Context(), policy, registrations)
	if err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("applied apps = %d, want 1", applied)
	}
	matchers, err := targetStore.appCollectionMatchers(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !meshPolicyAllowsRecord(policy, matchers, "private.notes.v1.page") {
		t.Fatal("replicated app registry does not authorize its collection")
	}

	applied, err = target.ImportMeshApps(t.Context(), policy, registrations)
	if err != nil {
		t.Fatal(err)
	}
	if applied != 0 {
		t.Fatalf("idempotent app import applied %d entries", applied)
	}
}

func TestPairingHandlersRequireOperatorAndConsumeInvite(t *testing.T) {
	source, sourceStore, _ := testServer(t)
	target, targetStore, _ := testServer(t)
	source.cfg.AdminToken = "operator-secret"
	target.cfg.AdminToken = "operator-secret"
	sourceHTTP := httptest.NewServer(source.Routes())
	t.Cleanup(sourceHTTP.Close)
	source.cfg.BaseURL = sourceHTTP.URL
	target.cfg.BaseURL = "http://192.168.1.11:8080"

	requestBody, err := json.Marshal(createInviteRequest{
		DisplayName: "Home",
		Addresses:   []string{sourceHTTP.URL},
		Policy: NodeSyncPolicy{
			Direction: "bidirectional",
			Apps:      []string{"inbe"},
			Data:      []string{"encrypted_records"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	inviteRequest := httptest.NewRequest(http.MethodPost,
		"/api/v1/node/pairing/invites", bytes.NewReader(requestBody))
	inviteRequest.Header.Set("X-Daochi-Admin", "operator-secret")
	inviteResponse := httptest.NewRecorder()
	source.Routes().ServeHTTP(inviteResponse, inviteRequest)
	if inviteResponse.Code != http.StatusOK {
		t.Fatalf("create invite status = %d body=%s", inviteResponse.Code, inviteResponse.Body.String())
	}
	var invite PairingInvite
	if err := json.Unmarshal(inviteResponse.Body.Bytes(), &invite); err != nil {
		t.Fatal(err)
	}

	accept := func() *httptest.ResponseRecorder {
		body, err := json.Marshal(invite)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost,
			"/api/v1/node/pairing/accept", bytes.NewReader(body))
		req.Header.Set("X-Daochi-Admin", "operator-secret")
		response := httptest.NewRecorder()
		target.Routes().ServeHTTP(response, req)
		return response
	}
	if response := accept(); response.Code != http.StatusOK {
		t.Fatalf("accept invite status = %d body=%s", response.Code, response.Body.String())
	}
	if response := accept(); response.Code != http.StatusConflict {
		t.Fatalf("reused invite status = %d, want 409", response.Code)
	}
	if _, found, err := sourceStore.TrustedPeerPublicKey(t.Context(), target.node.ID); err != nil || !found {
		t.Fatalf("inviter reciprocal trust = %v, %v", found, err)
	}
	if _, found, err := targetStore.TrustedPeerPublicKey(t.Context(), source.node.ID); err != nil || !found {
		t.Fatalf("acceptor trust = %v, %v", found, err)
	}
	meshBody := []byte(`{"policy":{"direction":"bidirectional","apps":["inbe"],"data":["encrypted_records"]}}`)
	meshRequest := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/node/mesh/export",
		bytes.NewReader(meshBody),
	)
	target.signNodeRequest(meshRequest, meshBody)
	if err := source.verifyNodeRequest(t.Context(), meshRequest, meshBody); err != nil {
		t.Fatalf("reciprocally paired request rejected: %v", err)
	}
}

func trustServer(t *testing.T, store *Store, peer *Server) {
	t.Helper()
	invite := PairingInvite{
		Version:     1,
		InviteID:    randomHex(16),
		NodeID:      peer.node.ID,
		PublicKey:   encodeHex(peer.node.PublicKey),
		DisplayName: "Peer",
		Addresses:   []string{"http://192.168.1.11:8080"},
		ExpiresAt:   time.Now().Add(time.Minute).Unix(),
		Nonce:       randomHex(16),
	}
	peer.node.signInvite(&invite)
	publicKey, err := validatePairingInvite(invite, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.TrustPeer(t.Context(), invite, ed25519.PublicKey(publicKey)); err != nil {
		t.Fatal(err)
	}
}

func encodeHex(value []byte) string {
	const digits = "0123456789abcdef"
	encoded := make([]byte, len(value)*2)
	for i, current := range value {
		encoded[i*2] = digits[current>>4]
		encoded[i*2+1] = digits[current&15]
	}
	return string(encoded)
}
