package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func sequencedRegistration(t *testing.T, sequence int64, status string, appKey, nodeKey ed25519.PrivateKey) SignedAppRegistrationRequest {
	t.Helper()
	request := SignedAppRegistrationRequest{Manifest: AppManifest{
		ManifestVersion: 1, ManifestSequence: sequence, AppID: "demo", DisplayName: "Demo", Status: status,
		Keys: []AppKey{{KeyID: "key-main1", Algorithm: "ed25519", PublicKey: hex.EncodeToString(appKey.Public().(ed25519.PublicKey))}},
	}}
	signRegistrationFixture(t, &request, appKey, nodeKey)
	return request
}

func postRegistration(t *testing.T, handler http.Handler, request SignedAppRegistrationRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	post := httptest.NewRequest(http.MethodPost, "/api/v1/apps/register-signed", bytes.NewReader(body))
	post.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, post)
	return recorder
}

// Anyone can resubmit a signed manifest, and an old approval stays signed. A
// higher manifest_sequence must win so an old approval cannot undo a later
// suspension or key revocation.
func TestOlderSignedManifestCannotReplaceNewer(t *testing.T) {
	server, store, _ := testServer(t)
	appKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x52}, ed25519.SeedSize))
	nodeKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x53}, ed25519.SeedSize))
	server.Cfg.NodeRegistryPublicKey = nodeKey.Public().(ed25519.PublicKey)
	handler := server.Routes()

	active := sequencedRegistration(t, 1, "active", appKey, nodeKey)
	suspended := sequencedRegistration(t, 2, "suspended", appKey, nodeKey)
	unsequenced := sequencedRegistration(t, 0, "active", appKey, nodeKey)
	if response := postRegistration(t, handler, active); response.Code != http.StatusOK {
		t.Fatalf("first registration = %d %s", response.Code, response.Body.String())
	}
	if response := postRegistration(t, handler, suspended); response.Code != http.StatusOK {
		t.Fatalf("newer registration = %d %s", response.Code, response.Body.String())
	}
	for name, replay := range map[string]SignedAppRegistrationRequest{"older": active, "unsequenced": unsequenced} {
		if response := postRegistration(t, handler, replay); response.Code != http.StatusConflict {
			t.Fatalf("%s replay = %d %s; expected conflict", name, response.Code, response.Body.String())
		}
	}
	app := AppStore_ByID(store.Database, t.Context(), "demo")
	if app.Error != nil || !app.Found || app.Value.Status != "suspended" {
		t.Fatalf("installed app = %#v", app)
	}
	if response := postRegistration(t, handler, suspended); response.Code != http.StatusOK {
		t.Fatalf("resubmitting the installed manifest = %d %s", response.Code, response.Body.String())
	}

	// Mesh import keeps the newer manifest and skips the stale copy.
	policy := NodeSyncPolicy{Direction: "pull", Apps: []string{"demo"}, Data: []string{"app_registry"}}
	key := server.Cfg.NodeRegistryPublicKey
	stale := MeshApps_Import(store.Database, t.Context(), key, policy, []SignedAppRegistrationRequest{active}, AuthenticationError_Convert)
	if stale.Error != nil || stale.Value != 0 {
		t.Fatalf("stale mesh manifest = %#v", stale)
	}
	newer := sequencedRegistration(t, 3, "active", appKey, nodeKey)
	imported := MeshApps_Import(store.Database, t.Context(), key, policy, []SignedAppRegistrationRequest{newer}, AuthenticationError_Convert)
	if imported.Error != nil || imported.Value != 1 {
		t.Fatalf("newer mesh manifest = %#v", imported)
	}
	app = AppStore_ByID(store.Database, t.Context(), "demo")
	if app.Error != nil || !app.Found || app.Value.Status != "active" {
		t.Fatalf("mesh did not install the newer manifest: %#v", app)
	}
}
