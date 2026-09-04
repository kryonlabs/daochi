package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAppRegistrationOwnsItsDeclaredScopes(t *testing.T) {
	valid := `{"app_id":"ukuvota","display_name":"Ukuvota","status":"active","collections":[{"collection_prefix":"private.ukuvota.v1.records.*","visibility":"private"}],"features":[{"id":"records.sync","collections":["private.ukuvota.v1.records.*"]}]}`
	req := httptest.NewRequest("POST", "/api/v1/apps", strings.NewReader(valid))
	if _, err := readAppRegistrationRequest(httptest.NewRecorder(), req, 1<<20); err != nil {
		t.Fatalf("own scope rejected: %v", err)
	}

	foreign := `{"app_id":"ukuvota","display_name":"Ukuvota","status":"active","collections":[{"collection_prefix":"private.krait.v1.records.*","visibility":"private"}]}`
	req = httptest.NewRequest("POST", "/api/v1/apps", strings.NewReader(foreign))
	if _, err := readAppRegistrationRequest(httptest.NewRecorder(), req, 1<<20); err == nil {
		t.Fatal("app registration accepted another app's scope")
	}

	mismatchedVisibility := `{"app_id":"ukuvota","display_name":"Ukuvota","status":"active","collections":[{"collection_prefix":"public.ukuvota.v1.records.*","visibility":"private"}]}`
	req = httptest.NewRequest("POST", "/api/v1/apps", strings.NewReader(mismatchedVisibility))
	if _, err := readAppRegistrationRequest(httptest.NewRecorder(), req, 1<<20); err == nil {
		t.Fatal("app registration accepted a visibility mismatch")
	}
}

func TestAppFeatureReferencesDeclaredScope(t *testing.T) {
	manifest := AppManifest{
		ManifestVersion: 1,
		AppID:           "ukuvota",
		DisplayName:     "Ukuvota",
		Status:          appStatusActive,
		Collections: []AppCollection{{
			CollectionPrefix: "private.ukuvota.v1.records.*",
			Visibility:       "private",
		}},
		Features: []AppFeature{{
			ID:          "archive.sync",
			Collections: []string{"private.ukuvota.v1.archive.*"},
		}},
		Keys: []AppKey{{
			KeyID:     "main-key",
			Algorithm: "Ed25519",
			PublicKey: strings.Repeat("00", 32),
		}},
	}
	if err := validateAppManifest(manifest); err == nil {
		t.Fatal("manifest feature accepted an undeclared scope")
	}
}

func TestInbeReleasedAndCurrentScopesRemainValid(t *testing.T) {
	for _, scope := range []AppCollection{
		{CollectionPrefix: "inbe.habits", Visibility: "private"},
		{CollectionPrefix: "inbe.habit_days", Visibility: "private"},
		{CollectionPrefix: "inbe.sessions", Visibility: "private"},
		{CollectionPrefix: "private.inbe.v1.records.*", Visibility: "private"},
		{CollectionPrefix: "shared.inbe.v1.records.*", Visibility: "shared"},
	} {
		if !appOwnsDeclaredScope("inbe", scope) {
			t.Fatalf("Inbe scope rejected: %#v", scope)
		}
	}
}

func TestSignedTransactionContextIsNotCallerDefined(t *testing.T) {
	tx := SignedTxEnvelope{ProtocolVersion: 6, SignatureContext: "attacker-context"}
	message := string(canonicalSignedTxMessage(tx))
	if !strings.HasPrefix(message, daochiTxContext+"\n") || strings.Contains(message, "attacker-context") {
		t.Fatalf("canonical transaction context was caller-controlled: %q", message)
	}
}
