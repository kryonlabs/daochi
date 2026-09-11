package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeGooglePlay stands in for the androidpublisher API and the OAuth
// token endpoint, mirroring the fakeMoneroWalletRPC pattern.
type fakeGooglePlay struct {
	API   *httptest.Server
	Token *httptest.Server

	mu               sync.Mutex
	purchaseState    int64
	consumptionState int64
	orderID          string
	consumeCalls     int64
	tokenCalls       int64
}

func newFakeGooglePlay(t *testing.T) *fakeGooglePlay {
	t.Helper()
	fake := &fakeGooglePlay{orderID: "GPA.3306-TEST-0001"}
	fake.Token = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fake.mu.Lock()
		fake.tokenCalls++
		fake.mu.Unlock()
		if err := r.ParseForm(); err != nil || r.PostForm.Get("grant_type") == "" {
			t.Errorf("oauth request missing form: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fake-access-token"})
	}))
	fake.API = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fake-access-token" {
			t.Errorf("androidpublisher call without bearer token: %q", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if strings.HasSuffix(r.URL.Path, ":consume") {
			fake.mu.Lock()
			fake.consumeCalls++
			fake.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		}
		fake.mu.Lock()
		purchaseState, consumptionState, orderID := fake.purchaseState, fake.consumptionState, fake.orderID
		fake.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"purchaseState":        purchaseState,
			"consumptionState":     consumptionState,
			"acknowledgementState": 1,
			"orderId":              orderID,
		})
	}))
	t.Cleanup(fake.API.Close)
	t.Cleanup(fake.Token.Close)
	return fake
}

func (f *fakeGooglePlay) setPurchaseState(purchase, consumption int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.purchaseState = purchase
	f.consumptionState = consumption
}

func (f *fakeGooglePlay) consumeCount() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.consumeCalls
}

func (f *fakeGooglePlay) serviceAccountJSON(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	payload, err := json.Marshal(googleServiceAccount{
		ClientEmail: "daochi-test@example.iam.gserviceaccount.com",
		PrivateKey:  pemKey,
		TokenURI:    f.Token.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}

// googleTestConfig wires the verifier at a fake Google Play + OAuth pair
// and restores the real endpoints afterwards.
func googleTestConfig(t *testing.T) (*fakeGooglePlay, Config, func()) {
	t.Helper()
	fake := newFakeGooglePlay(t)
	previous := googlePlayAPIBaseURL
	googlePlayAPIBaseURL = fake.API.URL
	cfg := Config{GoogleServiceAccountJSON: fake.serviceAccountJSON(t)}
	return fake, cfg, func() { googlePlayAPIBaseURL = previous }
}

func TestVerifyGooglePlayPurchaseAcceptsValidPurchase(t *testing.T) {
	_, cfg, restore := googleTestConfig(t)
	defer restore()
	req := GooglePurchaseVerifyRequest{
		PackageName:   "net.waozi.inbe",
		ProductID:     "waozi_tokens_small",
		PurchaseToken: "purchase-token-1",
	}
	ref, err := verifyGooglePlayPurchase(context.Background(), cfg, req)
	if err != nil {
		t.Fatal(err)
	}
	if want := "net.waozi.inbe:waozi_tokens_small:GPA.3306-TEST-0001"; ref != want {
		t.Fatalf("payment ref = %q, want %q", ref, want)
	}
}

func TestVerifyGooglePlayPurchaseRejectsBadStates(t *testing.T) {
	fake, cfg, restore := googleTestConfig(t)
	defer restore()
	req := GooglePurchaseVerifyRequest{
		PackageName:   "net.waozi.inbe",
		ProductID:     "waozi_tokens_small",
		PurchaseToken: "purchase-token-2",
	}
	verify := func() error {
		_, err := verifyGooglePlayPurchase(context.Background(), cfg, req)
		return err
	}
	if err := verify(); err != nil {
		t.Fatalf("valid purchase rejected: %v", err)
	}
	fake.setPurchaseState(1, 0)
	if err := verify(); err == nil || !strings.Contains(err.Error(), "not purchased") {
		t.Fatalf("canceled purchase accepted: %v", err)
	}
	fake.setPurchaseState(0, 1)
	if err := verify(); err == nil || !strings.Contains(err.Error(), "already consumed") {
		t.Fatalf("consumed purchase accepted: %v", err)
	}
}

func TestConsumeGooglePlayPurchase(t *testing.T) {
	fake, cfg, restore := googleTestConfig(t)
	defer restore()
	req := GooglePurchaseVerifyRequest{
		PackageName:   "net.waozi.inbe",
		ProductID:     "waozi_tokens_small",
		PurchaseToken: "purchase-token-3",
	}
	if err := consumeGooglePlayPurchase(context.Background(), cfg, req); err != nil {
		t.Fatal(err)
	}
	if fake.consumeCount() != 1 {
		t.Fatalf("consume calls = %d, want 1", fake.consumeCount())
	}
}

func TestGoogleRefreshAccessTokenUsesClientTokenURI(t *testing.T) {
	fake := newFakeGooglePlay(t)
	clientFile, err := json.Marshal(googleOAuthClientFile{
		Web: googleOAuthClient{ClientID: "cid", ClientSecret: "secret", TokenURI: fake.Token.URL},
	})
	if err != nil {
		t.Fatal(err)
	}
	token, err := googleRefreshAccessToken(context.Background(), string(clientFile), "refresh-token")
	if err != nil {
		t.Fatal(err)
	}
	if token != "fake-access-token" {
		t.Fatalf("access token = %q", token)
	}
}
