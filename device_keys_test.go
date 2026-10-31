package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDeviceKeyRegistrationReplayAndRevocation(t *testing.T) {
	server, store, _ := testServer(t)
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x41)
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	registration := DeviceRegistrationRequest{
		AppID:     "inbe",
		KeyID:     "device-key-1",
		ClientID:  "test-client-1",
		PublicKey: hex.EncodeToString(publicKey),
		Nonce:     "register-device-1",
		ExpiresAt: time.Now().Add(time.Minute).Unix(),
		Signature: identity.Signature,
	}
	registrationBody, err := json.Marshal(registration)
	if err != nil {
		t.Fatal(err)
	}
	register := func() *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/account/devices",
			bytes.NewReader(registrationBody))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+identity.Token)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	if response := register(); response.Code != http.StatusOK {
		t.Fatalf("register status=%d body=%s", response.Code, response.Body.String())
	}
	if response := register(); response.Code != http.StatusConflict {
		t.Fatalf("registration replay status=%d body=%s", response.Code, response.Body.String())
	}
	if active := DeviceKeys_Active(store.Database, context.Background(), identity.UserID,
		"inbe", "device-key-1"); active.Error != nil || !active.Found {
		t.Fatalf("registered device not active: found=%v err=%v", active.Found, active.Error)
	}

	revocation := DeviceRevocationRequest{
		AppID:     "inbe",
		KeyID:     "device-key-1",
		Nonce:     "revoke-device-1",
		ExpiresAt: time.Now().Add(time.Minute).Unix(),
		Signature: identity.Signature,
	}
	revocationBody, err := json.Marshal(revocation)
	if err != nil {
		t.Fatal(err)
	}
	revoke := func() *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodDelete, "/api/v1/account/devices",
			bytes.NewReader(revocationBody))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+identity.Token)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	if response := revoke(); response.Code != http.StatusOK {
		t.Fatalf("revoke status=%d body=%s", response.Code, response.Body.String())
	}
	if active := DeviceKeys_Active(store.Database, context.Background(), identity.UserID,
		"inbe", "device-key-1"); active.Error != nil || active.Found {
		t.Fatalf("revoked device remains active: found=%v err=%v", active.Found, active.Error)
	}
	revokedRequest := httptest.NewRequest(http.MethodGet, "/api/v1/tokens/balance", nil)
	revokedRequest.Header.Set("X-Daochi-User", identity.UserID)
	revokedRequest.Header.Set("Authorization", "Bearer "+identity.Token)
	revokedResponse := httptest.NewRecorder()
	handler.ServeHTTP(revokedResponse, revokedRequest)
	if revokedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("revoked-device bearer status = %d body=%s", revokedResponse.Code, revokedResponse.Body.String())
	}
	replacementToken, _ := loginWithKey(t, handler, "", identity.UserID,
		hex.EncodeToString(identity.PublicKey), identity.Signature)
	revocationRequest := httptest.NewRequest(http.MethodDelete, "/api/v1/account/devices", bytes.NewReader(revocationBody))
	revocationRequest.Header.Set("Content-Type", "application/json")
	revocationRequest.Header.Set("Authorization", "Bearer "+replacementToken)
	revocationResponse := httptest.NewRecorder()
	handler.ServeHTTP(revocationResponse, revocationRequest)
	if revocationResponse.Code != http.StatusConflict {
		t.Fatalf("revoked-device replay status = %d body=%s", revocationResponse.Code, revocationResponse.Body.String())
	}
}

func TestLegacyWritePolicyUsesRollingWindow(t *testing.T) {
	server, store, _ := testServer(t)
	identity := newTestIdentity(t, server.Routes(), 0x42)
	ctx := context.Background()

	required, epoch, err := store.LegacyWritePolicy(ctx, identity.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if required || epoch != 0 {
		t.Fatalf("new account policy required=%v epoch=%d", required, epoch)
	}
	if err := store.RecordClientSync(ctx, identity.UserID, "legacy-client-1", 0, 0, 5, 0); err != nil {
		t.Fatal(err)
	}
	required, epoch, err = store.LegacyWritePolicy(ctx, identity.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if !required || epoch <= 0 {
		t.Fatalf("recent legacy client policy required=%v epoch=%d", required, epoch)
	}

	oldTimestamp := Timestamp_CanonicalTimestamp(time.Now().Add(-LegacyWriteWindow - time.Hour))
	if _, err := store.Database.ExecContext(ctx, `
UPDATE server_clients SET last_sync_at=?3
WHERE user_id_hash=?1 AND client_id=?2`, identity.UserID, "legacy-client-1", oldTimestamp); err != nil {
		t.Fatal(err)
	}
	required, epoch, err = store.LegacyWritePolicy(ctx, identity.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if required || epoch != 0 {
		t.Fatalf("expired legacy client policy required=%v epoch=%d", required, epoch)
	}
}

// Registering a revoked device key ID again must not bring a lost or stolen
// device back.
func TestRevokedDeviceKeyCannotBeRegisteredAgain(t *testing.T) {
	server, store, _ := testServer(t)
	identity := newTestIdentity(t, server.Routes(), 0x75)
	device := DeviceKey{AccountID: identity.UserID, AppID: "inbe", KeyID: "device-key", ClientID: "phone",
		PublicKey: strings.Repeat("ab", 32)}
	if err := DeviceKeys_Register(store.Database, t.Context(), device, "nonce-1", errSignedTxReplay); err != nil {
		t.Fatal(err)
	}
	revocation := DeviceRevocationRequest{AppID: "inbe", KeyID: "device-key", Nonce: "nonce-2"}
	if err := DeviceKeys_Revoke(store.Database, t.Context(), identity.UserID, revocation, errSignedTxReplay); err != nil {
		t.Fatal(err)
	}
	err := DeviceKeys_Register(store.Database, t.Context(), device, "nonce-3", errSignedTxReplay)
	if !errors.Is(err, ErrDeviceKeyRevoked) {
		t.Fatalf("re-registering a revoked key = %v; expected %v", err, ErrDeviceKeyRevoked)
	}
	active := DeviceKeys_Active(store.Database, t.Context(), identity.UserID, "inbe", "device-key")
	if active.Error != nil || active.Found {
		t.Fatalf("revoked key is active again: %#v", active)
	}
}
