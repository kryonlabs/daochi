package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		ClientID:  "inbe-client-1",
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
	if _, found, err := store.ActiveDeviceKey(context.Background(), identity.UserID,
		"inbe", "device-key-1"); err != nil || !found {
		t.Fatalf("registered device not active: found=%v err=%v", found, err)
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
	if _, found, err := store.ActiveDeviceKey(context.Background(), identity.UserID,
		"inbe", "device-key-1"); err != nil || found {
		t.Fatalf("revoked device remains active: found=%v err=%v", found, err)
	}
	if response := revoke(); response.Code != http.StatusConflict {
		t.Fatalf("revocation replay status=%d body=%s", response.Code, response.Body.String())
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

	oldTimestamp := canonicalTimestamp(time.Now().Add(-legacyWriteWindow - time.Hour))
	if _, err := store.db.ExecContext(ctx, `
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
