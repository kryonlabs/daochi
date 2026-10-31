package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"testing"
	"time"
)

func ownerWebSocketAccount(t *testing.T, server *Server) string {
	t.Helper()
	publicKey := bytes.Repeat([]byte{0xa1}, mlDSA44PublicKeySize)
	userHash := sha256.Sum256(publicKey)
	userID := hex.EncodeToString(userHash[:])
	_, err := server.Store.Database.Exec(
		"INSERT INTO server_users(user_id_hash,public_key) VALUES(?,?)",
		userID,
		publicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	return userID
}

func ownerWebSocketToken(t *testing.T, server *Server, userID string, expiresAt time.Time) string {
	t.Helper()
	issued := Token_IssueAuthToken(server.Cfg.TokenSecret, userID, expiresAt.Unix())
	if issued.Error != "" {
		t.Fatal(issued.Error)
	}
	if err := AuthSessions_RecordIssued(server.Store.Database, t.Context(),
		server.Cfg.TokenSecret, issued.Value, "owner-websocket"); err != nil {
		t.Fatal(err)
	}
	return issued.Value
}

func requireOwnerSocketRemoved(t *testing.T, server *Server, userID string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if SyncHub_Count(server.SyncHub, userID) == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("owner websocket subscription remained active")
}

func requireCredentialSecondElapsed(t *testing.T, expiresAt time.Time) {
	t.Helper()
	for time.Now().Unix() <= expiresAt.Unix() {
		time.Sleep(20 * time.Millisecond)
	}
}

func TestOwnerWebSocketCredentialExpiry(t *testing.T) {
	server, _, _ := testServer(t)
	userID := ownerWebSocketAccount(t, server)
	expiresAt := time.Now().Add(2 * time.Second)
	token := ownerWebSocketToken(t, server, userID, expiresAt)
	target := httptest.NewServer(server.Routes())
	t.Cleanup(target.Close)

	reader, connection := openSyncWebSocket(t, target.URL, token)
	t.Cleanup(func() { _ = connection.Close() })
	if ready := readTestWebSocketEvent(t, reader); ready.Type != "sync_ready" {
		t.Fatalf("ready event = %#v", ready)
	}
	if err := connection.SetReadDeadline(time.Unix(expiresAt.Unix()+1, 0).Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	frame := Websocket_ReadFrame(reader)
	if frame.Error == nil {
		t.Fatalf("expired websocket returned %q", frame.Payload)
	}
	requireOwnerSocketRemoved(t, server, userID)
}

func TestOwnerWebSocketAccountDeletion(t *testing.T) {
	server, _, _ := testServer(t)
	userID := ownerWebSocketAccount(t, server)
	token := ownerWebSocketToken(t, server, userID, time.Now().Add(time.Hour))
	target := httptest.NewServer(server.Routes())
	t.Cleanup(target.Close)

	reader, connection := openSyncWebSocket(t, target.URL, token)
	t.Cleanup(func() { _ = connection.Close() })
	if ready := readTestWebSocketEvent(t, reader); ready.Type != "sync_ready" {
		t.Fatalf("ready event = %#v", ready)
	}
	if err := AccountState_Delete(server.Store.Database, t.Context(), userID); err != nil {
		t.Fatal(err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if frame := Websocket_ReadFrame(reader); frame.Error == nil {
		t.Fatalf("deleted-account websocket returned %q", frame.Payload)
	}
	requireOwnerSocketRemoved(t, server, userID)
}

func TestOwnerWebSocketNoEventsAfterExpiry(t *testing.T) {
	server, _, _ := testServer(t)
	userID := ownerWebSocketAccount(t, server)
	expiresAt := time.Now().Add(2 * time.Second)
	token := ownerWebSocketToken(t, server, userID, expiresAt)
	target := httptest.NewServer(server.Routes())
	t.Cleanup(target.Close)

	reader, connection := openSyncWebSocket(t, target.URL, token)
	t.Cleanup(func() { _ = connection.Close() })
	if ready := readTestWebSocketEvent(t, reader); ready.Type != "sync_ready" {
		t.Fatalf("ready event = %#v", ready)
	}
	requireCredentialSecondElapsed(t, expiresAt)
	credential := Credential{UserID: userID, Bearer: token, ExpiresAt: expiresAt.Unix(), Valid: true}
	if SyncWs_CredentialActive(server.syncSocket(), t.Context(), credential) {
		t.Fatal("expired credential remained active")
	}
	SyncHub_Publish(server.SyncHub, userID, int64(41))
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	frame := Websocket_ReadFrame(reader)
	if frame.Error == nil {
		t.Fatalf("expired websocket emitted event %q", frame.Payload)
	}
	requireOwnerSocketRemoved(t, server, userID)
}

func TestOwnerWebSocketCleanup(t *testing.T) {
	server, _, _ := testServer(t)
	userID := ownerWebSocketAccount(t, server)
	token := ownerWebSocketToken(t, server, userID, time.Now().Add(time.Hour))
	target := httptest.NewServer(server.Routes())
	t.Cleanup(target.Close)

	reader, connection := openSyncWebSocket(t, target.URL, token)
	if ready := readTestWebSocketEvent(t, reader); ready.Type != "sync_ready" {
		t.Fatalf("ready event = %#v", ready)
	}
	if SyncHub_Count(server.SyncHub, userID) != 1 {
		t.Fatal("owner websocket was not subscribed")
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	requireOwnerSocketRemoved(t, server, userID)
}
