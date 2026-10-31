package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type bearerStore struct {
	Database *sql.DB
}

func bearerSessionFixture(t *testing.T) *bearerStore {
	t.Helper()
	database, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = database.Close() })
	_, err = database.Exec(`
PRAGMA foreign_keys=ON;
CREATE TABLE server_users(
 user_id_hash TEXT PRIMARY KEY,
 public_key BLOB NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE server_apps(app_id TEXT PRIMARY KEY);
CREATE TABLE server_device_keys (
 account_id TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
 app_id TEXT NOT NULL REFERENCES server_apps(app_id) ON DELETE CASCADE,
 device_key_id TEXT NOT NULL,
 client_id TEXT NOT NULL,
 public_key TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 last_used_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 revoked_at TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(account_id,app_id,device_key_id)
);
CREATE TABLE server_device_registration_nonces (
 account_id TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
 nonce TEXT NOT NULL,
 created_at TEXT NOT NULL,
 PRIMARY KEY(account_id,nonce)
);`)
	if err != nil {
		t.Fatal(err)
	}
	return &bearerStore{Database: database}
}

func initializeBearerSessions(t *testing.T, store *bearerStore) {
	t.Helper()
	if err := AuthSessions_Initialize(store.Database, context.Background(), time.Hour); err != nil {
		t.Fatal(err)
	}
}

func bearerSessionUser(t *testing.T, store *bearerStore, userID string) []byte {
	t.Helper()
	publicKey := make([]byte, 32)
	copy(publicKey, userID)
	if _, err := store.Database.Exec(
		"INSERT INTO server_users(user_id_hash,public_key) VALUES(?1,?2)", userID, publicKey); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Database.Exec("INSERT OR IGNORE INTO server_apps VALUES('inbe')"); err != nil {
		t.Fatal(err)
	}
	return publicKey
}

func issueBearerSession(t *testing.T, store *bearerStore, secret []byte, userID, clientID string) string {
	t.Helper()
	issued := Token_IssueAuthToken(secret, userID, time.Now().Add(time.Hour).Unix())
	if issued.Error != "" {
		t.Fatal(issued.Error)
	}
	if err := AuthSessions_RecordIssued(store.Database, context.Background(), secret, issued.Value, clientID); err != nil {
		t.Fatal(err)
	}
	return issued.Value
}

func authenticateBearer(t *testing.T, store *bearerStore, secret []byte, bearer string) (string, error) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
	request.Header.Set("Authorization", "Bearer "+bearer)
	result := HttpAuth_AuthenticateToken(store.Database, request, secret)
	return result.Value, AuthenticationError_Convert(result.Authentication)
}

func legacyBearerToken(secret []byte, userID string, expiresAt int64) string {
	payload := fmt.Sprintf("v1\n%s\n%d\n", userID, expiresAt)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func assertBearerAccepted(t *testing.T, store *bearerStore, secret []byte, userID, bearer string) {
	t.Helper()
	got, err := authenticateBearer(t, store, secret, bearer)
	if err != nil || got != userID {
		t.Fatalf("bearer rejected: user=%q error=%v", got, err)
	}
	if !HttpAuth_BearerSessionActive(store.Database, context.Background(), bearer, userID, time.Now().Unix()) {
		t.Fatal("durable bearer session is inactive")
	}
}

func assertBearerRejected(t *testing.T, store *bearerStore, secret []byte, userID, bearer string) {
	t.Helper()
	got, err := authenticateBearer(t, store, secret, bearer)
	if err == nil || got != "" {
		t.Fatalf("bearer accepted: user=%q error=%v", got, err)
	}
	if HttpAuth_BearerSessionActive(store.Database, context.Background(), bearer, userID, time.Now().Unix()) {
		t.Fatal("revoked bearer session is active")
	}
}

func TestBearerSessionRevocation(t *testing.T) {
	store := bearerSessionFixture(t)
	secret := []byte("bearer session secret")
	bearerSessionUser(t, store, strings.Repeat("a", 64))
	bearerSessionUser(t, store, strings.Repeat("b", 64))
	initializeBearerSessions(t, store)
	current := issueBearerSession(t, store, secret, strings.Repeat("a", 64), "client-current")
	other := issueBearerSession(t, store, secret, strings.Repeat("a", 64), "client-other")
	otherAccount := issueBearerSession(t, store, secret, strings.Repeat("b", 64), "client-current")
	expired := Token_IssueAuthToken(secret, strings.Repeat("a", 64), time.Now().Add(-time.Hour).Unix())
	if expired.Error != "" {
		t.Fatal(expired.Error)
	}
	if err := AuthSessions_RecordIssued(store.Database, context.Background(), secret, expired.Value, "client-expired"); err != nil {
		t.Fatal(err)
	}
	assertBearerRejected(t, store, secret, strings.Repeat("a", 64), expired.Value)

	missing := Token_IssueAuthToken(secret, strings.Repeat("a", 64), time.Now().Add(time.Hour).Unix())
	if missing.Error != "" {
		t.Fatal(missing.Error)
	}
	assertBearerRejected(t, store, secret, strings.Repeat("a", 64), missing.Value)

	wrongAccount := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
	wrongAccount.Header.Set("Authorization", "Bearer "+current)
	wrongAccount.Header.Set("X-Daochi-User", strings.Repeat("b", 64))
	if result := HttpAuth_BearerUser(store.Database, wrongAccount, secret); result.Value != "" ||
		result.Authentication.Status == 0 {
		t.Fatal("wrong-account bearer accepted")
	}

	currentMetadata := Token_InspectAuthToken(secret, current)
	if currentMetadata.Error != "" {
		t.Fatal(currentMetadata.Error)
	}
	if err := AuthSessions_RevokeSession(store.Database, context.Background(), strings.Repeat("a", 64),
		currentMetadata.Value.SessionID); err != nil {
		t.Fatal(err)
	}
	assertBearerRejected(t, store, secret, strings.Repeat("a", 64), current)
	assertBearerAccepted(t, store, secret, strings.Repeat("a", 64), other)

	assertBearerAccepted(t, store, secret, strings.Repeat("b", 64), otherAccount)

	if _, err := authenticateBearer(t, store, secret, "not a token"); err == nil {
		t.Fatal("malformed bearer accepted")
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
	if result := HttpAuth_AuthenticateToken(store.Database, request, secret); result.Value != "" ||
		AuthenticationError_Convert(result.Authentication) == nil {
		t.Fatal("missing bearer accepted")
	}
}

func TestBearerDeviceRevocation(t *testing.T) {
	store := bearerSessionFixture(t)
	secret := []byte("bearer device secret")
	userID := strings.Repeat("a", 64)
	bearerSessionUser(t, store, userID)
	bearerSessionUser(t, store, strings.Repeat("b", 64))
	initializeBearerSessions(t, store)
	stolen := issueBearerSession(t, store, secret, userID, "client-stolen")
	current := issueBearerSession(t, store, secret, userID, "client-current")
	otherAccount := issueBearerSession(t, store, secret, strings.Repeat("b", 64), "client-stolen")
	devices := [][3]string{
		{"inbe", "stolen-device", "client-stolen"},
		{"inbe", "current-device", "client-current"},
	}
	for _, device := range devices {
		if _, err := store.Database.Exec(
			"INSERT INTO server_device_keys(account_id,app_id,device_key_id,client_id,public_key) VALUES(?1,?2,?3,?4,?5)",
			userID, device[0], device[1], device[2], "public-key"); err != nil {
			t.Fatal(err)
		}
	}

	revocation := DeviceRevocationRequest{AppID: "inbe", KeyID: "stolen-device", Nonce: "revocation-nonce"}
	if err := DeviceKeys_Revoke(store.Database, context.Background(), userID, revocation,
		fmt.Errorf("device replay")); err != nil {
		t.Fatal(err)
	}
	assertBearerRejected(t, store, secret, userID, stolen)
	assertBearerAccepted(t, store, secret, userID, current)
	assertBearerAccepted(t, store, secret, strings.Repeat("b", 64), otherAccount)
	legacy := legacyBearerToken(secret, userID, time.Now().Add(time.Hour).Unix())
	assertBearerRejected(t, store, secret, userID, legacy)
}

func TestBearerLogout(t *testing.T) {
	store := bearerSessionFixture(t)
	secret := []byte("bearer logout secret")
	userID := strings.Repeat("a", 64)
	bearerSessionUser(t, store, userID)
	initializeBearerSessions(t, store)
	bearer := issueBearerSession(t, store, secret, userID, "logout-client")
	assertBearerAccepted(t, store, secret, userID, bearer)

	var group sync.WaitGroup
	results := make([]error, 4)
	for index := range results {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			results[index] = AuthSessions_RevokeBearer(store.Database, context.Background(), userID, bearer)
		}(index)
	}
	group.Wait()
	var revoked bool
	for _, err := range results {
		if err == nil {
			revoked = true
			continue
		}
		if err != sql.ErrNoRows {
			t.Fatal(err)
		}
	}
	if !revoked {
		t.Fatal("concurrent logout did not revoke the bearer")
	}
	assertBearerRejected(t, store, secret, userID, bearer)
}

func TestBearerLegacyMigration(t *testing.T) {
	bootstrap := bearerSessionFixture(t)
	bootstrapSecret := []byte("bearer bootstrap secret")
	bootstrapUser := strings.Repeat("d", 64)
	initializeBearerSessions(t, bootstrap)
	bootstrapBearer := legacyBearerToken(bootstrapSecret, bootstrapUser,
		time.Now().Add(time.Hour).Unix())
	authorized := AuthSessions_AuthorizeBearer(bootstrap.Database, context.Background(),
		bootstrapSecret, bootstrapBearer, bootstrapUser, time.Now().Unix())
	if authorized.Error != nil || !authorized.Bootstrap || !authorized.Value {
		t.Fatal("public bootstrap legacy bearer rejected")
	}

	createdAfterMigration := bearerSessionFixture(t)
	createdAfterSecret := []byte("bearer post migration secret")
	createdAfterUser := strings.Repeat("c", 64)
	initializeBearerSessions(t, createdAfterMigration)
	bearerSessionUser(t, createdAfterMigration, createdAfterUser)
	createdAfterMigrationBearer := legacyBearerToken(createdAfterSecret, createdAfterUser,
		time.Now().Add(time.Hour).Unix())
	assertBearerRejected(t, createdAfterMigration, createdAfterSecret, createdAfterUser,
		createdAfterMigrationBearer)

	store := bearerSessionFixture(t)
	secret := []byte("bearer migration secret")
	userID := strings.Repeat("a", 64)
	bearerSessionUser(t, store, userID)
	if _, err := store.Database.Exec(
		"UPDATE server_users SET created_at='2020-01-01 00:00:00' WHERE user_id_hash=?1", userID); err != nil {
		t.Fatal(err)
	}
	initializeBearerSessions(t, store)
	valid := legacyBearerToken(secret, userID, time.Now().Add(time.Hour).Unix())
	expired := legacyBearerToken(secret, userID, time.Now().Add(-time.Hour).Unix())
	assertBearerAccepted(t, store, secret, userID, valid)
	if _, err := authenticateBearer(t, store, secret, expired); err == nil {
		t.Fatal("expired legacy bearer accepted")
	}
	if err := AuthSessions_RevokeBearer(store.Database, context.Background(), userID, valid); err != nil {
		t.Fatal(err)
	}
	assertBearerRejected(t, store, secret, userID, valid)
}

func TestBearerAccountDeleteRecreate(t *testing.T) {
	store := bearerSessionFixture(t)
	secret := []byte("bearer recreation secret")
	userID := strings.Repeat("a", 64)
	bearerSessionUser(t, store, userID)
	initializeBearerSessions(t, store)
	oldBearer := issueBearerSession(t, store, secret, userID, "old-client")
	assertBearerAccepted(t, store, secret, userID, oldBearer)

	if _, err := store.Database.Exec("DELETE FROM server_users WHERE user_id_hash=?1", userID); err != nil {
		t.Fatal(err)
	}
	assertBearerRejected(t, store, secret, userID, oldBearer)
	if _, err := store.Database.Exec(
		"INSERT INTO server_users(user_id_hash,public_key,created_at) VALUES(?1,x'01','2030-01-01 00:00:00')",
		userID); err != nil {
		t.Fatal(err)
	}
	assertBearerRejected(t, store, secret, userID, oldBearer)

	newBearer := issueBearerSession(t, store, secret, userID, "new-client")
	assertBearerAccepted(t, store, secret, userID, newBearer)
}
