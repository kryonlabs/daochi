package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Every node offers the account's entity data as a built-in app, unless an
// operator registered a signed manifest for it.
func TestEntityDataIsBuiltIn(t *testing.T) {
	_, store, _ := testServer(t)
	result := AppStore_ByID(store.Database, context.Background(), "entity")
	app, found, err := result.Value, result.Found, result.Error
	if err != nil || !found || app.Status != appStatusActive || len(app.Collections) != 1 ||
		app.Collections[0].CollectionPrefix != "private.entity.v1.*" || app.Collections[0].Visibility != "private" {
		t.Fatalf("entity app = %#v found=%v err=%v", app, found, err)
	}
	if _, err := store.Database.Exec(`
INSERT INTO server_app_manifests(app_id,manifest_version,manifest_json,manifest_hash,manifest_signature,approval_signature,status)
VALUES('entity',1,'{}','signed-entity-test','signature','approval','active')`); err != nil {
		t.Fatal(err)
	}
	if err := AppStore_Upsert(store.Database, context.Background(), AppRegistration{
		AppID: "entity", DisplayName: "Entity", Status: appStatusActive,
		Collections: []AppCollection{{CollectionPrefix: "private.entity.v2.*", Visibility: "private"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := AppStore_SeedEntity(store.Database, context.Background()); err != nil {
		t.Fatal(err)
	}
	result = AppStore_ByID(store.Database, context.Background(), "entity")
	if result.Error != nil || len(result.Value.Collections) != 1 ||
		result.Value.Collections[0].CollectionPrefix != "private.entity.v2.*" {
		t.Fatalf("signed entity manifest was overwritten: %#v", result.Value)
	}
}

// Any app of the account writes its entity data through requests the account
// signed; a bearer token alone cannot.
func TestEntityRecordsNeedTheAccountsSignature(t *testing.T) {
	server, store, _ := testServer(t)
	now := time.Now().UTC().Format(time.RFC3339)
	photo := EncryptedRecord{Collection: "private.entity.v1.photos", ID: "photo-1", KeyID: "main",
		Nonce: "n1", Ciphertext: "sealed", UpdatedAt: now}
	request := func(protocol int, appID string, records ...EncryptedRecord) SyncRequest {
		return SyncRequest{ProtocolVersion: protocol, AppID: appID, UserIDHash: strings.Repeat("a", 64),
			ClientID: "entity-client", EncryptedRecords: records}
	}
	for _, appID := range []string{"inbe", "entity", "werkzeug"} {
		if appID == "werkzeug" {
			if err := AppStore_Upsert(store.Database, context.Background(), AppRegistration{
				AppID: "werkzeug", DisplayName: "Werkzeug", Status: appStatusActive,
				Collections: []AppCollection{{CollectionPrefix: "private.werkzeug.v1.auth", Visibility: "private"}},
			}); err != nil {
				t.Fatal(err)
			}
		}
		if err := SyncValidation_Validate(store.Database, context.Background(), request(6, appID, photo)); err != nil {
			t.Fatalf("%s could not write entity data in a signed request: %v", appID, err)
		}
	}
	err := SyncValidation_Validate(store.Database, context.Background(), request(5, "", photo))
	if err == nil || !strings.Contains(err.Error(), "entity records need a signed request") {
		t.Fatalf("an unsigned request wrote entity data: %v", err)
	}
	foreign := EncryptedRecord{Collection: "private.werkzeug.v1.auth", ID: "vault", KeyID: "main",
		Nonce: "n2", Ciphertext: "sealed", UpdatedAt: now}
	err = SyncValidation_Validate(store.Database, context.Background(), request(6, "inbe", photo, foreign))
	if err == nil {
		t.Fatal("entity data opened another app's collection")
	}
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x7a)
	record := `{"collection":"private.entity.v1.levels","id":"level-1","key_id":"main","nonce":"n3","ciphertext":"c","updated_at":"` + now + `"}`
	status, body := postSync(t, handler, identity, syncRecordBody(identity, "5", "", record))
	if status != http.StatusBadRequest || !strings.Contains(body, "signed request") {
		t.Fatalf("status = %d body=%s; expected an unsigned entity write to be refused", status, body)
	}
}

// A photo's sealed bytes are stored once for the account, whichever app put
// them, and read back by any app signing as entity.
func TestEntityBlobsBelongToTheAccount(t *testing.T) {
	server, user, key := registryHTTPFixture(t)
	server.Verifier = testVerifier(&transactionVerifier{accept: true})
	server.Cfg.DBPath = filepath.Join(t.TempDir(), "node.sqlite")
	data := []byte("\x00sealed photo bytes\xff")
	path := "/api/v1/blobs/entity/" + Signing_SHA256Hex(data)
	request := func(signer string, method string, body []byte, nonce string) *http.Request {
		request := httptest.NewRequest(method, path, bytes.NewReader(body))
		token := Token_IssueAuthToken(server.Cfg.TokenSecret, user, time.Now().Add(time.Hour).Unix()).Value
		request.Header.Set("Authorization", "Bearer "+token)
		tx := SignedTxEnvelope{ProtocolVersion: 6, TxID: nonce, Nonce: nonce, AccountID: user,
			AppID: signer, DeviceKeyID: "device-key", Method: method, Path: path,
			BodySHA256: Signing_SHA256Hex(body), ExpiresAt: time.Now().Add(time.Minute).Unix(),
			Signature: hex.EncodeToString(bytes.Repeat([]byte{0x33}, mlDSA44SignatureSize))}
		signDeviceTransaction(&tx, key)
		encoded, err := json.Marshal(tx)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("X-Daochi-Tx", string(encoded))
		return request
	}
	recorder := httptest.NewRecorder()
	Server_HandleBlobHttpRoute(server, recorder, request("target", "PUT", data, "entity-put"))
	if recorder.Code != 204 {
		t.Fatalf("put: %d %s", recorder.Code, recorder.Body)
	}
	recorder = httptest.NewRecorder()
	Server_HandleBlobHttpRoute(server, recorder, request("target", "GET", nil, "entity-get"))
	if recorder.Code != 200 || !bytes.Equal(recorder.Body.Bytes(), data) {
		t.Fatalf("get: %d %q", recorder.Code, recorder.Body)
	}
	// An app deletes a copy it no longer references, once; retries succeed.
	for _, nonce := range []string{"entity-delete", "entity-delete-again"} {
		recorder = httptest.NewRecorder()
		Server_HandleBlobHttpRoute(server, recorder, request("target", "DELETE", nil, nonce))
		if recorder.Code != 204 {
			t.Fatalf("delete: %d %s", recorder.Code, recorder.Body)
		}
	}
	recorder = httptest.NewRecorder()
	Server_HandleBlobHttpRoute(server, recorder, request("target", "GET", nil, "entity-gone"))
	if recorder.Code != 404 {
		t.Fatalf("deleted blob still readable: %d", recorder.Code)
	}
	stored := AccountStorage_BlobStored(server.Store.Database, t.Context(), user, "entity", Signing_SHA256Hex(data))
	if stored.Error != nil || stored.Value {
		t.Fatalf("deleted blob still counts toward storage: %#v", stored)
	}
	// An app the node does not know, or one without the device key, cannot.
	recorder = httptest.NewRecorder()
	Server_HandleBlobHttpRoute(server, recorder, request("unknown", "GET", nil, "entity-unknown"))
	if recorder.Code != 403 {
		t.Fatalf("unknown signer: %d %s", recorder.Code, recorder.Body)
	}
	recorder = httptest.NewRecorder()
	Server_HandleBlobHttpRoute(server, recorder, request("source", "GET", nil, "entity-unregistered"))
	if recorder.Code != 401 {
		t.Fatalf("signer without a device key: %d %s", recorder.Code, recorder.Body)
	}
}
