package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func recordPageFixture(t *testing.T) (*Server, *Store, testIdentity, ed25519.PrivateKey) {
	t.Helper()
	server, store, _ := testServer(t)
	identity := newTestIdentity(t, server.Routes(), 0x71)
	if err := AppStore_Upsert(store.Database, t.Context(), AppRegistration{
		AppID: "pageapp", DisplayName: "Page App", Status: "active",
		Collections: []AppCollection{{CollectionPrefix: "private.pageapp.v1.records.*", Visibility: "private"}},
	}); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x53}, ed25519.SeedSize))
	if err := DeviceKeys_Register(store.Database, t.Context(), DeviceKey{
		AccountID: identity.UserID, AppID: "pageapp", KeyID: "page-key", ClientID: "page-client",
		PublicKey: hex.EncodeToString(key.Public().(ed25519.PublicKey)),
	}, "page-registration", errSignedTxReplay); err != nil {
		t.Fatal(err)
	}
	return server, store, identity, key
}

func insertPageRecord(t *testing.T, store *Store, user, collection, id, payload string, version int64) {
	t.Helper()
	lifecycleExecute(t, store, `INSERT INTO server_encrypted_records
		(user_id_hash,collection,id,key_id,nonce,ciphertext,updated_at,server_version)
		VALUES(?1,?2,?3,'main','nonce',?4,?5,?6)`, user, collection, id, payload, lifecycleFixtureTime, version)
}

func TestRecordPagesBoundBytesPreserveVersionTiesAndAppScope(t *testing.T) {
	_, store, identity, _ := recordPageFixture(t)
	const collection = "private.pageapp.v1.records.media"
	for index := 0; index < 35; index++ {
		insertPageRecord(t, store, identity.UserID, collection, fmt.Sprintf("record-%03d", index), strings.Repeat("x", 256*1024), 5)
	}
	insertPageRecord(t, store, identity.UserID, "private.foreign.v1.records.media", "foreign-app", "secret", 5)
	other := strings.Repeat("b", 64)
	if err := store.RegisterUser(t.Context(), other, []byte("other-account")); err != nil {
		t.Fatal(err)
	}
	insertPageRecord(t, store, other, collection, "foreign-account", "secret", 5)
	input := SyncRequest{ProtocolVersion: 6, AppID: "pageapp", UserIDHash: identity.UserID}
	options := RecordPageOptions{}
	seen := make(map[string]bool)
	pages := 0
	for {
		page := RecordSync_Page(store.Database, t.Context(), input, options, 5)
		if page.Error != nil {
			t.Fatal(page.Error)
		}
		var payloadBytes int
		for _, record := range page.Records {
			if record.Collection != collection || seen[record.ID] || strings.HasPrefix(record.ID, "foreign") {
				t.Fatalf("duplicate or foreign record: %s", record.ID)
			}
			seen[record.ID] = true
			payloadBytes += len(record.Ciphertext)
		}
		if payloadBytes > 4*1024*1024 {
			t.Fatalf("unbounded page: %d bytes", payloadBytes)
		}
		pages++
		if page.Cursor == nil {
			break
		}
		options.RecordCursor = page.Cursor
	}
	if len(seen) != 35 || pages != 3 {
		t.Fatalf("version ties lost records: %d records in %d pages", len(seen), pages)
	}
}

func TestRecordPageWatermarkAndConcurrentEdit(t *testing.T) {
	_, store, identity, _ := recordPageFixture(t)
	const collection = "private.pageapp.v1.records.media"
	insertPageRecord(t, store, identity.UserID, collection, "first", "original", 1)
	insertPageRecord(t, store, identity.UserID, collection, "second", "original", 2)
	insertPageRecord(t, store, identity.UserID, collection, "future", "new", 3)
	input := SyncRequest{ProtocolVersion: 6, AppID: "pageapp", UserIDHash: identity.UserID}
	options := RecordPageOptions{RecordLimit: 1}
	first := RecordSync_Page(store.Database, t.Context(), input, options, 2)
	if first.Error != nil || len(first.Records) != 1 || first.Records[0].ID != "first" || first.Cursor == nil {
		t.Fatalf("first page: %#v", first)
	}
	lifecycleExecute(t, store, "UPDATE server_encrypted_records SET ciphertext='edited',server_version=4 WHERE user_id_hash=?1 AND id='first'", identity.UserID)
	options.RecordCursor = first.Cursor
	second := RecordSync_Page(store.Database, t.Context(), input, options, 2)
	if second.Error != nil || len(second.Records) != 1 || second.Records[0].ID != "second" || second.Cursor != nil {
		t.Fatalf("page skipped a record or crossed its watermark: %#v", second)
	}
	options.RecordCursor = nil
	input.SinceServerVersion = 2
	options.RecordLimit = 200
	next := RecordSync_Page(store.Database, t.Context(), input, options, 4)
	if next.Error != nil || len(next.Records) != 2 || next.Records[1].Ciphertext != "edited" {
		t.Fatalf("concurrent changes were lost: %#v", next)
	}
}

func TestSignedRecordPageRejectsUnsignedReplayMixedAndAheadCursor(t *testing.T) {
	server, store, identity, key := recordPageFixture(t)
	input := SyncRequest{ProtocolVersion: 6, AppID: "pageapp", UserIDHash: identity.UserID,
		ClientID: "page-client",
		EncryptedRecords: []EncryptedRecord{{Collection: "private.pageapp.v1.records.media", ID: "original",
			KeyID: "main", Nonce: "nonce", Ciphertext: "opaque", UpdatedAt: lifecycleFixtureTime}}}
	sequence := 0
	call := func(input SyncRequest, header string, sign bool) (*httptest.ResponseRecorder, string) {
		t.Helper()
		fields := map[string]any{}
		initial, _ := json.Marshal(input)
		_ = json.Unmarshal(initial, &fields)
		fields["encrypted_records_only"] = true
		fields["record_limit"] = 1
		body, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		sequence++
		if sign && header == "" {
			header = signedTxHeader(t, identity.UserID, "pageapp", "page-key", "POST", "/api/v1/sync", body, key, fmt.Sprintf("page-tx-%d", sequence))
		}
		request := httptest.NewRequest("POST", "/api/v1/sync", bytes.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+identity.Token)
		request.Header.Set("X-Daochi-User", identity.UserID)
		request.Header.Set("X-Daochi-Tx", header)
		recorder := httptest.NewRecorder()
		server.Routes().ServeHTTP(recorder, request)
		return recorder, header
	}
	unsigned, _ := call(input, "", false)
	if unsigned.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned page rejected at unexpected boundary: %d %s", unsigned.Code, unsigned.Body.String())
	}
	good, header := call(input, "", true)
	var response RecordSyncResponse
	if good.Code != http.StatusOK || json.Unmarshal(good.Body.Bytes(), &response) != nil ||
		!response.EncryptedRecordsOnly || !response.ChangesComplete || response.Applied.EncryptedRecords != 1 ||
		len(response.Changes.EncryptedRecords) != 1 {
		t.Fatalf("invalid record sync: %d %s", good.Code, good.Body.String())
	}
	replay, _ := call(input, header, true)
	if replay.Code != http.StatusConflict {
		t.Fatalf("replay accepted: %d", replay.Code)
	}
	input.EncryptedRecords[0].ID = "must-not-upload"
	input.SinceServerVersion = response.ServerVersion + 100
	ahead, _ := call(input, "", true)
	if ahead.Code != http.StatusConflict {
		t.Fatalf("ahead cursor accepted: %d", ahead.Code)
	}
	var count int
	if err := store.Database.QueryRow("SELECT COUNT(*) FROM server_encrypted_records WHERE id='must-not-upload'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("rejected cursor still uploaded data: %d %v", count, err)
	}
	input.SinceServerVersion = 0
	input.FullSyncRequested = true
	mixed, _ := call(input, "", true)
	if mixed.Code != http.StatusBadRequest {
		t.Fatalf("mixed replacement request accepted: %d", mixed.Code)
	}
}
