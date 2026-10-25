package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func savePackingFixture(t *testing.T, store *Store, user string, record EncryptedRecord, limit int64, commit bool) {
	t.Helper()
	transaction, err := store.Database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := transaction.Rollback(); err != nil && err != sql.ErrTxDone {
			t.Error(err)
		}
	}()
	if err := RecordPacking_SaveCurrent(transaction, t.Context(), user, record, limit); err != nil {
		t.Fatal(err)
	}
	if commit {
		if err := transaction.Commit(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRecordPackingNegotiationQuotaInvalidationAndRollback(t *testing.T) {
	_, store, identity, _ := recordPageFixture(t)
	collection := "private.pageapp.v1.records.media"
	insertPageRecord(t, store, identity.UserID, collection, "record", "identity", 1)
	lifecycleExecute(t, store, `UPDATE server_encrypted_records SET schema_version=1,content_hash=?1 WHERE id='record'`, strings.Repeat("a", 64))
	record := EncryptedRecord{Collection: collection, ID: "record", KeyID: "main", Nonce: "nonce", Ciphertext: "identity", SchemaVersion: 1,
		PackedNonce: "packed-nonce", PackedCiphertext: "packed", ContentHash: strings.Repeat("a", 64)}
	input := SyncRequest{ProtocolVersion: 6, AppID: "pageapp", UserIDHash: identity.UserID}
	check := func(packed bool) {
		t.Helper()
		for _, encoding := range []string{"", "gzip-v1"} {
			page := RecordSync_Page(store.Database, t.Context(), input, RecordPageOptions{RecordEncoding: encoding}, 1)
			if page.Error != nil || len(page.Records) != 1 {
				t.Fatalf("page: %#v", page)
			}
			expected := "identity"
			if packed && encoding == "gzip-v1" {
				expected = "packed"
			}
			if page.Records[0].Ciphertext != expected {
				t.Fatalf("encoding %q got %q want %q", encoding, page.Records[0].Ciphertext, expected)
			}
		}
		assertStorageUsage(t, store, identity.UserID)
	}
	check(false)
	// The optional cache cannot consume the space needed by identity data.
	used := AccountStorage_Used(store.Database, t.Context(), identity.UserID)
	if used.Error != nil {
		t.Fatal(used.Error)
	}
	savePackingFixture(t, store, identity.UserID, record, used.Value+1, true)
	check(false)
	savePackingFixture(t, store, identity.UserID, record, 0, false)
	check(false)
	savePackingFixture(t, store, identity.UserID, record, 0, true)
	check(true)
	// An older writer replaces identity and invalidates the cached variant.
	lifecycleExecute(t, store, `UPDATE server_encrypted_records SET nonce='new-nonce' WHERE id='record'`)
	check(false)
	// Matching authenticated content metadata permits reseeding after re-encryption.
	savePackingFixture(t, store, identity.UserID, record, 0, true)
	check(true)
	lifecycleExecute(t, store, `UPDATE server_encrypted_records SET content_hash=?1 WHERE id='record'`, strings.Repeat("b", 64))
	record.Nonce = "stale-nonce"
	record.Ciphertext = "stale-body"
	savePackingFixture(t, store, identity.UserID, record, 0, true)
	check(false)
	// No variant can be attached across account or schema boundaries.
	other := strings.Repeat("c", 64)
	if err := store.RegisterUser(t.Context(), other, []byte("other")); err != nil {
		t.Fatal(err)
	}
	savePackingFixture(t, store, other, record, 0, true)
	record.ContentHash = strings.Repeat("b", 64)
	record.SchemaVersion = 2
	savePackingFixture(t, store, identity.UserID, record, 0, true)
	check(false)
	record.SchemaVersion = 1
	savePackingFixture(t, store, identity.UserID, record, 0, true)
	check(true)
	lifecycleExecute(t, store, `UPDATE server_encrypted_records SET deleted_at=1 WHERE id='record'`)
	check(false)
	savePackingFixture(t, store, identity.UserID, record, 0, true)
	check(false)
	lifecycleExecute(t, store, `DELETE FROM server_users WHERE user_id_hash=?1`, identity.UserID)
	var count int
	if err := store.Database.QueryRow(`SELECT COUNT(*) FROM server_record_packing`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("orphan packing: %d %v", count, err)
	}
}

func TestSignedRecordPackingUploadRetainsIdentityAndScopesNegotiatedReply(t *testing.T) {
	server, store, identity, key := recordPageFixture(t)
	record := EncryptedRecord{Collection: "private.pageapp.v1.records.media", ID: "packed-upload", KeyID: "main", Nonce: "raw-nonce", Ciphertext: "raw-ciphertext", UpdatedAt: lifecycleFixtureTime, SchemaVersion: 1, PackedNonce: "zip-nonce", PackedCiphertext: "zip-ciphertext"}
	body, err := json.Marshal(map[string]any{"protocol_version": 6, "app_id": "pageapp", "user_id_hash": identity.UserID, "client_id": "page-client", "encrypted_records_only": true, "record_encoding": "gzip-v1", "encrypted_records": []EncryptedRecord{record}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("POST", "/api/v1/sync", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+identity.Token)
	request.Header.Set("X-Daochi-User", identity.UserID)
	request.Header.Set("X-Daochi-Tx", signedTxHeader(t, identity.UserID, "pageapp", "page-key", "POST", "/api/v1/sync", body, key, "packed-upload-transaction"))
	reply := httptest.NewRecorder()
	server.Routes().ServeHTTP(reply, request)
	var response RecordSyncResponse
	if reply.Code != 200 || json.Unmarshal(reply.Body.Bytes(), &response) != nil || len(response.Changes.EncryptedRecords) != 1 || response.Changes.EncryptedRecords[0].Ciphertext != "zip-ciphertext" {
		t.Fatalf("packed signed upload: %d %s", reply.Code, reply.Body.String())
	}
	input := SyncRequest{ProtocolVersion: 6, AppID: "pageapp", UserIDHash: identity.UserID}
	legacy := RecordSync_Page(store.Database, t.Context(), input, RecordPageOptions{}, response.ServerVersion)
	if legacy.Error != nil || len(legacy.Records) != 1 || legacy.Records[0].Ciphertext != "raw-ciphertext" {
		t.Fatalf("identity changed: %#v", legacy)
	}
	input.AppID = "unrelated"
	foreign := RecordSync_Page(store.Database, t.Context(), input, RecordPageOptions{RecordEncoding: "gzip-v1"}, response.ServerVersion)
	if foreign.Error != nil || len(foreign.Records) != 0 {
		t.Fatalf("app scope leaked: %#v", foreign)
	}
	assertStorageUsage(t, store, identity.UserID)
}

func TestRecordPackingRejectsMalformedPairsAndLegacyProtocols(t *testing.T) {
	record := EncryptedRecord{Collection: "private.pageapp.v1.records.media", ID: "valid", UpdatedAt: lifecycleFixtureTime, Nonce: "raw", Ciphertext: "raw", PackedNonce: "packed", PackedCiphertext: "packed"}
	if !EncryptedRecord_ValidForProtocol(record, 6) || EncryptedRecord_ValidForProtocol(record, 5) {
		t.Fatal("protocol boundary")
	}
	record.PackedNonce = ""
	if EncryptedRecord_Valid(record) {
		t.Fatal("unpaired variant")
	}
	record.PackedNonce = "packed"
	record.DeletedAt = 1
	if EncryptedRecord_Valid(record) {
		t.Fatal("tombstone packing")
	}
	record.DeletedAt = 0
	record.PackedCiphertext = strings.Repeat("x", 262145)
	if EncryptedRecord_Valid(record) {
		t.Fatal("oversized variant")
	}
}
