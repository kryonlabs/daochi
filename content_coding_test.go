package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func gzipFixture(t *testing.T, plain []byte) []byte {
	t.Helper()
	var encoded bytes.Buffer
	writer := gzip.NewWriter(&encoded)
	if _, err := writer.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return encoded.Bytes()
}

func TestContentCodingNegotiatesGzipQuality(t *testing.T) {
	for header, want := range map[string]bool{
		"": false, "identity": false, "gzip": true, "br, GZip;q=0.5": true,
		"gzip;q=0": false, "*;q=1, gzip;q=0": false, "*;q=0.2": true,
		"gzip;q=0.000": false, "gzip;q=0.001": true, "gzip;q=1.000": true,
		"gzip;q=1.001": false, "gzip;q=-1": false, "gzip;q=0.0001": false,
		"gzip;q=1;q=0": false, "gzip;q=no": false, "gzip;q=0,gzip;q=1": false,
	} {
		if got := ContentCoding_AcceptsGzip(header); got != want {
			t.Fatalf("%q: %v, want %v", header, got, want)
		}
	}
}

func TestContentCodingBoundsDecodedRequestsAndRejectsCorruption(t *testing.T) {
	plain := []byte(`{"value":"` + strings.Repeat("x", 4096) + `"}`)
	encoded := gzipFixture(t, plain)
	for _, test := range []struct {
		name     string
		body     []byte
		encoding string
		limit    int64
		valid    bool
	}{
		{"identity", plain, "", 8192, true},
		{"gzip", encoded, "gzip", 8192, true},
		{"case", encoded, "GZip", 8192, true},
		{"expansion", encoded, "gzip", 512, false},
		{"wire limit", encoded, "gzip", 8, false},
		{"truncated", encoded[:len(encoded)-3], "gzip", 8192, false},
		{"trailing", append(append([]byte{}, encoded...), 'x'), "gzip", 8192, false},
		{"unknown", encoded, "zstd", 8192, false},
		{"multiple", encoded, "gzip, gzip", 8192, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest("POST", "/api/v1/sync", bytes.NewReader(test.body))
			request.Header.Set("Content-Encoding", test.encoding)
			got := HttpBody_ReadJSON(httptest.NewRecorder(), request, test.limit)
			if (got.Error == nil) != test.valid {
				t.Fatalf("valid=%v error=%v", test.valid, got.Error)
			}
			if test.valid && !bytes.Equal(got.Value, plain) {
				t.Fatal("decoded JSON changed")
			}
		})
	}
}

func TestRecordPagesNegotiateMetadataAndGzipWithDecodedSignature(t *testing.T) {
	server, store, identity, key := recordPageFixture(t)
	lifecycleExecute(t, store, `UPDATE server_users SET alias='fixture-alias',profile_icon=7 WHERE user_id_hash=?1`, identity.UserID)
	for index, record := range []string{"one", "two"} {
		insertPageRecord(t, store, identity.UserID, "private.pageapp.v1.records.media", record, strings.Repeat("opaque", 64), int64(index+1))
	}
	lifecycleExecute(t, store, `UPDATE server_sync_state SET server_version=2 WHERE user_id_hash=?1`, identity.UserID)
	for trial := 0; trial < 3; trial++ {
		body, err := json.Marshal(map[string]any{"protocol_version": 6, "app_id": "pageapp", "user_id_hash": identity.UserID, "client_id": "page-client", "since_server_version": 0, "encrypted_records_only": true, "record_limit": 1, "include_metadata": true})
		if err != nil {
			t.Fatal(err)
		}
		signedBody := body
		wire := gzipFixture(t, body)
		if trial == 2 {
			signedBody = wire
		}
		header := signedTxHeader(t, identity.UserID, "pageapp", "page-key", "POST", "/api/v1/sync", signedBody, key, fmt.Sprintf("gzip-page-tx-%d", trial))
		request := httptest.NewRequest("POST", "/api/v1/sync", bytes.NewReader(wire))
		request.Header.Set("Authorization", "Bearer "+identity.Token)
		request.Header.Set("X-Daochi-User", identity.UserID)
		request.Header.Set("X-Daochi-Tx", header)
		request.Header.Set("Content-Encoding", "gzip")
		request.Header.Set("Accept-Encoding", "gzip")
		request.Header.Set("Origin", "https://inbe.waozi.xyz")
		recorder := httptest.NewRecorder()
		server.Routes().ServeHTTP(recorder, request)
		if trial == 2 {
			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("signature of wire bytes accepted: %d %s", recorder.Code, recorder.Body.String())
			}
			continue
		}
		if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Encoding") != "gzip" {
			t.Fatalf("gzip page: %d %s", recorder.Code, recorder.Body.String())
		}
		if !strings.Contains(recorder.Header().Get("Vary"), "Origin") || !strings.Contains(recorder.Header().Get("Vary"), "Accept-Encoding") {
			t.Fatal("Vary lost an origin or content-coding selector")
		}
		reader, err := gzip.NewReader(recorder.Body)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		_ = reader.Close()
		var reply RecordSyncResponse
		if err := json.Unmarshal(decoded, &reply); err != nil {
			t.Fatal(err)
		}
		if reply.ChangesComplete || reply.RecordCursor == nil || reply.AccountAlias != nil {
			t.Fatalf("first page metadata or cursor: %s", decoded)
		}
	}
	options := RecordPageOptions{RecordLimit: 200, IncludeMetadata: true}
	input := SyncRequest{ProtocolVersion: 6, AppID: "pageapp", UserIDHash: identity.UserID, ClientID: "page-client"}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("POST", "/api/v1/sync", nil)
	committed := false
	if !RecordSync_Handle(store.Database, server.Metrics, server.SyncHub, ErrSyncUserNotFound, recorder, request, input, options, nil, 0, &committed, server.Cfg.DBPath) {
		t.Fatalf("terminal metadata: %s", recorder.Body.String())
	}
	var reply RecordSyncResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	if !reply.ChangesComplete || reply.AccountAlias == nil || *reply.AccountAlias != "fixture-alias" || reply.ProfileIcon == nil || *reply.ProfileIcon != 7 || len(reply.ServerCapabilities) == 0 {
		t.Fatalf("metadata missing: %s", recorder.Body.String())
	}
}
