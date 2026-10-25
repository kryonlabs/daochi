package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

// Opt-in bounded local audit, using throwaway SQLite databases and existing test identities.
// Account signature verification is stubbed by testServer. Device verification,
// signed-transaction storage, SQL, response generation and middleware are real.
func TestSyncPerformanceAudit(t *testing.T) {
	if os.Getenv("DAOCHI_PERFORMANCE_AUDIT") != "1" {
		t.Skip("set DAOCHI_PERFORMANCE_AUDIT=1 for the bounded local timing audit")
	}
	var rows []map[string]any
	var usageRows []map[string]any
	for _, count := range []int{1, 100, 1000, 5000} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			server, store, identity, key := recordPageFixture(t)
			tx, err := store.Database.Begin()
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < count; i++ {
				_, err = tx.Exec(`INSERT INTO server_encrypted_records
				(user_id_hash,collection,id,key_id,nonce,ciphertext,updated_at,server_version)
				VALUES(?1,'private.pageapp.v1.records.media',?2,'main','nonce',?3,?4,5)`,
					identity.UserID, fmt.Sprintf("record-%06d", i), strings.Repeat("a5", 1024), lifecycleFixtureTime)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Database.Exec("UPDATE server_sync_state SET server_version=5 WHERE user_id_hash=?1", identity.UserID); err != nil {
				t.Fatal(err)
			}
			handler := server.Routes()
			sequence := 0
			call := func(paged bool) (float64, int, int, int) {
				sequence++
				body, err := json.Marshal(map[string]any{
					"protocol_version": 6, "app_id": "pageapp", "user_id_hash": identity.UserID,
					"client_id": "page-client", "since_server_version": 5, "client_clock": 5,
					"encrypted_records_only": paged, "record_limit": 64, "include_metadata": true,
				})
				if err != nil {
					t.Fatal(err)
				}
				header := signedTxHeader(t, identity.UserID, "pageapp", "page-key", "POST", "/api/v1/sync", body, key, fmt.Sprintf("performance-audit-%08d", sequence))
				request := httptest.NewRequest("POST", "/api/v1/sync", bytes.NewReader(body))
				request.Header.Set("Authorization", "Bearer "+identity.Token)
				request.Header.Set("X-Daochi-User", identity.UserID)
				request.Header.Set("X-Daochi-Tx", header)
				request.Header.Set("Content-Type", "application/json")
				recorder := httptest.NewRecorder()
				start := time.Now()
				handler.ServeHTTP(recorder, request)
				elapsed := float64(time.Since(start).Nanoseconds()) / 1e6
				if recorder.Code != 200 {
					t.Fatalf("status %d: %s", recorder.Code, recorder.Body.String())
				}
				var reply map[string]any
				if err := json.Unmarshal(recorder.Body.Bytes(), &reply); err != nil {
					t.Fatal(err)
				}
				if reply["server_version"] != float64(5) {
					t.Fatalf("unexpected version: %v", reply["server_version"])
				}
				return elapsed, recorder.Body.Len(), len(body), len(header)
			}
			call(false)
			call(true)
			for _, paged := range []bool{false, true} {
				var timings []float64
				var response, request, header int
				for i := 0; i < 9; i++ {
					var elapsed float64
					elapsed, response, request, header = call(paged)
					timings = append(timings, elapsed)
				}
				sort.Float64s(timings)
				row := map[string]any{"records": count, "stored_ciphertext_bytes": count * 2048,
					"paged": paged, "median_ms": timings[4], "min_ms": timings[0], "max_ms": timings[8],
					"response_bytes": response, "request_body_bytes": request, "transaction_header_bytes": header}
				rows = append(rows, row)
				t.Logf("records=%d paged=%v median_ms=%.3f response_bytes=%d", count, paged, timings[4], response)
			}
			var usageTimings []float64
			for i := 0; i < 9; i++ {
				start := time.Now()
				used := AccountStorage_Used(store.Database, t.Context(), identity.UserID)
				usageTimings = append(usageTimings, float64(time.Since(start).Nanoseconds())/1e6)
				if used.Error != nil {
					t.Fatal(used.Error)
				}
				if used.Value < int64(count*2048) {
					t.Fatal("incorrect usage")
				}
			}
			sort.Float64s(usageTimings)
			usageRows = append(usageRows, map[string]any{"records": count, "median_ms": usageTimings[4]})
		})
	}
	result := map[string]any{"scope": "local HTTP handler, no network/TLS, no device-registration call, mock ML-DSA verification; real Ed25519 verification and SQLite; warm cache; nine sequential samples per case", "rows": rows, "account_usage_lookup": usageRows}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("backup/sync-performance/server-after.json", append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}
