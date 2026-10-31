package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFriendAliasLegacyCaseLookup(t *testing.T) {
	store := schemaFixture(t, `CREATE TABLE server_users(user_id_hash TEXT PRIMARY KEY, alias TEXT UNIQUE, created_at TEXT);
INSERT INTO server_users VALUES('older','Shiori','2026-01-01T00:00:00Z');
INSERT INTO server_users VALUES('newer','shiori','2026-02-01T00:00:00Z');
INSERT INTO server_users VALUES('short','Ab','2026-01-01T00:00:00Z');`)
	for _, spelling := range []string{"Shiori", "shiori", "@SHIORI", "  @sHiOrI  "} {
		got := AccountLookup_Resolve(store.Database, t.Context(), spelling)
		if got.Error != nil || !got.Found || got.Value != "older" {
			t.Fatalf("lookup %q: %+v", spelling, got)
		}
	}
	got := AccountLookup_Resolve(store.Database, t.Context(), " @AB ")
	if got.Error != nil || !got.Found || got.Value != "short" {
		t.Fatalf("registered short alias: %+v", got)
	}
}

func TestFriendRequestAcceptsAliasCaseVariants(t *testing.T) {
	server, users := socialHTTPFixture(t)
	if _, err := server.Store.Database.Exec("UPDATE server_users SET alias='Shiori' WHERE user_id_hash=?", users[2]); err != nil {
		t.Fatal(err)
	}
	for _, spelling := range []string{"Shiori", "@SHIORI", "  shiori  "} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/friends/requests", strings.NewReader(fmt.Sprintf(`{"target":%q}`, spelling)))
		req.Header.Set("X-Daochi-User", users[0])
		req.Header.Set("Authorization", "Bearer "+issueTestBearer(t, server, users[0], time.Now().Add(time.Hour)))
		res := httptest.NewRecorder()
		SocialHttp_CreateRequest(server.social(), res, req)
		if res.Code != http.StatusCreated || !strings.Contains(res.Body.String(), users[2]) {
			t.Fatalf("Add %q: %d %s", spelling, res.Code, res.Body.String())
		}
	}
}
