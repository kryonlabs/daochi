package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func seedGameEvidence(t *testing.T, store *Store, account string, through int32) {
	t.Helper()
	board := evidenceMap()
	for level := int32(1); level <= through; level++ {
		registerEvidenceMap(t, store, board, level, "test")
		if value := GameEvidence_Put(store.Database, context.Background(), account, evidenceAttempt(level, board, true)); value.Error != nil {
			t.Fatal(value.Error)
		}
	}
}

func TestGameEvidenceHTTPAuthenticatesMapPublisherAndAccountOwner(t *testing.T) {
	server, _, _, _ := unlockFixture(t)
	server.Cfg.AdminToken = "evidence-fixture-admin"
	handler := server.Routes()
	player, other := newTestIdentity(t, handler, 0xb5), newTestIdentity(t, handler, 0xb6)
	board := evidenceMap()
	hash := GameEvidence_MapHash("shovey.classic", 1, board)
	registration := MapRegistration{Game: "shovey.classic", SourceVersion: "v1",
		Maps: []MapRevision{{Level: 1, MapHash: hash, Map: board}}}
	encode := func(value any) []byte {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	admin := func(value MapRegistration, key string, status int) {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "/api/v1/admin/game-maps", bytes.NewReader(encode(value)))
		request.Header.Set("X-Daochi-Admin", key)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != status {
			t.Fatalf("register: %d %s", response.Code, response.Body.String())
		}
	}
	admin(registration, "", 401)
	if response := tokenJSONRequest(t, handler, http.MethodPost, "/api/v1/admin/game-maps", player.Token, encode(registration)); response.Code != 401 {
		t.Fatalf("ordinary account registered maps: %d", response.Code)
	}
	admin(registration, server.Cfg.AdminToken, 200)
	c := evidenceAttempt(1, board, true)
	post := func(token string, value any, status int) *httptest.ResponseRecorder {
		t.Helper()
		response := tokenJSONRequest(t, handler, http.MethodPost, "/api/v1/game-completions", token, encode(value))
		if response.Code != status {
			t.Fatalf("completion: %d %s", response.Code, response.Body.String())
		}
		return response
	}
	post("", c, 401)
	post(player.Token, c, 200)
	var repeated EvidenceResult
	response := post(player.Token, c, 200)
	if json.Unmarshal(response.Body.Bytes(), &repeated) != nil || repeated.Created || response.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("repeat or cache policy: %s", response.Body.String())
	}
	// A later map revision cannot redirect or erase the earlier evidence.
	v2 := board[:986] + "39" + board[988:]
	registration.SourceVersion = "v2"
	registration.Maps[0].Map = v2
	admin(registration, server.Cfg.AdminToken, 400)
	registration.Maps[0].MapHash = GameEvidence_MapHash("shovey.classic", 1, v2)
	admin(registration, server.Cfg.AdminToken, 200)
	path := "/api/v1/game-completions?game=shovey.classic&level=1&map_hash=" + hash
	for _, query := range []struct {
		token string
		count int
	}{{player.Token, 1}, {other.Token, 0}} {
		response := tokenJSONRequest(t, handler, http.MethodGet, path, query.token, nil)
		var history EvidenceHistory
		if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &history) != nil || len(history.Completions) != query.count {
			t.Fatalf("history isolation: %d %s", response.Code, response.Body.String())
		}
		if query.count > 0 && (history.Map != board || history.Completions[0].Trace != c.Trace) {
			t.Fatal("old evidence no longer uses old exact map")
		}
	}
	bad := c
	bad.Trace = "0d000e"
	post(player.Token, bad, 400)
	bad = c
	bad.Level = 2
	post(player.Token, bad, 400)
	post(player.Token, map[string]any{"account_id": other.UserID, "game": "shovey.classic"}, 400)
}
