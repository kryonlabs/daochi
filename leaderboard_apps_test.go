package main

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestInstalledAppLeaderboardIsolation(t *testing.T) {
	server, users := socialHTTPFixture(t)
	seedLeaderboard(t, server.Store, users, time.Now())
	request := func(method, path, body string, user int, authenticated bool) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if authenticated {
			r.Header.Set("Authorization", "Bearer "+Token_IssueAuthToken(server.Cfg.TokenSecret, users[user], time.Now().Add(time.Hour).Unix()).Value)
			r.Header.Set("X-Daochi-User", users[user])
		}
		w := httptest.NewRecorder()
		if method == "PUT" {
			SocialHttp_PutStats(server.social(), w, r)
		} else {
			SocialHttp_FriendStats(server.social(), w, r)
		}
		return w
	}
	put := func(user int, app, name string, value int) {
		t.Helper()
		body := fmt.Sprintf(`{"app":%q,"metrics":[{"practice":%q,"metric":"achievements","value":%d,"label":"untrusted label"}]}`, app, name, value)
		if w := request("PUT", "/api/v1/profile/stats", body, user, true); w.Code != 200 {
			t.Fatalf("publish app stats: %d %s", w.Code, w.Body)
		}
	}
	read := func(name string) []FriendStatRow {
		t.Helper()
		w := request("GET", "/api/v1/friends/stats?app=inbe&practice="+name+"&metric=achievements", "", 0, true)
		if w.Code != 200 {
			t.Fatalf("read app board: %d %s", w.Code, w.Body)
		}
		var body FriendStatsResponse
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body.Rows
	}
	put(0, "inbe", "habits", 2)
	put(1, "inbe", "habits", 7)
	put(2, "inbe", "habits", 100) // Pending requests confer no visibility.
	put(1, "inbe", "diary", 4)
	put(1, "another-app", "habits", 99)
	for name, want := range map[string][]float64{"habits": {7, 2}, "diary": {4, 0}, "radio": {0, 0}} {
		rows := read(name)
		if len(rows) != 2 {
			t.Fatalf("%s exposed a non-friend: %#v", name, rows)
		}
		for i, row := range rows {
			if row.Value != want[i] || row.Label != fmt.Sprint(int(want[i])) || row.Practice != name || row.App != "inbe" {
				t.Fatalf("%s reused another board or untrusted label: %#v", name, rows)
			}
		}
	}
	// A refreshed app board uses the latest published value, independently of
	// the breathing-derived cache and its source version.
	put(0, "inbe", "habits", 9)
	if rows := read("habits"); rows[0].UserIDHash != users[0] || rows[0].Value != 9 {
		t.Fatalf("app update retained a cached score: %#v", rows)
	}
	for _, method := range []string{"GET", "PUT"} {
		path := "/api/v1/friends/stats?app=inbe&practice=habits&metric=achievements"
		if method == "PUT" {
			path = "/api/v1/profile/stats"
		}
		if w := request(method, path, `{}`, 0, false); w.Code != 401 {
			t.Fatalf("unauthenticated %s returned %d", method, w.Code)
		}
	}
	if _, err := server.Store.Database.Exec("DELETE FROM server_friendships"); err != nil {
		t.Fatal(err)
	}
	if rows := read("habits"); len(rows) != 1 || rows[0].UserIDHash != users[0] {
		t.Fatalf("removed friend retained access: %#v", rows)
	}
}

func TestGameLevelBoardsStaySeparate(t *testing.T) {
	server, users := socialHTTPFixture(t)
	seedLeaderboard(t, server.Store, users, time.Now())
	request := func(method, path, body string, user int) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+Token_IssueAuthToken(server.Cfg.TokenSecret, users[user], time.Now().Add(time.Hour).Unix()).Value)
		r.Header.Set("X-Daochi-User", users[user])
		w := httptest.NewRecorder()
		if method == "PUT" {
			SocialHttp_PutStats(server.social(), w, r)
		} else {
			SocialHttp_FriendStats(server.social(), w, r)
		}
		return w
	}
	put := func(user int, game string, value int) {
		t.Helper()
		body := fmt.Sprintf(`{"app":"inbe","metrics":[{"practice":%q,"metric":"levels","value":%d,"label":"untrusted"}]}`, game, value)
		if w := request("PUT", "/api/v1/profile/stats", body, user); w.Code != 200 {
			t.Fatalf("publish levels: %d %s", w.Code, w.Body)
		}
	}
	read := func(game, metric string) []FriendStatRow {
		t.Helper()
		w := request("GET", "/api/v1/friends/stats?app=inbe&practice="+game+"&metric="+metric, "", 0)
		if w.Code != 200 {
			t.Fatalf("read %s %s: %d %s", game, metric, w.Code, w.Body)
		}
		var body FriendStatsResponse
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body.Rows
	}
	put(0, "arcade.shovey", 12)
	put(1, "arcade.shovey", 140)
	put(1, "arcade.shovey-island", 3)
	put(2, "arcade.shovey", 175) // Pending requests confer no visibility.
	for game, want := range map[string][]float64{"arcade.shovey": {140, 12}, "arcade.shovey-island": {3, 0}} {
		rows := read(game, "levels")
		if len(rows) != 2 {
			t.Fatalf("%s exposed a non-friend: %#v", game, rows)
		}
		for i, row := range rows {
			if row.Value != want[i] || row.Label != fmt.Sprint(int(want[i])) || row.Practice != game || row.Metric != "levels" {
				t.Fatalf("%s mixed boards or kept an untrusted label: %#v", game, rows)
			}
		}
	}
	// Levels are their own board, never an achievements count.
	if rows := read("arcade.shovey", "achievements"); rows[0].Value != 0 || rows[1].Value != 0 {
		t.Fatalf("levels leaked into achievements: %#v", rows)
	}
}
