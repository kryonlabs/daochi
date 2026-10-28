package main

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLeaderboardPublicAppearance(t *testing.T) {
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
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
		return w
	}
	put := func(user int, app, game, metric string, value float64) {
		t.Helper()
		request("PUT", "/api/v1/profile/stats", fmt.Sprintf(`{"app":%q,"metrics":[{"practice":%q,"metric":%q,"value":%v}]}`, app, game, metric, value), user)
	}
	read := func(game string) []FriendStatRow {
		t.Helper()
		w := request("GET", "/api/v1/friends/stats?app=inbe&practice="+game+"&metric=score", "", 0)
		var body FriendStatsResponse
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if len(body.Rows) != 2 {
			t.Fatalf("non-friend visibility: %#v", body.Rows)
		}
		return body.Rows
	}
	put(0, "inbe", "xyz.waozi.wurm", "score", 10)
	put(1, "inbe", "xyz.waozi.wurm", "score", 20)
	put(1, "inbe", "xyz.waozi.wurm", "appearance", 4)
	put(2, "inbe", "xyz.waozi.wurm", "score", 100)
	put(2, "inbe", "xyz.waozi.wurm", "appearance", 9)
	put(1, "another-app", "xyz.waozi.wurm", "appearance", 8)
	put(1, "inbe", "another-game", "appearance", 7)
	rows := read("xyz.waozi.wurm")
	if rows[0].UserIDHash != users[1] || rows[0].GameIcon != 4 || rows[0].Value != 20 || rows[0].Label != "20" || rows[1].GameIcon != 0 {
		t.Fatalf("appearance changed rank, leaked scope or lost selector: %#v", rows)
	}
	for _, value := range []float64{9, 1, 0, -1, 1.5, 257} {
		put(1, "inbe", "xyz.waozi.wurm", "appearance", value)
		want := 0
		if value == 9 || value == 1 {
			want = int(value)
		}
		rows = read("xyz.waozi.wurm")
		if rows[0].GameIcon != want || rows[0].Value != 20 {
			t.Fatalf("latest bounded appearance %v: %#v", value, rows)
		}
	}
	if rows = read("no-such-game"); rows[0].GameIcon != 0 || rows[1].GameIcon != 0 {
		t.Fatalf("appearance crossed games: %#v", rows)
	}
}
