package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func seedLeaderboard(t *testing.T, store *Store, users []string) {
	t.Helper()
	for index, user := range users {
		for _, activity := range []int{0, 1, 2} {
			for day := 0; day < 4-index; day++ {
				id := fmt.Sprintf("session-%d-%d-%d", index, activity, day)
				date := time.Now().UTC().AddDate(0, 0, -day).Format("20060102")
				if _, err := store.Database.Exec("INSERT INTO server_sessions(user_id_hash,id,started_at,local_date,topic,activity,source,rounds_hash,updated_at) VALUES(?,?,?,?,'0',?,'test','rounds','2026-01-01T00:00:00Z')", user, id, "2026-01-01T00:00:00Z", date, activity); err != nil {
					t.Fatal(err)
				}
				for round, hold := range []int{0, -1, 80 + index*100, 81 + index*100} {
					if _, err := store.Database.Exec("INSERT INTO server_session_rounds VALUES(?,?,?,?,?)", user, id, round, 30, hold); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
		for index, duration := range []int{0, -2, 900, 1200} {
			id := fmt.Sprintf("log-%s-%d", user[:1], index)
			completed := time.Now().UTC().AddDate(0, 0, -index).Format(time.RFC3339)
			if _, err := store.Database.Exec("INSERT INTO server_meditation_logs(id,user_id_hash,session_id,duration_seconds,completed_at) VALUES(?,?,?,?,?)", id, user, id, duration, completed); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func compareLeaderboard(t *testing.T, actual, expected *Store, context context.Context, user, practice, metric string) {
	t.Helper()
	got := Leaderboard_Friends(actual.Database, context, user, "inbe", practice, metric)
	want, err := expected.baselineLeaderboardFriendStats(context, user, "inbe", practice, metric)
	if !reflect.DeepEqual(got.Value, want) || !sameIdentityError(got.Error, err) {
		t.Fatalf("leaderboard %s/%s differs:\ngot %#v\nwant %#v, %v", practice, metric, got, want, err)
	}
	if err := actual.Database.Ping(); err != nil {
		t.Fatal("leaderboard retained its SQL connection", err)
	}
}

func TestZiranLeaderboardAgainstBaseline(t *testing.T) {
	actual, users := socialHTTPFixture(t)
	expected, _ := socialHTTPFixture(t)
	seedLeaderboard(t, actual.store, users)
	seedLeaderboard(t, expected.store, users)
	for _, user := range append(users, "missing", "' OR 1=1 --") {
		for _, practice := range []string{"whm", "meditation", "sun_salutation", "unknown"} {
			for _, metric := range []string{"streak", "avg_hold", "avg_time", "unknown"} {
				compareLeaderboard(t, actual.store, expected.store, t.Context(), user, practice, metric)
				compareLeaderboard(t, actual.store, expected.store, t.Context(), user, practice, metric)
			}
		}
	}
	for _, query := range []string{
		"UPDATE server_leaderboard_stats SET calc_version=0",
		"UPDATE server_leaderboard_stats SET source_version=-1",
		"UPDATE server_leaderboard_stats SET local_date=19000101",
		"UPDATE server_users SET alias=NULL,profile_icon=11",
		"UPDATE server_sessions SET deleted_at=1",
	} {
		for _, store := range []*Store{actual.store, expected.store} {
			if _, err := store.Database.Exec(query); err != nil {
				t.Fatal(err)
			}
		}
		for _, metric := range []string{"streak", "avg_hold", "avg_time"} {
			compareLeaderboard(t, actual.store, expected.store, t.Context(), users[0], "meditation", metric)
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	compareLeaderboard(t, actual.store, expected.store, cancelled, users[0], "whm", "streak")
	if result := Leaderboard_Friends(actual.store.Database, cancelled, users[0], "inbe", "whm", "streak"); !errors.Is(result.Error, context.Canceled) {
		t.Fatal("cancelled leaderboard lost native context error")
	}
}

func TestZiranLeaderboardFailureBoundaries(t *testing.T) {
	for _, query := range []string{
		"DROP TABLE server_friendships",
		"DROP TABLE server_sessions",
		"DROP TABLE server_session_rounds",
		"DROP TABLE server_leaderboard_stats",
		"CREATE TRIGGER reject_stats BEFORE INSERT ON server_leaderboard_stats BEGIN SELECT RAISE(ABORT,'stats rejected'); END",
		"INSERT INTO server_leaderboard_stats VALUES('" + strings.Repeat("a", 64) + "','inbe','whm','avg_hold',7,4,'invalid','label',0,'updated')",
	} {
		t.Run(query, func(t *testing.T) {
			actual, users := socialHTTPFixture(t)
			expected, _ := socialHTTPFixture(t)
			for _, store := range []*Store{actual.store, expected.store} {
				if _, err := store.Database.Exec(query); err != nil {
					t.Fatal(err)
				}
			}
			compareLeaderboard(t, actual.store, expected.store, t.Context(), users[0], "whm", "avg_hold")
		})
	}
}

func TestZiranLeaderboardSortAndLabels(t *testing.T) {
	random := rand.New(rand.NewSource(20261001))
	for _, count := range []int{0, 1, 2, 3, 17, 128, 1025} {
		values := make([]FriendStatRow, count)
		for index := range values {
			values[index] = FriendStatRow{UserIDHash: fmt.Sprintf("%04d", random.Intn(13)), Alias: []string{"", "a", "日本語", "\xff", "b"}[random.Intn(5)], Value: float64(random.Intn(9) - 4), Label: fmt.Sprintf("row %d", index)}
		}
		expected := append([]FriendStatRow{}, values...)
		sort.SliceStable(expected, func(left, right int) bool {
			a, b := expected[left], expected[right]
			if a.Value != b.Value {
				return a.Value > b.Value
			}
			leftName, rightName := a.Alias, b.Alias
			if leftName == "" {
				leftName = a.UserIDHash
			}
			if rightName == "" {
				rightName = b.UserIDHash
			}
			if leftName != rightName {
				return leftName < rightName
			}
			return a.UserIDHash < b.UserIDHash
		})
		Leaderboard_SortRows(values)
		if !reflect.DeepEqual(values, expected) {
			t.Fatalf("stable leaderboard ordering changed for %d rows", count)
		}
	}
	for _, seconds := range []int{math.MinInt, -1, 0, 1, 59, 60, 3599, 3600, math.MaxInt} {
		if got := Leaderboard_TimeLabel(seconds); got != baselineLeaderboardLeaderboardTimeLabel(seconds) {
			t.Fatalf("leaderboard duration label changed for %d: %q", seconds, got)
		}
	}
}
