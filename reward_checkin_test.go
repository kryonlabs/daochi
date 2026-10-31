package main

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// Wurm's Dew days pay once the node has counted enough UTC check-in days. A
// claim checks the account in for today even when it is refused, a day is
// counted once, and each Dew day credits an account once.
func TestDailyRewardsNeedCheckInDays(t *testing.T) {
	_, store, handler, _ := unlockFixture(t)
	ctx := context.Background()
	player := newTestIdentity(t, handler, 0xc1)
	other := newTestIdentity(t, handler, 0xc2)
	claim := func(token, reward string, status int) rewardClaimResponse {
		t.Helper()
		res := tokenJSONRequest(t, handler, http.MethodPost, "/api/v1/rewards", token, []byte(`{"reward":"`+reward+`"}`))
		if res.Code != status {
			t.Fatalf("claim %s: %d %s", reward, res.Code, res.Body.String())
		}
		var value rewardClaimResponse
		if status == 200 {
			if err := json.Unmarshal(res.Body.Bytes(), &value); err != nil {
				t.Fatal(err)
			}
		}
		return value
	}
	days := func(account string) int64 {
		t.Helper()
		var count int64
		if err := store.Database.QueryRowContext(ctx, "SELECT COUNT(*) FROM reward_checkins WHERE account_id=? AND game='wurm'", account).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	// Earlier days the node counted, as if the player had claimed on each.
	today := time.Now().Unix() / 86400
	checkIn := func(account string, day int64) {
		t.Helper()
		if _, err := store.Database.ExecContext(ctx, "INSERT INTO reward_checkins(account_id,game,day,created_at) VALUES(?,?,?,?)",
			account, "wurm", day, day*86400); err != nil {
			t.Fatal(err)
		}
	}

	claim(player.Token, "wurm.daily-05", 403)
	if got := days(player.UserID); got != 1 {
		t.Fatalf("a refused claim checks in once: %d days", got)
	}
	for range 3 {
		claim(player.Token, "wurm.daily-05", 403)
	}
	if got := days(player.UserID); got != 1 {
		t.Fatalf("today is counted once: %d days", got)
	}
	for day := today - 3; day < today; day++ {
		checkIn(player.UserID, day)
	}
	claim(player.Token, "wurm.daily-05", 403)
	checkIn(player.UserID, today-10)
	first := claim(player.Token, "wurm.daily-05", 200)
	if !first.Credited || first.Units != UnitsPerDew || first.Balance != UnitsPerDew {
		t.Fatalf("day five: %+v", first)
	}
	again := claim(player.Token, "wurm.daily-05", 200)
	if again.Credited || again.Balance != UnitsPerDew {
		t.Fatalf("repeated day five: %+v", again)
	}
	// Five days are not ten; the next Dew day waits for its own days.
	claim(player.Token, "wurm.daily-10", 403)
	for day := today - 9; day <= today-5; day++ {
		checkIn(player.UserID, day)
	}
	if got := claim(player.Token, "wurm.daily-10", 200); !got.Credited || got.Units != 2*UnitsPerDew || got.Balance != 3*UnitsPerDew {
		t.Fatalf("day ten: %+v", got)
	}
	claim(player.Token, "wurm.daily-25", 403)
	if got := days(player.UserID); got != 10 {
		t.Fatalf("check-in days: %d", got)
	}

	// Another account's days and Dew are its own.
	claim(other.Token, "wurm.daily-05", 403)
	if got := days(other.UserID); got != 1 {
		t.Fatalf("another account's check-ins: %d", got)
	}
	if got := TokenLedger_Balance(store.Database, ctx, other.UserID, AssetID); got.Error != nil || got.Value != 0 {
		t.Fatalf("another account received Dew: %+v", got)
	}
	// The client cannot invent a Dew day or claim without an account.
	claim(player.Token, "wurm.daily-30", 404)
	claim(player.Token, "wurm.daily-01", 404)
	res := tokenJSONRequest(t, handler, http.MethodPost, "/api/v1/rewards", "", []byte(`{"reward":"wurm.daily-05"}`))
	if res.Code != 401 {
		t.Fatalf("unauthenticated daily claim: %d", res.Code)
	}
	if got := TokenLedger_Balance(store.Database, ctx, player.UserID, AssetID); got.Error != nil || got.Value != 3*UnitsPerDew {
		t.Fatalf("balance after daily rewards: %+v", got)
	}
}
