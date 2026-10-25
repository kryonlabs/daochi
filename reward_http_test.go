package main

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

type rewardClaimResponse struct {
	Reward   string `json:"reward"`
	Units    int64  `json:"units"`
	Credited bool   `json:"credited"`
	Balance  int64  `json:"balance"`
}

// A game reward is the node's to give: the client names it, the node sets its
// Dew, and each account gets it once however often it asks.
func TestGameRewardsCreditEachAccountOnce(t *testing.T) {
	_, store, handler, _ := unlockFixture(t)
	ctx := context.Background()
	player := newTestIdentity(t, handler, 0xa1)
	other := newTestIdentity(t, handler, 0xa2)
	claim := func(token, body string, status int) rewardClaimResponse {
		t.Helper()
		res := tokenJSONRequest(t, handler, http.MethodPost, "/api/v1/rewards", token, []byte(body))
		if res.Code != status {
			t.Fatalf("claim %s: %d %s", body, res.Code, res.Body.String())
		}
		var value rewardClaimResponse
		if status == 200 {
			if res.Header().Get("Cache-Control") != "private, no-store" {
				t.Fatal("reward response may be cached")
			}
			if err := json.Unmarshal(res.Body.Bytes(), &value); err != nil {
				t.Fatal(err)
			}
		}
		return value
	}
	first := claim(player.Token, `{"reward":"shovey.secret-chest"}`, 200)
	if !first.Credited || first.Units != 2*UnitsPerDew || first.Balance != 2*UnitsPerDew {
		t.Fatalf("first claim: %+v", first)
	}
	// Asking again, even many times, credits nothing more.
	for range 3 {
		again := claim(player.Token, `{"reward":"shovey.secret-chest"}`, 200)
		if again.Credited || again.Balance != 2*UnitsPerDew {
			t.Fatalf("repeated claim: %+v", again)
		}
	}
	done := claim(player.Token, `{"reward":"shovey.campaign-complete"}`, 200)
	if !done.Credited || done.Units != 5*UnitsPerDew || done.Balance != 2*UnitsPerDew+5*UnitsPerDew {
		t.Fatalf("second reward: %+v", done)
	}
	if got := TokenLedger_Balance(store.Database, ctx, other.UserID, AssetID); got.Error != nil || got.Value != 0 {
		t.Fatalf("a reward reached another account: %+v", got)
	}
	// The client cannot name an amount or a reward the node does not offer.
	claim(player.Token, `{"reward":"shovey.secret-chest","units":100000000}`, 400)
	claim(player.Token, `{"reward":"shovey.free-dew"}`, 404)
	claim(player.Token, `{"reward":""}`, 400)
	claim(player.Token, `not json`, 400)
	res := tokenJSONRequest(t, handler, http.MethodPost, "/api/v1/rewards", "", []byte(`{"reward":"shovey.secret-chest"}`))
	if res.Code != 401 {
		t.Fatalf("unauthenticated claim: %d", res.Code)
	}
	if got := TokenLedger_Balance(store.Database, ctx, player.UserID, AssetID); got.Error != nil || got.Value != 2*UnitsPerDew+5*UnitsPerDew {
		t.Fatalf("refused claims changed the balance: %+v", got)
	}
	listed := tokenJSONRequest(t, handler, http.MethodGet, "/api/v1/rewards", player.Token, nil)
	var offers struct {
		Rewards []struct {
			Reward string `json:"reward"`
			Units  int64  `json:"units"`
		} `json:"rewards"`
	}
	if listed.Code != 200 || json.Unmarshal(listed.Body.Bytes(), &offers) != nil || len(offers.Rewards) != 2 {
		t.Fatalf("listed rewards: %d %s", listed.Code, listed.Body.String())
	}
}
