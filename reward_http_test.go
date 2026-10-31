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
	Place    int64  `json:"place"`
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
	claim(player.Token, `{"reward":"shovey.secret-chest"}`, 403)
	seedGameEvidence(t, store, player.UserID, 28)
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
	claim(player.Token, `{"reward":"shovey.campaign-complete"}`, 403)
	seedGameEvidence(t, store, player.UserID, 175)
	// The first to finish the campaign gets the first place's 100 Dew.
	done := claim(player.Token, `{"reward":"shovey.campaign-complete"}`, 200)
	if !done.Credited || done.Units != 100*UnitsPerDew || done.Place != 1 || done.Balance != 2*UnitsPerDew+100*UnitsPerDew {
		t.Fatalf("second reward: %+v", done)
	}
	if again := claim(player.Token, `{"reward":"shovey.campaign-complete"}`, 200); again.Credited || again.Units != 100*UnitsPerDew || again.Place != 1 {
		t.Fatalf("repeated campaign claim: %+v", again)
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
	if got := TokenLedger_Balance(store.Database, ctx, player.UserID, AssetID); got.Error != nil || got.Value != 2*UnitsPerDew+100*UnitsPerDew {
		t.Fatalf("refused claims changed the balance: %+v", got)
	}
	listed := tokenJSONRequest(t, handler, http.MethodGet, "/api/v1/rewards", player.Token, nil)
	var offers struct {
		Rewards []struct {
			Reward string `json:"reward"`
			Units  int64  `json:"units"`
		} `json:"rewards"`
	}
	if listed.Code != 200 || json.Unmarshal(listed.Body.Bytes(), &offers) != nil || len(offers.Rewards) != 7 {
		t.Fatalf("listed rewards: %d %s", listed.Code, listed.Body.String())
	}
	// The list names what the next claim gives: the second place is still 100 Dew.
	if offers.Rewards[0].Units != 2*UnitsPerDew || offers.Rewards[1].Units != 100*UnitsPerDew {
		t.Fatalf("listed rewards: %+v", offers.Rewards)
	}
	daily := []int64{1, 2, 2, 2, 3}
	for index, reward := range []string{"wurm.daily-05", "wurm.daily-10", "wurm.daily-15", "wurm.daily-20", "wurm.daily-25"} {
		if offers.Rewards[index+2].Reward != reward || offers.Rewards[index+2].Units != daily[index]*UnitsPerDew {
			t.Fatalf("listed daily rewards: %+v", offers.Rewards)
		}
	}
}

func TestRewardRejectsForgedEvidence(t *testing.T) {
	board := evidenceMap()
	completion := evidenceAttempt(1, board, true)
	completion.Actions = completion.Actions[:len(completion.Actions)-1] + "1"
	if err := GameEvidence_Validate(completion, board); err == nil {
		t.Fatal("structurally valid actions that do not make the recorded trace were accepted")
	}
}

func TestRewardRejectsIllegalTrace(t *testing.T) {
	board := evidenceMap()
	completion := evidenceAttempt(1, board, true)
	completion.Actions = "11111111111"
	if err := GameEvidence_Validate(completion, board); err == nil {
		t.Fatal("a recorded route was accepted without replaying its actions")
	}
}

func TestRewardProofBindsMapSessionAccount(t *testing.T) {
	_, store, handler, _ := unlockFixture(t)
	player, other := newTestIdentity(t, handler, 0xb7), newTestIdentity(t, handler, 0xb8)
	board := evidenceMap()
	seedGameEvidence(t, store, player.UserID, 28)
	registerEvidenceMap(t, store, board, 29, "bound")

	unbound := evidenceAttempt(29, board, true)
	unbound.MapHash = GameEvidence_MapHash("shovey.classic", 1, board)
	if result := GameEvidence_Put(store.Database, context.Background(), player.UserID, unbound); result.Error == nil {
		t.Fatal("evidence was accepted for an unbound map revision")
	}
	if eligible := GameEvidence_Eligible(store.Database, context.Background(), other.UserID, "shovey.secret-chest"); eligible.Error != nil || eligible.Eligible {
		t.Fatalf("another authenticated account became eligible: %+v", eligible)
	}
	response := tokenJSONRequest(t, handler, http.MethodPost, "/api/v1/rewards", other.Token, []byte(`{"reward":"shovey.secret-chest"}`))
	if response.Code != 403 {
		t.Fatalf("unbound account claimed reward: %d %s", response.Code, response.Body.String())
	}
}

func TestRewardLegitimateCompletion(t *testing.T) {
	_, store, handler, _ := unlockFixture(t)
	player := newTestIdentity(t, handler, 0xb9)
	seedGameEvidence(t, store, player.UserID, 28)
	response := tokenJSONRequest(t, handler, http.MethodPost, "/api/v1/rewards", player.Token, []byte(`{"reward":"shovey.secret-chest"}`))
	var claim rewardClaimResponse
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &claim) != nil || !claim.Credited || claim.Units != 2*UnitsPerDew {
		t.Fatalf("legitimate completion: %d %s", response.Code, response.Body.String())
	}
}

func TestRewardReplayIdempotency(t *testing.T) {
	_, store, handler, _ := unlockFixture(t)
	player := newTestIdentity(t, handler, 0xba)
	board := evidenceMap()
	registerEvidenceMap(t, store, board, 1, "idempotency")
	completion := evidenceAttempt(1, board, true)
	first := GameEvidence_Put(store.Database, context.Background(), player.UserID, completion)
	again := GameEvidence_Put(store.Database, context.Background(), player.UserID, completion)
	if first.Error != nil || !first.Created || again.Error != nil || again.Created || again.ID != first.ID {
		t.Fatalf("evidence replay: first=%+v again=%+v", first, again)
	}
	seedGameEvidence(t, store, player.UserID, 28)
	var balance int64
	for range 2 {
		response := tokenJSONRequest(t, handler, http.MethodPost, "/api/v1/rewards", player.Token, []byte(`{"reward":"shovey.secret-chest"}`))
		var claim rewardClaimResponse
		if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &claim) != nil || claim.Balance != 2*UnitsPerDew {
			t.Fatalf("reward replay: %d %s", response.Code, response.Body.String())
		}
		balance = claim.Balance
	}
	if balance != 2*UnitsPerDew {
		t.Fatalf("reward replay changed balance: %d", balance)
	}
}
