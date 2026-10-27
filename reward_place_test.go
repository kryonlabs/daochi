package main

import (
	"context"
	"sync"
	"testing"
)

// The campaign's Dew by finishing place: 100 for the first 10, 50 for the
// next 20, 20 up to the 100th and 5 after.
func TestCampaignRewardPlaces(t *testing.T) {
	for _, want := range []struct {
		place int64
		dew   int64
	}{
		{1, 100}, {10, 100}, {11, 50}, {30, 50}, {31, 20}, {100, 20}, {101, 5}, {5000, 5},
	} {
		if got := TokenReward_PlaceUnits(want.place, CampaignPlaces[:], CampaignUnits[:]); got != want.dew*UnitsPerDew {
			t.Fatalf("place %d: %d units, want %d Dew", want.place, got, want.dew)
		}
	}
	if !TokenReward_ValidPlaces(CampaignPlaces[:], CampaignUnits[:]) {
		t.Fatal("campaign places invalid")
	}
	for _, bad := range []struct {
		places []int64
		units  []int64
	}{
		{nil, []int64{1}},
		{[]int64{2}, []int64{3}},
		{[]int64{2, 2}, []int64{3, 2, 1}},
		{[]int64{2}, []int64{3, 0}},
	} {
		if TokenReward_ValidPlaces(bad.places, bad.units) {
			t.Fatalf("invalid places accepted: %v %v", bad.places, bad.units)
		}
	}
}

// Accounts claiming at once each get their own place, and an account that
// claims again keeps its place and credits nothing.
func TestRewardByPlaceGivesEachPlaceOnce(t *testing.T) {
	_, store, handler, private := unlockFixture(t)
	ctx := context.Background()
	places := []int64{2, 3}
	units := []int64{30 * UnitsPerDew, 20 * UnitsPerDew, 10 * UnitsPerDew}
	players := make([]testIdentity, 5)
	for index := range players {
		players[index] = newTestIdentity(t, handler, byte(0xc0+index))
	}
	results := make([]RewardResult, len(players))
	var group sync.WaitGroup
	for index, player := range players {
		group.Add(1)
		go func() {
			defer group.Done()
			results[index] = TokenReward_GiveByPlace(store.Database, ctx, private, "test.finish", player.UserID, places, units)
		}()
	}
	group.Wait()
	taken := map[int64]bool{}
	for index, result := range results {
		if result.Error != nil || !result.Credited || result.Place < 1 || result.Place > int64(len(players)) || taken[result.Place] {
			t.Fatalf("claim %d: %+v", index, result)
		}
		taken[result.Place] = true
		if want := TokenReward_PlaceUnits(result.Place, places, units); result.Units != want || result.Balance != want {
			t.Fatalf("place %d gave %d units, balance %d, want %d", result.Place, result.Units, result.Balance, want)
		}
	}
	for index, player := range players {
		again := TokenReward_GiveByPlace(store.Database, ctx, private, "test.finish", player.UserID, places, units)
		if again.Error != nil || again.Credited || again.Place != results[index].Place || again.Units != results[index].Units {
			t.Fatalf("repeated claim %d: %+v, first %+v", index, again, results[index])
		}
	}
	if next := TokenReward_NextPlaceUnits(store.Database, ctx, "test.finish", places, units); next.Error != nil || next.Value != 10*UnitsPerDew {
		t.Fatalf("next place: %+v", next)
	}
	// Another reward has places of its own.
	other := TokenReward_GiveByPlace(store.Database, ctx, private, "test.other", players[0].UserID, places, units)
	if other.Error != nil || other.Place != 1 || other.Units != 30*UnitsPerDew {
		t.Fatalf("other reward: %+v", other)
	}
}

// Finishers credited the old flat Dew keep their places and get the rest of
// their place's Dew once; later finishers come after them.
func TestSettleCampaignTopsUpEarlierFinishers(t *testing.T) {
	_, store, handler, private := unlockFixture(t)
	ctx := context.Background()
	first := newTestIdentity(t, handler, 0xd1)
	second := newTestIdentity(t, handler, 0xd2)
	third := newTestIdentity(t, handler, 0xd3)
	balance := func(account string) int64 {
		t.Helper()
		got := TokenLedger_Balance(store.Database, ctx, account, AssetID)
		if got.Error != nil {
			t.Fatal(got.Error)
		}
		return got.Value
	}
	// Before places, a finisher got 0.5 Dew (5 Dew after the tenfold rescale)
	// and later 5 Dew.
	for _, early := range []struct {
		account string
		units   int64
	}{
		{first.UserID, UnitsPerDew / 2},
		{second.UserID, 5 * UnitsPerDew},
	} {
		if given := TokenReward_Give(store.Database, ctx, private, CampaignReward, early.account, early.units); given.Error != nil || !given.Credited {
			t.Fatalf("flat reward: %+v", given)
		}
	}
	if _, err := store.Database.Exec(`UPDATE token_processed_payments SET created_at='2026-10-25 12:00:00' WHERE provider='reward-v1'`); err != nil {
		t.Fatal(err)
	}
	placed := TokenReward_GiveByPlace(store.Database, ctx, private, CampaignReward, third.UserID, CampaignPlaces[:], CampaignUnits[:])
	if placed.Error != nil || placed.Place != 3 || placed.Units != 100*UnitsPerDew {
		t.Fatalf("third finisher: %+v", placed)
	}
	settled := RewardHttp_SettleCampaign(store.Database, ctx, private)
	if settled.Error != nil || settled.Accounts != 2 || settled.Units != 2*95*UnitsPerDew {
		t.Fatalf("settle: %+v", settled)
	}
	if got := balance(first.UserID); got != UnitsPerDew/2+95*UnitsPerDew {
		t.Fatalf("first finisher balance %d", got)
	}
	if got := balance(second.UserID); got != 100*UnitsPerDew {
		t.Fatalf("second finisher balance %d", got)
	}
	if got := balance(third.UserID); got != 100*UnitsPerDew {
		t.Fatalf("placed finisher was topped up: %d", got)
	}
	if again := RewardHttp_SettleCampaign(store.Database, ctx, private); again.Error != nil || again.Accounts != 0 {
		t.Fatalf("second settle: %+v", again)
	}
	// An earlier finisher claiming again keeps its place and credits nothing.
	repeat := TokenReward_GiveByPlace(store.Database, ctx, private, CampaignReward, second.UserID, CampaignPlaces[:], CampaignUnits[:])
	if repeat.Error != nil || repeat.Credited || repeat.Place != 2 || balance(second.UserID) != 100*UnitsPerDew {
		t.Fatalf("earlier finisher claimed again: %+v", repeat)
	}
}
