package main

import (
	"context"
	"testing"
)

func TestRewardDewCreditsOneAccountOnce(t *testing.T) {
	_, store, handler, private := unlockFixture(t)
	ctx := context.Background()
	donor := newTestIdentity(t, handler, 0x93)
	other := newTestIdentity(t, handler, 0x94)
	if _, err := store.Database.Exec(`UPDATE server_users SET alias='emerald' WHERE user_id_hash=?`, donor.UserID); err != nil {
		t.Fatal(err)
	}
	balance := func(account string) int64 {
		t.Helper()
		got := TokenLedger_Balance(store.Database, ctx, account, AssetID)
		if got.Error != nil {
			t.Fatal(got.Error)
		}
		return got.Value
	}

	given := TokenReward_Give(store.Database, ctx, private, "donation-2026-06", "@Emerald", 209*UnitsPerDew)
	if given.Error != nil || !given.Credited || given.Account != donor.UserID || given.Balance != 209*UnitsPerDew {
		t.Fatalf("reward: %+v", given)
	}
	if got := balance(other.UserID); got != 0 {
		t.Fatalf("reward reached another account: %d", got)
	}
	// The reward is spendable on a server-priced unlock.
	postUnlock(t, handler, donor.Token, `{"product":"inbe.practice.taichi"}`, 200)
	spent := balance(donor.UserID)
	if spent >= 209*UnitsPerDew {
		t.Fatalf("unlock did not spend the reward: %d", spent)
	}

	again := TokenReward_Give(store.Database, ctx, private, "donation-2026-06", donor.UserID, 209*UnitsPerDew)
	if again.Error != nil || again.Credited || again.Balance != spent {
		t.Fatalf("second reward: %+v", again)
	}
	changed := TokenReward_Give(store.Database, ctx, private, "donation-2026-06", "emerald", 300*UnitsPerDew)
	if changed.Error == nil {
		t.Fatalf("same reward with another amount accepted: %+v", changed)
	}
	if got := balance(donor.UserID); got != spent {
		t.Fatalf("rejected reward changed the balance: %d, want %d", got, spent)
	}

	next := TokenReward_Give(store.Database, ctx, private, "bug-report-2026-10", "emerald", 5*UnitsPerDew)
	if next.Error != nil || !next.Credited || next.Balance != spent+5*UnitsPerDew {
		t.Fatalf("second, different reward: %+v", next)
	}

	for _, bad := range []struct {
		reward  string
		account string
		units   int64
	}{
		{"", "emerald", UnitsPerDew},
		{"Donation Reward", "emerald", UnitsPerDew},
		{"donation-2026-06", "emerald", 0},
		{"donation-2026-06", "nobody_here", UnitsPerDew},
		{"donation-2026-06", "", UnitsPerDew},
	} {
		if result := TokenReward_Give(store.Database, ctx, private, bad.reward, bad.account, bad.units); result.Error == nil {
			t.Fatalf("invalid reward %q to %q for %d accepted", bad.reward, bad.account, bad.units)
		}
	}
	if got := balance(other.UserID); got != 0 {
		t.Fatalf("other account changed: %d", got)
	}
}
