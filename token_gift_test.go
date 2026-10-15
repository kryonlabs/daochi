package main

import (
	"context"
	"testing"
)

func TestGiftDewCreditsEveryAccountOnce(t *testing.T) {
	_, store, handler, private := unlockFixture(t)
	ctx := context.Background()
	first := newTestIdentity(t, handler, 0x91)
	second := newTestIdentity(t, handler, 0x92)
	creditDew(t, store, private, second.UserID, "gift-before", UnitsPerDew)
	var users int64
	if err := store.Database.QueryRow(`SELECT COUNT(*) FROM server_users`).Scan(&users); err != nil || users < 2 {
		t.Fatalf("users: %d, %v", users, err)
	}
	given := TokenGift_Give(store.Database, ctx, private, "welcome-test", 10*UnitsPerDew)
	if given.Error != nil || given.Accounts != users || given.Credited != users || given.Units != 10*UnitsPerDew {
		t.Fatalf("gift: %+v, users %d", given, users)
	}
	check := func() {
		t.Helper()
		for account, want := range map[string]int64{first.UserID: 10 * UnitsPerDew, second.UserID: 11 * UnitsPerDew} {
			if got := TokenLedger_Balance(store.Database, ctx, account, AssetID); got.Error != nil || got.Value != want {
				t.Fatalf("balance %s: %+v, want %d", account[:8], got, want)
			}
		}
	}
	check()
	// The gift is spendable on a server-priced unlock.
	postUnlock(t, handler, first.Token, `{"product":"inbe.practice.taichi"}`, 200)
	again := TokenGift_Give(store.Database, ctx, private, "welcome-test", 10*UnitsPerDew)
	if again.Error != nil || again.Accounts != users || again.Credited != 0 {
		t.Fatalf("second gift: %+v", again)
	}
	if got := TokenLedger_Balance(store.Database, ctx, second.UserID, AssetID); got.Value != 11*UnitsPerDew {
		t.Fatalf("second gift changed a balance: %+v", got)
	}
	for _, bad := range []struct {
		name  string
		units int64
	}{{"", UnitsPerDew}, {"Welcome Gift", UnitsPerDew}, {"welcome-test", 0}} {
		if result := TokenGift_Give(store.Database, ctx, private, bad.name, bad.units); result.Error == nil {
			t.Fatalf("invalid gift %q %d accepted", bad.name, bad.units)
		}
	}
}
