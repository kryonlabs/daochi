package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIslandQuoteAndCalendarSale(t *testing.T) {
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC).Unix()
	end := time.Date(2027, 5, 1, 0, 0, 0, 0, time.UTC).Unix()
	if Unlock_IslandSaleUntil(start) != end || Unlock_IslandSaleUntil(0) != 0 {
		t.Fatal("sale must last six calendar months from configured launch")
	}
	for _, tc := range []struct{ now, launch, want int64 }{
		{start - 1, start, 85000000}, {start, start, 51000000}, {end - 1, start, 51000000},
		{end, start, 85000000}, {start, 0, 85000000},
	} {
		if got := Unlock_ProductPrice(ShoveyIsland, tc.now, end+100, tc.launch); got != tc.want {
			t.Fatalf("quote %+v: %d", tc, got)
		}
	}
	server, _, handler, _ := unlockFixture(t)
	server.Cfg.ShoveyIslandLaunchAt = time.Now().AddDate(0, -1, 0).Unix()
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/api/v1/unlocks/products", nil))
	var prices struct {
		Products []UnlockProduct `json:"products"`
	}
	if res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &prices) != nil || len(prices.Products) != 2 {
		t.Fatalf("catalog: %d %s", res.Code, res.Body.String())
	}
	island := prices.Products[1]
	if island.Product != ShoveyIsland || island.PriceUnits != 51000000 || island.RegularPriceUnits != 85000000 || island.TrialUntil != 0 {
		t.Fatalf("island quote: %+v", island)
	}
}

func TestIslandConfirmedPurchaseRestoreAndIsolation(t *testing.T) {
	server, store, handler, private := unlockFixture(t)
	owner := newTestIdentity(t, handler, 0xb1)
	other := newTestIdentity(t, handler, 0xb2)
	creditDew(t, store, private, owner.UserID, "island-fixture", 200000000)
	server.Cfg.ShoveyIslandLaunchAt = time.Now().AddDate(0, -1, 0).Unix()
	for _, body := range []string{
		`{"product":"shovey.island"}`, `{"product":"shovey.island","expected_units":1}`,
		`{"product":"shovey.island","expected_units":85000000}`,
	} {
		postUnlock(t, handler, owner.Token, body, 409)
	}
	body := `{"product":"shovey.island","expected_units":51000000}`
	postUnlock(t, handler, other.Token, body, 402)
	postUnlock(t, handler, "", body, 401)
	first := postUnlock(t, handler, owner.Token, body, 200)
	if first.PriceUnits != 51000000 || first.Balance != 149000000 || !first.Unlocked {
		t.Fatalf("sale: %+v", first)
	}
	// After the sale, the same stale confirmation restores the original receipt.
	server.Cfg.ShoveyIslandLaunchAt = time.Now().AddDate(0, -7, 0).Unix()
	again := postUnlock(t, handler, owner.Token, body, 200)
	if first != again {
		t.Fatalf("duplicate: %+v / %+v", first, again)
	}
	if _, err := store.Database.Exec("DELETE FROM account_unlocks WHERE account_id=?", owner.UserID); err != nil {
		t.Fatal(err)
	}
	restored := postUnlock(t, handler, owner.Token, body, 200)
	if restored != first {
		t.Fatalf("restore: %+v", restored)
	}
	postUnlock(t, handler, other.Token, body, 409)
	creditDew(t, store, private, other.UserID, "island-regular", 85000000)
	regular := postUnlock(t, handler, other.Token, `{"product":"shovey.island","expected_units":85000000}`, 200)
	if regular.PriceUnits != 85000000 || regular.Balance != 0 {
		t.Fatalf("regular: %+v", regular)
	}
	var count int
	if err := store.Database.QueryRow("SELECT COUNT(*) FROM token_ledger WHERE source_type='unlock' AND source_ref='shovey.island'").Scan(&count); err != nil || count != 2 {
		t.Fatalf("debits %d: %v", count, err)
	}
}

func TestIslandForgedSpendCannotRestoreUnlock(t *testing.T) {
	_, store, handler, private := unlockFixture(t)
	owner := newTestIdentity(t, handler, 0xb3)
	creditDew(t, store, private, owner.UserID, "island-forged", 85000000)
	// Even a signed generic spend with the exact nonce/amount is not an unlock.
	input := TokenEventInput{AccountID: owner.UserID, AppID: "entity", EventType: "debit", AmountDelta: -51000000, SourceType: "spend", SourceRef: ShoveyIsland}
	spent := TokenLedger_Spend(store.Database, context.Background(), private, input, "unlock:"+ShoveyIsland, errTokenIssuerReadOnly)
	if spent.Error != nil {
		t.Fatal(spent.Error)
	}
	postUnlock(t, handler, owner.Token, fmt.Sprintf(`{"product":"shovey.island","expected_units":%d}`, 85000000), 503)
	owned := Unlock_Owned(store.Database, context.Background(), owner.UserID, ShoveyIsland)
	if owned.Error != nil || owned.Value {
		t.Fatalf("forged entitlement: %+v", owned)
	}
}

func TestIslandLaunchConfiguration(t *testing.T) {
	clearConfigEnvironment(t)
	if Config_Load().ShoveyIslandLaunchAt != 0 {
		t.Fatal("sale starts only when configured")
	}
	t.Setenv("DAOCHI_SHOVEY_ISLAND_LAUNCH_AT", "1793491200")
	if Config_Load().ShoveyIslandLaunchAt != 1793491200 {
		t.Fatal("launch timestamp not loaded")
	}
}
