package main

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestReferralTrustedShopCatalogAndLegacyStableKey(t *testing.T) {
	server, users := referralFixture(t)
	db, ctx := server.Store.Database, context.Background()
	for _, app := range []string{"wurm", "shovey", "choano"} {
		if _, err := db.Exec("INSERT OR IGNORE INTO server_apps(app_id,display_name) VALUES(?,?)", app, app); err != nil {
			t.Fatal(err)
		}
	}
	allocationCredit(t, server.Store, users[0], "shovey", "google_play", "shop-shovey-credit", 100000000)
	bearer := issueTestBearer(t, server, users[0], time.Now().Add(time.Hour))
	handler := server.Routes()
	request := func(app, action, key string, amount int64, status int) TokenSpendResponse {
		t.Helper()
		body := fmt.Sprintf(`{"app_id":%q,"asset_id":"waozi:token","action":%q,"amount":%d,"idempotency_key":%q}`, app, action, amount, key)
		response := tokenJSONRequest(t, handler, "POST", "/api/v1/tokens/spend", bearer, []byte(body))
		if response.Code != status {
			t.Fatalf("%s %s: %d %s", app, action, response.Code, response.Body.String())
		}
		var result TokenSpendResponse
		if status == 200 {
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
		}
		return result
	}
	request("shovey", "wurm.mint", "skin-wurm-mint-v2", 10000000, 400)
	request("wurm", "wurm.mint", "skin-wurm-mint-v2", 1, 400)
	request("wurm", "wurm.mint", "skin-wurm-mint-v2", 10000000, 409)
	first := request("shovey", "shovey.night", "skin-shovey-night-v1", 10000000, 200)
	if first.Receipt.AppID != "shovey" {
		t.Fatal("wrong signed title", first)
	}
	again := request("shovey", "shovey.night", "skin-shovey-night-v1", 10000000, 200)
	if first.Receipt.ReceiptID != again.Receipt.ReceiptID {
		t.Fatal("shop retry charged twice")
	}
	request("shovey", "shovey.coins", "coins-shovey-1-1-v1", 2000000, 200)
	request("shovey", "shovey.coins", "coins-wurm-1-1-v1", 2000000, 400)
	request("shovey", "shovey.coins", "coins-shovey-1-0-v1", 2000000, 400)
	request("shovey", "shovey.coins", "coins-shovey-1-1-v1", 1, 400)
	request("shovey", "shovey.unknown", "unknown-product", 1000000, 400)
	// Historical signed Entity debit is replayed across attribution migration.
	allocationCredit(t, server.Store, users[0], "", "admin", "shop-legacy-funds", 100000000)
	old := TokenLedger_Spend(db, ctx, server.Cfg.WaoziIssuerPrivateKey, TokenEventInput{AccountID: users[0], AppID: "entity", EventType: "debit", AmountDelta: -30000000, SourceType: "spend", SourceRef: "shovey.crystal:skin-shovey-crystal-v1"}, "skin-shovey-crystal-v1", errTokenIssuerReadOnly)
	if old.Error != nil {
		t.Fatal(old.Error)
	}
	balance := referralBalance(t, server, users[0])
	replay := request("shovey", "shovey.crystal", "skin-shovey-crystal-v1", 30000000, 200)
	if replay.Receipt.ReceiptID != old.Value.ReceiptID || referralBalance(t, server, users[0]) != balance {
		t.Fatal("legacy stable key recharged", replay)
	}
}

func TestReferralLedgerBoundedCrossTitleRestore(t *testing.T) {
	server, users := referralFixture(t)
	db := server.Store.Database
	for i := 0; i < 105; i++ {
		allocationCredit(t, server.Store, users[0], "", "admin", fmt.Sprintf("restore-%d", i), 1)
	}
	allocationCredit(t, server.Store, users[1], "", "admin", "private-other-account", 1)
	bearer := issueTestBearer(t, server, users[0], time.Now().Add(time.Hour))
	handler := server.Routes()
	var cursor int64
	total := 0
	for {
		response := tokenJSONRequest(t, handler, "GET", fmt.Sprintf("/api/v1/tokens/ledger?since=%d&limit=100", cursor), bearer, nil)
		if response.Code != 200 {
			t.Fatal(response.Code, response.Body.String())
		}
		var page TokenLedgerResponse
		if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		if len(page.Events) > 100 {
			t.Fatal("unbounded page")
		}
		for _, event := range page.Events {
			if event.AccountID != users[0] || event.LedgerSeq <= cursor {
				t.Fatal("pagination or privacy", event)
			}
			cursor = event.LedgerSeq
			total++
		}
		if len(page.Events) < 100 {
			break
		}
	}
	var expected int
	if err := db.QueryRow("SELECT COUNT(*) FROM token_ledger WHERE account_id=?", users[0]).Scan(&expected); err != nil {
		t.Fatal(err)
	}
	if total != expected {
		t.Fatal("restore lost receipts", total, expected)
	}
	for _, limit := range []string{"0", "101", "nope"} {
		if r := tokenJSONRequest(t, handler, "GET", "/api/v1/tokens/ledger?limit="+limit, bearer, nil); r.Code != 400 {
			t.Fatal("invalid page", limit, r.Code)
		}
	}
}
