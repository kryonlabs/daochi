package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func dewActivityFixture(t *testing.T) (*Server, *Store, *fakeMoneroWalletRPC, http.Handler, testIdentity, MoneroAccountAddress) {
	t.Helper()
	server, store, wallet, handler, identity := moneroReconcileTestServer(t)
	server.Cfg.MoneroRateAtomicAmount = 1000000000
	server.Cfg.MoneroRateTokenUnits = 1000000
	server.Cfg.MoneroConfirmationsRequired = 10
	res := tokenJSONRequest(t, handler, http.MethodGet, "/api/v1/tokens/purchases/monero/address", identity.Token, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("address: %d %s", res.Code, res.Body.String())
	}
	mapping := MoneroDepositStore_AccountAddress(store.Database, context.Background(), identity.UserID)
	if mapping.Error != nil || !mapping.Found {
		t.Fatalf("address mapping: %+v", mapping)
	}
	return server, store, wallet, handler, identity, mapping.Value
}

// A deposit keeps the XMR/USD rate that was current when the transfer was
// first observed, as a first-write-wins snapshot beside the funding ratio.
func TestMoneroDepositSnapshotsUSDRateAtFirstObservation(t *testing.T) {
	server, store, wallet, handler, identity, mapping := dewActivityFixture(t)
	now := time.Now().Unix()
	ExchangeRate_Remember(XmrRate{Cents: 21500, UpdatedAt: now, Sources: []string{"coingecko", "kraken"}})
	defer ExchangeRate_Remember(XmrRate{})

	wallet.walletHeight = 300
	wallet.setTransfer(moneroTransfer{TxID: "tx-usd-snap", Amount: 1000000000, Confirmations: 10,
		Height: 300, Major: mapping.AccountIndex, Minor: mapping.AddressIndex})
	if err := MoneroDeposits_Reconcile(server.monero(), context.Background()); err != nil {
		t.Fatal(err)
	}
	// The rate disappears before a later reconcile of the same transfer; the
	// snapshot from first observation must survive it.
	ExchangeRate_Remember(XmrRate{})
	if err := MoneroDeposits_Reconcile(server.monero(), context.Background()); err != nil {
		t.Fatal(err)
	}

	cents, updatedAt, sources := int64(0), int64(0), ""
	row := store.Database.QueryRow(
		`SELECT usd_cents,usd_updated_at,usd_sources FROM monero_deposits WHERE tx_id='tx-usd-snap'`)
	if err := row.Scan(&cents, &updatedAt, &sources); err != nil {
		t.Fatal(err)
	}
	if cents != 21500 || sources != "coingecko,kraken" || updatedAt < now-60 {
		t.Fatalf("usd snapshot cents=%d updated_at=%d sources=%q, want 21500/recent/coingecko,kraken",
			cents, updatedAt, sources)
	}

	deposits := tokenJSONRequest(t, handler, http.MethodGet, "/api/v1/tokens/purchases/monero/deposits", identity.Token, nil)
	if deposits.Code != http.StatusOK || !strings.Contains(deposits.Body.String(), `"usd_cents":21500`) ||
		!strings.Contains(deposits.Body.String(), `"usd_sources":"coingecko,kraken"`) {
		t.Fatalf("deposits response status=%d body=%s", deposits.Code, deposits.Body.String())
	}
}

// The activity endpoint serves the profile's Dew screen: the balance plus the
// account's full history, newest first, across sources, with Monero credits
// carrying their paid atomic amount and USD snapshot.
func TestTokenActivityShowsFullDewHistoryAcrossApps(t *testing.T) {
	server, store, wallet, handler, identity, mapping := dewActivityFixture(t)
	ExchangeRate_Remember(XmrRate{Cents: 21500, UpdatedAt: time.Now().Unix(), Sources: []string{"coingecko", "kraken"}})
	defer ExchangeRate_Remember(XmrRate{})

	wallet.walletHeight = 300
	wallet.setTransfer(moneroTransfer{TxID: "tx-activity", Amount: 1000000000, Confirmations: 10,
		Height: 300, Major: mapping.AccountIndex, Minor: mapping.AddressIndex})
	if err := MoneroDeposits_Reconcile(server.monero(), context.Background()); err != nil {
		t.Fatal(err)
	}
	adminCredit := TokenEventInput{
		AccountID:   identity.UserID,
		AppID:       "inbe",
		EventType:   "credit",
		AmountDelta: 500000,
		SourceType:  "admin",
		SourceRef:   "test:activity",
	}
	credited := TokenLedger_CreditPayment(store.Database, context.Background(),
		server.Cfg.WaoziIssuerPrivateKey, "admin", "test:activity", adminCredit, nil)
	if credited.Error != nil {
		t.Fatalf("admin credit: %v", credited.Error)
	}

	res := tokenJSONRequest(t, handler, http.MethodGet, "/api/v1/tokens/activity", identity.Token, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("activity status=%d body=%s", res.Code, res.Body.String())
	}
	var page TokenActivityResponse
	if err := json.Unmarshal(res.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Balance != 1500000 {
		t.Fatalf("activity balance=%d, want 1500000", page.Balance)
	}
	if len(page.Events) != 2 {
		t.Fatalf("activity events=%d, want 2 (body=%s)", len(page.Events), res.Body.String())
	}
	if page.Events[0].Seq <= page.Events[1].Seq {
		t.Fatalf("activity is not newest first: seq %d then %d", page.Events[0].Seq, page.Events[1].Seq)
	}
	admin, deposit := page.Events[0], page.Events[1]
	if admin.SourceType != "admin" || admin.Monero != nil {
		t.Fatalf("admin event source=%q monero=%v, want admin/none", admin.SourceType, admin.Monero)
	}
	if deposit.SourceType != "monero_account" || deposit.Monero == nil {
		t.Fatalf("deposit event source=%q monero=%v, want monero_account/joined", deposit.SourceType, deposit.Monero)
	}
	if deposit.Monero.TxID != "tx-activity" || deposit.Monero.AmountAtomic != 1000000000 ||
		deposit.Monero.UsdCents != 21500 {
		t.Fatalf("deposit monero block=%+v, want tx-activity/1000000000/21500", deposit.Monero)
	}

	limited := tokenJSONRequest(t, handler, http.MethodGet, "/api/v1/tokens/activity?limit=1", identity.Token, nil)
	if limited.Code != http.StatusOK {
		t.Fatalf("limited activity status=%d", limited.Code)
	}
	var firstPage TokenActivityResponse
	if err := json.Unmarshal(limited.Body.Bytes(), &firstPage); err != nil {
		t.Fatal(err)
	}
	if len(firstPage.Events) != 1 || firstPage.Events[0].Seq != admin.Seq {
		t.Fatalf("limited page events=%+v, want only newest event", firstPage.Events)
	}

	paged := tokenJSONRequest(t, handler, http.MethodGet,
		"/api/v1/tokens/activity?limit=1&before_seq="+strconv.FormatInt(admin.Seq, 10), identity.Token, nil)
	if paged.Code != http.StatusOK {
		t.Fatalf("paged activity status=%d", paged.Code)
	}
	var olderPage TokenActivityResponse
	if err := json.Unmarshal(paged.Body.Bytes(), &olderPage); err != nil {
		t.Fatal(err)
	}
	if len(olderPage.Events) != 1 || olderPage.Events[0].Seq != deposit.Seq {
		t.Fatalf("paged events=%+v, want the deposit event next", olderPage.Events)
	}
}
