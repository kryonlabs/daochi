package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestStoragePlansChargeOnceAndExpire(t *testing.T) {
	server, store, _ := testServer(t)
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	server.Cfg.WaoziIssuerPublicKey = public
	server.Cfg.WaoziIssuerPrivateKey = private
	server.Cfg.StoragePlansEnabled = true
	server.Cfg.MoneroRateAtomicAmount = 1000000000
	server.Cfg.MoneroRateTokenUnits = UnitsPerDew
	handler := server.Routes()
	owner := newTestIdentity(t, handler, 0x73)
	other := newTestIdentity(t, handler, 0x74)
	ctx := context.Background()
	credit := TokenLedger_CreditPayment(store.Database, ctx, private, "monero", "storage-fixture", TokenEventInput{
		AccountID: owner.UserID, AppID: "inbe", EventType: "credit", AmountDelta: 12000000,
		SourceType: "monero", SourceRef: "storage-fixture",
	}, errTokenIssuerReadOnly)
	if credit.Error != nil {
		t.Fatal(credit.Error)
	}
	read := func(token string) map[string]any {
		t.Helper()
		res := tokenJSONRequest(t, handler, http.MethodGet, "/api/v1/storage/plan", token, nil)
		if res.Code != 200 {
			t.Fatalf("status %d: %s", res.Code, res.Body.String())
		}
		var result map[string]any
		if err := json.Unmarshal(res.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	status := read(owner.Token)
	if status["monthly_xmr_atomic_units"] != float64(1000000000) || status["yearly_xmr_atomic_units"] != float64(10000000000) {
		t.Fatalf("fixed XMR prices: %v", status)
	}
	if got := status["plan"].(map[string]any); got["balance"] != float64(12000000) || got["limit_bytes"] != float64(FreeBytes) {
		t.Fatalf("free plan: %v", got)
	}
	if got := read(other.Token)["plan"].(map[string]any)["balance"]; got != float64(0) {
		t.Fatalf("other user's balance: %v", got)
	}
	body := []byte(`{"period":"monthly","request_id":"storage-monthly-fixture"}`)
	for attempt := 0; attempt < 2; attempt++ {
		res := tokenJSONRequest(t, handler, http.MethodPost, "/api/v1/storage/plan", owner.Token, body)
		if res.Code != 200 {
			t.Fatalf("purchase %d: %s", res.Code, res.Body.String())
		}
	}
	plan := StoragePlan_Read(store.Database, ctx, owner.UserID, time.Now().Unix())
	if plan.Error != nil || plan.Balance != 11000000 || plan.LimitBytes != PaidBytes {
		t.Fatalf("paid plan: %+v", plan)
	}
	monthlyEnd := plan.ExpiresAt
	reused := tokenJSONRequest(t, handler, http.MethodPost, "/api/v1/storage/plan", owner.Token,
		[]byte(`{"period":"yearly","request_id":"storage-monthly-fixture"}`))
	if reused.Code != 409 {
		t.Fatalf("reused key: %d %s", reused.Code, reused.Body.String())
	}
	year := StoragePlan_Purchase(store.Database, ctx, private, owner.UserID, "yearly", "storage-yearly-fixture", time.Now().Unix())
	if year.Error != nil || year.Balance != 1000000 || year.ExpiresAt != StoragePlan_PeriodEnd(monthlyEnd, "yearly") {
		t.Fatalf("yearly extension: %+v", year)
	}
	ended := StoragePlan_Read(store.Database, ctx, owner.UserID, year.ExpiresAt)
	if ended.Error != nil || ended.LimitBytes != FreeBytes {
		t.Fatalf("expired allowance: %+v", ended)
	}
	limited := AccountStorage_Limit(store.Database, ctx, owner.UserID, 5, true)
	if limited.Error != nil || limited.Value != PaidBytes {
		t.Fatalf("paid sync allowance: %+v", limited)
	}
	limited = AccountStorage_Limit(store.Database, ctx, other.UserID, 5, true)
	if limited.Error != nil || limited.Value != FreeBytes {
		t.Fatalf("other account allowance: %+v", limited)
	}
	if _, err := store.Database.Exec("UPDATE server_storage_plans SET expires_at=0 WHERE user_id=?", owner.UserID); err != nil {
		t.Fatal(err)
	}
	limited = AccountStorage_Limit(store.Database, ctx, owner.UserID, 5, true)
	if limited.Error != nil || limited.Value != FreeBytes {
		t.Fatalf("expired sync allowance: %+v", limited)
	}
	if !AccountStorage_Exceeds(PaidBytes, PaidBytes+1, FreeBytes) || AccountStorage_Exceeds(PaidBytes, PaidBytes-1, FreeBytes) {
		t.Fatal("expiry must block growth and allow freeing space")
	}
}

func TestStoragePlanRejectsInvalidUnaffordableAndRollsBack(t *testing.T) {
	server, store, _ := testServer(t)
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	server.Cfg.WaoziIssuerPrivateKey = private
	server.Cfg.StoragePlansEnabled = true
	server.Cfg.MoneroRateAtomicAmount = 1000000000
	server.Cfg.MoneroRateTokenUnits = UnitsPerDew
	handler := server.Routes()
	owner := newTestIdentity(t, handler, 0x76)
	for _, tc := range []struct {
		token, body string
		status      int
	}{
		{"", `{"period":"monthly","request_id":"missing-auth"}`, 401},
		{owner.Token, `{"period":"weekly","request_id":"invalid-period"}`, 400},
		{owner.Token, `{"period":"monthly","request_id":""}`, 400},
		{owner.Token, `{"period":"monthly","request_id":"empty-balance"}`, 402},
	} {
		res := tokenJSONRequest(t, handler, http.MethodPost, "/api/v1/storage/plan", tc.token, []byte(tc.body))
		if res.Code != tc.status {
			t.Fatalf("%s: %d %s", tc.body, res.Code, res.Body.String())
		}
	}
	ctx := context.Background()
	credit := TokenLedger_CreditPayment(store.Database, ctx, private, "monero", "rollback-fixture", TokenEventInput{
		AccountID: owner.UserID, EventType: "credit", AmountDelta: 1000000, SourceType: "monero", SourceRef: "rollback-fixture",
	}, errTokenIssuerReadOnly)
	if credit.Error != nil {
		t.Fatal(credit.Error)
	}
	_, err = store.Database.Exec(`CREATE TRIGGER reject_storage BEFORE INSERT ON server_storage_plans BEGIN SELECT RAISE(ABORT,'fixture failure'); END`)
	if err != nil {
		t.Fatal(err)
	}
	failed := StoragePlan_Purchase(store.Database, ctx, private, owner.UserID, "monthly", "rollback-request", time.Now().Unix())
	if failed.Error == nil || !strings.Contains(failed.Error.Error(), "fixture failure") {
		t.Fatalf("expected transaction failure: %+v", failed)
	}
	balance := TokenLedger_Balance(store.Database, ctx, owner.UserID, AssetID)
	if balance.Error != nil || balance.Value != 1000000 {
		t.Fatalf("failed upgrade charged Dew: %+v", balance)
	}
}

func TestStoragePlanCalendarEnds(t *testing.T) {
	for _, tc := range []struct{ start, period, end string }{
		{"2027-01-31T12:00:00Z", "monthly", "2027-02-28T12:00:00Z"},
		{"2028-01-31T12:00:00Z", "monthly", "2028-02-29T12:00:00Z"},
		{"2028-02-29T12:00:00Z", "yearly", "2029-02-28T12:00:00Z"},
	} {
		start, _ := time.Parse(time.RFC3339, tc.start)
		got := time.Unix(StoragePlan_PeriodEnd(start.Unix(), tc.period), 0).UTC().Format(time.RFC3339)
		if got != tc.end {
			t.Fatalf("%s + %s: %s, want %s", tc.start, tc.period, got, tc.end)
		}
	}
}

func TestStoragePlansConfigIsOptIn(t *testing.T) {
	clearConfigEnvironment(t)
	if Config_Load().StoragePlansEnabled {
		t.Fatal("storage plans enabled without node configuration")
	}
	t.Setenv("DAOCHI_STORAGE_PLANS_ENABLED", "true")
	if !Config_Load().StoragePlansEnabled {
		t.Fatal("configured storage plans disabled")
	}
}

func TestStorageMoneroPrices(t *testing.T) {
	for _, tc := range []struct {
		period        string
		atomic, units int64
		want          int64
	}{
		{"monthly", 1000000000, UnitsPerDew, 1000000000},
		{"yearly", 1000000000, UnitsPerDew, 10000000000},
		{"monthly", 7, 3, 2333334},
		{"monthly", 1, 2000000, 1},
		{"monthly", math.MaxInt64, UnitsPerDew, math.MaxInt64},
	} {
		got := StoragePlan_MoneroPrice(tc.period, tc.atomic, tc.units)
		if got.Error != nil || got.Value != tc.want {
			t.Fatalf("%+v: %+v", tc, got)
		}
	}
	for _, tc := range []struct {
		period        string
		atomic, units int64
	}{
		{"monthly", 0, UnitsPerDew},
		{"monthly", 1, 0},
		{"weekly", 1, UnitsPerDew},
		{"yearly", math.MaxInt64, UnitsPerDew},
	} {
		if got := StoragePlan_MoneroPrice(tc.period, tc.atomic, tc.units); got.Error == nil {
			t.Fatalf("accepted invalid XMR price: %+v", tc)
		}
	}
}

func TestStorageUpgradeNeedsConfiguredXMRPrice(t *testing.T) {
	server, _, _ := testServer(t)
	server.Cfg.StoragePlansEnabled = true
	handler := server.Routes()
	owner := newTestIdentity(t, handler, 0x77)
	res := tokenJSONRequest(t, handler, http.MethodGet, "/api/v1/storage/plan", owner.Token, nil)
	var status map[string]any
	if err := json.Unmarshal(res.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if res.Code != 200 || status["enabled"] != false || status["monthly_xmr_atomic_units"] != float64(0) {
		t.Fatalf("unconfigured XMR pricing: %d %v", res.Code, status)
	}
	res = tokenJSONRequest(t, handler, http.MethodPost, "/api/v1/storage/plan", owner.Token,
		[]byte(`{"period":"monthly","request_id":"missing-xmr-price"}`))
	if res.Code != 503 {
		t.Fatalf("purchase without XMR price: %d %s", res.Code, res.Body.String())
	}
}
