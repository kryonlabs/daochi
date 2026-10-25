package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"math"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The free allowance comes from the node's configured account storage limit.
const testFreeBytes int64 = 20971520

func TestStoragePlansChargeOnceAndExpire(t *testing.T) {
	server, store, _ := testServer(t)
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	server.Cfg.WaoziIssuerPublicKey = public
	server.Cfg.WaoziIssuerPrivateKey = private
	server.Cfg.StoragePlansEnabled = true
	server.Cfg.AccountStorageLimitBytes = testFreeBytes
	server.Cfg.MoneroRateAtomicAmount = 1000000000
	server.Cfg.MoneroRateTokenUnits = 10 * UnitsPerDew
	handler := server.Routes()
	owner := newTestIdentity(t, handler, 0x73)
	other := newTestIdentity(t, handler, 0x74)
	ctx := context.Background()
	credit := TokenLedger_CreditPayment(store.Database, ctx, private, "monero", "storage-fixture", TokenEventInput{
		AccountID: owner.UserID, AppID: "inbe", EventType: "credit", AmountDelta: 240 * UnitsPerDew,
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
	if status["monthly_units"] != float64(20000000) || status["yearly_units"] != float64(200000000) {
		t.Fatalf("Dew prices: %v", status)
	}
	if status["monthly_xmr_atomic_units"] != float64(2000000000) || status["yearly_xmr_atomic_units"] != float64(20000000000) {
		t.Fatalf("fixed XMR prices: %v", status)
	}
	offers, _ := json.Marshal(status["plans"])
	if status["free_bytes"] != float64(testFreeBytes) || string(offers) != `[`+
		`{"limit_bytes":1073741824,"monthly_units":20000000,"monthly_xmr_atomic_units":2000000000,"size":"1gb","yearly_units":200000000,"yearly_xmr_atomic_units":20000000000},`+
		`{"limit_bytes":5368709120,"monthly_units":60000000,"monthly_xmr_atomic_units":6000000000,"size":"5gb","yearly_units":600000000,"yearly_xmr_atomic_units":60000000000}]` {
		t.Fatalf("plans: %v %s", status["free_bytes"], offers)
	}
	if got := status["plan"].(map[string]any); got["balance"] != float64(240*UnitsPerDew) || got["limit_bytes"] != float64(testFreeBytes) || got["size"] != "" {
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
	plan := StoragePlan_Read(store.Database, ctx, owner.UserID, time.Now().Unix(), testFreeBytes)
	if plan.Error != nil || plan.Balance != 220*UnitsPerDew || plan.LimitBytes != PaidBytes || plan.Size != "1gb" {
		t.Fatalf("paid plan: %+v", plan)
	}
	monthlyEnd := plan.ExpiresAt
	reused := tokenJSONRequest(t, handler, http.MethodPost, "/api/v1/storage/plan", owner.Token,
		[]byte(`{"period":"yearly","request_id":"storage-monthly-fixture"}`))
	if reused.Code != 409 {
		t.Fatalf("reused key: %d %s", reused.Code, reused.Body.String())
	}
	year := StoragePlan_Purchase(store.Database, ctx, private, owner.UserID, "1gb", "yearly", "storage-yearly-fixture", time.Now().Unix(), testFreeBytes)
	if year.Error != nil || year.Balance != 20*UnitsPerDew || year.ExpiresAt != StoragePlan_PeriodEnd(monthlyEnd, "yearly") {
		t.Fatalf("yearly extension: %+v", year)
	}
	ended := StoragePlan_Read(store.Database, ctx, owner.UserID, year.ExpiresAt, testFreeBytes)
	if ended.Error != nil || ended.LimitBytes != testFreeBytes {
		t.Fatalf("expired allowance: %+v", ended)
	}
	limited := AccountStorage_Limit(store.Database, ctx, owner.UserID, testFreeBytes, true)
	if limited.Error != nil || limited.Value != PaidBytes {
		t.Fatalf("paid sync allowance: %+v", limited)
	}
	limited = AccountStorage_Limit(store.Database, ctx, other.UserID, testFreeBytes, true)
	if limited.Error != nil || limited.Value != testFreeBytes {
		t.Fatalf("other account allowance: %+v", limited)
	}
	if _, err := store.Database.Exec("UPDATE server_storage_plans SET expires_at=0 WHERE user_id=?", owner.UserID); err != nil {
		t.Fatal(err)
	}
	limited = AccountStorage_Limit(store.Database, ctx, owner.UserID, testFreeBytes, true)
	if limited.Error != nil || limited.Value != testFreeBytes {
		t.Fatalf("expired sync allowance: %+v", limited)
	}
	if !AccountStorage_Exceeds(PaidBytes, PaidBytes+1, testFreeBytes) || AccountStorage_Exceeds(PaidBytes, PaidBytes-1, testFreeBytes) {
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
	server.Cfg.MoneroRateTokenUnits = 10 * UnitsPerDew
	handler := server.Routes()
	owner := newTestIdentity(t, handler, 0x76)
	for _, tc := range []struct {
		token, body string
		status      int
	}{
		{"", `{"period":"monthly","request_id":"missing-auth"}`, 401},
		{owner.Token, `{"period":"weekly","request_id":"invalid-period"}`, 400},
		{owner.Token, `{"period":"monthly","size":"2gb","request_id":"invalid-size"}`, 400},
		{owner.Token, `{"period":"monthly","size":"","request_id":"empty-size-means-1gb"}`, 402},
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
		AccountID: owner.UserID, EventType: "credit", AmountDelta: 200 * UnitsPerDew, SourceType: "monero", SourceRef: "rollback-fixture",
	}, errTokenIssuerReadOnly)
	if credit.Error != nil {
		t.Fatal(credit.Error)
	}
	_, err = store.Database.Exec(`CREATE TRIGGER reject_storage BEFORE INSERT ON server_storage_plans BEGIN SELECT RAISE(ABORT,'fixture failure'); END`)
	if err != nil {
		t.Fatal(err)
	}
	failed := StoragePlan_Purchase(store.Database, ctx, private, owner.UserID, "1gb", "monthly", "rollback-request", time.Now().Unix(), testFreeBytes)
	if failed.Error == nil || !strings.Contains(failed.Error.Error(), "fixture failure") {
		t.Fatalf("expected transaction failure: %+v", failed)
	}
	balance := TokenLedger_Balance(store.Database, ctx, owner.UserID, AssetID)
	if balance.Error != nil || balance.Value != 200*UnitsPerDew {
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
		size, period  string
		atomic, units int64
		want          int64
	}{
		// At 10000 Dew per XMR, 1 GB costs 0.002 XMR a month and 0.02 XMR a year;
		// 5 GB costs three times that.
		{"1gb", "monthly", 1000000000000, 10000 * UnitsPerDew, 2000000000},
		{"1gb", "yearly", 1000000000000, 10000 * UnitsPerDew, 20000000000},
		{"5gb", "monthly", 1000000000000, 10000 * UnitsPerDew, 6000000000},
		{"5gb", "yearly", 1000000000000, 10000 * UnitsPerDew, 60000000000},
		{"1gb", "monthly", 7, 3, 46666667},
		{"1gb", "monthly", 1, 400000000, 1},
		{"1gb", "monthly", math.MaxInt64 / 20, UnitsPerDew, math.MaxInt64 / 20 * 20},
	} {
		got := StoragePlan_MoneroPrice(tc.size, tc.period, tc.atomic, tc.units)
		if got.Error != nil || got.Value != tc.want {
			t.Fatalf("%+v: %+v", tc, got)
		}
	}
	for _, tc := range []struct {
		size, period  string
		atomic, units int64
	}{
		{"1gb", "monthly", 0, UnitsPerDew},
		{"1gb", "monthly", 1, 0},
		{"1gb", "weekly", 1, UnitsPerDew},
		{"2gb", "monthly", 1, UnitsPerDew},
		{"1gb", "monthly", math.MaxInt64, UnitsPerDew},
		{"5gb", "yearly", math.MaxInt64 / 50, UnitsPerDew},
	} {
		if got := StoragePlan_MoneroPrice(tc.size, tc.period, tc.atomic, tc.units); got.Error == nil {
			t.Fatalf("accepted invalid XMR price: %+v", tc)
		}
	}
	if StoragePlan_Priced(math.MaxInt64/50, UnitsPerDew) || !StoragePlan_Priced(1000000000000, 10000*UnitsPerDew) {
		t.Fatal("every plan needs an XMR price")
	}
}

func TestStoragePlanPrices(t *testing.T) {
	for _, tc := range []struct {
		size, period string
		dew          int64
	}{
		{"1gb", "monthly", 20},
		{"1gb", "yearly", 200},
		{"5gb", "monthly", 60},
		{"5gb", "yearly", 600},
		{"1gb", "weekly", 0},
		{"2gb", "monthly", 0},
		{"", "monthly", 0},
	} {
		if got := StoragePlan_Price(tc.size, tc.period); got != tc.dew*UnitsPerDew {
			t.Fatalf("%s %s: %d", tc.size, tc.period, got)
		}
	}
	if StoragePlan_SizeBytes("1gb") != PaidBytes || StoragePlan_SizeBytes("5gb") != 5368709120 || StoragePlan_SizeBytes("") != 0 {
		t.Fatal("plan sizes")
	}
}

func TestStorageConvertedSeconds(t *testing.T) {
	day := int64(86400)
	for _, tc := range []struct {
		remaining int64
		from, to  string
		want      int64
	}{
		{3 * day, "1gb", "5gb", day},
		{day, "5gb", "1gb", 3 * day},
		{10, "1gb", "5gb", 3},
		{0, "1gb", "5gb", 0},
		{-5, "5gb", "1gb", 0},
		{day, "1gb", "2gb", 0},
		{MaximumExpiry, "5gb", "1gb", 3 * MaximumExpiry},
		{math.MaxInt64, "1gb", "5gb", math.MaxInt64 / 3},
	} {
		if got := StoragePlan_ConvertedSeconds(tc.remaining, tc.from, tc.to); got != tc.want {
			t.Fatalf("%d %s->%s: %d, want %d", tc.remaining, tc.from, tc.to, got, tc.want)
		}
	}
}

func TestStoragePlanSizeChangesConvertRemainingTime(t *testing.T) {
	server, store, _ := testServer(t)
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	server.Cfg.WaoziIssuerPrivateKey = private
	server.Cfg.StoragePlansEnabled = true
	server.Cfg.MoneroRateAtomicAmount = 1000000000000
	server.Cfg.MoneroRateTokenUnits = 10000 * UnitsPerDew
	handler := server.Routes()
	owner := newTestIdentity(t, handler, 0x78)
	ctx := context.Background()
	credit := TokenLedger_CreditPayment(store.Database, ctx, private, "monero", "size-fixture", TokenEventInput{
		AccountID: owner.UserID, EventType: "credit", AmountDelta: 1000 * UnitsPerDew,
		SourceType: "monero", SourceRef: "size-fixture",
	}, errTokenIssuerReadOnly)
	if credit.Error != nil {
		t.Fatal(credit.Error)
	}
	day := int64(86400)
	start := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	small := StoragePlan_Purchase(store.Database, ctx, private, owner.UserID, "1gb", "monthly", "size-small", start, testFreeBytes)
	if small.Error != nil || small.ExpiresAt != start+31*day || small.LimitBytes != PaidBytes || small.Balance != 980*UnitsPerDew {
		t.Fatalf("1 GB month: %+v", small)
	}
	// Thirty days of 1 GB left become ten days of 5 GB, then a month.
	now := start + day
	large := StoragePlan_Purchase(store.Database, ctx, private, owner.UserID, "5gb", "monthly", "size-large", now, testFreeBytes)
	if large.Error != nil || large.Size != "5gb" || large.LimitBytes != LargeBytes || large.Balance != 920*UnitsPerDew ||
		large.ExpiresAt != StoragePlan_PeriodEnd(now+10*day, "monthly") {
		t.Fatalf("5 GB month: %+v", large)
	}
	read := StoragePlan_Read(store.Database, ctx, owner.UserID, now, testFreeBytes)
	if read.Error != nil || read.Size != "5gb" || read.LimitBytes != LargeBytes || read.ExpiresAt != large.ExpiresAt {
		t.Fatalf("5 GB plan: %+v", read)
	}
	if limited := AccountStorage_Limit(store.Database, ctx, owner.UserID, testFreeBytes, true); limited.Error != nil || limited.Value != LargeBytes {
		t.Fatalf("5 GB sync allowance: %+v", limited)
	}
	// Another 5 GB month extends from the current end.
	longer := StoragePlan_Purchase(store.Database, ctx, private, owner.UserID, "5gb", "monthly", "size-large-again", now, testFreeBytes)
	if longer.Error != nil || longer.ExpiresAt != StoragePlan_PeriodEnd(large.ExpiresAt, "monthly") {
		t.Fatalf("5 GB extension: %+v", longer)
	}
	// Back to 1 GB: each remaining 5 GB second becomes three 1 GB seconds.
	later := now + 2*day
	smaller := StoragePlan_Purchase(store.Database, ctx, private, owner.UserID, "1gb", "monthly", "size-small-again", later, testFreeBytes)
	if smaller.Error != nil || smaller.Size != "1gb" || smaller.LimitBytes != PaidBytes ||
		smaller.ExpiresAt != StoragePlan_PeriodEnd(later+3*(longer.ExpiresAt-later), "monthly") {
		t.Fatalf("back to 1 GB: %+v", smaller)
	}
	// A retry returns the recorded purchase; another size or period for the same ID is refused.
	retry := StoragePlan_Purchase(store.Database, ctx, private, owner.UserID, "5gb", "monthly", "size-large", later, testFreeBytes)
	if retry.Error != nil || retry.Balance != smaller.Balance || retry.Size != "1gb" {
		t.Fatalf("retry: %+v", retry)
	}
	for _, reused := range []struct{ size, period string }{{"1gb", "monthly"}, {"5gb", "yearly"}} {
		if got := StoragePlan_Purchase(store.Database, ctx, private, owner.UserID, reused.size, reused.period, "size-large", later, testFreeBytes); got.Error == nil ||
			got.Error.Error() != "storage request id reused" {
			t.Fatalf("reused %+v: %+v", reused, got)
		}
	}
	res := tokenJSONRequest(t, handler, http.MethodPost, "/api/v1/storage/plan", owner.Token,
		[]byte(`{"period":"monthly","size":"1gb","request_id":"size-http"}`))
	if res.Code != 200 {
		t.Fatalf("1 GB over HTTP: %d %s", res.Code, res.Body.String())
	}
	res = tokenJSONRequest(t, handler, http.MethodPost, "/api/v1/storage/plan", owner.Token,
		[]byte(`{"period":"monthly","size":"5gb","request_id":"size-http"}`))
	if res.Code != 409 {
		t.Fatalf("size changed for the same request: %d %s", res.Code, res.Body.String())
	}
	// An app that predates sizes buys 1 GB, and a retry with the size named matches it.
	res = tokenJSONRequest(t, handler, http.MethodPost, "/api/v1/storage/plan", owner.Token,
		[]byte(`{"period":"monthly","request_id":"size-legacy"}`))
	var status struct {
		Plan Plan `json:"plan"`
	}
	if res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &status) != nil || status.Plan.Size != "1gb" || status.Plan.LimitBytes != PaidBytes {
		t.Fatalf("legacy purchase: %d %s", res.Code, res.Body.String())
	}
	res = tokenJSONRequest(t, handler, http.MethodPost, "/api/v1/storage/plan", owner.Token,
		[]byte(`{"period":"monthly","size":"1gb","request_id":"size-legacy"}`))
	if res.Code != 200 {
		t.Fatalf("legacy retry with size: %d %s", res.Code, res.Body.String())
	}
	var purchases int
	if err := store.Database.QueryRow(`SELECT COUNT(*) FROM server_storage_purchases WHERE user_id=? AND size='5gb'`, owner.UserID).Scan(&purchases); err != nil || purchases != 2 {
		t.Fatalf("5 GB purchases: %d, %v", purchases, err)
	}
}

func TestStoragePlanSizesMigrateExistingPlans(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "plans-before-sizes.db")
	db, err := sql.Open("sqlite3", dbPath+"?_busy_timeout=5000")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
CREATE TABLE server_storage_plans (
 user_id TEXT PRIMARY KEY REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
 period TEXT NOT NULL CHECK(period IN ('monthly','yearly')), expires_at INTEGER NOT NULL
);
CREATE TABLE server_storage_purchases (
 user_id TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
 request_id TEXT NOT NULL, period TEXT NOT NULL, expires_at INTEGER NOT NULL,
 receipt_id TEXT NOT NULL, PRIMARY KEY(user_id,request_id)
);
INSERT INTO server_storage_plans(user_id,period,expires_at) VALUES('paid-before-sizes','monthly',4102444800);
INSERT INTO server_storage_purchases(user_id,request_id,period,expires_at,receipt_id) VALUES('paid-before-sizes','old','monthly',4102444800,'receipt');
`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("open store with plans before sizes: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	var plan, purchase string
	if err := store.Database.QueryRow(`SELECT size FROM server_storage_plans WHERE user_id='paid-before-sizes'`).Scan(&plan); err != nil || plan != "1gb" {
		t.Fatalf("plan size: %q, %v", plan, err)
	}
	if err := store.Database.QueryRow(`SELECT size FROM server_storage_purchases WHERE request_id='old'`).Scan(&purchase); err != nil || purchase != "1gb" {
		t.Fatalf("purchase size: %q, %v", purchase, err)
	}
	limit := AccountStorage_Limit(store.Database, context.Background(), "paid-before-sizes", testFreeBytes, true)
	if limit.Error != nil || limit.Value != PaidBytes {
		t.Fatalf("allowance before sizes: %+v", limit)
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
	offers := status["plans"].([]any)
	for _, item := range offers {
		offer := item.(map[string]any)
		if offer["monthly_units"] == float64(0) || offer["monthly_xmr_atomic_units"] != float64(0) || offer["yearly_xmr_atomic_units"] != float64(0) {
			t.Fatalf("unconfigured plan prices: %v", offer)
		}
	}
	if len(offers) != 2 {
		t.Fatalf("plans: %v", offers)
	}
	res = tokenJSONRequest(t, handler, http.MethodPost, "/api/v1/storage/plan", owner.Token,
		[]byte(`{"period":"monthly","request_id":"missing-xmr-price"}`))
	if res.Code != 503 {
		t.Fatalf("purchase without XMR price: %d %s", res.Code, res.Body.String())
	}
}
