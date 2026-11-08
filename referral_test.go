package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func referralFixture(t *testing.T) (*Server, []string) {
	t.Helper()
	server, users := socialHTTPFixture(t)
	server.Cfg.BaseURL = "https://api.waozi.xyz"
	server.Cfg.WaoziIssuerPrivateKey = tokenLedgerSigner()
	server.Cfg.WaoziIssuerPublicKey = tokenLedgerSigner().Public().(ed25519.PublicKey)
	return server, users
}

func referralCode(t *testing.T, server *Server, account string) string {
	t.Helper()
	result := Referral_Code(server.Store.Database, context.Background(), account, "")
	if result.Error != nil {
		t.Fatal(result.Error)
	}
	return result.Code
}

func referralBalance(t *testing.T, server *Server, account string) int64 {
	t.Helper()
	result := TokenLedger_Balance(server.Store.Database, context.Background(), account, AssetID)
	if result.Error != nil {
		t.Fatal(result.Error)
	}
	return result.Value
}

func referralSettle(t *testing.T, server *Server) {
	t.Helper()
	if err := ReferralSettlement_Reconcile(server.Store.Database, context.Background(), server.Cfg); err != nil {
		t.Fatal(err)
	}
}

func TestReferralHTTPImmediateWelcomePaginationAndIsolation(t *testing.T) {
	server, users := referralFixture(t)
	handler := server.Routes()
	token := func(account string) string { return issueTestBearer(t, server, account, time.Now().Add(time.Hour)) }
	request := func(account, method, path, body string, status int) map[string]any {
		t.Helper()
		bearer := ""
		if account != "" {
			bearer = token(account)
		}
		result := tokenJSONRequest(t, handler, method, path, bearer, []byte(body))
		if result.Code != status {
			t.Fatalf("%s %s: %d %s; want%d", method, path, result.Code, result.Body.String(), status)
		}
		if result.Header().Get("Cache-Control") != "private, no-store" {
			t.Fatal("private result cached")
		}
		var value map[string]any
		if err := json.Unmarshal(result.Body.Bytes(), &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	request("", "GET", "/api/v1/referrals/me", "", 401)
	me := request(users[0], "GET", "/api/v1/referrals/me", "", 200)
	code, ok := me["code"].(string)
	if !ok || len(code) != 32 {
		t.Fatalf("me=%v", me)
	}
	body := fmt.Sprintf(`{"code":%q,"request_id":"claim-request-1","source_app_id":"inbe"}`, code)
	claimed := request(users[1], "POST", "/api/v1/referrals/claim", body, 200)
	if claimed["welcome_units"] != float64(20000000) || claimed["status"] != "bound" || claimed["referrer_id"] != users[0] || referralBalance(t, server, users[1]) != 20000000 {
		t.Fatalf("claim=%v", claimed)
	}
	repeated := request(users[1], "POST", "/api/v1/referrals/claim", body, 200)
	if repeated["welcome_receipt_id"] != claimed["welcome_receipt_id"] || repeated["status"] != "already_bound" || referralBalance(t, server, users[1]) != 20000000 {
		t.Fatal("replay changed gift", repeated)
	}
	receipt := TokenLedger_ByID(server.Store.Database, context.Background(), claimed["welcome_receipt_id"].(string))
	if receipt.Error != nil || !TokenReceipt_ValidSignature(server.Cfg.WaoziIssuerPublicKey, receipt.Value) {
		t.Fatal("welcome unsigned", receipt)
	}
	request(users[0], "POST", "/api/v1/referrals/claim", body, 409)
	request(users[2], "POST", "/api/v1/referrals/claim", fmt.Sprintf(`{"code":%q,"request_id":"claim-request-2"}`, code), 200)
	page := request(users[0], "GET", "/api/v1/referrals/accepted?limit=1", "", 200)
	if len(page["accepted"].([]any)) != 1 || page["next_cursor"] == "" {
		t.Fatal("bad page", page)
	}
	next := request(users[0], "GET", "/api/v1/referrals/accepted?limit=1&cursor="+page["next_cursor"].(string), "", 200)
	if len(next["accepted"].([]any)) != 1 || next["next_cursor"] != "" {
		t.Fatal("bad next", next)
	}
	empty := request(users[1], "GET", "/api/v1/referrals/accepted", "", 200)
	if len(empty["accepted"].([]any)) != 0 {
		t.Fatal("another inviter list leaked", empty)
	}
	request(users[0], "GET", "/api/v1/referrals/accepted?cursor=-1", "", 400)
	request(users[2], "POST", "/api/v1/referrals/claim", fmt.Sprintf(`{"code":%q,"request_id":"claim-request-2","balance":999}`, code), 400)
	rotation := request(users[0], "POST", "/api/v1/referrals/code/rotate", `{"request_id":"rotation-request-1"}`, 200)
	if rotation["code"] == code {
		t.Fatal("code not rotated")
	}
	if request(users[0], "POST", "/api/v1/referrals/code/rotate", `{"request_id":"rotation-request-1"}`, 200)["code"] != rotation["code"] {
		t.Fatal("rotation replay changed")
	}
	server.Cfg.BaseURL = "https://private.waozi.xyz"
	if request(users[0], "GET", "/api/v1/referrals/me", "", 409)["error"] != "wrong_node" {
		t.Fatal("node authority not enforced")
	}
}

func TestReferralAtomicRollbackRaceAndRetainedBinding(t *testing.T) {
	server, users := referralFixture(t)
	db := server.Store.Database
	ctx := context.Background()
	code := referralCode(t, server, users[0])
	if _, err := db.Exec(`CREATE TRIGGER referral_failure BEFORE INSERT ON referral_claims BEGIN SELECT RAISE(ABORT,'injected claim failure'); END`); err != nil {
		t.Fatal(err)
	}
	failed := Referral_Claim(db, ctx, server.Cfg.WaoziIssuerPrivateKey, users[1], code, "rollback-claim", "inbe")
	if failed.Error == nil || referralBalance(t, server, users[1]) != 0 {
		t.Fatal("claim credit escaped rollback", failed)
	}
	if _, err := db.Exec("DROP TRIGGER referral_failure"); err != nil {
		t.Fatal(err)
	}
	other := referralCode(t, server, users[2])
	db.SetMaxOpenConns(4)
	var wg sync.WaitGroup
	results := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			candidate := code
			if i%2 == 1 {
				candidate = other
			}
			r := Referral_Claim(db, ctx, server.Cfg.WaoziIssuerPrivateKey, users[1], candidate, fmt.Sprintf("race-request-%02d", i), "")
			results <- r.Error
		}(i)
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if err.Error() != "already_bound" {
			t.Fatal(err)
		}
	}
	if successes == 0 || referralBalance(t, server, users[1]) != 20000000 {
		t.Fatal("race duplicated/lost welcome")
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM referral_claims WHERE account_id=?", users[1]).Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	if _, err := db.Exec("DELETE FROM server_users WHERE user_id_hash=?", users[1]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO server_users(user_id_hash,public_key) VALUES(?,?)", users[1], []byte{2}); err != nil {
		t.Fatal(err)
	}
	var acceptedCode string
	if err := db.QueryRow("SELECT code FROM referral_claims WHERE account_id=?", users[1]).Scan(&acceptedCode); err != nil {
		t.Fatal(err)
	}
	again := Referral_Claim(db, ctx, server.Cfg.WaoziIssuerPrivateKey, users[1], acceptedCode, "after-deletion", "")
	if again.Error != nil || referralBalance(t, server, users[1]) != 20000000 {
		t.Fatal("deletion reset welcome", again)
	}
}

func TestReferralPaidPurchasesPartialRefundBackfillAndDebt(t *testing.T) {
	server, users := referralFixture(t)
	db := server.Store.Database
	ctx := context.Background()
	signer := server.Cfg.WaoziIssuerPrivateKey
	credit := func(provider, id string, units int64) TokenReceipt {
		t.Helper()
		r := TokenLedger_CreditPayment(db, ctx, signer, provider, id, TokenEventInput{AccountID: users[1], AppID: "inbe", EventType: "credit", AmountDelta: units, SourceType: provider, SourceRef: id}, errTokenIssuerReadOnly)
		if r.Error != nil {
			t.Fatal(r.Error)
		}
		return r.Value
	}
	credit("monero", "before-claim", 100000000)
	claim := Referral_Claim(db, ctx, signer, users[1], referralCode(t, server, users[0]), "paid-claim-1", "")
	if claim.Error != nil {
		t.Fatal(claim.Error)
	}
	first := credit("monero", "paid-1", 100000019)
	credit("monero", "paid-2", 200000000)
	credit("gift", "not-paid", 800000000)
	// Simulate restart/outbox loss after durable receipt: backfill must recover.
	if _, err := db.Exec("DELETE FROM referral_outbox"); err != nil {
		t.Fatal(err)
	}
	referralSettle(t, server)
	referralSettle(t, server)
	if got := referralBalance(t, server, users[0]); got != 15000000 {
		t.Fatalf("paid commission=%d", got)
	}
	reverse := func(amount int64) {
		t.Helper()
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		r := TokenLedger_Insert(tx, ctx, signer, TokenEventInput{AccountID: users[1], AppID: "inbe", EventType: "debit", AmountDelta: -amount, SourceType: "monero", SourceRef: first.SourceRef}, errTokenIssuerReadOnly)
		if r.Error != nil {
			t.Fatal(r.Error)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	reverse(20000000)
	referralSettle(t, server)
	if got := referralBalance(t, server, users[0]); got != 14000000 {
		t.Fatalf("partial refund commission=%d", got)
	}
	spent := TokenLedger_Spend(db, ctx, signer, TokenEventInput{AccountID: users[0], AppID: "inbe", EventType: "debit", AmountDelta: -14000000, SourceType: "test_spend", SourceRef: "spent"}, "spend-all", errTokenIssuerReadOnly)
	if spent.Error != nil {
		t.Fatal(spent.Error)
	}
	reverse(80000019)
	referralSettle(t, server)
	me := Referral_Me(db, ctx, users[0])
	if me.Error != nil || me.PendingOffsetUnits != 4000000 || referralBalance(t, server, users[0]) != 0 {
		t.Fatal("debt not retained", me)
	}
	credit("monero", "paid-3", 100000000)
	referralSettle(t, server)
	me = Referral_Me(db, ctx, users[0])
	if me.Error != nil || me.PendingOffsetUnits != 0 || referralBalance(t, server, users[0]) != 1000000 {
		t.Fatal("debt not offset", me, referralBalance(t, server, users[0]))
	}
	if referralBalance(t, server, users[1]) < 20000000 {
		t.Fatal("welcome reversed")
	}
	if strings.Contains(fmt.Sprint(me), "not-paid") {
		t.Fatal("private purchases in summary")
	}
}

// Only this feature's exact new objects are excluded from the released schema
// oracle. All original table/index/trigger definitions and seeded rows remain
// compared; referral transactional constraints are exercised above.
func schemaReferralExtension(entry map[string]any) bool {
	name := entry["name"].(string)
	switch name {
	case "referral_state", "referral_codes", "referral_rotations", "referral_claims", "referral_outbox", "referral_monero_invoices", "referral_commissions":
		return entry["type"] == "table"
	case "referral_active_code", "referral_accepted_page", "referral_pending", "referral_earnings",
		"sqlite_autoindex_referral_codes_1", "sqlite_autoindex_referral_rotations_1", "sqlite_autoindex_referral_claims_1", "sqlite_autoindex_referral_claims_2", "sqlite_autoindex_referral_outbox_1", "sqlite_autoindex_referral_monero_invoices_1", "sqlite_autoindex_referral_commissions_1":
		return entry["type"] == "index"
	case "referral_paid_receipt", "referral_deposit_state", "referral_invoice_state":
		return entry["type"] == "trigger"
	}
	return false
}

func TestReferralGooglePackageAppMapping(t *testing.T) {
	clearConfigEnvironment(t)
	cfg := Config_Load()
	for name, app := range map[string]string{"xyz.waozi.inbe": "inbe", "xyz.waozi.shovey": "shovey", "xyz.waozi.wurm": "wurm"} {
		if got := Config_GoogleApp(cfg, name); got != app {
			t.Fatalf("package%s title%s want%s", name, got, app)
		}
	}
	if Config_GoogleApp(cfg, "attacker.package") != "" {
		t.Fatal("unknown package accepted")
	}
	t.Setenv("DAOCHI_GOOGLE_PACKAGE_APPS", "xyz.waozi.wurm=wurm,example.invalid=custom")
	cfg = Config_Load()
	if Config_GoogleApp(cfg, "example.invalid") != "custom" || cfg.GooglePackageApps["xyz.waozi.wurm"] != "wurm" {
		t.Fatal("operator title config ignored")
	}
}

func TestReferralVerifiedGoogleQuantityPartialRefundAndScope(t *testing.T) {
	server, users := referralFixture(t)
	ctx := context.Background()
	db := server.Store.Database
	fake, cfg, restore := googleTestConfig(t)
	defer restore()
	fake.setAccountBinding(googleAccountBinding(users[1]))
	fake.mu.Lock()
	fake.quantity = 3
	remaining := int64(3)
	fake.refundableQuantity = &remaining
	fake.mu.Unlock()
	server.Cfg.GoogleServiceAccountJSON = cfg.GoogleServiceAccountJSON
	server.Cfg.TokenProducts = map[string]TokenProduct{"waozi_tokens_small": {ProductID: "waozi_tokens_small", TokenUnits: 100000019}}
	code := referralCode(t, server, users[0])
	if r := Referral_Claim(db, ctx, server.Cfg.WaoziIssuerPrivateKey, users[1], code, "google-referral-claim", ""); r.Error != nil {
		t.Fatal(r.Error)
	}
	handler := server.Routes()
	bearer := issueTestBearer(t, server, users[1], time.Now().Add(time.Hour))
	body := `{"package_name":"net.waozi.inbe","product_id":"waozi_tokens_small","purchase_token":"quantity-token","app_id":"inbe"}`
	response := tokenJSONRequest(t, handler, "POST", "/api/v1/tokens/purchases/google/verify", bearer, []byte(body))
	if response.Code != 200 {
		t.Fatal(response.Code, response.Body.String())
	}
	if got := referralBalance(t, server, users[1]); got != 320000057 {
		t.Fatalf("verified quantity credit%d", got)
	}
	referralSettle(t, server)
	if got := referralBalance(t, server, users[0]); got != 15000002 {
		t.Fatalf("quantity commission%d", got)
	}
	partial := GoogleVoidedPurchase{PurchaseToken: "quantity-token", OrderID: fake.orderID, VoidedTimeMillis: 1770000000001, VoidedQuantity: 1}
	fake.mu.Lock()
	remaining = 2
	fake.voidedPurchases = []GoogleVoidedPurchase{partial}
	fake.mu.Unlock()
	for i := 0; i < 2; i++ {
		if r := GooglePlayReconciliation_ReconcileRecentRefunds(db, ctx, server.Cfg, "net.waozi.inbe", server.Cfg.WaoziIssuerPrivateKey, errTokenIssuerReadOnly); r.Error != nil {
			t.Fatal(r.Error)
		}
	}
	referralSettle(t, server)
	if got := referralBalance(t, server, users[0]); got != 10000001 {
		t.Fatalf("net floor partial%d", got)
	}
	if got := referralBalance(t, server, users[1]); got != 220000038 {
		t.Fatalf("partial purchase%d", got)
	}
	if pools := TokenAllocation_Balances(db, ctx, users[0], AssetID, "shovey"); pools.Error != nil || pools.Spendable != 0 {
		t.Fatal("commission crossed title", pools)
	}
	full := partial
	full.VoidedQuantity = 0
	full.VoidedTimeMillis++
	fake.mu.Lock()
	remaining = 0
	fake.voidedPurchases = []GoogleVoidedPurchase{full}
	fake.mu.Unlock()
	if r := GooglePlayReconciliation_ReconcileRecentRefunds(db, ctx, server.Cfg, "net.waozi.inbe", server.Cfg.WaoziIssuerPrivateKey, errTokenIssuerReadOnly); r.Error != nil {
		t.Fatal(r.Error)
	}
	referralSettle(t, server)
	if referralBalance(t, server, users[0]) != 0 || referralBalance(t, server, users[1]) != 20000000 {
		t.Fatal("refund changed welcome or retained commission")
	}
	forged := strings.Replace(body, `"app_id":"inbe"`, `"app_id":"shovey"`, 1)
	if response := tokenJSONRequest(t, handler, "POST", "/api/v1/tokens/purchases/google/verify", bearer, []byte(forged)); response.Code != 400 {
		t.Fatal("forged store app accepted", response.Code, response.Body.String())
	}
}

func TestReferralShoveyStoreCreditBuysOwnIslandAndLegacyPaymentRestores(t *testing.T) {
	server, users := referralFixture(t)
	db := server.Store.Database
	ctx := context.Background()
	signer := server.Cfg.WaoziIssuerPrivateKey
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := TokenAllocation_BindGoogleTx(tx, ctx, "shovey-island", users[0], "xyz.waozi.shovey", "shovey", 100000000); err != nil {
		t.Fatal(err)
	}
	paid := TokenLedger_CreditPaymentTx(tx, ctx, signer, "google_play", "shovey-island", TokenEventInput{AccountID: users[0], AppID: "shovey", EventType: "credit", AmountDelta: 100000000, SourceType: "google_play", SourceRef: "shovey-island"}, errTokenIssuerReadOnly)
	if paid.Error != nil {
		t.Fatal(paid.Error)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	result := Unlock_Confirmed(db, ctx, signer, users[0], "shovey.island", 2000000000, 0, 0, 85000000)
	if result.Error != nil || !result.Unlocked {
		t.Fatal("own title purchase failed", result)
	}
	// Reconstruct a released Entity-scoped signed unlock; restore without charge.
	credit := TokenLedger_CreditPayment(db, ctx, signer, "monero", "legacy-island-fixture", TokenEventInput{AccountID: users[1], EventType: "credit", AmountDelta: 100000000, SourceType: "monero", SourceRef: "legacy-island-fixture"}, errTokenIssuerReadOnly)
	if credit.Error != nil {
		t.Fatal(credit.Error)
	}
	legacy := TokenLedger_Spend(db, ctx, signer, TokenEventInput{AccountID: users[1], AppID: "entity", EventType: "debit", AmountDelta: -85000000, SourceType: "unlock", SourceRef: "shovey.island"}, "unlock:shovey.island", errTokenIssuerReadOnly)
	if legacy.Error != nil {
		t.Fatal(legacy.Error)
	}
	restored := Unlock_Confirmed(db, ctx, signer, users[1], "shovey.island", 2000000000, 0, 0, 85000000)
	if restored.Error != nil || restored.ReceiptId != legacy.Value.ReceiptID || referralBalance(t, server, users[1]) != 15000000 {
		t.Fatal("legacy payment charged twice", restored)
	}
}

func TestReferralMoneroInvoiceWalletConflictAndDoubleSpend(t *testing.T) {
	server, users := referralFixture(t)
	ctx := context.Background()
	db := server.Store.Database
	wallet := newFakeMoneroWalletRPC(t)
	server.Cfg.MoneroWalletRPCURL = wallet.URL
	server.Cfg.TokenDirectPurchasesEnabled = true
	server.Cfg.TokenProducts = map[string]TokenProduct{"waozi_tokens_small": {ProductID: "waozi_tokens_small", TokenUnits: 5000000, MoneroAtomicAmount: 1000000000000}}
	claim := Referral_Claim(db, ctx, server.Cfg.WaoziIssuerPrivateKey, users[1], referralCode(t, server, users[0]), "monero-invoice-claim", "")
	if claim.Error != nil {
		t.Fatal(claim.Error)
	}
	handler := server.Routes()
	bearer := issueTestBearer(t, server, users[1], time.Now().Add(time.Hour))
	invoice := createTestMoneroInvoice(t, handler, bearer, []byte(`{"app_id":"inbe","product_id":"waozi_tokens_small"}`))
	transfer := moneroTransfer{TxID: "referral-invoice-paid", Amount: invoice.AtomicAmount, Confirmations: 10, Major: 0, Minor: invoice.AddressIndex, Height: 900}
	wallet.setTransfer(transfer)
	settled := MoneroInvoices_Settle(server.monero(), ctx, users[1], invoice)
	if settled.Error != nil {
		t.Fatal(settled.Error)
	}
	referralSettle(t, server)
	if referralBalance(t, server, users[0]) != 250000 {
		t.Fatal("invoice commission absent")
	}
	wallet.setTransfer()
	if err := ReferralMonero_Reconcile(db, ctx, server.Cfg); err != nil {
		t.Fatal(err)
	}
	referralSettle(t, server)
	if referralBalance(t, server, users[0]) != 250000 || referralBalance(t, server, users[1]) != 25000000 {
		t.Fatal("wallet omission reversed money")
	}
	transfer.DoubleSpend = true
	wallet.setTransfer(transfer)
	if err := ReferralMonero_Reconcile(db, ctx, server.Cfg); err != nil {
		t.Fatal(err)
	}
	referralSettle(t, server)
	if referralBalance(t, server, users[0]) != 0 || referralBalance(t, server, users[1]) != 20000000 {
		t.Fatal("double spend commission/principal not reversed independently of welcome")
	}
	if err := ReferralMonero_Reconcile(db, ctx, server.Cfg); err != nil {
		t.Fatal(err)
	}
	referralSettle(t, server)
	if referralBalance(t, server, users[1]) != 20000000 {
		t.Fatal("reorg replay charged twice")
	}
}

func TestReferralFutureRewardOffsetsMoreThanOneHundredDebts(t *testing.T) {
	server, users := referralFixture(t)
	ctx := context.Background()
	db := server.Store.Database
	signer := server.Cfg.WaoziIssuerPrivateKey
	if result := Referral_Claim(db, ctx, signer, users[1], referralCode(t, server, users[0]), "many-debts-claim", ""); result.Error != nil {
		t.Fatal(result.Error)
	}
	originals := make([]TokenReceipt, 0, 101)
	for i := 0; i < 101; i++ {
		key := fmt.Sprintf("debt-original-%03d", i)
		result := TokenLedger_CreditPayment(db, ctx, signer, "monero", key, TokenEventInput{AccountID: users[1], AppID: "inbe", EventType: "credit", AmountDelta: 20, SourceType: "monero", SourceRef: key}, errTokenIssuerReadOnly)
		if result.Error != nil {
			t.Fatal(result.Error)
		}
		originals = append(originals, result.Value)
	}
	for i := 0; i < 3; i++ {
		referralSettle(t, server)
	}
	if referralBalance(t, server, users[0]) != 101 {
		t.Fatal("original rewards absent")
	}
	spent := TokenLedger_Spend(db, ctx, signer, TokenEventInput{AccountID: users[0], AppID: "inbe", EventType: "debit", AmountDelta: -101, SourceType: "spend", SourceRef: "spent-before-refunds"}, "many-debt-spend", errTokenIssuerReadOnly)
	if spent.Error != nil {
		t.Fatal(spent.Error)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, original := range originals {
		refund := TokenLedger_Insert(tx, ctx, signer, TokenEventInput{AccountID: users[1], AppID: "inbe", EventType: "debit", AmountDelta: -20, SourceType: "monero", SourceRef: original.SourceRef}, errTokenIssuerReadOnly)
		if refund.Error != nil {
			t.Fatal(refund.Error)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		referralSettle(t, server)
	}
	if me := Referral_Me(db, ctx, users[0]); me.Error != nil || me.PendingOffsetUnits != 101 {
		t.Fatal("101 debts not retained", me)
	}
	later := TokenLedger_CreditPayment(db, ctx, signer, "monero", "later-large-commission", TokenEventInput{AccountID: users[1], AppID: "inbe", EventType: "credit", AmountDelta: 2020, SourceType: "monero", SourceRef: "later-large-commission"}, errTokenIssuerReadOnly)
	if later.Error != nil {
		t.Fatal(later.Error)
	}
	referralSettle(t, server)
	me := Referral_Me(db, ctx, users[0])
	if me.Error != nil || me.PendingOffsetUnits != 0 || referralBalance(t, server, users[0]) != 0 {
		t.Fatal("new earnings escaped second debt page", me, referralBalance(t, server, users[0]))
	}
	var offsets int
	if err := db.QueryRow("SELECT COUNT(*) FROM token_referral_offsets WHERE credit_receipt_id IN (SELECT receipt_id FROM token_ledger WHERE source_type='referral_commission' AND source_ref=?)", later.Value.ReceiptID).Scan(&offsets); err != nil {
		t.Fatal(err)
	}
	if offsets != 101 {
		t.Fatalf("only%d debts have explicit offset audit", offsets)
	}
}

func TestReferralSharedMoneroDebtOffsetsAcrossAuditAppsAndPurchasePaths(t *testing.T) {
	server, users := referralFixture(t)
	db, ctx := server.Store.Database, context.Background()
	signer := server.Cfg.WaoziIssuerPrivateKey
	if r := Referral_Claim(db, ctx, signer, users[1], referralCode(t, server, users[0]), "shared-debt-claim", ""); r.Error != nil {
		t.Fatal(r.Error)
	}
	old := TokenLedger_CreditPayment(db, ctx, signer, "monero", "shared-invoice", TokenEventInput{AccountID: users[1], AppID: "inbe", EventType: "credit", AmountDelta: 100000000, SourceType: "monero", SourceRef: "shared-invoice"}, errTokenIssuerReadOnly)
	if old.Error != nil {
		t.Fatal(old.Error)
	}
	referralSettle(t, server)
	spent := TokenLedger_Spend(db, ctx, signer, TokenEventInput{AccountID: users[0], AppID: "inbe", EventType: "debit", AmountDelta: -5000000, SourceType: "test_spend", SourceRef: "old-shared-spent"}, "old-shared-spent", errTokenIssuerReadOnly)
	if spent.Error != nil {
		t.Fatal(spent.Error)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	refund := TokenLedger_Insert(tx, ctx, signer, TokenEventInput{AccountID: users[1], AppID: "inbe", EventType: "debit", AmountDelta: -100000000, SourceType: "monero", SourceRef: "shared-invoice"}, errTokenIssuerReadOnly)
	if refund.Error != nil {
		t.Fatal(refund.Error)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	referralSettle(t, server)
	if got := Referral_Me(db, ctx, users[0]); got.Error != nil || got.PendingOffsetUnits != 5000000 {
		t.Fatal(got)
	}
	next := TokenLedger_CreditPayment(db, ctx, signer, "monero_account", "shared-account-deposit", TokenEventInput{AccountID: users[1], AppID: "wurm", EventType: "credit", AmountDelta: 120000000, SourceType: "monero_account", SourceRef: "shared-account-deposit"}, errTokenIssuerReadOnly)
	if next.Error != nil {
		t.Fatal(next.Error)
	}
	referralSettle(t, server)
	if got := Referral_Me(db, ctx, users[0]); got.Error != nil || got.PendingOffsetUnits != 0 || referralBalance(t, server, users[0]) != 1000000 {
		t.Fatal("shared debt stranded by audit attribution", got)
	}
	if referralBalance(t, server, users[1]) != 140000000 {
		t.Fatal("offset touched purchaser welcome or paid funds")
	}
}

func TestReferralUnregisteredHostAttributionDoesNotGateWelcomeOrGrantPolicy(t *testing.T) {
	type referralClaimReply struct {
		Status           string `json:"status"`
		WelcomeUnits     int64  `json:"welcome_units"`
		WelcomeReceiptID string `json:"welcome_receipt_id"`
	}
	server, users := referralFixture(t)
	db, ctx := server.Store.Database, context.Background()
	handler := server.Routes()
	bearer := issueTestBearer(t, server, users[1], time.Now().Add(time.Hour))
	code := referralCode(t, server, users[0])
	const host = "future-host.unregistered"
	var registrations, permissions int
	if err := db.QueryRow("SELECT COUNT(*) FROM server_apps").Scan(&registrations); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM token_app_permissions").Scan(&permissions); err != nil {
		t.Fatal(err)
	}
	claim := func(hint string, status int) referralClaimReply {
		t.Helper()
		body := fmt.Sprintf(`{"code":%q,"request_id":"unregistered-host-claim","source_app_id":%q}`, code, hint)
		response := tokenJSONRequest(t, handler, "POST", "/api/v1/referrals/claim", bearer, []byte(body))
		if response.Code != status {
			t.Fatalf("claim with hint%q: %d %s", hint, response.Code, response.Body.String())
		}
		var value referralClaimReply
		if status == 200 {
			if err := json.Unmarshal(response.Body.Bytes(), &value); err != nil {
				t.Fatal(err)
			}
		}
		return value
	}
	claim("invalid/host", 400)
	claim(strings.Repeat("a", 65), 400)
	if referralBalance(t, server, users[1]) != 0 {
		t.Fatal("invalid attribution credited welcome")
	}
	first := claim(host, 200)
	if first.Status != "bound" || first.WelcomeUnits != 20000000 || first.WelcomeReceiptID == "" {
		t.Fatal(first)
	}
	replay := claim("another-unregistered-host", 200)
	if replay.Status != "already_bound" || replay.WelcomeReceiptID != first.WelcomeReceiptID || referralBalance(t, server, users[1]) != 20000000 {
		t.Fatal("hint replay changed welcome", replay)
	}
	var actual string
	if err := db.QueryRow("SELECT source_app_id FROM referral_claims WHERE account_id=?", users[1]).Scan(&actual); err != nil || actual != host {
		t.Fatal("audit hint changed or rewritten", actual, err)
	}
	var afterRegistrations, afterPermissions int
	if err := db.QueryRow("SELECT COUNT(*) FROM server_apps").Scan(&afterRegistrations); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM token_app_permissions").Scan(&afterPermissions); err != nil {
		t.Fatal(err)
	}
	if afterRegistrations != registrations || afterPermissions != permissions {
		t.Fatal("untrusted hint granted registry/policy authority")
	}
	receipt := TokenLedger_ByID(db, ctx, first.WelcomeReceiptID)
	if receipt.Error != nil || receipt.Value.AppID != "" {
		t.Fatal("hint changed shared welcome source", receipt)
	}
	pools := TokenAllocation_Balances(db, ctx, users[1], AssetID, host)
	if pools.Error != nil || pools.Shared != 20000000 || pools.Scoped != 0 {
		t.Fatal("welcome became a scoped purchase", pools)
	}
	spendBody := fmt.Sprintf(`{"app_id":%q,"action":"host.purchase","amount":1,"idempotency_key":"untrusted-hint-spend"}`, host)
	response := tokenJSONRequest(t, handler, "POST", "/api/v1/tokens/spend", bearer, []byte(spendBody))
	if response.Code != 400 || !strings.Contains(response.Body.String(), "unknown app_id") || referralBalance(t, server, users[1]) != 20000000 {
		t.Fatal("hint bypassed real app registry", response.Code, response.Body.String())
	}
}
