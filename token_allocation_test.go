package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

func allocationInput(account, app, source, reference string, amount int64) TokenEventInput {
	event := "credit"
	if amount < 0 {
		event = "debit"
	}
	return TokenEventInput{AccountID: account, AppID: app, EventType: event,
		AmountDelta: amount, SourceType: source, SourceRef: reference}
}

func allocationInsert(store *Store, input TokenEventInput) (TokenReceipt, error) {
	tx, err := store.Database.BeginTx(context.Background(), nil)
	if err != nil {
		return TokenReceipt{}, err
	}
	defer tx.Rollback()
	result := TokenLedger_Insert(tx, context.Background(), tokenLedgerSigner(), input, errTokenIssuerReadOnly)
	if result.Error != nil {
		return TokenReceipt{}, result.Error
	}
	return result.Value, tx.Commit()
}

func allocationCredit(t *testing.T, store *Store, account, app, provider, payment string, units int64) TokenReceipt {
	t.Helper()
	tx, err := store.Database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if provider == "google_play" {
		if err := TokenAllocation_BindGoogleTx(tx, context.Background(), payment, account, "xyz.waozi."+app, app, units); err != nil {
			t.Fatal(err)
		}
	}
	result := TokenLedger_CreditPaymentTx(tx, context.Background(), tokenLedgerSigner(), provider, payment,
		allocationInput(account, app, provider, payment, units), errTokenIssuerReadOnly)
	if result.Error != nil {
		t.Fatal(result.Error)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return result.Value
}

func allocationSpend(t *testing.T, store *Store, account, app, source, key string, units int64, allowed bool) TokenReceipt {
	t.Helper()
	result := TokenLedger_Spend(store.Database, context.Background(), tokenLedgerSigner(),
		allocationInput(account, app, source, key, -units), key, errTokenIssuerReadOnly)
	if (result.Error == nil) != allowed {
		t.Fatalf("%s %s spend %d: allowed=%v, result=%+v", app, source, units, allowed, result)
	}
	return result.Value
}

func allocationBalances(t *testing.T, store *Store, account, app string, total, shared, scoped, spendable int64) {
	t.Helper()
	got := TokenAllocation_Balances(store.Database, context.Background(), account, AssetID, app)
	if got.Error != nil || got.Balance != total || got.Shared != shared || got.Scoped != scoped || got.Spendable != spendable {
		t.Fatalf("%s pools = %+v, want total/shared/scoped/spendable=%d/%d/%d/%d", app, got, total, shared, scoped, spendable)
	}
}

func allocationCount(t *testing.T, store *Store, table string) int {
	t.Helper()
	var count int
	if err := store.Database.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestTokenAllocationTitleSpendAndGiftIsolation(t *testing.T) {
	store := tokenLedgerStore(t)
	account := strings.Repeat("a", 64)
	paid := allocationCredit(t, store, account, "inbe", "google_play", "paid-a", 100)
	allocationBalances(t, store, account, "inbe", 100, 0, 100, 100)
	allocationBalances(t, store, account, "shovey", 100, 0, 100, 0)
	allocationBalances(t, store, account, "", 100, 0, 100, 0)
	for _, scenario := range []struct{ app, source string }{
		{"shovey", "spend"}, {"", "spend"}, {"inbe", "gift"}, {"inbe", "conversion"}, {"inbe", "storage"},
	} {
		allocationSpend(t, store, account, scenario.app, scenario.source, scenario.app+scenario.source, 1, false)
	}
	if _, err := allocationInsert(store, allocationInput(account, "shovey", "spend", "direct", -1)); err == nil {
		t.Fatal("direct Insert bypassed universal enforcement")
	}
	if allocationCount(t, store, "token_ledger") != 1 {
		t.Fatal("rejected spends left signed receipts")
	}
	spent := allocationSpend(t, store, account, "inbe", "spend", "matching", 40, true)
	allocationSpend(t, store, account, "inbe", "spend", "matching", 40, true)
	if allocationCount(t, store, "token_allocation_debits") != 1 {
		t.Fatal("spend retry consumed an allocation twice")
	}
	tx, err := store.Database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for _, receipt := range []TokenReceipt{paid, spent, paid, spent} {
		if err := TokenAllocation_RecordTx(tx, context.Background(), receipt); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	allocationBalances(t, store, account, "inbe", 60, 0, 60, 60)
	welcome, err := allocationInsert(store, allocationInput(account, "", "referral_welcome", account, 20_000_000))
	if err != nil || welcome.AmountDelta != 20_000_000 {
		t.Fatalf("immediate promotional welcome: %+v/%v", welcome, err)
	}
	allocationSpend(t, store, account, "shovey", "gift", "shared-gift", 20_000_000, true)
	allocationBalances(t, store, account, "inbe", 60, 0, 60, 60)
	allocationSpend(t, store, account, "inbe", "gift", "gift-bypass", 1, false)
	if _, err := allocationInsert(store, allocationInput(account, "", "rescale", "ratio", 60)); err == nil {
		t.Fatal("global rescale converted restricted balance to shared credit")
	}
}

func TestTokenAllocationRefundDebtStaysWithTitle(t *testing.T) {
	store := tokenLedgerStore(t)
	account := strings.Repeat("a", 64)
	allocationCredit(t, store, account, "inbe", "google_play", "title-a", 100)
	allocationCredit(t, store, account, "shovey", "google_play", "title-b", 40)
	allocationCredit(t, store, account, "", "admin", "shared", 30)
	allocationSpend(t, store, account, "inbe", "spend", "use-title-a", 100, true)
	refund, err := allocationInsert(store, allocationInput(account, "inbe", "google_play", "title-a", -100))
	if err != nil {
		t.Fatal(err)
	}
	allocationBalances(t, store, account, "inbe", -30, 30, -60, 30)
	allocationBalances(t, store, account, "shovey", -30, 30, -60, 70)
	allocationSpend(t, store, account, "", "gift", "gift-after-chargeback", 10, true)
	allocationSpend(t, store, account, "shovey", "spend", "valid-other-title", 40, true)
	allocationBalances(t, store, account, "shovey", -80, 20, -100, 20)
	allocationSpend(t, store, account, "inbe", "spend", "debt-no-unlock", 21, false)
	allocationSpend(t, store, account, "", "gift", "rest-shared", 20, true)
	allocationBalances(t, store, account, "inbe", -100, 0, -100, 0)
	tx, err := store.Database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := TokenAllocation_RecordTx(tx, context.Background(), refund); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := allocationInsert(store, allocationInput(account, "inbe", "google_play", "title-a", -1)); err == nil {
		t.Fatal("refund exceeded original purchase")
	}
	allocationBalances(t, store, account, "shovey", -100, 0, -100, 0)
}

func TestTokenAllocationPartialRefundAndBindingValidation(t *testing.T) {
	store := tokenLedgerStore(t)
	account := strings.Repeat("a", 64)
	unbound := TokenLedger_CreditPayment(store.Database, context.Background(), tokenLedgerSigner(), "google_play", "unverified",
		allocationInput(account, "inbe", "google_play", "unverified", 100), errTokenIssuerReadOnly)
	if unbound.Error == nil || allocationCount(t, store, "token_ledger") != 0 {
		t.Fatal("new Google credit accepted without verified origin")
	}
	allocationCredit(t, store, account, "inbe", "google_play", "partial", 100)
	if _, err := allocationInsert(store, allocationInput(account, "inbe", "google_play", "partial", 100)); err == nil {
		t.Fatal("direct receipt duplicated the verified paid credit")
	}
	tx, err := store.Database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := TokenAllocation_BindGoogleTx(tx, context.Background(), "partial", account, "xyz.waozi.inbe", "shovey", 100); err == nil {
		t.Fatal("existing verified origin changed title")
	}
	_ = tx.Rollback()
	if _, err := allocationInsert(store, allocationInput(account, "shovey", "google_play", "partial", -25)); err == nil {
		t.Fatal("refund changed source title")
	}
	for _, units := range []int64{25, 75} {
		if _, err := allocationInsert(store, allocationInput(account, "inbe", "google_play", "partial", -units)); err != nil {
			t.Fatal(err)
		}
	}
	allocationBalances(t, store, account, "inbe", 0, 0, 0, 0)
	if _, err := allocationInsert(store, allocationInput(account, "inbe", "google_play", "partial", -1)); err == nil {
		t.Fatal("cumulative partial refunds exceeded paid amount")
	}
}

func TestTokenAllocationReferralUsesVerifiedOriginalSource(t *testing.T) {
	for _, provider := range []string{"google_play", "monero"} {
		t.Run(provider, func(t *testing.T) {
			store := tokenLedgerStore(t)
			buyer, inviter := strings.Repeat("a", 64), strings.Repeat("b", 64)
			paid := allocationCredit(t, store, buyer, "inbe", provider, "original", 1000)
			reward := allocationInput(inviter, "inbe", "referral_commission", paid.ReceiptID, 50)
			if _, err := allocationInsert(store, reward); err != nil {
				t.Fatal(err)
			}
			if provider == "google_play" {
				allocationBalances(t, store, inviter, "shovey", 50, 0, 50, 0)
				allocationSpend(t, store, inviter, "inbe", "gift", "reward-gift", 1, false)
			} else {
				allocationBalances(t, store, inviter, "shovey", 50, 50, 0, 50)
			}
			allocationSpend(t, store, inviter, "inbe", "spend", "use-reward", 30, true)
			allocationCredit(t, store, inviter, "", "admin", "unrelated", 90)
			tx, err := store.Database.Begin()
			if err != nil {
				t.Fatal(err)
			}
			available := TokenLedger_AvailableTx(tx, context.Background(), inviter, "inbe", "referral_reversal", paid.ReceiptID)
			_ = tx.Rollback()
			if available.Error != nil || available.Value != 20 {
				t.Fatalf("source reversal availability=%+v, want20", available)
			}
			if _, err := allocationInsert(store, allocationInput(inviter, "inbe", "referral_reversal", paid.ReceiptID, -21)); err == nil {
				t.Fatal("reversal consumed unrelated shared credit")
			}
			if _, err := allocationInsert(store, allocationInput(inviter, "shovey", "referral_reversal", paid.ReceiptID, -1)); err == nil {
				t.Fatal("reversal changed original purchase title")
			}
			if _, err := allocationInsert(store, allocationInput(inviter, "inbe", "referral_reversal", paid.ReceiptID, -20)); err != nil {
				t.Fatal(err)
			}
			allocationBalances(t, store, inviter, "inbe", 90, 90, 0, 90)
			reward.AppID = "shovey"
			if _, err := allocationInsert(store, reward); err == nil {
				t.Fatal("commission changed original purchase title")
			}
			reward.AppID, reward.SourceRef = "inbe", "not-a-paid-receipt"
			if _, err := allocationInsert(store, reward); err == nil {
				t.Fatal("commission accepted unverified original receipt")
			}
		})
	}
}

func TestTokenAllocationHistoricalMigrationPreservesSignedBalance(t *testing.T) {
	store := tokenLedgerStore(t)
	account := strings.Repeat("a", 64)
	input := allocationInput(account, "inbe", "google_play", "legacy-paid", 100)
	old, _, err := store.baselineCreditTokenPayment(context.Background(), tokenLedgerSigner(), "google_play", "legacy-paid", baselineTokenEventInput(input))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Database.Exec("DROP TABLE token_allocation_migration"); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := store.Database.Exec(TokenAllocation_SchemaSQL()); err != nil {
			t.Fatal(err)
		}
	}
	retry := TokenLedger_CreditPayment(store.Database, context.Background(), tokenLedgerSigner(), "google_play", "legacy-paid", input, errTokenIssuerReadOnly)
	if retry.Error != nil || retry.Created || !reflect.DeepEqual(old, retry.Value) {
		t.Fatalf("historical provider retry changed signed receipt: %+v/%+v", old, retry)
	}
	tx, err := store.Database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := TokenAllocation_RecordTx(tx, context.Background(), old); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	allocationBalances(t, store, account, "shovey", 100, 100, 0, 100)
	allocationSpend(t, store, account, "shovey", "gift", "legacy-gift", 30, true)
	allocationCredit(t, store, account, "inbe", "google_play", "new-paid", 50)
	allocationBalances(t, store, account, "shovey", 120, 70, 50, 70)
	if _, err := store.Database.Exec(TokenAllocation_SchemaSQL()); err != nil {
		t.Fatal(err)
	}
	allocationBalances(t, store, account, "inbe", 120, 70, 50, 120)
	loaded := TokenLedger_ByID(store.Database, context.Background(), old.ReceiptID)
	if loaded.Error != nil || !reflect.DeepEqual(old, loaded.Value) {
		t.Fatal("migration rewrote signed history")
	}
}

func TestTokenAllocationAtomicRollback(t *testing.T) {
	for _, failedTable := range []string{"token_allocations", "token_processed_payments", "token_allocation_debits", "token_spend_nonces"} {
		t.Run(failedTable, func(t *testing.T) {
			store := tokenLedgerStore(t)
			account := strings.Repeat("a", 64)
			debit := failedTable == "token_allocation_debits" || failedTable == "token_spend_nonces"
			if debit {
				allocationCredit(t, store, account, "inbe", "google_play", "seed", 100)
			}
			before := allocationCount(t, store, "token_ledger")
			trigger := fmt.Sprintf("CREATE TRIGGER fail_allocation BEFORE INSERT ON %s BEGIN SELECT RAISE(ABORT,'injected allocation failure'); END", failedTable)
			if _, err := store.Database.Exec(trigger); err != nil {
				t.Fatal(err)
			}
			if debit {
				allocationSpend(t, store, account, "inbe", "spend", "rollback", 40, false)
				allocationBalances(t, store, account, "inbe", 100, 0, 100, 100)
			} else {
				got := TokenLedger_CreditPayment(store.Database, context.Background(), tokenLedgerSigner(), "admin", "rollback",
					allocationInput(account, "", "admin", "rollback", 100), errTokenIssuerReadOnly)
				if got.Error == nil {
					t.Fatal("injected failure committed")
				}
			}
			if allocationCount(t, store, "token_ledger") != before {
				t.Fatal("partial signed history survived allocation failure")
			}
			if _, err := store.Database.Exec("DROP TRIGGER fail_allocation"); err != nil {
				t.Fatal(err)
			}
			if debit {
				allocationSpend(t, store, account, "inbe", "spend", "rollback", 40, true)
			} else {
				allocationCredit(t, store, account, "", "admin", "rollback", 100)
			}
		})
	}
	store := tokenLedgerStore(t)
	tx, err := store.Database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	bad := TokenLedger_Insert(tx, context.Background(), tokenLedgerSigner(),
		allocationInput(strings.Repeat("a", 64), "inbe", "spend", "no-funds", -1), errTokenIssuerReadOnly)
	if bad.Error == nil || !errors.Is(tx.Commit(), sql.ErrTxDone) {
		t.Fatal("failed allocation allowed caller to commit signed debit")
	}
	if _, err := allocationInsert(store, allocationInput(strings.Repeat("a", 64), "inbe", "spend", "overflow", math.MinInt64)); err == nil {
		t.Fatal("minimum integer bypassed debit bound")
	}
}

func TestTokenAllocationVerifiedGoogleLifecycle(t *testing.T) {
	store := googleLifecycleStore(t)
	fake, cfg, restore := googleTestConfig(t)
	defer restore()
	account := googlePurchaseAccountID(0)
	fake.setAccountBinding(googleAccountBinding(account))
	request := googlePurchaseRequest("allocated-lifecycle")
	inspected := inspectGooglePurchase(t, cfg, request)
	paid := processGooglePurchase(t, store, cfg, inspected, account)
	if paid.Error != nil {
		t.Fatal(paid.Error)
	}
	allocationBalances(t, store, account, "inbe", 100, 0, 100, 100)
	allocationSpend(t, store, account, "shovey", "spend", "cross-title", 1, false)
	retry := processGooglePurchase(t, store, cfg, inspected, account)
	if retry.Error != nil || retry.Receipt.ReceiptID != paid.Receipt.ReceiptID || allocationCount(t, store, "token_allocations") != 1 {
		t.Fatalf("Google lifecycle retry duplicated allocation: %+v", retry)
	}
	allocationSpend(t, store, account, "inbe", "spend", "use-before-void", 60, true)
	voided := GoogleVoidedPurchase{PurchaseToken: request.PurchaseToken, OrderID: inspected.OrderID, VoidedTimeMillis: 1770000000000}
	for attempt := 0; attempt < 2; attempt++ {
		if err := GooglePlayReconciliation_CompensateVoided(store.Database, context.Background(), voided, tokenLedgerSigner(), errTokenIssuerReadOnly); err != nil {
			t.Fatal(err)
		}
	}
	allocationBalances(t, store, account, "inbe", -60, 0, -60, 0)
}

func TestTokenAllocationOverflowRollsBack(t *testing.T) {
	store := tokenLedgerStore(t)
	account := strings.Repeat("a", 64)
	allocationCredit(t, store, account, "", "admin", "maximum", math.MaxInt64)
	if _, err := allocationInsert(store, allocationInput(account, "", "admin", "overflow", 1)); err == nil {
		t.Fatal("credit overflow committed")
	}
	allocationBalances(t, store, account, "", math.MaxInt64, math.MaxInt64, 0, math.MaxInt64)
	if allocationCount(t, store, "token_ledger") != 1 || allocationCount(t, store, "token_allocations") != 1 {
		t.Fatal("overflow left partial ledger or allocation state")
	}
}

func TestTokenAllocationBalanceHTTPMetadata(t *testing.T) {
	server, users := socialHTTPFixture(t)
	account := users[0]
	allocationCredit(t, server.Store, account, "inbe", "google_play", "metadata-paid", 100)
	allocationCredit(t, server.Store, account, "", "admin", "metadata-shared", 20)
	token := issueTestBearer(t, server, account, time.Now().Add(time.Hour))
	handler := server.Routes()
	for _, scenario := range []struct {
		query     string
		balance   int64
		spendable int64
	}{
		{"", 120, 20},
		{"?app_id=inbe", 100, 120},
		{"?app_id=shovey", 0, 20},
	} {
		response := tokenJSONRequest(t, handler, http.MethodGet, "/api/v1/tokens/balance"+scenario.query, token, nil)
		if response.Code != http.StatusOK {
			t.Fatalf("balance HTTP%s: %d %s", scenario.query, response.Code, response.Body.String())
		}
		var value map[string]json.RawMessage
		if err := json.Unmarshal(response.Body.Bytes(), &value); err != nil {
			t.Fatal(err)
		}
		for field, want := range map[string]int64{
			"balance": scenario.balance, "shared_balance": 20,
			"scoped_balance": 100, "spendable_balance": scenario.spendable,
		} {
			var got int64
			if err := json.Unmarshal(value[field], &got); err != nil || got != want {
				t.Fatalf("%s %s=%s, want%d (error%v)", scenario.query, field, value[field], want, err)
			}
		}
	}
}

func TestTokenAllocationExplicitFutureReferralOffset(t *testing.T) {
	store := tokenLedgerStore(t)
	buyer, inviter := strings.Repeat("a", 64), strings.Repeat("b", 64)
	oldPaid := allocationCredit(t, store, buyer, "inbe", "google_play", "old-paid", 1000)
	oldReward, err := allocationInsert(store, allocationInput(inviter, "inbe", "referral_commission", oldPaid.ReceiptID, 50))
	if err != nil {
		t.Fatal(err)
	}
	allocationSpend(t, store, inviter, "inbe", "spend", "spent-old-reward", 50, true)
	unrelated := allocationCredit(t, store, inviter, "", "admin", "unrelated-shared", 90)
	otherTitlePaid := allocationCredit(t, store, buyer, "shovey", "google_play", "other-title", 1000)
	otherReward, err := allocationInsert(store, allocationInput(inviter, "shovey", "referral_commission", otherTitlePaid.ReceiptID, 50))
	if err != nil {
		t.Fatal(err)
	}
	otherProviderPaid := allocationCredit(t, store, buyer, "inbe", "monero", "other-provider", 1000)
	otherProviderReward, err := allocationInsert(store, allocationInput(inviter, "inbe", "referral_commission", otherProviderPaid.ReceiptID, 50))
	if err != nil {
		t.Fatal(err)
	}
	newPaid := allocationCredit(t, store, buyer, "inbe", "google_play", "future-paid", 1000)
	newReward, err := allocationInsert(store, allocationInput(inviter, "inbe", "referral_commission", newPaid.ReceiptID, 50))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := store.Database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, excluded := range []TokenReceipt{unrelated, otherReward, otherProviderReward, oldReward} {
		got := TokenAllocation_AuthorizeReferralOffsetTx(tx, context.Background(), inviter, oldPaid.ReceiptID, excluded.ReceiptID, 40)
		if got.Error != nil || got.Value != 0 {
			t.Fatalf("unrelated/prior commission authorized for offset: %+v/%+v", excluded, got)
		}
	}
	for attempt := 0; attempt < 2; attempt++ {
		got := TokenAllocation_AuthorizeReferralOffsetTx(tx, context.Background(), inviter, oldPaid.ReceiptID, newReward.ReceiptID, 40)
		if got.Error != nil || got.Value != 40 {
			t.Fatalf("bounded idempotent future offset: %+v", got)
		}
	}
	reversal := TokenLedger_Insert(tx, context.Background(), tokenLedgerSigner(),
		allocationInput(inviter, "inbe", "referral_reversal", oldPaid.ReceiptID, -40), errTokenIssuerReadOnly)
	if reversal.Error != nil {
		t.Fatal(reversal.Error)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	allocationBalances(t, store, inviter, "inbe", 200, 140, 60, 150)
	allocationBalances(t, store, inviter, "shovey", 200, 140, 60, 190)
	var consumed int64
	if err := store.Database.QueryRow("SELECT units FROM token_allocation_debits WHERE debit_receipt_id=? AND credit_receipt_id=?",
		reversal.Value.ReceiptID, newReward.ReceiptID).Scan(&consumed); err != nil || consumed != 40 {
		t.Fatalf("explicit offset audit=%d/%v", consumed, err)
	}
	if _, err := allocationInsert(store, allocationInput(inviter, "inbe", "referral_reversal", oldPaid.ReceiptID, -1)); err == nil {
		t.Fatal("consumed authorization reused unrelated remaining funds")
	}
}

func TestTokenAllocationGlobalStorageAndTitleUnlock(t *testing.T) {
	server, users := socialHTTPFixture(t)
	store, account := server.Store, users[0]
	allocationCredit(t, store, account, "inbe", "google_play", "title-unlock", 200*UnitsPerDew)
	now := time.Now().Unix()
	blocked := StoragePlan_Purchase(store.Database, context.Background(), tokenLedgerSigner(),
		account, "1gb", "monthly", "storage-pool", now, testFreeBytes)
	if blocked.Error == nil || allocationCount(t, store, "server_storage_purchases") != 0 {
		t.Fatal("title-scoped credit bought global storage")
	}
	unlocked := Unlock_Unlock(store.Database, context.Background(), tokenLedgerSigner(), account, TaiChi, now, 0)
	if unlocked.Error != nil || !unlocked.Unlocked || unlocked.PriceUnits <= 0 {
		t.Fatalf("matching title unlock rejected: %+v", unlocked)
	}
	price := StoragePlan_Price("1gb", "monthly")
	if _, err := allocationInsert(store, allocationInput(account, "", "referral_welcome", account, price)); err != nil {
		t.Fatal(err)
	}
	paid := StoragePlan_Purchase(store.Database, context.Background(), tokenLedgerSigner(),
		account, "1gb", "monthly", "storage-pool", now, testFreeBytes)
	if paid.Error != nil || paid.LimitBytes != PaidBytes {
		t.Fatalf("shared promotional credit could not buy storage: %+v", paid)
	}
	remaining := 200*UnitsPerDew - unlocked.PriceUnits
	allocationBalances(t, store, account, "inbe", remaining, 0, remaining, remaining)
}
