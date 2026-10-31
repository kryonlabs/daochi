package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func googlePurchaseAccountID(seed byte) string {
	return strings.Repeat(string(rune('a'+seed)), 64)
}

func googleAccountBinding(accountID string) string {
	digest := sha256.Sum256([]byte(accountID))
	return hex.EncodeToString(digest[:])
}

func googleLifecycleStore(t *testing.T) *Store {
	t.Helper()
	return googleLifecycleStoreAt(t, filepath.Join(t.TempDir(), "google-lifecycle.db"))
}

func googleLifecycleStoreAt(t *testing.T, path string) *Store {
	t.Helper()
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := GooglePlayReconciliation_Ensure(store.Database, context.Background()); err != nil {
		t.Fatal(err)
	}
	return store
}

func googlePurchaseRequest(token string) GooglePurchaseVerifyRequest {
	return GooglePurchaseVerifyRequest{
		PackageName:   "net.waozi.inbe",
		ProductID:     "waozi_tokens_small",
		PurchaseToken: token,
	}
}

func inspectGooglePurchase(t *testing.T, cfg Config, request GooglePurchaseVerifyRequest) GooglePurchaseResult {
	t.Helper()
	result := GooglePlay_InspectPurchase(context.Background(), cfg, request)
	if result.Error != nil {
		t.Fatal(result.Error)
	}
	if result.PaymentID != request.PurchaseToken {
		t.Fatalf("payment id = %q, want %q", result.PaymentID, request.PurchaseToken)
	}
	return result
}

func processGooglePurchase(t *testing.T, store *Store, cfg Config, inspected GooglePurchaseResult, accountID string) PurchaseResult {
	t.Helper()
	return GooglePlayReconciliation_ProcessPurchase(store.Database, context.Background(), tokenLedgerSigner(),
		errTokenIssuerReadOnly, inspected, googlePurchaseRequest(inspected.PaymentID), accountID, "inbe", 100)
}

func lifecycleState(t *testing.T, store *Store, token string) string {
	t.Helper()
	var state string
	err := store.Database.QueryRowContext(context.Background(),
		"SELECT state FROM google_play_purchase_lifecycle WHERE provider='google_play' AND purchase_token=?1", token).Scan(&state)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func paymentMapping(t *testing.T, store *Store, paymentID string) (accountID, receiptID string) {
	t.Helper()
	err := store.Database.QueryRowContext(context.Background(),
		"SELECT account_id,receipt_id FROM token_processed_payments WHERE provider='google_play' AND provider_payment_id=?1",
		paymentID).Scan(&accountID, &receiptID)
	if err != nil {
		t.Fatal(err)
	}
	return accountID, receiptID
}

func TestGooglePlayPurchaseAccountBinding(t *testing.T) {
	store := googleLifecycleStore(t)
	fake, cfg, restore := googleTestConfig(t)
	defer restore()
	accountID := googlePurchaseAccountID(0)
	binding := googleAccountBinding(accountID)
	fake.setAccountBinding(binding)
	request := googlePurchaseRequest("binding-token")
	inspected := inspectGooglePurchase(t, cfg, request)
	if inspected.AccountBinding != binding {
		t.Fatalf("provider binding = %q, want %q", inspected.AccountBinding, binding)
	}

	attacker := processGooglePurchase(t, store, cfg, inspected, googlePurchaseAccountID(1))
	if attacker.Error == nil || !strings.Contains(attacker.Error.Error(), "account mismatch") {
		t.Fatalf("wrong account result = %+v, want account mismatch", attacker)
	}
	var claimed int
	if err := store.Database.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM google_play_purchase_lifecycle WHERE purchase_token=?1", request.PurchaseToken).Scan(&claimed); err != nil {
		t.Fatal(err)
	}
	if claimed != 0 {
		t.Fatal("foreign claimant persisted a lifecycle")
	}

	owner := processGooglePurchase(t, store, cfg, inspected, accountID)
	if owner.Error != nil || owner.BindingMissing || owner.Receipt.ReceiptID == "" {
		t.Fatalf("owner result = %+v", owner)
	}
	gotAccount, receiptID := paymentMapping(t, store, request.PurchaseToken)
	if gotAccount != accountID || receiptID != owner.Receipt.ReceiptID {
		t.Fatalf("owner mapping = %q/%q, want %q/%q", gotAccount, receiptID, accountID, owner.Receipt.ReceiptID)
	}
}

func TestGooglePlayPurchaseTokenUniqueness(t *testing.T) {
	store := googleLifecycleStore(t)
	fake, cfg, restore := googleTestConfig(t)
	defer restore()
	ownerID := googlePurchaseAccountID(0)
	fake.setAccountBinding(googleAccountBinding(ownerID))
	inspected := inspectGooglePurchase(t, cfg, googlePurchaseRequest("unique-token"))
	first := processGooglePurchase(t, store, cfg, inspected, ownerID)
	if first.Error != nil {
		t.Fatal(first.Error)
	}
	second := processGooglePurchase(t, store, cfg, inspected, googlePurchaseAccountID(1))
	if second.Error == nil || !strings.Contains(second.Error.Error(), "account mismatch") {
		t.Fatalf("cross-account replay = %+v, want account mismatch", second)
	}
	var mappings int
	if err := store.Database.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM token_processed_payments WHERE provider='google_play' AND provider_payment_id='unique-token'").Scan(&mappings); err != nil {
		t.Fatal(err)
	}
	if mappings != 1 {
		t.Fatalf("token mappings = %d, want 1", mappings)
	}
	balance := TokenLedger_Balance(store.Database, context.Background(), ownerID, AssetID)
	if balance.Error != nil || balance.Value != 100 {
		t.Fatalf("owner balance = %d/%v, want 100", balance.Value, balance.Error)
	}
}

func TestGooglePlayMissingBindingRemainsUnclaimed(t *testing.T) {
	store := googleLifecycleStore(t)
	fake, cfg, restore := googleTestConfig(t)
	defer restore()
	request := googlePurchaseRequest("unbound-token")
	inspected := inspectGooglePurchase(t, cfg, request)
	for _, account := range []string{googlePurchaseAccountID(0), googlePurchaseAccountID(1)} {
		result := processGooglePurchase(t, store, cfg, inspected, account)
		if result.Error != nil || !result.BindingMissing || result.Receipt.ReceiptID != "" {
			t.Fatalf("unbound purchase = %+v", result)
		}
	}
	var owner string
	if err := store.Database.QueryRow("SELECT account_id FROM google_play_purchase_lifecycle WHERE purchase_token='unbound-token'").Scan(&owner); err != nil || owner != "" {
		t.Fatalf("unbound claimant = %q, error = %v", owner, err)
	}
	fake.setAccountBinding(googleAccountBinding(googlePurchaseAccountID(0)))
	inspected = inspectGooglePurchase(t, cfg, request)
	result := processGooglePurchase(t, store, cfg, inspected, googlePurchaseAccountID(0))
	if result.Error != nil || result.BindingMissing || result.Receipt.ReceiptID == "" {
		t.Fatalf("verified account recovery = %+v", result)
	}
}

func TestGooglePlayBackgroundRecoveryWithoutPurchaseTraffic(t *testing.T) {
	store := googleLifecycleStore(t)
	fake, cfg, restore := googleTestConfig(t)
	defer restore()
	cfg.WaoziIssuerPrivateKey = tokenLedgerSigner()
	owner := googlePurchaseAccountID(0)
	fake.setAccountBinding(googleAccountBinding(owner))
	inspected := inspectGooglePurchase(t, cfg, googlePurchaseRequest("background-token"))
	if result := processGooglePurchase(t, store, cfg, inspected, owner); result.Error != nil {
		t.Fatal(result.Error)
	}
	// Refund eligibility is based on when Google observes the void, not purchase age.
	if _, err := store.Database.Exec("UPDATE google_play_purchase_lifecycle SET created_at=datetime('now','-31 days')"); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	fake.voidedPurchases = []GoogleVoidedPurchase{{PurchaseToken: "background-token", OrderID: inspected.OrderID, VoidedTimeMillis: time.Now().UnixMilli()}}
	fake.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	done := make(chan struct{})
	go func() {
		defer close(done)
		GooglePlayReconciliation_Run(store.Database, ctx, cfg, errTokenIssuerReadOnly, time.Millisecond)
	}()
	defer func() { cancel(); <-done }()
	for lifecycleState(t, store, "background-token") != "refunded" {
		select {
		case <-ctx.Done():
			t.Fatal("background worker did not reconcile pending consume and refund")
		case <-time.After(time.Millisecond):
		}
	}
	if fake.consumeCount() != 1 {
		t.Fatalf("background consume count = %d, want 1", fake.consumeCount())
	}
	if result := TokenLedger_Balance(store.Database, context.Background(), owner, AssetID); result.Error != nil || result.Value != 0 {
		t.Fatalf("background refund balance = %+v", result)
	}
}

func TestGooglePlayConcurrentPurchaseProcessing(t *testing.T) {
	store := googleLifecycleStore(t)
	fake, cfg, restore := googleTestConfig(t)
	defer restore()
	accountID := googlePurchaseAccountID(5)
	fake.setAccountBinding(googleAccountBinding(accountID))
	inspected := inspectGooglePurchase(t, cfg, googlePurchaseRequest("concurrent-token"))

	const workers = 8
	var group sync.WaitGroup
	start := make(chan struct{})
	results := make(chan PurchaseResult, workers)
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			results <- GooglePlayReconciliation_ProcessPurchase(store.Database, context.Background(),
				tokenLedgerSigner(), errTokenIssuerReadOnly, inspected,
				googlePurchaseRequest("concurrent-token"), accountID, "inbe", 100)
		}()
	}
	close(start)
	group.Wait()
	close(results)

	successes := 0
	for result := range results {
		if result.Error != nil {
			t.Logf("concurrent purchase result: %v", result.Error)
			continue
		}
		if result.BindingMissing || result.Receipt.ReceiptID == "" {
			t.Fatalf("concurrent purchase result = %+v", result)
		}
		successes++
	}
	if successes == 0 {
		t.Fatal("no concurrent purchase attempt succeeded")
	}
	var lifecycles, mappings, events int
	if err := store.Database.QueryRowContext(context.Background(),
		"SELECT (SELECT COUNT(*) FROM google_play_purchase_lifecycle WHERE purchase_token='concurrent-token'),(SELECT COUNT(*) FROM token_processed_payments WHERE provider='google_play' AND provider_payment_id='concurrent-token'),(SELECT COUNT(*) FROM token_ledger WHERE source_type='google_play' AND source_ref='concurrent-token')").Scan(&lifecycles, &mappings, &events); err != nil {
		t.Fatal(err)
	}
	if lifecycles != 1 || mappings != 1 || events != 1 {
		t.Fatalf("concurrent rows = %d/%d/%d, want 1/1/1", lifecycles, mappings, events)
	}
	balance := TokenLedger_Balance(store.Database, context.Background(), accountID, AssetID)
	if balance.Error != nil || balance.Value != 100 {
		t.Fatalf("concurrent balance = %d/%v, want 100", balance.Value, balance.Error)
	}
}

func TestGooglePlayConsumeRetryCrashSafety(t *testing.T) {
	path := filepath.Join(t.TempDir(), "google-restart.db")
	store := googleLifecycleStoreAt(t, path)
	fake, cfg, restore := googleTestConfig(t)
	defer restore()
	accountID := googlePurchaseAccountID(2)
	fake.setAccountBinding(googleAccountBinding(accountID))
	inspected := inspectGooglePurchase(t, cfg, googlePurchaseRequest("retry-token"))
	credited := processGooglePurchase(t, store, cfg, inspected, accountID)
	if credited.Error != nil {
		t.Fatal(credited.Error)
	}
	if state := lifecycleState(t, store, "retry-token"); state != "consume_pending" {
		t.Fatalf("post-credit state = %q, want consume_pending", state)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = googleLifecycleStoreAt(t, path)
	if balance := TokenLedger_Balance(store.Database, context.Background(), accountID, AssetID); balance.Error != nil || balance.Value != 100 {
		t.Fatalf("persisted credit after restart = %+v", balance)
	}

	fake.setConsumeFailure(http.StatusInternalServerError, false)
	first := GooglePlayReconciliation_RetryConsume(store.Database, context.Background(), cfg, "retry-token")
	if first.Error == nil || first.Consumed {
		t.Fatalf("failed retry = %+v, want deferred pending consume", first)
	}
	if state := lifecycleState(t, store, "retry-token"); state != "consume_pending" {
		t.Fatalf("failed retry state = %q, want consume_pending", state)
	}

	fake.setConsumeFailure(0, true)
	retryContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	swept := GooglePlayReconciliation_ReconcilePendingConsumes(store.Database, retryContext, cfg)
	if swept.Error != nil || swept.Attempted != 1 || swept.Consumed != 1 {
		t.Fatalf("pending consume sweep = %+v", swept)
	}
	if fake.consumeCount() != 2 {
		t.Fatalf("consume calls = %d, want 2", fake.consumeCount())
	}
	if state := lifecycleState(t, store, "retry-token"); state != "consumed" {
		t.Fatalf("successful retry state = %q, want consumed", state)
	}
	third := GooglePlayReconciliation_RetryConsume(store.Database, context.Background(), cfg, "retry-token")
	if third.Error != nil || !third.Consumed || fake.consumeCount() != 2 {
		t.Fatalf("idempotent retry = %+v with %d calls", third, fake.consumeCount())
	}
}

func TestGooglePlayRefundReconciliation(t *testing.T) {
	store := googleLifecycleStore(t)
	fake, cfg, restore := googleTestConfig(t)
	defer restore()
	accountID := googlePurchaseAccountID(3)
	fake.setAccountBinding(googleAccountBinding(accountID))
	inspected := inspectGooglePurchase(t, cfg, googlePurchaseRequest("refund-token"))
	credited := processGooglePurchase(t, store, cfg, inspected, accountID)
	if credited.Error != nil {
		t.Fatal(credited.Error)
	}
	if retry := GooglePlayReconciliation_RetryConsume(store.Database, context.Background(), cfg, "refund-token"); retry.Error != nil {
		t.Fatal(retry.Error)
	}
	voided := GoogleVoidedPurchase{
		PurchaseToken:    "refund-token",
		OrderID:          inspected.OrderID,
		VoidedTimeMillis: 1770000000000,
	}
	wrongOrder := voided
	wrongOrder.OrderID = "different-order"
	err := GooglePlayReconciliation_CompensateVoided(store.Database, context.Background(), wrongOrder,
		tokenLedgerSigner(), errTokenIssuerReadOnly)
	if err == nil || !strings.Contains(err.Error(), "refund order mismatch") {
		t.Fatalf("wrong-order refund error = %v, want refund order mismatch", err)
	}
	if state := lifecycleState(t, store, "refund-token"); state != "consumed" {
		t.Fatalf("wrong-order refund state = %q, want consumed", state)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := GooglePlayReconciliation_CompensateVoided(store.Database, context.Background(), voided, tokenLedgerSigner(), errTokenIssuerReadOnly); err != nil {
			t.Fatal(err)
		}
	}
	var state, refundReceiptID string
	var voidedMillis int64
	err = store.Database.QueryRowContext(context.Background(),
		"SELECT state,refund_receipt_id,voided_millis FROM google_play_purchase_lifecycle WHERE purchase_token='refund-token'").Scan(&state, &refundReceiptID, &voidedMillis)
	if err != nil {
		t.Fatal(err)
	}
	if state != "refunded" || refundReceiptID == "" || voidedMillis != voided.VoidedTimeMillis {
		t.Fatalf("refund lifecycle = %q/%q/%d", state, refundReceiptID, voidedMillis)
	}
	var events int
	if err := store.Database.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM token_ledger WHERE source_type='google_play' AND source_ref='refund-token'").Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 2 {
		t.Fatalf("refund ledger events = %d, want credit and debit", events)
	}
	balance := TokenLedger_Balance(store.Database, context.Background(), accountID, AssetID)
	if balance.Error != nil || balance.Value != 0 {
		t.Fatalf("refunded balance = %d/%v, want zero", balance.Value, balance.Error)
	}
}

func TestGooglePlayLegacyPurchaseMigrationAndMalformedStates(t *testing.T) {
	store := googleLifecycleStore(t)
	fake, cfg, restore := googleTestConfig(t)
	defer restore()
	accountID := googlePurchaseAccountID(4)
	request := googlePurchaseRequest("legacy-token")
	inspected := inspectGooglePurchase(t, cfg, request)
	legacyInput := TokenEventInput{
		AccountID: accountID, AppID: "inbe", EventType: "credit", AmountDelta: 100,
		SourceType: "google_play", SourceRef: inspected.Value,
	}
	legacy := TokenLedger_CreditPayment(store.Database, context.Background(), tokenLedgerSigner(),
		"google_play", inspected.Value, legacyInput, errTokenIssuerReadOnly)
	if legacy.Error != nil {
		t.Fatal(legacy.Error)
	}
	fake.setPurchaseState(0, 1)
	inspected = inspectGooglePurchase(t, cfg, request)
	migrated := processGooglePurchase(t, store, cfg, inspected, accountID)
	if migrated.Error != nil || migrated.Created {
		t.Fatalf("legacy migration = %+v", migrated)
	}
	_, tokenReceipt := paymentMapping(t, store, "legacy-token")
	if tokenReceipt != legacy.Value.ReceiptID {
		t.Fatalf("legacy mapping receipt = %q, want %q", tokenReceipt, legacy.Value.ReceiptID)
	}
	if state := lifecycleState(t, store, "legacy-token"); state != "consumed" {
		t.Fatalf("legacy state = %q, want consumed", state)
	}

	fake.setPurchaseState(2, 0)
	malformed := GooglePlay_InspectPurchase(context.Background(), cfg, googlePurchaseRequest("malformed-token"))
	rejected := processGooglePurchase(t, store, cfg, malformed, accountID)
	if rejected.Error == nil || !strings.Contains(rejected.Error.Error(), "not purchased") {
		t.Fatalf("malformed purchase result = %+v, want rejection", rejected)
	}
	var count int
	if err := store.Database.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM google_play_purchase_lifecycle WHERE purchase_token='malformed-token'").Scan(&count); err != nil && err != sql.ErrNoRows {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("malformed lifecycle rows = %d, want 0", count)
	}
}
