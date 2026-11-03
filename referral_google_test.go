package main

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestReferralGoogleVerifiedPaidKindAndHistoricalProof(t *testing.T) {
	server, users := referralFixture(t)
	db, ctx := server.Store.Database, context.Background()
	fake, cfg, restore := googleTestConfig(t)
	defer restore()
	server.Cfg.GoogleServiceAccountJSON = cfg.GoogleServiceAccountJSON
	fake.setAccountBinding(googleAccountBinding(users[1]))
	if r := Referral_Claim(db, ctx, server.Cfg.WaoziIssuerPrivateKey, users[1], referralCode(t, server, users[0]), "kind-claim-1", ""); r.Error != nil {
		t.Fatal(r.Error)
	}
	if err := GooglePlayReconciliation_Ensure(db, ctx); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []int64{0, 1, 2} {
		fake.mu.Lock()
		fake.purchaseType = &kind
		fake.mu.Unlock()
		request := googlePurchaseRequest(fmt.Sprintf("nonpaid-%d", kind))
		inspected := inspectGooglePurchase(t, cfg, request)
		paid := GooglePlayReconciliation_ProcessPurchase(db, ctx, server.Cfg.WaoziIssuerPrivateKey, errTokenIssuerReadOnly, inspected, request, users[1], "inbe", 100000000)
		if paid.Error != nil {
			t.Fatal(paid.Error)
		}
		// A pre-feature record with no persisted type must be reverified, never
		// assumed paid from its signed source label or lifecycle.
		if _, err := db.Exec("DELETE FROM google_play_purchase_proofs WHERE purchase_token=?", request.PurchaseToken); err != nil {
			t.Fatal(err)
		}
		referralSettle(t, server)
		if got := referralBalance(t, server, users[0]); got != 0 {
			t.Fatalf("nonpaid kind%d generated%d", kind, got)
		}
		var proof string
		if err := db.QueryRow("SELECT payment_kind FROM google_play_purchase_proofs WHERE purchase_token=?", request.PurchaseToken).Scan(&proof); err != nil || proof == "paid" {
			t.Fatal(proof, err)
		}
	}
	fake.mu.Lock()
	fake.purchaseType = nil
	fake.mu.Unlock()
	request := googlePurchaseRequest("standard-paid")
	inspected := inspectGooglePurchase(t, cfg, request)
	result := GooglePlayReconciliation_ProcessPurchase(db, ctx, server.Cfg.WaoziIssuerPrivateKey, errTokenIssuerReadOnly, inspected, request, users[1], "inbe", 100000000)
	if result.Error != nil {
		t.Fatal(result.Error)
	}
	if _, err := db.Exec("DELETE FROM google_play_purchase_proofs WHERE purchase_token=?", request.PurchaseToken); err != nil {
		t.Fatal(err)
	}
	// Processed payment alone is not paid proof, even when its outbox is ready.
	if err := ReferralSettlement_Process(db, ctx, server.Cfg.WaoziIssuerPrivateKey, result.Receipt.ReceiptID, true); err != nil {
		t.Fatal(err)
	}
	if referralBalance(t, server, users[0]) != 0 {
		t.Fatal("unclassified purchase paid commission")
	}
	referralSettle(t, server)
	if referralBalance(t, server, users[0]) != 5000000 {
		t.Fatal("provider reinspection did not backfill paid reward")
	}
	// Unknown future kinds and invalid provider quantities fail closed.
	unknown := int64(99)
	invalid := int64(2)
	fake.mu.Lock()
	fake.purchaseType = &unknown
	fake.mu.Unlock()
	if got := GooglePlay_InspectPurchase(ctx, cfg, googlePurchaseRequest("unknown")); got.Error == nil {
		t.Fatal("unknown kind accepted")
	}
	fake.mu.Lock()
	fake.purchaseType = nil
	fake.refundableQuantity = &invalid
	fake.mu.Unlock()
	if got := GooglePlay_InspectPurchase(ctx, cfg, googlePurchaseRequest("invalid-net")); got.Error == nil {
		t.Fatal("invalid refundable quantity accepted")
	}
}

func TestReferralGoogleInitialRefundSnapshotAndSubsequentVoid(t *testing.T) {
	server, users := referralFixture(t)
	db, ctx := server.Store.Database, context.Background()
	fake, cfg, restore := googleTestConfig(t)
	defer restore()
	server.Cfg.GoogleServiceAccountJSON = cfg.GoogleServiceAccountJSON
	server.Cfg.TokenProducts = map[string]TokenProduct{"waozi_tokens_small": {ProductID: "waozi_tokens_small", TokenUnits: 100000019}}
	fake.setAccountBinding(googleAccountBinding(users[1]))
	remaining := int64(2)
	fake.mu.Lock()
	fake.quantity = 3
	fake.refundableQuantity = &remaining
	fake.mu.Unlock()
	if r := Referral_Claim(db, ctx, server.Cfg.WaoziIssuerPrivateKey, users[1], referralCode(t, server, users[0]), "net-claim-1", ""); r.Error != nil {
		t.Fatal(r.Error)
	}
	// This void predates the local lifecycle. Initial authenticated snapshot must
	// still exclude it even when the voided-purchases list no longer contains it.
	bearer := issueTestBearer(t, server, users[1], time.Now().Add(time.Hour))
	body := []byte(`{"package_name":"net.waozi.inbe","product_id":"waozi_tokens_small","purchase_token":"net-snapshot","app_id":"inbe"}`)
	r := tokenJSONRequest(t, server.Routes(), "POST", "/api/v1/tokens/purchases/google/verify", bearer, body)
	if r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	if got := referralBalance(t, server, users[1]); got != 220000038 {
		t.Fatalf("initial net%d", got)
	}
	referralSettle(t, server)
	if got := referralBalance(t, server, users[0]); got != 10000001 {
		t.Fatalf("initial net commission%d", got)
	}
	// A late duplicate event covered by the first snapshot must not debit again.
	old := GoogleVoidedPurchase{PurchaseToken: "net-snapshot", OrderID: fake.orderID, VoidedTimeMillis: time.Now().Add(-time.Hour).UnixMilli(), VoidedQuantity: 1}
	fake.mu.Lock()
	fake.voidedPurchases = []GoogleVoidedPurchase{old}
	fake.mu.Unlock()
	for i := 0; i < 2; i++ {
		if result := GooglePlayReconciliation_ReconcileRecentRefunds(db, ctx, server.Cfg, "net.waozi.inbe", server.Cfg.WaoziIssuerPrivateKey, errTokenIssuerReadOnly); result.Error != nil {
			t.Fatal(result.Error)
		}
	}
	if got := referralBalance(t, server, users[1]); got != 220000038 {
		t.Fatalf("snapshot overlap double refund%d", got)
	}
	// Provider may initially return a stale cumulative snapshot. Persist a
	// watch before recording the notification; the list may disappear later.
	next := old
	next.VoidedTimeMillis = time.Now().Add(-time.Minute).UnixMilli()
	fake.mu.Lock()
	fake.refundableQuantity = &remaining
	fake.voidedPurchases = []GoogleVoidedPurchase{old, next}
	fake.mu.Unlock()
	if result := GooglePlayReconciliation_ReconcileRecentRefunds(db, ctx, server.Cfg, "net.waozi.inbe", server.Cfg.WaoziIssuerPrivateKey, errTokenIssuerReadOnly); result.Error != nil {
		t.Fatal(result.Error)
	}
	if got := referralBalance(t, server, users[1]); got != 220000038 {
		t.Fatalf("stale snapshot guessed refund%d", got)
	}
	fake.mu.Lock()
	remaining = 1
	fake.refundableQuantity = &remaining
	fake.voidedPurchases = nil
	fake.mu.Unlock()
	if err := GooglePlayReconciliation_ReconcileSnapshotWatch(db, ctx, server.Cfg, server.Cfg.WaoziIssuerPrivateKey, errTokenIssuerReadOnly); err != nil {
		t.Fatal(err)
	}
	referralSettle(t, server)
	if got := referralBalance(t, server, users[1]); got != 120000019 {
		t.Fatalf("next net%d", got)
	}
	if got := referralBalance(t, server, users[0]); got != 5000000 {
		t.Fatalf("next commission%d", got)
	}
	remaining = 0
	full := next
	full.VoidedTimeMillis++
	full.VoidedQuantity = 0
	fake.mu.Lock()
	fake.refundableQuantity = &remaining
	fake.purchaseState = 1
	fake.voidedPurchases = []GoogleVoidedPurchase{full}
	fake.mu.Unlock()
	if result := GooglePlayReconciliation_ReconcileRecentRefunds(db, ctx, server.Cfg, "net.waozi.inbe", server.Cfg.WaoziIssuerPrivateKey, errTokenIssuerReadOnly); result.Error != nil {
		t.Fatal(result.Error)
	}
	referralSettle(t, server)
	if referralBalance(t, server, users[1]) != 20000000 || referralBalance(t, server, users[0]) != 0 {
		t.Fatal("full refund retained reward or changed welcome")
	}
}

func TestReferralGoogleNetSnapshotFailureRollsBackGrossCredit(t *testing.T) {
	server, users := referralFixture(t)
	db, ctx := server.Store.Database, context.Background()
	fake, cfg, restore := googleTestConfig(t)
	defer restore()
	fake.setAccountBinding(googleAccountBinding(users[1]))
	remaining := int64(1)
	fake.mu.Lock()
	fake.quantity = 2
	fake.refundableQuantity = &remaining
	fake.mu.Unlock()
	if err := GooglePlayReconciliation_Ensure(db, ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TRIGGER reject_net_refund BEFORE INSERT ON token_ledger WHEN NEW.source_type='google_play' AND NEW.event_type='debit' BEGIN SELECT RAISE(ABORT,'test snapshot failure'); END"); err != nil {
		t.Fatal(err)
	}
	request := googlePurchaseRequest("rollback-net")
	inspected := inspectGooglePurchase(t, cfg, request)
	result := GooglePlayReconciliation_ProcessPurchase(db, ctx, server.Cfg.WaoziIssuerPrivateKey, errTokenIssuerReadOnly, inspected, request, users[1], "inbe", 200000000)
	if result.Error == nil {
		t.Fatal("snapshot failure succeeded")
	}
	for _, table := range []string{"token_ledger", "google_play_purchase_lifecycle", "google_play_purchase_quantities", "google_play_purchase_proofs", "token_google_origins"} {
		var count int
		query := "SELECT COUNT(*) FROM " + table
		if err := db.QueryRow(query).Scan(&count); err != nil || count != 0 {
			t.Fatal("partial state after net refund rollback", table, count, err)
		}
	}
}
