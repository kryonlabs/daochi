package main

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func moneroReconcileTestServer(t *testing.T) (*Server, *Store, *fakeMoneroWalletRPC, http.Handler, testIdentity) {
	t.Helper()
	server, store, _ := testServer(t)
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	wallet := newFakeMoneroWalletRPC(t)
	server.cfg.WaoziIssuerPrivateKey = privateKey
	server.cfg.TokenProducts = map[string]TokenProduct{
		"waozi_tokens_small": {
			ProductID:          "waozi_tokens_small",
			TokenUnits:         5000000,
			MoneroAtomicAmount: 1000000000000,
		},
	}
	server.cfg.TokenDirectPurchasesEnabled = true
	server.cfg.MoneroWalletRPCURL = wallet.URL
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0xA1)
	return server, store, wallet, handler, identity
}

func expireTestMoneroInvoice(t *testing.T, store *Store, handler http.Handler, identity testIdentity, invoice MoneroInvoiceResponse) {
	t.Helper()
	if _, err := store.db.Exec(`UPDATE token_payment_intents SET expires_at=?1 WHERE id=?2`,
		time.Now().UTC().Add(-time.Minute).Format(canonicalTimestampLayout), invoice.ID); err != nil {
		t.Fatal(err)
	}
	res := tokenJSONRequest(t, handler, http.MethodGet, "/api/v1/tokens/purchases/monero/invoices/"+invoice.ID, identity.Token, nil)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"status":"expired"`) {
		t.Fatalf("expire poll status = %d body=%s", res.Code, res.Body.String())
	}
}

// A payment that lands after the invoice expired used to vanish: nothing
// re-checked expired invoices. The sweep must credit it.
func TestExpiredMoneroInvoiceLatePaymentCredited(t *testing.T) {
	server, store, wallet, handler, identity := moneroReconcileTestServer(t)
	invoice := createTestMoneroInvoice(t, handler, identity.Token, []byte(`{"app_id":"inbe","product_id":"waozi_tokens_small"}`))
	expireTestMoneroInvoice(t, store, handler, identity, invoice)

	wallet.setTransfer(moneroTransfer{
		TxID: "tx-late", Amount: invoice.AtomicAmount, Confirmations: 10,
		Major: 0, Minor: invoice.AddressIndex, Height: 900,
	})
	if err := server.reconcileMoneroExpiredInvoices(context.Background(), 50); err != nil {
		t.Fatal(err)
	}
	balance, err := store.TokenBalance(context.Background(), identity.UserID, waoziTokenAssetID)
	if err != nil || balance != 5000000 {
		t.Fatalf("late payment balance=%d err=%v, want 5000000", balance, err)
	}
	paid := tokenJSONRequest(t, handler, http.MethodGet, "/api/v1/tokens/purchases/monero/invoices/"+invoice.ID, identity.Token, nil)
	if paid.Code != http.StatusOK || !strings.Contains(paid.Body.String(), `"status":"paid"`) {
		t.Fatalf("swept invoice status = %d body=%s", paid.Code, paid.Body.String())
	}
}

// Partial transfers to a pending invoice must accumulate until they cover
// the price, with a deterministic composite payment id.
func TestMoneroInvoicePartialPaymentsAccumulate(t *testing.T) {
	server, store, wallet, handler, identity := moneroReconcileTestServer(t)
	invoice := createTestMoneroInvoice(t, handler, identity.Token, []byte(`{"app_id":"inbe","product_id":"waozi_tokens_small"}`))
	half := invoice.AtomicAmount / 2
	wallet.setTransfer(
		moneroTransfer{TxID: "tx-part-b", Amount: half, Confirmations: 10, Major: 0, Minor: invoice.AddressIndex},
		moneroTransfer{TxID: "tx-part-a", Amount: invoice.AtomicAmount - half, Confirmations: 10, Major: 0, Minor: invoice.AddressIndex},
	)
	if err := server.reconcileMoneroInvoices(context.Background(), 100); err != nil {
		t.Fatal(err)
	}
	balance, err := store.TokenBalance(context.Background(), identity.UserID, waoziTokenAssetID)
	if err != nil || balance != 5000000 {
		t.Fatalf("top-up balance=%d err=%v, want 5000000", balance, err)
	}
	paid := tokenJSONRequest(t, handler, http.MethodGet, "/api/v1/tokens/purchases/monero/invoices/"+invoice.ID, identity.Token, nil)
	if paid.Code != http.StatusOK || !strings.Contains(paid.Body.String(), `"status":"paid"`) ||
		!strings.Contains(paid.Body.String(), "tx-part-a+tx-part-b:0:"+strconv.Itoa(invoice.AddressIndex)) {
		t.Fatalf("accumulated invoice status = %d body=%s", paid.Code, paid.Body.String())
	}
}

// Partial funds on an expired invoice cannot be credited or refunded
// automatically; they must be reported once, not silently dropped.
func TestMoneroExpiredInvoicePartialFundsReportedStuck(t *testing.T) {
	server, store, wallet, handler, identity := moneroReconcileTestServer(t)
	invoice := createTestMoneroInvoice(t, handler, identity.Token, []byte(`{"app_id":"inbe","product_id":"waozi_tokens_small"}`))
	expireTestMoneroInvoice(t, store, handler, identity, invoice)

	wallet.setTransfer(moneroTransfer{
		TxID: "tx-stuck", Amount: invoice.AtomicAmount / 10, Confirmations: 10,
		Major: 0, Minor: invoice.AddressIndex, Height: 901,
	})
	for i := 0; i < 2; i++ {
		if err := server.reconcileMoneroExpiredInvoices(context.Background(), 50); err != nil {
			t.Fatal(err)
		}
	}
	balance, err := store.TokenBalance(context.Background(), identity.UserID, waoziTokenAssetID)
	if err != nil || balance != 0 {
		t.Fatalf("partial expired invoice must not credit: balance=%d err=%v", balance, err)
	}
	if stuck := server.metrics.moneroStuckInvoices.Load(); stuck != 1 {
		t.Fatalf("stuck invoice counter=%d, want 1 (reported once)", stuck)
	}
}

// The whole-wallet deposit scan must advance a persisted height bookmark
// instead of rescanning the full history on every poll.
func TestMoneroDepositScanBookmarkAdvances(t *testing.T) {
	server, store, wallet, handler, identity := moneroReconcileTestServer(t)
	server.cfg.MoneroRateAtomicAmount = 1000000000000
	server.cfg.MoneroRateTokenUnits = 5000000
	server.cfg.MoneroConfirmationsRequired = 10

	address := tokenJSONRequest(t, handler, http.MethodGet, "/api/v1/tokens/purchases/monero/address", identity.Token, nil)
	if address.Code != http.StatusOK {
		t.Fatalf("address status = %d body=%s", address.Code, address.Body.String())
	}
	mapping, found, err := store.MoneroAccountAddress(context.Background(), identity.UserID)
	if err != nil || !found {
		t.Fatalf("address mapping found=%v err=%v", found, err)
	}
	wallet.setTransfer(moneroTransfer{
		TxID: "tx-heightmark", Amount: 1000000000000, Confirmations: 10, Height: 5000,
		Major: mapping.AccountIndex, Minor: mapping.AddressIndex,
	})
	if err := server.reconcileMoneroAccountDeposits(context.Background()); err != nil {
		t.Fatal(err)
	}
	height, err := store.MoneroScanHeight(context.Background())
	if err != nil || height != 5000 {
		t.Fatalf("scan bookmark=%d err=%v, want 5000", height, err)
	}
	wallet.mu.Lock()
	firstMin := wallet.minHeights[0]
	wallet.mu.Unlock()
	if firstMin != 0 {
		t.Fatalf("first whole-wallet scan min_height=%d, want 0", firstMin)
	}
	if err := server.reconcileMoneroAccountDeposits(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The confirmed-history query must carry the bookmark; the pool query
	// is intentionally unfiltered (height 0).
	wallet.mu.Lock()
	maxSeen := int64(0)
	for _, minHeight := range wallet.minHeights {
		if minHeight > maxSeen {
			maxSeen = minHeight
		}
	}
	wallet.mu.Unlock()
	if maxSeen < 5000 {
		t.Fatalf("rescan min_height=%d, want >= 5000 (bookmark used)", maxSeen)
	}
}
