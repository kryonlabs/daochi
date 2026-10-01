package main

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/json"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const invoiceFixtureID = "0123456789abcdef0123456789abcdef"

func seedInvoiceFixture(t *testing.T, server *Server, account, status, expiry string) {
	t.Helper()
	_, err := server.store.Database.Exec(`INSERT INTO token_payment_intents
(id,provider,account_id,app_id,product_id,asset_id,token_units,provider_amount,
provider_address,provider_ref,status,expires_at,created_at)
VALUES(?1,'monero',?2,'target','a','waozi:token',10,20,'test-address','17',?3,?4,'2026-01-01T00:00:00Z')`,
		invoiceFixtureID, account, status, expiry)
	if err != nil {
		t.Fatal(err)
	}
}

func invoiceRecordsFromBaseline(values []baselineInvoiceMoneroInvoiceRecord) []InvoiceRecord {
	if values == nil {
		return nil
	}
	result := make([]InvoiceRecord, len(values))
	for index, value := range values {
		result[index] = InvoiceRecord{AccountID: value.AccountID, Invoice: value.Invoice}
	}
	return result
}

func TestZiranMoneroInvoiceStorageMatchesBaseline(t *testing.T) {
	for _, mode := range []string{"pending", "paid", "expired", "missing", "wrong account", "bad scan", "cancelled", "closed database"} {
		t.Run(mode, func(t *testing.T) {
			actual, account, _ := paymentHTTPFixture(t)
			baseline, _, _ := paymentHTTPFixture(t)
			status := "pending"
			if mode == "paid" || mode == "expired" {
				status = mode
			}
			expiry := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
			for _, server := range []*Server{actual, baseline} {
				seedInvoiceFixture(t, server, account, status, expiry)
				if mode == "bad scan" {
					if _, err := server.store.Database.Exec(`UPDATE token_payment_intents SET provider_ref='not-an-integer'`); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "closed database" {
					_ = server.store.Close()
				}
			}
			ctx := context.Background()
			if mode == "cancelled" {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			id, user := invoiceFixtureID, account
			if mode == "missing" {
				id = "missing"
			}
			if mode == "wrong account" {
				user = "other"
			}
			got := MoneroInvoiceStore_Invoice(actual.store.Database, ctx, user, id)
			want, found, err := baseline.store.baselineInvoiceMoneroInvoice(ctx, user, id)
			if !reflect.DeepEqual(got.Value, want) || got.Found != found || websocketErrorText(got.Error) != websocketErrorText(err) {
				t.Fatalf("invoice result changed: %#v / %#v, %v, %v", got, want, found, err)
			}
			for _, limit := range []int{-1, 0, 1, 100} {
				pending := MoneroInvoiceStore_Pending(actual.store.Database, ctx, limit)
				pendingBaseline, pendingError := baseline.store.baselineInvoicePendingMoneroInvoices(ctx, limit)
				if !reflect.DeepEqual(pending.Value, invoiceRecordsFromBaseline(pendingBaseline)) || websocketErrorText(pending.Error) != websocketErrorText(pendingError) {
					t.Fatalf("pending query changed: %#v / %#v, %v", pending, pendingBaseline, pendingError)
				}
				expired := MoneroInvoiceStore_Expired(actual.store.Database, ctx, limit)
				expiredBaseline, expiredError := baseline.store.baselineInvoiceExpiredMoneroInvoices(ctx, limit)
				if !reflect.DeepEqual(expired.Value, invoiceRecordsFromBaseline(expiredBaseline)) || websocketErrorText(expired.Error) != websocketErrorText(expiredError) {
					t.Fatalf("expired query changed: %#v / %#v, %v", expired, expiredBaseline, expiredError)
				}
			}
		})
	}
}

func TestZiranMoneroInvoiceStateChangesMatchBaseline(t *testing.T) {
	for _, mode := range []string{"paid", "expire", "settle expired", "not pending", "wrong account", "missing", "cancelled", "failed update"} {
		t.Run(mode, func(t *testing.T) {
			actual, account, _ := paymentHTTPFixture(t)
			baseline, _, _ := paymentHTTPFixture(t)
			status := "pending"
			if mode == "settle expired" || mode == "not pending" {
				status = "expired"
			}
			for _, server := range []*Server{actual, baseline} {
				seedInvoiceFixture(t, server, account, status, "2100-01-01T00:00:00Z")
				if mode == "failed update" {
					if _, err := server.store.Database.Exec(`CREATE TRIGGER invoice_write_failure BEFORE UPDATE ON token_payment_intents BEGIN SELECT RAISE(FAIL,'invoice write failed'); END`); err != nil {
						t.Fatal(err)
					}
				}
			}
			ctx := context.Background()
			if mode == "cancelled" {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			id, user := invoiceFixtureID, account
			if mode == "missing" {
				id = "missing"
			}
			if mode == "wrong account" {
				user = "other"
			}
			var got, want error
			switch mode {
			case "expire":
				got = MoneroInvoiceStore_MarkExpired(actual.store.Database, ctx, user, id)
				want = baseline.store.baselineInvoiceMarkMoneroInvoiceExpired(ctx, user, id)
			case "settle expired":
				got = MoneroInvoiceStore_SettleExpired(actual.store.Database, ctx, user, id, "receipt", "payment")
				want = baseline.store.baselineInvoiceSettleExpiredMoneroInvoice(ctx, user, id, "receipt", "payment")
			default:
				got = MoneroInvoiceStore_MarkPendingPaid(actual.store.Database, ctx, user, id, "receipt", "payment")
				want = baseline.store.baselineInvoiceMarkMoneroInvoicePaid(ctx, user, id, "receipt", "payment")
			}
			if websocketErrorText(got) != websocketErrorText(want) {
				t.Fatalf("state update error changed: %v / %v", got, want)
			}
			for index, server := range []*Server{actual, baseline} {
				var storedStatus, receiptID, paymentID string
				if err := server.store.Database.QueryRow(`SELECT status,receipt_id,provider_payment_id FROM token_payment_intents WHERE id=?1`, invoiceFixtureID).Scan(&storedStatus, &receiptID, &paymentID); err != nil {
					t.Fatal(err)
				}
				if index == 0 {
					status = storedStatus + ":" + receiptID + ":" + paymentID
				} else if status != storedStatus+":"+receiptID+":"+paymentID {
					t.Fatal("persisted invoice state changed")
				}
			}
		})
	}
}

func TestZiranMoneroInvoiceHandlersMatchBaseline(t *testing.T) {
	for _, handler := range []string{"create", "read"} {
		for _, mode := range []string{"normal", "unauthenticated", "malformed body", "disabled", "unknown product", "unknown app", "invalid id", "missing", "cancelled", "closed database", "wallet unavailable"} {
			t.Run(handler+"/"+mode, func(t *testing.T) {
				actual, account, _ := paymentHTTPFixture(t)
				baseline, _, _ := paymentHTTPFixture(t)
				for _, server := range []*Server{actual, baseline} {
					server.cfg.TokenDirectPurchasesEnabled = true
					if mode == "disabled" {
						server.cfg.TokenDirectPurchasesEnabled = false
					}
					seedInvoiceFixture(t, server, account, "pending", "2100-01-01T00:00:00Z")
					if mode == "closed database" {
						_ = server.store.Close()
					}
				}
				path := "/api/v1/tokens/purchases/monero/invoices"
				method, body := http.MethodPost, []byte(`{"app_id":"target","product_id":"a"}`)
				if handler == "read" {
					path += "/" + invoiceFixtureID
					method, body = http.MethodGet, nil
					if mode == "invalid id" {
						path = "/api/v1/tokens/purchases/monero/invoices/bad/id"
					}
					if mode == "missing" {
						path = "/api/v1/tokens/purchases/monero/invoices/missing"
					}
				}
				if mode == "malformed body" {
					body = []byte("{")
				}
				if mode == "unknown product" {
					body = []byte(`{"app_id":"target","product_id":"unknown"}`)
				}
				if mode == "unknown app" {
					body = []byte(`{"app_id":"unknown","product_id":"a"}`)
				}
				writers := []*httptest.ResponseRecorder{httptest.NewRecorder(), httptest.NewRecorder()}
				for index, server := range []*Server{actual, baseline} {
					request := paymentHTTPRequest(server, account, method, path, body)
					if mode == "unauthenticated" {
						request.Header.Del("Authorization")
					}
					if mode == "cancelled" {
						ctx, cancel := context.WithCancel(request.Context())
						cancel()
						request = request.WithContext(ctx)
					}
					if index == 0 && handler == "create" {
						MoneroInvoices_Create(server.monero(), writers[index], request)
					} else if index == 0 {
						MoneroInvoices_Read(server.monero(), writers[index], request)
					} else if handler == "create" {
						server.baselineInvoiceHandleMoneroInvoices(writers[index], request)
					} else {
						server.baselineInvoiceHandleMoneroInvoiceRoute(writers[index], request)
					}
				}
				compareHTTPResponse(t, writers[0], writers[1])
			})
		}
	}
}

func TestZiranMoneroInvoiceExpiryMatchesBaseline(t *testing.T) {
	for _, value := range []string{"", "invalid", "2020-01-01T00:00:00Z", "2100-01-01T00:00:00Z", "2020-01-01T01:00:00+01:00", "2020-01-01T00:00:00.123456789Z"} {
		invoice := MoneroInvoiceResponse{ExpiresAt: value}
		if MoneroInvoices_Expired(invoice) != baselineInvoiceMoneroInvoiceExpired(invoice) {
			t.Fatalf("expiry changed for %q", value)
		}
	}
}

func TestZiranMoneroStuckInvoiceConcurrencyAndPanicMatchBaseline(t *testing.T) {
	actual, _, _ := paymentHTTPFixture(t)
	baseline, _, _ := paymentHTTPFixture(t)
	payment := InvoicePaymentState{SeenAtomic: 19, ConfirmedAtomic: 10}
	for index, server := range []*Server{actual, baseline} {
		var workers sync.WaitGroup
		for worker := 0; worker < 64; worker++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				if index == 0 {
					MoneroInvoices_ReportStuck(server.monero(), "invoice", "account", payment)
				} else {
					server.baselineInvoiceReportStuckMoneroInvoice("invoice", "account", payment)
				}
			}()
		}
		workers.Wait()
		if server.metrics.MoneroStuckInvoices.Load() != 1 {
			t.Fatal("concurrent stuck notifications are no longer single-use")
		}
	}
	panicValue := errors.New("invoice log panic")
	previous := slog.Default()
	previousWriter, previousFlags := log.Default().Writer(), log.Flags()
	defer func() {
		slog.SetDefault(previous)
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
	}()
	slog.SetDefault(slog.New(httpPortPanickingLog{value: panicValue}))
	for index, server := range []*Server{actual, baseline} {
		func() {
			defer func() {
				if recover() != panicValue {
					t.Fatal("logging panic identity changed")
				}
			}()
			if index == 0 {
				MoneroInvoices_ReportStuck(server.monero(), "panic-invoice", "account", payment)
			} else {
				server.baselineInvoiceReportStuckMoneroInvoice("panic-invoice", "account", payment)
			}
		}()
		if server.metrics.MoneroStuckInvoices.Load() != 2 {
			t.Fatal("stuck counter must update before a logging panic")
		}
		if index == 0 {
			MoneroInvoices_ReportStuck(server.monero(), "panic-invoice", "account", payment)
		} else {
			server.baselineInvoiceReportStuckMoneroInvoice("panic-invoice", "account", payment)
		}
	}
}

func TestZiranMoneroInvoiceCreationMatchesBaseline(t *testing.T) {
	actual, account, _ := paymentHTTPFixture(t)
	baseline, _, _ := paymentHTTPFixture(t)
	var invoices [2]MoneroInvoiceResponse
	for index, server := range []*Server{actual, baseline} {
		wallet := newFakeMoneroWalletRPC(t)
		server.cfg.MoneroWalletRPCURL = wallet.URL
		server.cfg.TokenDirectPurchasesEnabled = true
		writer := httptest.NewRecorder()
		request := paymentHTTPRequest(server, account, http.MethodPost, "/api/v1/tokens/purchases/monero/invoices", []byte(`{"app_id":"target","product_id":"a"}`))
		if index == 0 {
			MoneroInvoices_Create(server.monero(), writer, request)
		} else {
			server.baselineInvoiceHandleMoneroInvoices(writer, request)
		}
		if writer.Code != http.StatusCreated {
			t.Fatalf("invoice creation failed: %d %s", writer.Code, writer.Body)
		}
		if err := json.Unmarshal(writer.Body.Bytes(), &invoices[index]); err != nil {
			t.Fatal(err)
		}
		invoice := invoices[index]
		expiry, err := time.Parse(time.RFC3339Nano, invoice.ExpiresAt)
		if err != nil || time.Until(expiry) < 44*time.Minute || time.Until(expiry) > 46*time.Minute || !Identity_ValidResourceID(invoice.ID) {
			t.Fatal("invoice identifier or expiration contract changed")
		}
		loaded := MoneroInvoiceStore_Invoice(server.store.Database, t.Context(), account, invoice.ID)
		if loaded.Error != nil || !loaded.Found || !reflect.DeepEqual(loaded.Value, invoice) {
			t.Fatal("created invoice response differs from its persisted row")
		}
		invoices[index].ID, invoices[index].ExpiresAt = "", ""
	}
	if !reflect.DeepEqual(invoices[0], invoices[1]) {
		t.Fatalf("created invoice fields changed: %#v / %#v", invoices[0], invoices[1])
	}
}

func TestZiranMoneroInvoiceSettlementMatchesBaseline(t *testing.T) {
	for _, mode := range []string{"pending", "expired", "paid", "missing issuer", "wallet unavailable", "failed mark"} {
		t.Run(mode, func(t *testing.T) {
			actual, account, _ := paymentHTTPFixture(t)
			baseline, _, _ := paymentHTTPFixture(t)
			var invoices [2]MoneroInvoiceResponse
			var balances [2]int64
			var failures [2]string
			for index, server := range []*Server{actual, baseline} {
				wallet := newFakeMoneroWalletRPC(t)
				server.cfg.MoneroWalletRPCURL = wallet.URL
				if mode == "wallet unavailable" {
					server.cfg.MoneroWalletRPCURL = ""
				}
				if mode == "missing issuer" {
					server.cfg.WaoziIssuerPrivateKey = nil
				}
				expiry := "2100-01-01T00:00:00Z"
				if mode == "expired" {
					expiry = "2020-01-01T00:00:00Z"
				}
				seedInvoiceFixture(t, server, account, "pending", expiry)
				loaded := MoneroInvoiceStore_Invoice(server.store.Database, t.Context(), account, invoiceFixtureID)
				if loaded.Error != nil || !loaded.Found {
					t.Fatal("fixture invoice missing")
				}
				if mode == "paid" || mode == "failed mark" {
					wallet.setTransfer(moneroTransfer{TxID: "confirmed", Amount: 20, Confirmations: 10, Major: 0, Minor: 17})
				}
				if mode == "failed mark" {
					if _, err := server.store.Database.Exec(`CREATE TRIGGER invoice_mark_failure BEFORE UPDATE ON token_payment_intents BEGIN SELECT RAISE(FAIL,'invoice mark failed'); END`); err != nil {
						t.Fatal(err)
					}
				}
				var err error
				if index == 0 {
					settled := MoneroInvoices_Settle(server.monero(), t.Context(), account, loaded.Value)
					invoices[index], err = settled.Value, settled.Error
				} else {
					invoices[index], err = server.baselineInvoiceTrySettleOrExpireMoneroInvoice(t.Context(), account, loaded.Value)
				}
				failures[index] = websocketErrorText(err)
				if invoices[index].Receipt != nil {
					if !TokenReceipt_ValidSignature(server.cfg.WaoziIssuerPublicKey, *invoices[index].Receipt) {
						t.Fatal("settled invoice receipt signature changed")
					}
					normalized := receiptWithoutGeneratedFields(*invoices[index].Receipt)
					invoices[index].Receipt = &normalized
				}
				balance := TokenLedger_Balance(server.store.Database, t.Context(), account, AssetID)
				if balance.Error != nil {
					t.Fatal(balance.Error)
				}
				balances[index] = balance.Value
			}
			if !reflect.DeepEqual(invoices[0], invoices[1]) || failures[0] != failures[1] || balances[0] != balances[1] {
				t.Fatalf("invoice settlement changed: %#v/%#v, %v/%v, %v", invoices[0], invoices[1], failures[0], failures[1], balances)
			}
			if mode == "failed mark" && (balances[0] != 10 || failures[0] == "") {
				t.Fatal("invoice mark failure must preserve the separately committed credit")
			}
		})
	}
}

func TestZiranMoneroInvoiceReplayCleanupMatchesBaseline(t *testing.T) {
	for _, mode := range []string{"wallet unavailable", "write failure", "log panic", "error response panic", "success response panic"} {
		t.Run(mode, func(t *testing.T) {
			actual, account, key := paymentHTTPFixture(t)
			baseline, _, _ := paymentHTTPFixture(t)
			body := []byte(`{"app_id":"target","product_id":"a"}`)
			path := "/api/v1/tokens/purchases/monero/invoices"
			header := signedTxHeader(t, account, "target", "device-key", http.MethodPost, path, body, key, "invoice-cleanup")
			previousRandom, previousLogger := cryptorand.Reader, slog.Default()
			previousWriter, previousFlags := log.Writer(), log.Flags()
			defer func() {
				cryptorand.Reader = previousRandom
				slog.SetDefault(previousLogger)
				log.SetOutput(previousWriter)
				log.SetFlags(previousFlags)
			}()
			panicValue := errors.New("invoice boundary panic")
			for index, server := range []*Server{actual, baseline} {
				wallet := newFakeMoneroWalletRPC(t)
				server.cfg.TokenDirectPurchasesEnabled = true
				server.cfg.MoneroWalletRPCURL = wallet.URL
				if mode == "wallet unavailable" {
					server.cfg.MoneroWalletRPCURL = ""
				}
				if mode == "write failure" || mode == "log panic" || mode == "error response panic" {
					if _, err := server.store.Database.Exec(`CREATE TRIGGER invoice_insert_failure BEFORE INSERT ON token_payment_intents BEGIN SELECT RAISE(FAIL,'invoice write failed'); END`); err != nil {
						t.Fatal(err)
					}
				}
				request := paymentHTTPRequest(server, account, http.MethodPost, path, body)
				request.Header.Set("X-Daochi-Tx", header)
				var writer http.ResponseWriter = httptest.NewRecorder()
				if strings.Contains(mode, "response panic") {
					writer = &httpPortWriter{header: make(http.Header), panicValue: panicValue}
				}
				if mode == "log panic" {
					slog.SetDefault(slog.New(httpPortPanickingLog{value: panicValue}))
				}
				cryptorand.Reader = bytes.NewReader(bytes.Repeat([]byte{0x42}, 4096))
				func() {
					defer func() {
						caught := recover()
						if strings.Contains(mode, "panic") && caught != panicValue {
							t.Fatalf("panic identity changed: %v", caught)
						}
						if !strings.Contains(mode, "panic") && caught != nil {
							t.Fatalf("unexpected panic: %v", caught)
						}
					}()
					if index == 0 {
						MoneroInvoices_Create(server.monero(), writer, request)
					} else {
						server.baselineInvoiceHandleMoneroInvoices(writer, request)
					}
				}()
				slog.SetDefault(previousLogger)
				log.SetOutput(previousWriter)
				log.SetFlags(previousFlags)
			}
			got, want := signedTransactionRows(t, actual.store), signedTransactionRows(t, baseline.store)
			if !reflect.DeepEqual(got, want) || (len(got) == 1) != (mode == "success response panic") {
				t.Fatalf("invoice replay cleanup changed: %#v / %#v", got, want)
			}
			for _, server := range []*Server{actual, baseline} {
				var count int
				if err := server.store.Database.QueryRow(`SELECT COUNT(*) FROM token_payment_intents`).Scan(&count); err != nil {
					t.Fatal(err)
				}
				if (count == 1) != (mode == "success response panic") {
					t.Fatal("response panic changed whether the invoice persists")
				}
			}
		})
	}
}

func TestZiranMoneroInvoiceWorkerCancellationMatchesBaseline(t *testing.T) {
	for _, interval := range []time.Duration{-1, 0, time.Millisecond} {
		for _, baseline := range []bool{false, true} {
			server, _, _ := paymentHTTPFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			done := make(chan struct{})
			go func() {
				defer close(done)
				if baseline {
					server.baselineInvoiceRunMoneroInvoiceReconciler(ctx, interval)
				} else {
					MoneroInvoices_Run(server.monero(), ctx, interval)
				}
			}()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("cancelled reconciliation worker did not stop")
			}
		}
	}
}
