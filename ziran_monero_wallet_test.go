package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestZiranMoneroWalletPolicyAgainstBaseline(t *testing.T) {
	for _, value := range []int64{math.MinInt64, -1, 0, 1, 10, math.MaxInt64} {
		configuration := Config{
			MoneroRateAtomicAmount:       value,
			MoneroRateTokenUnits:         value,
			MoneroConfirmationsRequired:  value,
			MoneroMinimumAtomicAmount:    value,
		}
		if MoneroWallet_ValidRate(configuration) != baselineValidMoneroRate(configuration) ||
			MoneroWallet_ConfirmationsRequired(configuration) != baselineMoneroConfirmationsRequired(configuration) ||
			MoneroWallet_MinimumAtomicAmount(configuration) != baselineMoneroMinimumAtomicAmount(configuration) {
			t.Fatalf("wallet defaults changed for %d", value)
		}
	}
	cases := [][3]int64{
		{0, 1, 1}, {-1, 1, 1}, {1, 0, 1}, {1, 1, -1}, {1, 1, 1},
		{1, 100, 1}, {math.MaxInt64, math.MaxInt64, math.MaxInt64},
		{math.MaxInt64, 1, math.MaxInt64}, {math.MaxInt64, 2, 2},
	}
	random := rand.New(rand.NewSource(20261001))
	for index := 0; index < 300; index++ {
		cases = append(cases, [3]int64{random.Int63(), random.Int63(), random.Int63()})
	}
	for _, values := range cases {
		got := MoneroWallet_TokenUnits(values[0], values[1], values[2])
		want, err := baselineMoneroTokenUnits(values[0], values[1], values[2])
		if got.Value != want || !sameIdentityError(got.Error, err) {
			t.Fatalf("conversion %v = %#v, baseline %d %v", values, got, want, err)
		}
	}
}

func TestZiranMoneroWalletRequestAgainstBaseline(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"success", 200, `{"result":{"answer":42}}`},
		{"empty-result", 200, `{"result":{}}`},
		{"null-result", 200, `{"result":null}`},
		{"missing-result", 200, `{}`},
		{"duplicate-result", 200, `{"result":null,"result":{"answer":42}}`},
		{"error", 200, `{"error":{"code":-1,"message":"wallet 日本語"},"result":{}}`},
		{"null-error", 200, `{"error":null,"result":{"answer":42}}`},
		{"invalid-error-code", 200, `{"error":{"code":"wrong","message":"error"}}`},
		{"invalid-error-message", 200, `{"error":{"code":-1,"message":42}}`},
		{"invalid-error-object", 200, `{"error":"wrong"}`},
		{"invalid-result", 200, `{"result":[42]}`},
		{"invalid-json", 200, `{"result":`},
		{"empty-json", 200, ""},
		{"null-envelope", 200, "null"},
		{"array-envelope", 200, "[]"},
		{"unauthorized", 401, `{"result":{}}`},
		{"failed", 500, "private backend detail"},
		{"limit", 200, strings.Repeat(" ", 1<<20) + `{"result":{}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			wallet := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.Method != http.MethodPost || r.URL.Path != "/json_rpc" || r.Header.Get("Content-Type") != "application/json" {
					t.Error("wallet request method, path or content type changed")
				}
				user, password, ok := r.BasicAuth()
				if !ok || user != "user" || password != "password:日本語" {
					t.Error("wallet basic authentication changed")
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				var envelope map[string]any
				if err := json.Unmarshal(body, &envelope); err != nil {
					t.Error(err)
				}
				want := map[string]any{"id": "0", "jsonrpc": "2.0", "method": "fixture", "params": map[string]any{"number": float64(7), "text": "日本語"}}
				if !reflect.DeepEqual(envelope, want) {
					t.Errorf("wallet envelope = %#v", envelope)
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer wallet.Close()
			configuration := Config{MoneroWalletRPCURL: wallet.URL, MoneroWalletRPCUser: "user", MoneroWalletRPCPassword: "password:日本語"}
			parameters := map[string]any{"number": int64(7), "text": "日本語"}
			var got, want map[string]any
			actual := MoneroWallet_Request(context.Background(), configuration, "fixture", parameters, &got, errPaymentUnavailable)
			expected := baselineMoneroRPC(context.Background(), configuration, "fixture", parameters, &want)
			if !reflect.DeepEqual(got, want) || !sameIdentityError(actual, expected) {
				t.Fatalf("request = %#v, %v; baseline = %#v, %v", got, actual, want, expected)
			}
			if requests != 2 {
				t.Fatalf("wallet request count = %d", requests)
			}
		})
	}
}

func TestZiranMoneroWalletCreateAddressAgainstBaseline(t *testing.T) {
	for _, response := range []string{
		`{"result":{"address":"4日本語","address_index":17}}`,
		`{"result":{"address":"","address_index":17}}`,
		`{"result":{"address_index":17}}`,
		`{"result":{"address":42}}`,
		`{"result":{"address":"4address","address_index":"wrong"}}`,
		`{"error":{"message":"creation failed"}}`,
	} {
		t.Run(response, func(t *testing.T) {
			wallet := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var envelope struct {
					Method string         `json:"method"`
					Params map[string]any `json:"params"`
				}
				if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
					t.Error(err)
				}
				if envelope.Method != "create_address" || !reflect.DeepEqual(envelope.Params, map[string]any{"account_index": float64(0), "label": "account 日本語"}) {
					t.Error("address request changed")
				}
				_, _ = io.WriteString(w, response)
			}))
			defer wallet.Close()
			configuration := Config{MoneroWalletRPCURL: wallet.URL}
			got := MoneroWallet_CreateAddress(context.Background(), configuration, "account 日本語", errPaymentUnavailable)
			address, index, err := baselineCreateMoneroSubaddress(context.Background(), configuration, "account 日本語")
			if got.Address != address || got.Index != index || !sameIdentityError(got.Error, err) {
				t.Fatalf("address = %#v; baseline = %q %d %v", got, address, index, err)
			}
		})
	}
	got := MoneroWallet_CreateAddress(context.Background(), Config{}, "", errPaymentUnavailable)
	if !errors.Is(got.Error, errPaymentUnavailable) || got.Address != "" || got.Index != 0 {
		t.Fatal("missing wallet lost unavailable error identity")
	}
}

func TestZiranMoneroWalletInvoiceAgainstBaseline(t *testing.T) {
	incoming := []baselineMoneroTransferRPC{
		{TxID: "confirmed", Amount: 7, Confirmations: 10},
		{TxID: "unconfirmed", Amount: 3, Confirmations: 9},
		{TxID: "locked", Amount: 5, Confirmations: 10, Locked: true},
		{TxID: "unlock", Amount: 5, Confirmations: 10, UnlockTime: 1},
		{TxID: "double", Amount: 5, Confirmations: 10, DoubleSpendSeen: true},
		{TxID: "", Amount: 99, Confirmations: 10},
		{TxID: "zero", Amount: 0, Confirmations: 10},
		{TxID: "negative", Amount: -1, Confirmations: 10},
	}
	for index := range incoming {
		incoming[index].SubaddrIndex.Minor = 17
	}
	wrongAccount := incoming[0]
	wrongAccount.TxID = "other-account"
	wrongAccount.SubaddrIndex.Major = 1
	wrongAddress := incoming[0]
	wrongAddress.TxID = "other-address"
	wrongAddress.SubaddrIndex.Minor = 18
	incoming = append(incoming, wrongAccount, wrongAddress)
	pool := []baselineMoneroTransferRPC{incoming[0], incoming[1]}
	pool[0].Confirmations = 0
	pool[1].Amount = 11
	for _, required := range []int64{-1, 0, 1, 10, math.MaxInt64} {
		wallet := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var envelope struct {
				Method string         `json:"method"`
				Params map[string]any `json:"params"`
			}
			if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
				t.Error(err)
			}
			want := map[string]any{"in": true, "pending": true, "pool": true, "failed": false, "account_index": float64(0), "subaddr_indices": []any{float64(17)}}
			if envelope.Method != "get_transfers" || !reflect.DeepEqual(envelope.Params, want) {
				t.Error("invoice transfer query changed")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"in": incoming, "pool": pool}})
		}))
		configuration := Config{MoneroWalletRPCURL: wallet.URL, MoneroConfirmationsRequired: required}
		invoice := MoneroInvoiceResponse{AddressIndex: 17}
		got := MoneroWallet_InspectInvoice(context.Background(), configuration, invoice, errPaymentUnavailable)
		want, err := baselineInspectMoneroInvoicePayment(context.Background(), configuration, invoice)
		if got.Value.PaymentID != want.PaymentID || got.Value.SeenAtomic != want.SeenAtomic || got.Value.ConfirmedAtomic != want.ConfirmedAtomic || !sameIdentityError(got.Error, err) {
			t.Fatalf("invoice = %#v; baseline = %#v %v", got, want, err)
		}
		wallet.Close()
	}
}
