package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"log/slog"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestZiranPaymentRequestBytesAndValidationMatchBaseline(t *testing.T) {
	type result struct {
		value any
		body  []byte
		error error
	}
	readers := []struct {
		name     string
		actual   func(http.ResponseWriter, *http.Request, int64) result
		baseline func(http.ResponseWriter, *http.Request, int64) result
	}{
		{"spend", func(w http.ResponseWriter, r *http.Request, limit int64) result {
			value := PaymentRequest_ReadSpend(w, r, limit)
			return result{value.Value, value.Body, value.Error}
		}, func(w http.ResponseWriter, r *http.Request, limit int64) result {
			value, body, err := baselinePaymentReadTokenSpendRequest(w, r, limit)
			return result{value, body, err}
		}},
		{"google", func(w http.ResponseWriter, r *http.Request, limit int64) result {
			value := PaymentRequest_ReadGoogle(w, r, limit)
			return result{value.Value, value.Body, value.Error}
		}, func(w http.ResponseWriter, r *http.Request, limit int64) result {
			value, body, err := baselinePaymentReadGooglePurchaseVerifyRequest(w, r, limit)
			return result{value, body, err}
		}},
		{"invoice", func(w http.ResponseWriter, r *http.Request, limit int64) result {
			value := PaymentRequest_ReadInvoice(w, r, limit)
			return result{value.Value, value.Body, value.Error}
		}, func(w http.ResponseWriter, r *http.Request, limit int64) result {
			value, body, err := baselinePaymentReadMoneroInvoiceRequest(w, r, limit)
			return result{value, body, err}
		}},
	}
	inputs := []string{
		"", "null", "{}", "[]", "{", "true", "{}{}", "{} trailing",
		`{"app_id":" target ","amount":5,"action":" unlock ","idempotency_key":" request-1 ","metadata":" 日本語 ","product_id":" product ","package_name":" package ","purchase_token":" token "}`,
		`{"app_id":"target","asset_id":" custom ","amount":9223372036854775807,"action":"unlock","idempotency_key":"request-1"}`,
		`{"app_id":"target","amount":9223372036854775808,"action":"unlock","idempotency_key":"request-1"}`,
		`{"app_id":"target","amount":-1,"action":"unlock","idempotency_key":"request-1"}`,
		`{"app_id":"target","amount":1.5,"action":"unlock","idempotency_key":"request-1"}`,
		`{"app_id":"bad/app","amount":0,"action":"bad/action","idempotency_key":""}`,
		`{"app_id":"target","amount":2,"action":"bad/action","idempotency_key":""}`,
		`{"app_id":"target","amount":2,"action":"unlock","idempotency_key":"bad/id"}`,
		`{"app_id":"first","app_id":"target","amount":2,"action":"unlock","idempotency_key":"request-1"}`,
		"{\"app_id\":\"target\",\"product_id\":\"\xff\"}",
	}
	random := rand.New(rand.NewSource(20261002))
	for index := 0; index < 200; index++ {
		data := make([]byte, random.Intn(160))
		_, _ = random.Read(data)
		inputs = append(inputs, string(data))
	}
	for _, reader := range readers {
		t.Run(reader.name, func(t *testing.T) {
			for _, input := range inputs {
				for _, limit := range []int64{-1, 0, 1, int64(len(input)), int64(len(input) - 1), 4096} {
					actualWriter, baselineWriter := httptest.NewRecorder(), httptest.NewRecorder()
					actual := reader.actual(actualWriter, httptest.NewRequest("POST", "/", strings.NewReader(input)), limit)
					baseline := reader.baseline(baselineWriter, httptest.NewRequest("POST", "/", strings.NewReader(input)), limit)
					if !reflect.DeepEqual(actual.value, baseline.value) || !reflect.DeepEqual(actual.body, baseline.body) || websocketErrorText(actual.error) != websocketErrorText(baseline.error) {
						t.Fatalf("input %q, limit %d: %#v; baseline %#v", input, limit, actual, baseline)
					}
					compareHTTPResponse(t, actualWriter, baselineWriter)
				}
			}
		})
	}
}

func TestZiranPaymentPolicyValuesMatchBaseline(t *testing.T) {
	for _, privateSize := range []int{0, 31, 32, 63, 64, 65} {
		for _, publicSize := range []int{0, 31, 32, 33, 64} {
			configuration := Config{
				WaoziIssuerPrivateKey: bytes.Repeat([]byte{42}, privateSize),
				WaoziIssuerPublicKey:  bytes.Repeat([]byte{43}, publicSize),
			}
			server := &Server{Cfg: configuration, Signer: signAccountProof}
			if got, want := TokenPolicy_IssuerStatus(configuration), server.baselinePaymentTokenIssuerStatus(); got != want {
				t.Fatalf("issuer status changed for key sizes %d/%d: %s/%s", privateSize, publicSize, got, want)
			}
			got := TokenPolicy_Issuer(configuration, errTokenIssuerReadOnly)
			want, err := server.baselinePaymentRequireTokenIssuer()
			if !reflect.DeepEqual(got.Value, want) || got.Error != err {
				t.Fatal("issuer key or error identity changed")
			}
			if len(got.Value) != 0 {
				got.Value[0] = 1
				if want[0] != 1 {
					t.Fatal("issuer key no longer shares native storage")
				}
			}
		}
	}
	random := rand.New(rand.NewSource(20261003))
	for index := 0; index < 300; index++ {
		data := make([]byte, random.Intn(400))
		_, _ = random.Read(data)
		if TokenPolicy_ShortHash(string(data)) != baselinePaymentShortHash(string(data)) {
			t.Fatal("short hash changed for arbitrary bytes")
		}
	}
	for _, app := range []string{"", "target", " target ", "\u2003target\u2003", "bad/app", "target&other", "\xff", strings.Repeat("a", 100)} {
		request := httptest.NewRequest("GET", "/?app_id="+url.QueryEscape(app), nil)
		got := PaymentRequest_AppFilter(request)
		want, scoped, err := baselinePaymentTokenAppFilter(request)
		if got.Value != want || got.Scoped != scoped || websocketErrorText(got.Error) != websocketErrorText(err) {
			t.Fatalf("app filter changed for %q", app)
		}
	}
	for _, products := range []map[string]TokenProduct{
		nil, {}, {"empty": {}}, {"zero": {TokenUnits: 5}},
		{"negative": {TokenUnits: -1, MoneroAtomicAmount: 5}},
		{"valid": {TokenUnits: 5, MoneroAtomicAmount: 6}},
	} {
		want := false
		for _, product := range products {
			want = want || product.TokenUnits > 0 && product.MoneroAtomicAmount > 0
		}
		if TokenPolicy_HasMoneroProduct(products) != want {
			t.Fatal("Monero product availability changed")
		}
	}
}

func paymentHTTPFixture(t *testing.T) (*Server, string, ed25519.PrivateKey) {
	t.Helper()
	server, account, key := registryHTTPFixture(t)
	server.Cfg.WaoziIssuerPrivateKey = tokenLedgerSigner()
	server.Cfg.WaoziIssuerPublicKey = tokenLedgerSigner().Public().(ed25519.PublicKey)
	server.Cfg.TokenProducts = map[string]TokenProduct{
		"z": {ProductID: "z", TokenUnits: 50, MoneroAtomicAmount: 100},
		"a": {ProductID: "a", TokenUnits: 10, MoneroAtomicAmount: 20},
	}
	return server, account, key
}

func paymentHTTPRequest(server *Server, account string, method, path string, body []byte) *http.Request {
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	token := Token_IssueAuthToken(server.Cfg.TokenSecret, account, time.Now().Add(time.Hour).Unix()).Value
	request.Header.Set("Authorization", "Bearer "+token)
	return request
}

func TestZiranPaymentReadHandlersMatchBaseline(t *testing.T) {
	for _, mode := range []string{"normal", "direct purchases", "empty products", "read only", "missing issuer", "unauthenticated", "invalid app", "cancelled", "closed database", "rate limited", "no limiter"} {
		t.Run(mode, func(t *testing.T) {
			actual, account, _ := paymentHTTPFixture(t)
			baseline, _, _ := paymentHTTPFixture(t)
			seedMatchingTokenLedgers(t, actual.Store, baseline.Store)
			for _, server := range []*Server{actual, baseline} {
				switch mode {
				case "direct purchases":
					server.Cfg.TokenDirectPurchasesEnabled = true
				case "empty products":
					server.Cfg.TokenProducts = nil
				case "read only":
					server.Cfg.WaoziIssuerPrivateKey = nil
				case "missing issuer":
					server.Cfg.WaoziIssuerPrivateKey = nil
					server.Cfg.WaoziIssuerPublicKey = nil
				case "closed database":
					_ = server.Store.Close()
				case "no limiter":
					server.Limiter = nil
				}
			}
			query := "?app_id=inbe&since=0"
			if mode == "invalid app" {
				query = "?app_id=bad%2Fapp&since=bad"
			}
			var receiptID string
			if err := baseline.Store.Database.QueryRow("SELECT receipt_id FROM token_ledger ORDER BY ledger_seq LIMIT 1").Scan(&receiptID); err != nil && mode != "closed database" {
				t.Fatal(err)
			}
			if mode == "closed database" {
				receiptID = strings.Repeat("a", 32)
			}
			handlers := []struct {
				path     string
				actual   func(Tokens, http.ResponseWriter, *http.Request)
				baseline func(http.ResponseWriter, *http.Request)
			}{
				{"/api/v1/tokens/assets", TokenHttp_Assets, baseline.baselinePaymentHandleTokenAssets},
				{"/api/v1/tokens/products", TokenHttp_Products, baseline.baselinePaymentHandleTokenProducts},
				{"/api/v1/tokens/issuer", TokenHttp_Issuer, baseline.baselinePaymentHandleTokenIssuer},
				{"/api/v1/tokens/balance" + query, TokenHttp_Balance, baseline.baselinePaymentHandleTokenBalance},
				{"/api/v1/tokens/ledger" + query, TokenHttp_Ledger, baseline.baselinePaymentHandleTokenLedger},
				{"/api/v1/tokens/receipts/" + receiptID, TokenHttp_Receipt, baseline.baselinePaymentHandleTokenReceipt},
				{"/api/v1/tokens/receipts/bad", TokenHttp_Receipt, baseline.baselinePaymentHandleTokenReceipt},
				{"/api/v1/tokens/checkpoints/latest", TokenHttp_LatestCheckpoint, baseline.baselinePaymentHandleTokenCheckpointLatest},
			}
			for _, handler := range handlers {
				writers := []*httptest.ResponseRecorder{httptest.NewRecorder(), httptest.NewRecorder()}
				for index, server := range []*Server{actual, baseline} {
					request := paymentHTTPRequest(server, account, "GET", handler.path, nil)
					if mode == "unauthenticated" {
						request.Header.Del("Authorization")
					}
					if mode == "cancelled" {
						ctx, cancel := context.WithCancel(t.Context())
						cancel()
						request = request.WithContext(ctx)
					}
					if mode == "rate limited" && strings.Contains(handler.path, "/receipts/") {
						for count := 0; count < 60; count++ {
							server.allowRequest(request, "token-receipt:"+ClientAddress_FromRequest(request), 60, time.Minute)
						}
					}
					if index == 0 {
						handler.actual(server.tokens(), writers[index], request)
					} else {
						handler.baseline(writers[index], request)
					}
				}
				compareHTTPResponse(t, writers[0], writers[1])
			}
			if actual.Metrics.RateLimitedRequests != baseline.Metrics.RateLimitedRequests || actual.Metrics.AuthFailures != baseline.Metrics.AuthFailures {
				t.Fatal("payment rejection counters changed")
			}
		})
	}
}

func TestZiranPaymentAuthorizationAndReplayMatchBaseline(t *testing.T) {
	for _, mode := range []string{"unsigned", "signed", "malformed", "expired", "bad signature", "replay", "invalid permission", "denied", "legacy", "signed required", "query failure", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			actual, account, key := paymentHTTPFixture(t)
			baseline, _, _ := paymentHTTPFixture(t)
			body := []byte("payment payload")
			signedHeader := signedTxHeader(t, account, "target", "device-key", "POST", "/api/v1/tokens/spend", body, key, "payment-authorization")
			decoded, err := base64.RawURLEncoding.DecodeString(signedHeader)
			if err != nil {
				t.Fatal(err)
			}
			var transaction SignedTxEnvelope
			if err := json.Unmarshal(decoded, &transaction); err != nil {
				t.Fatal(err)
			}
			if mode == "expired" {
				transaction.ExpiresAt = time.Now().Add(-time.Hour).Unix()
				signDeviceTransaction(&transaction, key)
			}
			if mode == "bad signature" {
				transaction.DeviceSignature = strings.Repeat("0", 128)
			}
			wire, err := json.Marshal(transaction)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "malformed" {
				wire = []byte("{")
			}
			permission := "spend"
			if mode == "invalid permission" {
				permission = "bad"
			}
			for _, server := range []*Server{actual, baseline} {
				if mode == "denied" || mode == "legacy" || mode == "signed required" {
					allowedPermission, until := "spend", int64(0)
					if mode == "denied" {
						allowedPermission = "purchase"
					}
					if mode == "legacy" {
						until = time.Now().Add(time.Hour).Unix()
					}
					if _, err := server.Store.Database.Exec("INSERT INTO token_app_permissions(app_id,asset_id,permission,status,legacy_unsigned_until) VALUES('target',?1,?2,'active',?3)", AssetID, allowedPermission, until); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "query failure" {
					if _, err := server.Store.Database.Exec("DROP TABLE token_app_permissions"); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "replay" {
					if err := SignedTx_Record(server.Store.Database, t.Context(), transaction, errSignedTxReplay); err != nil {
						t.Fatal(err)
					}
				}
			}
			requests := []*http.Request{
				paymentHTTPRequest(actual, account, "POST", "/api/v1/tokens/spend", body),
				paymentHTTPRequest(baseline, account, "POST", "/api/v1/tokens/spend", body),
			}
			for index, request := range requests {
				if mode != "unsigned" && mode != "legacy" && mode != "signed required" {
					request.Header.Set("X-Daochi-Tx", string(wire))
				}
				if mode == "cancelled" {
					ctx, cancel := context.WithCancel(t.Context())
					cancel()
					requests[index] = request.WithContext(ctx)
				}
			}
			got := TokenPolicy_Authorize(actual.Store.Database, requests[0].Context(), requests[0], body, account, "target", AssetID, permission, actual.Verifier.Verify, errSignedTxReplay)
			want, signed, wantError := baseline.baselinePaymentAuthorizeTokenApp(requests[1].Context(), requests[1], body, account, "target", AssetID, permission)
			if got.Signed != signed || !reflect.DeepEqual(got.Value, want) || !equalAuthenticationError(AuthenticationError_Convert(got.Authentication), wantError) {
				t.Fatalf("authorization %s changed: %#v; baseline %#v/%t/%v", mode, got, want, signed, wantError)
			}
			if got, want := signedTransactionRows(t, actual.Store), signedTransactionRows(t, baseline.Store); !reflect.DeepEqual(got, want) {
				t.Fatalf("authorization replay state changed: %#v / %#v", got, want)
			}
		})
	}
}

func TestZiranPaymentSpendFailureCleanupMatchesBaseline(t *testing.T) {
	for _, mode := range []string{"insufficient", "denied", "write failure", "log panic", "error response panic", "success response panic"} {
		t.Run(mode, func(t *testing.T) {
			actual, account, key := paymentHTTPFixture(t)
			baseline, _, _ := paymentHTTPFixture(t)
			seedMatchingTokenLedgers(t, actual.Store, baseline.Store)
			amount := int64(10)
			if mode == "insufficient" {
				amount = 1000
			}
			body, err := json.Marshal(TokenSpendRequest{AppID: "target", Amount: amount, Action: "unlock", IdempotencyKey: "payment-spend", Metadata: "日本語"})
			if err != nil {
				t.Fatal(err)
			}
			header := signedTxHeader(t, account, "target", "device-key", "POST", "/api/v1/tokens/spend", body, key, "payment-cleanup")
			originalRandom, originalLogger := cryptorand.Reader, slog.Default()
			originalLogWriter, originalLogFlags := log.Writer(), log.Flags()
			defer func() {
				cryptorand.Reader = originalRandom
				slog.SetDefault(originalLogger)
				log.SetOutput(originalLogWriter)
				log.SetFlags(originalLogFlags)
			}()
			panicValue := errors.New("payment boundary panicked")
			responses := []*httptest.ResponseRecorder{httptest.NewRecorder(), httptest.NewRecorder()}
			for index, server := range []*Server{actual, baseline} {
				if mode == "denied" {
					if _, err := server.Store.Database.Exec("INSERT INTO token_app_permissions(app_id,asset_id,permission,status) VALUES('target',?1,'purchase','active')", AssetID); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "write failure" || mode == "log panic" || mode == "error response panic" {
					if _, err := server.Store.Database.Exec("CREATE TRIGGER reject_payment BEFORE INSERT ON token_ledger BEGIN SELECT RAISE(ABORT,'payment write rejected'); END"); err != nil {
						t.Fatal(err)
					}
				}
				request := paymentHTTPRequest(server, account, "POST", "/api/v1/tokens/spend", body)
				request.Header.Set("X-Daochi-Tx", header)
				var writer http.ResponseWriter = responses[index]
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
						if strings.Contains(mode, "panic") {
							if caught != panicValue {
								t.Fatalf("payment panic = %v, expected sentinel", caught)
							}
						} else if caught != nil {
							t.Fatalf("unexpected payment panic: %v", caught)
						}
					}()
					if index == 0 {
						TokenHttp_Spend(server.tokens(), writer, request)
					} else {
						server.baselinePaymentHandleTokenSpend(writer, request)
					}
				}()
				slog.SetDefault(originalLogger)
				log.SetOutput(originalLogWriter)
				log.SetFlags(originalLogFlags)
			}
			compareHTTPResponse(t, responses[0], responses[1])
			got, want := signedTransactionRows(t, actual.Store), signedTransactionRows(t, baseline.Store)
			if !reflect.DeepEqual(got, want) || (len(got) == 1) != (mode == "success response panic") {
				t.Fatalf("payment replay cleanup changed: %#v / %#v", got, want)
			}
			actualBalance := TokenLedger_Balance(actual.Store.Database, t.Context(), account, AssetID)
			baselineBalance := TokenLedger_Balance(baseline.Store.Database, t.Context(), account, AssetID)
			if actualBalance.Error != nil || baselineBalance.Error != nil || actualBalance.Value != baselineBalance.Value {
				t.Fatal("payment balance changed")
			}
			wantBalance := int64(90)
			if mode == "success response panic" {
				wantBalance = 80
			}
			if actualBalance.Value != wantBalance {
				t.Fatalf("payment balance = %d, expected %d", actualBalance.Value, wantBalance)
			}
		})
	}
}

func TestZiranPaymentAdminHandlersMatchBaseline(t *testing.T) {
	for _, mode := range []string{"success", "generated source", "unauthenticated", "malformed", "too large", "read only", "invalid account", "invalid amount", "write failure", "closed database", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			actual, account, _ := paymentHTTPFixture(t)
			baseline, _, _ := paymentHTTPFixture(t)
			seedMatchingTokenLedgers(t, actual.Store, baseline.Store)
			payload := map[string]any{
				"account_id": " " + strings.ToUpper(account) + " ",
				"app_id":     " target ", "amount": int64(25), "source_ref": " payment-admin ",
			}
			if mode == "generated source" {
				payload["source_ref"] = ""
			}
			if mode == "invalid account" {
				payload["account_id"] = "bad"
			}
			if mode == "invalid amount" {
				payload["amount"] = -1
			}
			body, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "malformed" {
				body = []byte("{")
			}
			for _, server := range []*Server{actual, baseline} {
				switch mode {
				case "too large":
					server.Cfg.MaxBodyBytes = 1
				case "read only":
					server.Cfg.WaoziIssuerPrivateKey = nil
				case "closed database":
					_ = server.Store.Close()
				case "write failure":
					if _, err := server.Store.Database.Exec(`CREATE TRIGGER reject_admin_payment BEFORE INSERT ON token_ledger BEGIN SELECT RAISE(ABORT,'admin payment rejected'); END;
CREATE TRIGGER reject_admin_checkpoint BEFORE INSERT ON token_checkpoints BEGIN SELECT RAISE(ABORT,'admin checkpoint rejected'); END;`); err != nil {
						t.Fatal(err)
					}
				}
			}
			originalRandom := cryptorand.Reader
			defer func() { cryptorand.Reader = originalRandom }()
			for _, checkpoint := range []bool{false, true} {
				path := "/api/v1/admin/tokens/manual-credit"
				if checkpoint {
					path = "/api/v1/admin/tokens/checkpoint"
				}
				writers := []*httptest.ResponseRecorder{httptest.NewRecorder(), httptest.NewRecorder()}
				for index, server := range []*Server{actual, baseline} {
					cryptorand.Reader = bytes.NewReader(bytes.Repeat([]byte{0x42}, 4096))
					request := httptest.NewRequest("POST", path, bytes.NewReader(body))
					if mode != "unauthenticated" {
						request.Header.Set("X-Daochi-Admin", server.Cfg.AdminToken)
					}
					if mode == "cancelled" {
						ctx, cancel := context.WithCancel(t.Context())
						cancel()
						request = request.WithContext(ctx)
					}
					if index == 0 {
						if checkpoint {
							TokenHttp_CreateCheckpoint(server.tokens(), writers[index], request)
						} else {
							TokenHttp_ManualCredit(server.tokens(), writers[index], request)
						}
					} else if checkpoint {
						server.baselinePaymentHandleAdminTokenCheckpoint(writers[index], request)
					} else {
						server.baselinePaymentHandleAdminManualCredit(writers[index], request)
					}
				}
				if writers[0].Code != http.StatusOK || writers[1].Code != http.StatusOK {
					compareHTTPResponse(t, writers[0], writers[1])
					continue
				}
				if !reflect.DeepEqual(writers[0].Header(), writers[1].Header()) {
					t.Fatal("admin response headers changed")
				}
				if checkpoint {
					var got, want TokenCheckpoint
					if err := json.Unmarshal(writers[0].Body.Bytes(), &got); err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal(writers[1].Body.Bytes(), &want); err != nil {
						t.Fatal(err)
					}
					// A credit created in the preceding request has its own clock
					// value, so compare each checkpoint with its persisted result.
					for index, value := range []TokenCheckpoint{got, want} {
						store := []*Store{actual.Store, baseline.Store}[index]
						stored := TokenCheckpoint_Latest(store.Database, t.Context())
						if stored.Error != nil || !stored.Found || value != stored.Value || value.LedgerSeq != got.LedgerSeq || value.IssuerID != want.IssuerID || value.AssetID != want.AssetID {
							t.Fatal("admin checkpoint response changed")
						}
					}
				} else {
					var got, want TokenPurchaseResponse
					if err := json.Unmarshal(writers[0].Body.Bytes(), &got); err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal(writers[1].Body.Bytes(), &want); err != nil {
						t.Fatal(err)
					}
					if !TokenReceipt_ValidSignature(actual.Cfg.WaoziIssuerPublicKey, got.Receipt) || !TokenReceipt_ValidSignature(baseline.Cfg.WaoziIssuerPublicKey, want.Receipt) {
						t.Fatal("admin credit response has an invalid signature")
					}
					got.Receipt = receiptWithoutGeneratedFields(got.Receipt)
					want.Receipt = receiptWithoutGeneratedFields(want.Receipt)
					if mode == "generated source" {
						for _, value := range []string{got.Receipt.SourceRef, want.Receipt.SourceRef} {
							if !strings.HasPrefix(value, "manual:") {
								t.Fatal("generated admin source prefix changed")
							}
							if _, err := time.Parse(time.RFC3339Nano, strings.TrimPrefix(value, "manual:")); err != nil {
								t.Fatal(err)
							}
						}
						got.Receipt.SourceRef, want.Receipt.SourceRef = "", ""
					}
					if got != want || got.Status != "ok" || got.Balance != 115 {
						t.Fatalf("admin credit response changed: %#v / %#v", got, want)
					}
				}
			}
		})
	}
}
