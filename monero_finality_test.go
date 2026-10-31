package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type f03MoneroTransfer struct {
	TxID            string
	Amount          int64
	Confirmations   int64
	Height          int64
	UnlockTime      int64
	Locked          bool
	DoubleSpendSeen bool
	Major           int
	Minor           int
}

type f03MoneroWalletRPC struct {
	URL       string
	height    int64
	transfers []f03MoneroTransfer
	failRPC   bool
	malformed bool
	mu        sync.Mutex
}

func newF03MoneroWalletRPC(t *testing.T) *f03MoneroWalletRPC {
	t.Helper()
	wallet := &f03MoneroWalletRPC{height: 110}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		wallet.mu.Lock()
		defer wallet.mu.Unlock()
		if wallet.failRPC {
			http.Error(writer, "simulated wallet outage", http.StatusServiceUnavailable)
			return
		}
		var envelope struct {
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(request.Body).Decode(&envelope); err != nil {
			http.Error(writer, "invalid json", http.StatusBadRequest)
			return
		}
		authorization := request.Header.Get("Authorization")
		if !strings.HasPrefix(authorization, "Digest ") {
			writer.Header().Set("WWW-Authenticate", `Digest realm="daochi-test", qop="auth", nonce="f03-nonce", algorithm=MD5`)
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		if wallet.malformed || !f03DigestValid(authorization, request.RequestURI) {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch envelope.Method {
		case "get_height":
			f03WriteResult(writer, map[string]any{"height": wallet.height})
		case "get_transfers":
			var parameters struct {
				AccountIndex   int   `json:"account_index"`
				SubaddrIndices []int `json:"subaddr_indices"`
			}
			if err := json.Unmarshal(envelope.Params, &parameters); err != nil {
				http.Error(writer, "invalid parameters", http.StatusBadRequest)
				return
			}
			items := []map[string]any{}
			for _, transfer := range wallet.transfers {
				if transfer.Major != parameters.AccountIndex {
					continue
				}
				if len(parameters.SubaddrIndices) > 0 && transfer.Minor != parameters.SubaddrIndices[0] {
					continue
				}
				items = append(items, map[string]any{
					"txid":              transfer.TxID,
					"amount":            transfer.Amount,
					"confirmations":     transfer.Confirmations,
					"height":            transfer.Height,
					"unlock_time":       transfer.UnlockTime,
					"locked":            transfer.Locked,
					"double_spend_seen": transfer.DoubleSpendSeen,
					"subaddr_index": map[string]any{
						"major": transfer.Major,
						"minor": transfer.Minor,
					},
				})
			}
			f03WriteResult(writer, map[string]any{"in": items})
		default:
			f03WriteError(writer, "unexpected method")
		}
	}))
	t.Cleanup(server.Close)
	wallet.URL = server.URL
	return wallet
}

func f03WriteResult(writer http.ResponseWriter, result any) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{"jsonrpc": "2.0", "id": "0", "result": result})
}

func f03WriteError(writer http.ResponseWriter, message string) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"jsonrpc": "2.0", "id": "0", "error": map[string]any{"code": -1, "message": message},
	})
}

func f03AuthorizationField(authorization string, name string) string {
	authorization = strings.TrimPrefix(authorization, "Digest ")
	for _, field := range strings.Split(authorization, ",") {
		parts := strings.SplitN(strings.TrimSpace(field), "=", 2)
		if len(parts) != 2 || parts[0] != name {
			continue
		}
		return strings.Trim(parts[1], `"`)
	}
	return ""
}

func f03Digest(authorization string, method string) string {
	ha1 := f03MD5("user:daochi-test:digest-password")
	ha2 := f03MD5(method + ":" + f03AuthorizationField(authorization, "uri"))
	return f03MD5(strings.Join([]string{
		ha1,
		f03AuthorizationField(authorization, "nonce"),
		f03AuthorizationField(authorization, "nc"),
		f03AuthorizationField(authorization, "cnonce"),
		f03AuthorizationField(authorization, "qop"),
		ha2,
	}, ":"))
}

func f03MD5(value string) string {
	digest := md5.Sum([]byte(value))
	return hex.EncodeToString(digest[:])
}

func f03DigestValid(authorization string, uri string) bool {
	return f03AuthorizationField(authorization, "username") == "user" &&
		f03AuthorizationField(authorization, "realm") == "daochi-test" &&
		f03AuthorizationField(authorization, "nonce") == "f03-nonce" &&
		f03AuthorizationField(authorization, "uri") == uri &&
		f03AuthorizationField(authorization, "algorithm") == "MD5" &&
		f03AuthorizationField(authorization, "qop") == "auth" &&
		f03AuthorizationField(authorization, "response") == f03Digest(authorization, http.MethodPost)
}

func f03CreditedDeposit(t *testing.T) (*Server, *Store, *f03MoneroWalletRPC, testIdentity, MoneroAccountAddress) {
	t.Helper()
	server, store, wallet, owner, mapping := accountDepositFixture(t)
	wallet.mu.Lock()
	wallet.walletHeight = 110
	wallet.mu.Unlock()
	wallet.setTransfer(moneroTransfer{
		TxID: "f03-deposit", Amount: 1000000000, Confirmations: 10, Height: 100,
		Major: mapping.AccountIndex, Minor: mapping.AddressIndex,
	})
	if err := MoneroDeposits_Reconcile(server.monero(), context.Background()); err != nil {
		t.Fatal(err)
	}
	balance := TokenLedger_Balance(store.Database, context.Background(), owner.UserID, AssetID)
	if balance.Error != nil || balance.Value != 1000000 {
		t.Fatalf("fixture balance=%d err=%v, want 1000000", balance.Value, balance.Error)
	}
	rpc := newF03MoneroWalletRPC(t)
	server.Cfg.MoneroWalletRPCURL = rpc.URL
	server.Cfg.MoneroWalletRPCUser = "user"
	server.Cfg.MoneroWalletRPCPassword = "digest-password"
	return server, store, rpc, owner, mapping
}

func f03DepositStatus(t *testing.T, store *Store, transactionID string) string {
	t.Helper()
	var status string
	if err := store.Database.QueryRow(`SELECT status FROM monero_deposits WHERE tx_id=?1`, transactionID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	return status
}

func TestMoneroDepositMissingWalletResultHoldsWithoutDebit(t *testing.T) {
	server, store, rpc, owner, mapping := f03CreditedDeposit(t)
	rpc.mu.Lock()
	rpc.height = 200
	rpc.transfers = nil
	rpc.mu.Unlock()
	for attempt := 0; attempt < 3; attempt++ {
		if err := MoneroDeposits_Reconcile(server.monero(), context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	balance := TokenLedger_Balance(store.Database, context.Background(), owner.UserID, AssetID)
	if balance.Error != nil || balance.Value != 1000000 {
		t.Fatalf("incomplete wallet balance=%d err=%v, must retain credited funds", balance.Value, balance.Error)
	}
	if status := f03DepositStatus(t, store, "f03-deposit"); status != "conflict_hold" {
		t.Fatalf("incomplete wallet status=%s, want conflict_hold", status)
	}
	rpc.mu.Lock()
	rpc.transfers = []f03MoneroTransfer{{TxID: "f03-deposit", Amount: 1000000000,
		Height: 100, Confirmations: 100, Major: mapping.AccountIndex, Minor: mapping.AddressIndex}}
	rpc.mu.Unlock()
	if err := MoneroDeposits_Reconcile(server.monero(), context.Background()); err != nil {
		t.Fatal(err)
	}
	if status := f03DepositStatus(t, store, "f03-deposit"); status != "finalized" {
		t.Fatalf("recovered wallet status=%s, want finalized", status)
	}
	if balance := TokenLedger_Balance(store.Database, context.Background(), owner.UserID, AssetID); balance.Error != nil || balance.Value != 1000000 {
		t.Fatalf("recovered wallet changed paid balance: %+v", balance)
	}
}

func TestMoneroDepositDoubleSpendAfterCredit(t *testing.T) {
	server, store, rpc, owner, mapping := f03CreditedDeposit(t)
	rpc.mu.Lock()
	rpc.height = 111
	rpc.transfers = []f03MoneroTransfer{{
		TxID: "f03-deposit", Amount: 1000000000, Confirmations: 10, Height: 100,
		DoubleSpendSeen: true, Major: mapping.AccountIndex, Minor: mapping.AddressIndex,
	}}
	rpc.mu.Unlock()
	if err := MoneroDeposits_Reconcile(server.monero(), context.Background()); err != nil {
		t.Fatal(err)
	}
	balance := TokenLedger_Balance(store.Database, context.Background(), owner.UserID, AssetID)
	if balance.Error != nil || balance.Value != 0 {
		t.Fatalf("double-spend balance=%d err=%v, want 0", balance.Value, balance.Error)
	}
	if status := f03DepositStatus(t, store, "f03-deposit"); status != "compensated" {
		t.Fatalf("double-spend status=%s, want compensated", status)
	}
}

func TestMoneroDepositConflictAfterCreditHoldsWithoutDebit(t *testing.T) {
	server, store, rpc, owner, mapping := f03CreditedDeposit(t)
	rpc.mu.Lock()
	rpc.height = 200
	rpc.transfers = []f03MoneroTransfer{{
		TxID: "f03-deposit", Amount: 2000000000, Confirmations: 100, Height: 100,
		Major: mapping.AccountIndex, Minor: mapping.AddressIndex,
	}}
	rpc.mu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		if err := MoneroDeposits_Reconcile(server.monero(), context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	balance := TokenLedger_Balance(store.Database, context.Background(), owner.UserID, AssetID)
	if balance.Error != nil || balance.Value != 1000000 {
		t.Fatalf("conflict balance=%d err=%v, want no automatic debit", balance.Value, balance.Error)
	}
	if status := f03DepositStatus(t, store, "f03-deposit"); status != "conflict_hold" {
		t.Fatalf("conflict status=%s, want conflict_hold", status)
	}
}

func TestMoneroDepositReconcileIdempotency(t *testing.T) {
	server, store, rpc, owner, mapping := f03CreditedDeposit(t)
	rpc.mu.Lock()
	rpc.height = 200
	rpc.transfers = []f03MoneroTransfer{{
		TxID: "f03-deposit", Amount: 1000000000, Confirmations: 100, Height: 100,
		Major: mapping.AccountIndex, Minor: mapping.AddressIndex,
	}}
	rpc.mu.Unlock()
	var workers sync.WaitGroup
	var errors []error
	var errorMutex sync.Mutex
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			err := MoneroDeposits_Reconcile(server.monero(), context.Background())
			errorMutex.Lock()
			errors = append(errors, err)
			errorMutex.Unlock()
		}()
	}
	workers.Wait()
	for _, err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	balance := TokenLedger_Balance(store.Database, context.Background(), owner.UserID, AssetID)
	if balance.Error != nil || balance.Value != 1000000 {
		t.Fatalf("concurrent balance=%d err=%v, want one retained credit", balance.Value, balance.Error)
	}
	if status := f03DepositStatus(t, store, "f03-deposit"); status != "finalized" {
		t.Fatalf("finality status=%s, want finalized", status)
	}
}

func TestMoneroDepositReorgOutageThenRecoveredOnce(t *testing.T) {
	server, store, rpc, owner, mapping := f03CreditedDeposit(t)
	rpc.mu.Lock()
	rpc.failRPC = true
	rpc.mu.Unlock()
	outage := MoneroDeposits_Reconcile(server.monero(), context.Background())
	if outage == nil {
		t.Fatal("wallet outage was hidden")
	}
	balance := TokenLedger_Balance(store.Database, context.Background(), owner.UserID, AssetID)
	if balance.Error != nil || balance.Value != 1000000 {
		t.Fatalf("outage balance=%d err=%v, must not claw back", balance.Value, balance.Error)
	}
	if status := f03DepositStatus(t, store, "f03-deposit"); status != "credited" {
		t.Fatalf("outage status=%s, want credited", status)
	}
	rpc.mu.Lock()
	rpc.failRPC = false
	rpc.height = 200
	rpc.transfers = []f03MoneroTransfer{{TxID: "f03-deposit", DoubleSpendSeen: true,
		Major: mapping.AccountIndex, Minor: mapping.AddressIndex}}
	rpc.mu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		if err := MoneroDeposits_Reconcile(server.monero(), context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	balance = TokenLedger_Balance(store.Database, context.Background(), owner.UserID, AssetID)
	if balance.Error != nil || balance.Value != 0 {
		t.Fatalf("recovered outage balance=%d err=%v, want exactly one debit", balance.Value, balance.Error)
	}
}

func TestMoneroDepositInsufficientBalanceHoldsAndRetries(t *testing.T) {
	server, store, rpc, owner, mapping := f03CreditedDeposit(t)
	spent := TokenLedger_Spend(store.Database, context.Background(), server.Cfg.WaoziIssuerPrivateKey,
		TokenEventInput{AccountID: owner.UserID, AppID: "entity", EventType: "debit", AmountDelta: -900000,
			SourceType: "test", SourceRef: "f03-owner-spend"}, "f03-owner-spend", errPaymentUnavailable)
	if spent.Error != nil || spent.Balance != 100000 {
		t.Fatalf("owner spend=%d err=%v, want 100000 remaining", spent.Balance, spent.Error)
	}
	rpc.mu.Lock()
	rpc.height = 200
	rpc.transfers = []f03MoneroTransfer{{TxID: "f03-deposit", DoubleSpendSeen: true,
		Major: mapping.AccountIndex, Minor: mapping.AddressIndex}}
	rpc.mu.Unlock()
	insufficient := MoneroDeposits_Reconcile(server.monero(), context.Background())
	if insufficient == nil || !strings.Contains(insufficient.Error(), "insufficient balance") {
		t.Fatalf("insufficient reconciliation error=%v", insufficient)
	}
	if status := f03DepositStatus(t, store, "f03-deposit"); status != "compensation_hold" {
		t.Fatalf("insufficient status=%s, want compensation_hold", status)
	}
	funded := TokenLedger_CreditPayment(store.Database, context.Background(), server.Cfg.WaoziIssuerPrivateKey,
		"f03-test", "f03-recovery-funding", TokenEventInput{AccountID: owner.UserID, AppID: "entity",
			EventType: "credit", AmountDelta: 900000, SourceType: "test", SourceRef: "f03-recovery-funding"},
		errPaymentUnavailable)
	if funded.Error != nil {
		t.Fatal(funded.Error)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := MoneroDeposits_Reconcile(server.monero(), context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	balance := TokenLedger_Balance(store.Database, context.Background(), owner.UserID, AssetID)
	if balance.Error != nil || balance.Value != 0 {
		t.Fatalf("recovered balance=%d err=%v, want no created value", balance.Value, balance.Error)
	}
	if status := f03DepositStatus(t, store, "f03-deposit"); status != "compensated" {
		t.Fatalf("recovered status=%s, want compensated", status)
	}
}

func TestMoneroDepositWalletRollbackUsesExplicitHold(t *testing.T) {
	server, store, rpc, _, mapping := f03CreditedDeposit(t)
	if _, err := store.Database.Exec(`UPDATE monero_wallet_state SET last_height=600 WHERE wallet_id='default'`); err != nil {
		t.Fatal(err)
	}
	rollbackTransfer := moneroTransfer{TxID: "f03-after-rollback", Amount: 1000000000,
		Confirmations: 10, Height: 150, Major: mapping.AccountIndex, Minor: mapping.AddressIndex}
	rpc.mu.Lock()
	rpc.height = 300
	rpc.transfers = []f03MoneroTransfer{{
		TxID: rollbackTransfer.TxID, Amount: rollbackTransfer.Amount,
		Confirmations: rollbackTransfer.Confirmations, Height: rollbackTransfer.Height,
		Major: rollbackTransfer.Major, Minor: rollbackTransfer.Minor,
	}}
	rpc.mu.Unlock()
	if err := MoneroDeposits_Reconcile(server.monero(), context.Background()); err != nil {
		t.Fatal(err)
	}
	if status := f03DepositStatus(t, store, "f03-deposit"); status != "rollback_hold" {
		t.Fatalf("rollback status=%s, want rollback_hold", status)
	}
	bookmark := MoneroDepositStore_ScanHeight(store.Database, context.Background())
	if bookmark.Error != nil || bookmark.Value != 0 {
		t.Fatalf("rollback bookmark=%d err=%v, want full rescan", bookmark.Value, bookmark.Error)
	}
	var rollbackBalance int64
	if err := store.Database.QueryRow(`SELECT token_units FROM monero_deposits WHERE tx_id='f03-deposit'`).Scan(&rollbackBalance); err != nil {
		t.Fatal(err)
	}
	if rollbackBalance != 1000000 {
		t.Fatalf("rollback removed credit units=%d", rollbackBalance)
	}
}

func TestMoneroRPCTrustValidation(t *testing.T) {
	invalid := []Config{
		{MoneroWalletRPCURL: "http://wallet.example:18083", MoneroWalletRPCUser: "user", MoneroWalletRPCPassword: "password"},
		{MoneroWalletRPCURL: "ftp://wallet.example", MoneroWalletRPCUser: "user", MoneroWalletRPCPassword: "password"},
		{MoneroWalletRPCURL: "https://wallet.example", MoneroWalletRPCUser: "user"},
		{MoneroWalletRPCURL: "https://wallet.example", MoneroWalletRPCPassword: "password"},
		{MoneroWalletRPCURL: "https://wallet.example", MoneroWalletRPCUser: "user\"name", MoneroWalletRPCPassword: "password"},
		{MoneroWalletRPCURL: "://wallet.example", MoneroWalletRPCUser: "user", MoneroWalletRPCPassword: "password"},
	}
	for _, configuration := range invalid {
		if err := MoneroWallet_ValidateRPCConfiguration(configuration); err == nil {
			t.Fatalf("invalid configuration accepted: %+v", configuration)
		}
	}
	valid := []Config{
		{MoneroWalletRPCURL: "https://wallet.example", MoneroWalletRPCUser: "user", MoneroWalletRPCPassword: "password"},
		{MoneroWalletRPCURL: "http://127.0.0.1:18083", MoneroWalletRPCUser: "user", MoneroWalletRPCPassword: "password"},
		{MoneroWalletRPCURL: "http://[::1]:18083", MoneroWalletRPCUser: "user", MoneroWalletRPCPassword: "password"},
	}
	for _, configuration := range valid {
		if err := MoneroWallet_ValidateRPCConfiguration(configuration); err != nil {
			t.Fatalf("valid configuration rejected: %+v: %v", configuration, err)
		}
	}
}

func TestMoneroRPCDoesNotFollowCredentialRedirects(t *testing.T) {
	for _, status := range []int{http.StatusFound, http.StatusTemporaryRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var reached atomic.Bool
			destination := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				reached.Store(true)
				writer.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(destination.Close)
			origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				http.Redirect(writer, request, destination.URL, status)
			}))
			t.Cleanup(origin.Close)
			configuration := Config{MoneroWalletRPCURL: origin.URL, MoneroWalletRPCUser: "user", MoneroWalletRPCPassword: "password"}
			var output map[string]any
			err := MoneroWallet_Request(t.Context(), configuration, "get_height", map[string]any{}, &output, errPaymentUnavailable)
			if err == nil || reached.Load() {
				t.Fatalf("wallet redirect followed: reached=%v error=%v", reached.Load(), err)
			}
		})
	}
}

func TestMoneroRPCTrustRequestAuthentication(t *testing.T) {
	wallet := newF03MoneroWalletRPC(t)
	configuration := Config{
		MoneroWalletRPCURL: wallet.URL, MoneroWalletRPCUser: "user", MoneroWalletRPCPassword: "digest-password",
	}
	parameters := map[string]any{}
	var result struct {
		Height int64 `json:"height"`
	}
	if err := MoneroWallet_Request(context.Background(), configuration, "get_height", parameters, &result, errPaymentUnavailable); err != nil || result.Height != 110 {
		t.Fatalf("digest request height=%d err=%v", result.Height, err)
	}
	wallet.mu.Lock()
	wallet.malformed = true
	wallet.mu.Unlock()
	unauthorized := MoneroWallet_Request(context.Background(), configuration, "get_height", parameters, &result, errPaymentUnavailable)
	if unauthorized == nil || strings.Contains(unauthorized.Error(), "digest-password") {
		t.Fatalf("unauthorized request error=%v", unauthorized)
	}
}
