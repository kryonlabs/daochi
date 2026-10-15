package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func storageAccountFixture(t *testing.T) (*Server, *Store, http.Handler, testIdentity) {
	t.Helper()
	server, store, _ := testServer(t)
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	server.Cfg.WaoziIssuerPublicKey = public
	server.Cfg.WaoziIssuerPrivateKey = private
	server.Cfg.StoragePlansEnabled = true
	server.Cfg.MoneroRateAtomicAmount = 1000000000
	server.Cfg.MoneroRateTokenUnits = UnitsPerDew
	handler := server.Routes()
	owner := newTestIdentity(t, handler, 0x75)
	credit := TokenLedger_CreditPayment(store.Database, context.Background(), private,
		"monero", "production-storage-fixture", TokenEventInput{
			AccountID: owner.UserID, AppID: "inbe", EventType: "credit", AmountDelta: 60 * UnitsPerDew,
			SourceType: "monero", SourceRef: "production-storage-fixture",
		}, errTokenIssuerReadOnly)
	if credit.Error != nil {
		t.Fatal(credit.Error)
	}
	return server, store, handler, owner
}

func TestStorageConcurrentRetriesAndInsufficientBalance(t *testing.T) {
	_, store, handler, owner := storageAccountFixture(t)
	run := func(count int, sameID bool) (int, int) {
		start := make(chan struct{})
		codes := make(chan int, count)
		var group sync.WaitGroup
		for index := 0; index < count; index++ {
			group.Add(1)
			go func(index int) {
				defer group.Done()
				id := "concurrent-same-request"
				if !sameID {
					id = fmt.Sprintf("concurrent-distinct-%d", index)
				}
				request := httptest.NewRequest(http.MethodPost, "/api/v1/storage/plan",
					strings.NewReader(fmt.Sprintf(`{"period":"monthly","request_id":%q}`, id)))
				request.Header.Set("Authorization", "Bearer "+owner.Token)
				request.Header.Set("Content-Type", "application/json")
				recorder := httptest.NewRecorder()
				<-start
				handler.ServeHTTP(recorder, request)
				codes <- recorder.Code
			}(index)
		}
		close(start)
		group.Wait()
		close(codes)
		ok, insufficient := 0, 0
		for code := range codes {
			switch code {
			case 200:
				ok++
			case 402:
				insufficient++
			default:
				t.Fatalf("concurrent upgrade returned %d", code)
			}
		}
		return ok, insufficient
	}
	if ok, insufficient := run(12, true); ok != 12 || insufficient != 0 {
		t.Fatalf("idempotent replies: %d/%d", ok, insufficient)
	}
	if ok, insufficient := run(6, false); ok != 2 || insufficient != 4 {
		t.Fatalf("bounded balance: %d/%d", ok, insufficient)
	}
	plan := StoragePlan_Read(store.Database, context.Background(), owner.UserID, time.Now().Unix())
	if plan.Error != nil || plan.Balance != 0 {
		t.Fatalf("balance: %+v", plan)
	}
	var count int
	if err := store.Database.QueryRow(`SELECT COUNT(*) FROM server_storage_purchases WHERE user_id=?`, owner.UserID).Scan(&count); err != nil || count != 3 {
		t.Fatalf("purchases: %d, %v", count, err)
	}
}

func TestStorageRejectsAmbiguousCommandsAndReadOnlyIssuer(t *testing.T) {
	server, _, handler, owner := storageAccountFixture(t)
	for _, body := range []string{
		`{"period":"monthly","period":"yearly","request_id":"duplicate-period"}`,
		`{"Period":"monthly","request_id":"wrong-case-period"}`,
		`{"period":"monthly","request_id":"unknown-field","amount":1}`,
		`{"period":"monthly","request_id":"two-values"} {}`,
	} {
		result := tokenJSONRequest(t, handler, http.MethodPost, "/api/v1/storage/plan", owner.Token, []byte(body))
		if result.Code != 400 {
			t.Fatalf("ambiguous command: %d %s", result.Code, result.Body.String())
		}
	}
	server.Cfg.WaoziIssuerPrivateKey = nil
	result := tokenJSONRequest(t, handler, http.MethodGet, "/api/v1/storage/plan", owner.Token, nil)
	var status struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(result.Body.Bytes(), &status); err != nil || result.Code != 200 || status.Enabled {
		t.Fatalf("read-only issuer advertised billing: %d %v", result.Code, err)
	}
	result = tokenJSONRequest(t, handler, http.MethodPost, "/api/v1/storage/plan", owner.Token,
		[]byte(`{"period":"monthly","request_id":"read-only-upgrade"}`))
	if result.Code != 503 {
		t.Fatalf("read-only upgrade: %d", result.Code)
	}
}

func TestStorageRejectsExpiryOverflowBeforeDebit(t *testing.T) {
	server, store, _, owner := storageAccountFixture(t)
	now := time.Date(9999, 12, 15, 0, 0, 0, 0, time.UTC).Unix()
	plan := StoragePlan_Purchase(store.Database, context.Background(), server.Cfg.WaoziIssuerPrivateKey,
		owner.UserID, "monthly", "expiry-overflow", now)
	if plan.Error == nil || plan.Error.Error() != "storage expiry out of range" {
		t.Fatalf("expiry: %+v", plan)
	}
	read := StoragePlan_Read(store.Database, context.Background(), owner.UserID, now)
	if read.Error != nil || read.Balance != 60*UnitsPerDew || read.ExpiresAt != 0 {
		t.Fatalf("charged overflow: %+v", read)
	}
}

func TestStorageProductionConfigurationIsExplicit(t *testing.T) {
	server, _, _, _ := storageAccountFixture(t)
	valid := server.Cfg
	valid.TokenDirectPurchasesEnabled = true
	valid.MoneroWalletRPCURL = "http://127.0.0.1:18083/json_rpc"
	valid.MoneroNetwork = "mainnet"
	if err := StoragePlan_ConfigurationError(valid); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Config){
		func(c *Config) { c.TokenSecretEphemeral = true },
		func(c *Config) { c.WaoziIssuerPrivateKey = nil },
		func(c *Config) { c.MoneroRateAtomicAmount = 0 },
		func(c *Config) { c.TokenDirectPurchasesEnabled = false },
		func(c *Config) { c.MoneroWalletRPCURL = "" },
		func(c *Config) { c.MoneroNetwork = "" },
	} {
		bad := valid
		change(&bad)
		if err := StoragePlan_ConfigurationError(bad); err == nil {
			t.Fatal("unsafe configuration accepted")
		}
		bad.StoragePlansEnabled = false
		if err := StoragePlan_ConfigurationError(bad); err != nil {
			t.Fatal("disabled billing blocked startup", err)
		}
	}
}
