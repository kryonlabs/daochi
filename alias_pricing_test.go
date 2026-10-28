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

func premiumAliasFixture(t *testing.T) (*Server, []string, http.Handler) {
	t.Helper()
	server, users := socialHTTPFixture(t)
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	server.Cfg.WaoziIssuerPublicKey = public
	server.Cfg.WaoziIssuerPrivateKey = private
	server.Cfg.PremiumAliasesEnabled = true
	for _, user := range users {
		credit := TokenLedger_CreditPayment(server.Store.Database, context.Background(), private,
			"monero", "alias-fixture:"+user, TokenEventInput{
				AccountID: user, AppID: "entity", EventType: "credit", AmountDelta: 2000 * UnitsPerDew,
				SourceType: "monero", SourceRef: "alias-fixture",
			}, errTokenIssuerReadOnly)
		if credit.Error != nil {
			t.Fatal(credit.Error)
		}
	}
	return server, users, server.Routes()
}

func aliasRequest(server *Server, handler http.Handler, user, method, path, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	if user != "" {
		request.Header.Set("Authorization", "Bearer "+Token_IssueAuthToken(server.Cfg.TokenSecret, user, time.Now().Add(time.Hour).Unix()).Value)
		request.Header.Set("X-Daochi-User", user)
	}
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func aliasPurchaseBody(alias string, units int64, requestID string) string {
	return fmt.Sprintf(`{"alias":%q,"price_units":%d,"request_id":%q}`, alias, units, requestID)
}

func aliasState(t *testing.T, server *Server, user string) (string, int64) {
	t.Helper()
	var alias string
	if err := server.Store.Database.QueryRow("SELECT COALESCE(alias,'') FROM server_users WHERE user_id_hash=?", user).Scan(&alias); err != nil {
		t.Fatal(err)
	}
	balance := TokenLedger_Balance(server.Store.Database, context.Background(), user, "waozi:token")
	if balance.Error != nil {
		t.Fatal(balance.Error)
	}
	return alias, balance.Value
}

func TestPremiumAliasCatalogAndMinimum(t *testing.T) {
	for _, words := range []string{CommonNames, CommonWords, BrandWords} {
		seen := make(map[string]bool)
		for _, alias := range strings.Fields(words) {
			if !Identity_ValidAccountAlias(alias) || seen[alias] {
				t.Fatalf("invalid or repeated catalog entry %q", alias)
			}
			seen[alias] = true
		}
	}
	for _, alias := range []string{"abc", strings.Repeat("a", 33), "Abcd", "abc-", "abcdé"} {
		if Identity_ValidAccountAlias(alias) {
			t.Fatalf("invalid alias accepted: %q", alias)
		}
	}
	if !Identity_ValidAccountAlias(strings.Repeat("a", 32)) {
		t.Fatal("32-character name rejected")
	}
	for position := 0; position < 4; position++ {
		for _, char := range "abcdefghijklmnopqrstuvwxyz0123456789_" {
			name := []byte("zzzz")
			name[position] = byte(char)
			if !Identity_ValidAccountAlias(string(name)) || AliasCatalog_Find(string(name)).Units <= 0 {
				t.Fatalf("four-character alias is free or invalid: %q", name)
			}
		}
	}
	for alias, dew := range map[string]int64{"zzzz": 100, "12_a": 100, "james": 250, "moon": 250, "nike": 1000, "google": 1000, "waozi": 1000, "google_fan": 0, "mynewname": 0} {
		if price := AliasCatalog_Find(alias).Units; price != dew*UnitsPerDew {
			t.Fatalf("%s price %d, want %d DEW", alias, price, dew)
		}
	}
}

func TestPremiumAliasConfigurationAndQuotes(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("DAOCHI_PREMIUM_ALIASES_ENABLED", "")
	if Config_Load().PremiumAliasesEnabled {
		t.Fatal("other nodes unexpectedly enabled premium names")
	}
	t.Setenv("DAOCHI_PREMIUM_ALIASES_ENABLED", "true")
	if !Config_Load().PremiumAliasesEnabled {
		t.Fatal("production setting did not enable premium names")
	}
	server, users, handler := premiumAliasFixture(t)
	for _, sample := range []struct {
		query, alias, category string
		dew                    int64
	}{
		{"%20%40GoOgLe%20", "google", "brand", 1000},
		{"james", "james", "common", 250},
		{"zzzz", "zzzz", "four_character", 100},
		{"12_a", "12_a", "four_character", 100},
		{"google_fan", "google_fan", "standard", 0},
	} {
		res := aliasRequest(server, handler, users[0], "GET", "/api/v1/account/alias?alias="+sample.query, "")
		var quote AliasQuote
		if err := json.Unmarshal(res.Body.Bytes(), &quote); err != nil {
			t.Fatal(err)
		}
		if res.Code != 200 || quote.Alias != sample.alias || quote.Category != sample.category ||
			quote.PriceUnits != sample.dew*UnitsPerDew || !quote.Enabled || !quote.Available || quote.Owned ||
			quote.MinimumLength != 4 || quote.MaximumLength != 32 || quote.UnitsPerDew != 1000000 ||
			res.Header().Get("Cache-Control") != "private, no-store" {
			t.Fatalf("quote: %d %s", res.Code, res.Body.String())
		}
	}
	for _, enabled := range []bool{true, false} {
		server.Cfg.PremiumAliasesEnabled = enabled
		res := aliasRequest(server, handler, "", "GET", "/api/v1/node", "")
		if res.Code != 200 || strings.Contains(res.Body.String(), "premium-usernames-v1") != enabled {
			t.Fatalf("node rollout flag %t: %d %s", enabled, res.Code, res.Body.String())
		}
	}
}

func TestPremiumAliasKeepsExistingOwnersAndFreeClaims(t *testing.T) {
	server, users, handler := premiumAliasFixture(t)
	for i, alias := range []string{"google", "moon", "amy"} {
		if _, err := server.Store.Database.Exec("UPDATE server_users SET alias=? WHERE user_id_hash=?", alias, users[i]); err != nil {
			t.Fatal(err)
		}
		res := aliasRequest(server, handler, users[i], "GET", "/api/v1/account/alias?alias="+alias, "")
		var quote map[string]any
		if err := json.Unmarshal(res.Body.Bytes(), &quote); err != nil {
			t.Fatal(err)
		}
		if res.Code != 200 || quote["owned"] != true || quote["available"] != false || quote["price_units"] != float64(0) {
			t.Fatalf("existing owner's quote: %d %s", res.Code, res.Body.String())
		}
		res = aliasRequest(server, handler, users[i], "POST", "/api/v1/account/alias", fmt.Sprintf(`{"alias":%q}`, alias))
		if res.Code != 200 {
			t.Fatalf("keeping existing name: %d %s", res.Code, res.Body.String())
		}
		actual, balance := aliasState(t, server, users[i])
		if actual != alias || balance != 2000*UnitsPerDew {
			t.Fatal("existing username or balance changed")
		}
	}
	res := aliasRequest(server, handler, users[1], "POST", "/api/v1/account/alias/purchase", aliasPurchaseBody("google", 1000*UnitsPerDew, "taken-name-claim"))
	if res.Code != 409 {
		t.Fatalf("another owner's name offered: %d %s", res.Code, res.Body.String())
	}
	res = aliasRequest(server, handler, users[0], "POST", "/api/v1/account/alias", `{"alias":"@mynewname"}`)
	if res.Code != 200 {
		t.Fatalf("free rename failed: %d %s", res.Code, res.Body.String())
	}
	actual, balance := aliasState(t, server, users[0])
	if actual != "mynewname" || balance != 2000*UnitsPerDew {
		t.Fatal("free rename charged DEW")
	}
	server.Cfg.PremiumAliasesEnabled = false
	res = aliasRequest(server, handler, users[0], "POST", "/api/v1/account/alias", `{"alias":"zzzz"}`)
	if res.Code != 200 {
		t.Fatalf("disabled node changed legacy behavior: %d %s", res.Code, res.Body.String())
	}
}

func TestPremiumAliasPurchaseIsAtomicAndRetrySafe(t *testing.T) {
	server, users, handler := premiumAliasFixture(t)
	user := users[0]
	claim := aliasPurchaseBody(" @GoOgLe ", 1000*UnitsPerDew, "paid-claim-0001")
	for _, body := range []string{`{"alias":"google"}`, claim} {
		res := aliasRequest(server, handler, user, "POST", "/api/v1/account/alias", body)
		if res.Code != 402 {
			t.Fatalf("legacy endpoint allowed a premium claim: %d %s", res.Code, res.Body.String())
		}
	}
	if alias, balance := aliasState(t, server, user); alias != "user0" || balance != 2000*UnitsPerDew {
		t.Fatal("unconfirmed purchase changed account")
	}
	res := aliasRequest(server, handler, user, "POST", "/api/v1/account/alias/purchase", claim)
	var first struct {
		Alias string `json:"alias"`
		Price int64  `json:"price_units"`
		ID    string `json:"receipt_id"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if res.Code != 200 || first.Alias != "google" || first.Price != 1000*UnitsPerDew || first.ID == "" {
		t.Fatalf("purchase: %d %s", res.Code, res.Body.String())
	}
	for i := 0; i < 3; i++ {
		again := aliasRequest(server, handler, user, "POST", "/api/v1/account/alias/purchase", claim)
		if again.Code != 200 || again.Body.String() != res.Body.String() {
			t.Fatalf("retry changed result: %d %s", again.Code, again.Body.String())
		}
	}
	if alias, balance := aliasState(t, server, user); alias != "google" || balance != 1000*UnitsPerDew {
		t.Fatal("purchase or retry charged incorrectly")
	}
	receipt := TokenLedger_ByID(server.Store.Database, context.Background(), first.ID)
	if receipt.Error != nil || !receipt.Found || !TokenReceipt_ValidSignature(server.Cfg.WaoziIssuerPublicKey, receipt.Value) ||
		receipt.Value.AppID != "entity" || receipt.Value.SourceType != "username" || receipt.Value.SourceRef != "google" {
		t.Fatalf("purchase has no valid signed username receipt: %+v", receipt)
	}
	for _, body := range []string{aliasPurchaseBody("apple", 1000*UnitsPerDew, "paid-claim-0001"), aliasPurchaseBody("google", 100*UnitsPerDew, "paid-claim-0001")} {
		if changed := aliasRequest(server, handler, user, "POST", "/api/v1/account/alias/purchase", body); changed.Code != 409 {
			t.Fatalf("conflicting retry: %d %s", changed.Code, changed.Body.String())
		}
	}
	if renamed := aliasRequest(server, handler, user, "POST", "/api/v1/account/alias", `{"alias":"anothername"}`); renamed.Code != 200 {
		t.Fatal("free rename failed")
	}
	// Once released, another account can buy the name; the old receipt cannot reclaim it.
	if other := aliasRequest(server, handler, users[1], "POST", "/api/v1/account/alias/purchase", aliasPurchaseBody("google", 1000*UnitsPerDew, "other-paid-claim")); other.Code != 200 {
		t.Fatalf("released name purchase: %d %s", other.Code, other.Body.String())
	}
	if replay := aliasRequest(server, handler, user, "POST", "/api/v1/account/alias/purchase", claim); replay.Code != 409 {
		t.Fatalf("stale retry: %d %s", replay.Code, replay.Body.String())
	}
	if alias, balance := aliasState(t, server, user); alias != "anothername" || balance != 1000*UnitsPerDew {
		t.Fatal("stale retry changed current username or balance")
	}
}

func TestPremiumAliasFailuresLeaveNameAndDEWUntouched(t *testing.T) {
	server, users, handler := premiumAliasFixture(t)
	user := users[0]
	cases := []struct {
		body string
		want int
	}{
		{aliasPurchaseBody("abc", 100*UnitsPerDew, "invalid-name-claim"), 400},
		{aliasPurchaseBody("zzzz", 100*UnitsPerDew, "short"), 400},
		{aliasPurchaseBody("zzzz", -1, "negative-price-claim"), 400},
		{aliasPurchaseBody("zzzz", 0, "unconfirmed-claim"), 402},
		{aliasPurchaseBody("zzzz", 99*UnitsPerDew, "wrong-price-claim"), 409},
		{aliasPurchaseBody("mynewname", 100*UnitsPerDew, "wrong-free-price"), 409},
		{`{"alias":"zzzz","price_units":100000000,"request_id":"extra-field-claim","other":true}`, 400},
		{`{"alias":"zzzz","alias":"yyyy","price_units":100000000,"request_id":"duplicate-claim"}`, 400},
		{`not json`, 400},
	}
	for _, c := range cases {
		res := aliasRequest(server, handler, user, "POST", "/api/v1/account/alias/purchase", c.body)
		if res.Code != c.want {
			t.Fatalf("%s: %d %s, want %d", c.body, res.Code, res.Body.String(), c.want)
		}
	}
	for _, method := range []string{"GET", "POST"} {
		path := "/api/v1/account/alias?alias=zzzz"
		if method == "POST" {
			path = "/api/v1/account/alias/purchase"
		}
		if res := aliasRequest(server, handler, "", method, path, aliasPurchaseBody("zzzz", 100*UnitsPerDew, "unauthorized-claim")); res.Code != 401 {
			t.Fatalf("unauthenticated %s: %d", method, res.Code)
		}
	}
	// Insufficient balance and signer failure happen after the alias UPDATE,
	// so these assertions exercise rollback of both the name and payment.
	drained := TokenLedger_Spend(server.Store.Database, context.Background(), server.Cfg.WaoziIssuerPrivateKey,
		TokenEventInput{AccountID: user, AppID: "entity", EventType: "debit", AmountDelta: -1950 * UnitsPerDew,
			SourceType: "test", SourceRef: "insufficient-fixture"}, "insufficient-fixture", errTokenIssuerReadOnly)
	if drained.Error != nil {
		t.Fatal(drained.Error)
	}
	res := aliasRequest(server, handler, user, "POST", "/api/v1/account/alias/purchase", aliasPurchaseBody("zzzz", 100*UnitsPerDew, "unaffordable-claim"))
	if res.Code != 402 {
		t.Fatalf("unaffordable: %d %s", res.Code, res.Body.String())
	}
	if alias, balance := aliasState(t, server, user); alias != "user0" || balance != 50*UnitsPerDew {
		t.Fatal("failed purchase changed account")
	}
	server.Cfg.WaoziIssuerPrivateKey = nil
	res = aliasRequest(server, handler, users[1], "POST", "/api/v1/account/alias/purchase", aliasPurchaseBody("zzzz", 100*UnitsPerDew, "missing-issuer-claim"))
	if res.Code != 503 {
		t.Fatalf("missing issuer: %d %s", res.Code, res.Body.String())
	}
	if alias, balance := aliasState(t, server, users[1]); alias != "user1" || balance != 2000*UnitsPerDew {
		t.Fatal("missing issuer changed account")
	}
	var debits int
	if err := server.Store.Database.QueryRow("SELECT COUNT(*) FROM token_ledger WHERE source_type='username'").Scan(&debits); err != nil || debits != 0 {
		t.Fatalf("failed purchases left debits: %d %v", debits, err)
	}
}

func TestPremiumAliasConcurrentClaimsHaveOneWinner(t *testing.T) {
	server, users, handler := premiumAliasFixture(t)
	var group sync.WaitGroup
	codes := make(chan int, 2)
	start := make(chan struct{})
	for i, user := range users[:2] {
		group.Add(1)
		go func(i int, user string) {
			defer group.Done()
			<-start
			res := aliasRequest(server, handler, user, "POST", "/api/v1/account/alias/purchase", aliasPurchaseBody("zzzz", 100*UnitsPerDew, fmt.Sprintf("concurrent-claim-%d", i)))
			codes <- res.Code
		}(i, user)
	}
	close(start)
	group.Wait()
	close(codes)
	counts := make(map[int]int)
	for code := range codes {
		counts[code]++
	}
	if counts[200] != 1 || counts[409] != 1 {
		t.Fatalf("concurrent claims: %v", counts)
	}
	var debits int
	if err := server.Store.Database.QueryRow("SELECT COUNT(*) FROM token_ledger WHERE source_type='username'").Scan(&debits); err != nil || debits != 1 {
		t.Fatalf("concurrent claims charged %d times: %v", debits, err)
	}
}

func TestPremiumAliasEmptyNameIsNotGrandfathered(t *testing.T) {
	server, users, handler := premiumAliasFixture(t)
	if _, err := server.Store.Database.Exec("UPDATE server_users SET alias=NULL WHERE user_id_hash=?", users[0]); err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"GET", "POST"} {
		res := aliasRequest(server, handler, users[0], method, "/api/v1/account/alias", `{}`)
		if res.Code != 400 {
			t.Fatalf("empty name %s: %d %s", method, res.Code, res.Body.String())
		}
	}
	if alias, balance := aliasState(t, server, users[0]); alias != "" || balance != 2000*UnitsPerDew {
		t.Fatal("empty name changed account")
	}
}
