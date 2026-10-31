package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestDewGiftsMoveOnceBetweenFriends(t *testing.T) {
	server, users := socialHTTPFixture(t)
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	server.Cfg.WaoziIssuerPublicKey = public
	server.Cfg.WaoziIssuerPrivateKey = private
	server.Cfg.DewGiftsEnabled = true
	handler := server.Routes()
	ctx := context.Background()
	database := server.Store.Database
	sender, friend, stranger := users[0], users[1], users[2]
	credit := TokenLedger_CreditPayment(database, ctx, private, "monero", "gift-fixture", TokenEventInput{
		AccountID: sender, AppID: "inbe", EventType: "credit", AmountDelta: 5 * UnitsPerDew,
		SourceType: "monero", SourceRef: "gift-fixture",
	}, errTokenIssuerReadOnly)
	if credit.Error != nil {
		t.Fatal(credit.Error)
	}
	token := func(user string) string {
		return issueTestBearer(t, server, user, time.Now().Add(time.Hour))
	}
	send := func(from string, body string, want int) map[string]any {
		t.Helper()
		res := tokenJSONRequest(t, handler, http.MethodPost, "/api/v1/tokens/gifts", token(from), []byte(body))
		if res.Code != want {
			t.Fatalf("%s: got %d %s, want %d", body, res.Code, res.Body.String(), want)
		}
		if res.Header().Get("Cache-Control") != "private, no-store" {
			t.Fatalf("gift response cache control: %q", res.Header().Get("Cache-Control"))
		}
		var result map[string]any
		if want == 200 {
			if err := json.Unmarshal(res.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
		}
		return result
	}
	balance := func(account string) int64 {
		t.Helper()
		read := TokenLedger_Balance(database, ctx, account, "waozi:token")
		if read.Error != nil {
			t.Fatal(read.Error)
		}
		return read.Value
	}
	gift := func(recipient string, units int64, requestID string) string {
		raw, err := json.Marshal(map[string]any{"recipient": recipient, "units": units, "request_id": requestID})
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}

	first := send(sender, gift(friend, 1500000, "gift-request-1"), 200)
	if first["request_id"] != "gift-request-1" || first["recipient"] != friend ||
		first["units"] != float64(1500000) || first["balance"] != float64(3500000) || first["receipt_id"] == "" {
		t.Fatalf("gift result: %v", first)
	}
	if balance(sender) != 3500000 || balance(friend) != 1500000 {
		t.Fatalf("balances after gift: %d %d", balance(sender), balance(friend))
	}
	// The same request never moves Dew twice.
	again := send(sender, gift(friend, 1500000, "gift-request-1"), 200)
	if again["receipt_id"] != first["receipt_id"] || balance(sender) != 3500000 || balance(friend) != 1500000 {
		t.Fatalf("replayed gift moved Dew again: %v", again)
	}
	send(sender, gift(friend, 1000000, "gift-request-1"), 409)
	send(sender, gift(stranger, 1500000, "gift-request-1"), 409)

	// Both receipts are signed by the issuer and name the other account.
	rows, err := database.Query("SELECT account_id,amount_delta,source_ref FROM token_ledger WHERE source_type='gift' ORDER BY ledger_seq")
	if err != nil {
		t.Fatal(err)
	}
	var moves []string
	for rows.Next() {
		var account, reference string
		var amount int64
		if err := rows.Scan(&account, &amount, &reference); err != nil {
			t.Fatal(err)
		}
		moves = append(moves, fmt.Sprintf("%s:%s:%d", account[:1], reference[:1], amount))
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(moves, " ") != "a:b:-1500000 b:a:1500000" {
		t.Fatalf("gift receipts: %v", moves)
	}
	for _, account := range []string{sender, friend} {
		listed := TokenLedger_List(database, ctx, account, "waozi:token", 0)
		if listed.Error != nil {
			t.Fatal(listed.Error)
		}
		for _, receipt := range listed.Value {
			if !TokenReceipt_ValidSignature(public, receipt) {
				t.Fatalf("unsigned receipt %s", receipt.ReceiptID)
			}
		}
	}

	// Only friends receive gifts, and a refused gift leaves no receipt.
	send(sender, gift(stranger, 1000000, "gift-request-2"), 403)
	if balance(sender) != 3500000 || balance(stranger) != 0 {
		t.Fatal("a gift to a stranger moved Dew")
	}
	send(sender, gift(friend, 4000000, "gift-request-3"), 402)
	if balance(sender) != 3500000 || balance(friend) != 1500000 {
		t.Fatal("an unaffordable gift moved Dew")
	}
	var refused int
	if err := database.QueryRow("SELECT COUNT(*) FROM token_spend_nonces WHERE idempotency_key IN ('gift:gift-request-2','gift:gift-request-3')").Scan(&refused); err != nil {
		t.Fatal(err)
	}
	if refused != 0 {
		t.Fatal("a refused gift kept its request")
	}
	for _, body := range []string{
		gift(sender, 1000000, "gift-request-4"),
		gift(friend, 0, "gift-request-4"),
		gift(friend, -1000000, "gift-request-4"),
		gift(strings.ToUpper(friend), 1000000, "gift-request-4"),
		gift(friend, 1000000, "short"),
		`{"recipient":"` + friend + `","units":1000000,"request_id":"gift-request-4","note":"hi"}`,
		`{"recipient":"` + friend + `","units":"1","request_id":"gift-request-4"}`,
		`not json`,
	} {
		send(sender, body, 400)
	}
	res := tokenJSONRequest(t, handler, http.MethodPost, "/api/v1/tokens/gifts", "", []byte(gift(friend, 1000000, "gift-request-5")))
	if res.Code != 401 {
		t.Fatalf("unauthenticated gift: %d", res.Code)
	}
	if balance(sender) != 3500000 || balance(friend) != 1500000 {
		t.Fatal("a rejected gift moved Dew")
	}

	// A gift sent before the friendship ended still answers its retry.
	if _, err := database.Exec("DELETE FROM server_friendships"); err != nil {
		t.Fatal(err)
	}
	if retried := send(sender, gift(friend, 1500000, "gift-request-1"), 200); retried["receipt_id"] != first["receipt_id"] {
		t.Fatalf("retry after unfriending: %v", retried)
	}
	send(sender, gift(friend, 1000000, "gift-request-6"), 403)

	// Without the issuer key the node cannot sign gifts.
	server.Cfg.WaoziIssuerPrivateKey = nil
	send(sender, gift(friend, 1000000, "gift-request-7"), 503)
	if balance(sender) != 3500000 || balance(friend) != 1500000 {
		t.Fatal("balances changed without the issuer")
	}
}

// Anyone can open accounts and claim game rewards with each, so gifts stay
// paused unless the node turns them on: nothing moves and nothing is spent.
func TestDewGiftsArePausedByDefault(t *testing.T) {
	server, users := socialHTTPFixture(t)
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	server.Cfg.WaoziIssuerPublicKey = public
	server.Cfg.WaoziIssuerPrivateKey = private
	handler := server.Routes()
	ctx := context.Background()
	database := server.Store.Database
	sender, friend := users[0], users[1]
	credit := TokenLedger_CreditPayment(database, ctx, private, "monero", "paused-fixture", TokenEventInput{
		AccountID: sender, AppID: "inbe", EventType: "credit", AmountDelta: 2 * UnitsPerDew,
		SourceType: "monero", SourceRef: "paused-fixture",
	}, errTokenIssuerReadOnly)
	if credit.Error != nil {
		t.Fatal(credit.Error)
	}
	token := issueTestBearer(t, server, sender, time.Now().Add(time.Hour))
	body := `{"recipient":"` + friend + `","units":1000000,"request_id":"paused-request-1"}`
	res := tokenJSONRequest(t, handler, http.MethodPost, "/api/v1/tokens/gifts", token, []byte(body))
	if res.Code != 403 || !strings.Contains(res.Body.String(), "gifts are paused") {
		t.Fatalf("paused gift: %d %s", res.Code, res.Body.String())
	}
	for account, want := range map[string]int64{sender: 2 * UnitsPerDew, friend: 0} {
		if got := TokenLedger_Balance(database, ctx, account, AssetID); got.Error != nil || got.Value != want {
			t.Fatalf("paused gift moved Dew: %s has %d, want %d", account, got.Value, want)
		}
	}
}
