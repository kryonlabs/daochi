package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"math/rand"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func tokenLedgerStore(t *testing.T) *Store {
	t.Helper()
	store, err := OpenStore(filepath.Join(t.TempDir(), "ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	store.db.SetMaxOpenConns(1)
	return store
}

func tokenLedgerInput() TokenEventInput {
	return TokenEventInput{
		AccountID: strings.Repeat("a", 64), AppID: "inbe", EventType: "credit",
		AmountDelta: 100, SourceType: "purchase", SourceRef: "original purchase",
	}
}

func tokenLedgerSigner() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, 32))
}

func TestZiranTokenReceiptBytesMatchBaseline(t *testing.T) {
	random := rand.New(rand.NewSource(20261001))
	stringsToTest := []string{"", "日本語", "<>&\"\\\n\x00", "\xff\xfe", strings.Repeat("a", 256), strings.Repeat("a", 257)}
	for index := 0; index < 300; index++ {
		data := make([]byte, random.Intn(280))
		_, _ = random.Read(data)
		stringsToTest = append(stringsToTest, string(data))
	}
	key := tokenLedgerSigner()
	for index, value := range stringsToTest {
		input := tokenLedgerInput()
		input.SourceRef = value
		if got, want := TokenReceipt_Validate(input), baselineValidateTokenEventInput(baselineTokenEventInput(input)); websocketErrorText(got) != websocketErrorText(want) {
			t.Fatalf("validation changed for %q: %v/%v", value, got, want)
		}
		if got, want := TokenReceipt_SpendRequestHash(input), baselineTokenSpendRequestHash(baselineTokenEventInput(input)); got != want {
			t.Fatalf("spend hash changed for %q", value)
		}
		payload := ReceiptPayload{
			ReceiptID: value, IssuerID: "waozi", AssetID: "waozi:token", AccountID: input.AccountID,
			AppID: value, EventType: "credit", AmountDelta: int64(random.Uint64()),
			LedgerSeq: int64(index), PreviousHash: value, EventHash: "ignored when hashing",
			CreatedAt: "2026-09-30T00:00:00Z", SourceType: "purchase", SourceRef: value,
		}
		oldPayload := baselineTokenReceiptPayload(payload)
		if got, want := TokenReceipt_Canonical(payload), baselineCanonicalTokenReceiptPayload(oldPayload); !bytes.Equal(got, want) {
			t.Fatalf("canonical receipt bytes changed for %q", value)
		}
		payload.EventHash = baselineHashTokenReceiptPayload(oldPayload)
		oldPayload.EventHash = payload.EventHash
		if TokenReceipt_Hash(payload) != oldPayload.EventHash {
			t.Fatal("receipt hash changed")
		}
		signature := ed25519.Sign(key, baselineCanonicalTokenReceiptPayload(oldPayload))
		receipt := TokenReceipt_FromPayload(payload, signature)
		if want := baselineTokenReceiptFromPayload(oldPayload, signature); !reflect.DeepEqual(receipt, want) {
			t.Fatal("receipt fields or signature bytes changed")
		}
		publicKey := key.Public().(ed25519.PublicKey)
		if !baselineValidTokenReceiptSignature(publicKey, receipt) || !TokenReceipt_ValidSignature(publicKey, receipt) {
			t.Fatal("original signer receipt did not verify")
		}
		for _, invalid := range []string{"", "ff", "gg", strings.Repeat("0", 128)} {
			receipt.Signature = invalid
			if TokenReceipt_ValidSignature(publicKey, receipt) != baselineValidTokenReceiptSignature(publicKey, receipt) {
				t.Fatal("invalid signature handling changed")
			}
		}
	}
	for _, change := range []func(*TokenEventInput){
		func(value *TokenEventInput) { value.AccountID = "bad" },
		func(value *TokenEventInput) { value.AppID = "bad/app" },
		func(value *TokenEventInput) { value.EventType = "unknown" },
		func(value *TokenEventInput) { value.AmountDelta = 0 },
		func(value *TokenEventInput) { value.AmountDelta = -1 },
		func(value *TokenEventInput) { value.EventType = "debit" },
		func(value *TokenEventInput) { value.SourceType = "bad/source" },
	} {
		input := tokenLedgerInput()
		change(&input)
		if websocketErrorText(TokenReceipt_Validate(input)) != websocketErrorText(baselineValidateTokenEventInput(baselineTokenEventInput(input))) {
			t.Fatalf("ordered validation changed for %+v", input)
		}
	}
}

func seedMatchingTokenLedgers(t *testing.T, actual, baseline *Store) {
	t.Helper()
	context := context.Background()
	for index, amount := range []int64{100, 40, -10} {
		input := tokenLedgerInput()
		input.AmountDelta = amount
		input.SourceRef = "fixture"
		if index == 1 {
			input.AccountID = strings.Repeat("b", 64)
			input.AppID = ""
		}
		if amount < 0 {
			input.EventType = "debit"
		}
		tx, err := baseline.db.BeginTx(context, nil)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := baselineInsertTokenEventTx(context, tx, tokenLedgerSigner(), baselineTokenEventInput(input))
		if err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		_, err = actual.db.Exec(`INSERT INTO token_ledger(receipt_id,issuer_id,asset_id,account_id,app_id,event_type,amount_delta,ledger_seq,previous_hash,event_hash,signature,created_at,source_type,source_ref)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, receipt.ReceiptID, receipt.IssuerID, receipt.AssetID, receipt.AccountID, receipt.AppID, receipt.EventType, receipt.AmountDelta, receipt.LedgerSeq, receipt.PreviousHash, receipt.EventHash, receipt.Signature, receipt.CreatedAt, receipt.SourceType, receipt.SourceRef)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestZiranTokenLedgerReadsAndCheckpointsMatchBaseline(t *testing.T) {
	actual, baseline := tokenLedgerStore(t), tokenLedgerStore(t)
	background := context.Background()
	seedMatchingTokenLedgers(t, actual, baseline)
	for _, context := range []context.Context{background, func() context.Context {
		value, cancel := context.WithCancel(background)
		cancel()
		return value
	}()} {
		assets, err := baseline.baselineTokenAssets(context)
		got := TokenAssets_List(actual.db, context)
		if !reflect.DeepEqual(got.Value, assets) || websocketErrorText(got.Error) != websocketErrorText(err) {
			t.Fatal("asset list or errors changed")
		}
		for _, account := range []string{strings.Repeat("a", 64), strings.Repeat("b", 64), "missing"} {
			for _, asset := range []string{"waozi:token", "missing"} {
				balance, err := baseline.baselineTokenBalance(context, account, asset)
				got := TokenLedger_Balance(actual.db, context, account, asset)
				if got.Value != balance || websocketErrorText(got.Error) != websocketErrorText(err) {
					t.Fatal("balance changed")
				}
				for _, since := range []int64{math.MinInt64, 0, 1, 3, math.MaxInt64} {
					items, err := baseline.baselineTokenLedger(context, account, asset, since)
					got := TokenLedger_List(actual.db, context, account, asset, since)
					if !reflect.DeepEqual(got.Value, items) || websocketErrorText(got.Error) != websocketErrorText(err) {
						t.Fatal("ledger ordering, filtering, nil results or errors changed")
					}
					for _, app := range []string{"", "inbe", "missing"} {
						items, err := baseline.baselineTokenAppLedger(context, account, asset, app, since)
						got := TokenLedger_AppList(actual.db, context, account, asset, app, since)
						if !reflect.DeepEqual(got.Value, items) || websocketErrorText(got.Error) != websocketErrorText(err) {
							t.Fatal("app ledger changed")
						}
						balance, err := baseline.baselineTokenAppBalance(context, account, asset, app)
						appBalance := TokenLedger_AppBalance(actual.db, context, account, asset, app)
						if appBalance.Value != balance || websocketErrorText(appBalance.Error) != websocketErrorText(err) {
							t.Fatal("app balance changed")
						}
					}
				}
			}
		}
	}
	items, err := baseline.baselineTokenLedger(background, strings.Repeat("a", 64), "waozi:token", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{items[0].ReceiptID, "missing"} {
		want, found, err := baseline.baselineTokenReceipt(background, id)
		got := TokenLedger_ByID(actual.db, background, id)
		if got.Value != want || got.Found != found || websocketErrorText(got.Error) != websocketErrorText(err) {
			t.Fatal("receipt lookup changed")
		}
	}
	oldCheckpoint, err := baseline.baselineCreateTokenCheckpoint(background, tokenLedgerSigner())
	checkpoint := TokenCheckpoint_Create(actual.db, background, tokenLedgerSigner(), errTokenIssuerReadOnly)
	if checkpoint.Error != err || !checkpoint.Found {
		t.Fatal("checkpoint creation failed")
	}
	oldCheckpoint.CreatedAt, checkpoint.Value.CreatedAt = "", ""
	if checkpoint.Value != oldCheckpoint {
		t.Fatal("checkpoint root, sequence or signature changed")
	}
	if got := TokenCheckpoint_Create(actual.db, background, nil, errTokenIssuerReadOnly); got.Error != errTokenIssuerReadOnly || got.Value != (TokenCheckpoint{}) {
		t.Fatal("read-only issuer error identity changed")
	}
	for _, store := range []*Store{actual, baseline} {
		if _, err := store.db.Exec("UPDATE token_ledger SET amount_delta='bad' WHERE ledger_seq=3"); err != nil {
			t.Fatal(err)
		}
	}
	want, err := baseline.baselineTokenLedger(background, strings.Repeat("a", 64), "waozi:token", 0)
	got := TokenLedger_List(actual.db, background, strings.Repeat("a", 64), "waozi:token", 0)
	if !reflect.DeepEqual(got.Value, want) || websocketErrorText(got.Error) != websocketErrorText(err) || got.Value != nil {
		t.Fatal("partial row scan failure changed")
	}
	if actual.db.Stats().InUse != 0 || baseline.db.Stats().InUse != 0 {
		t.Fatal("row scan error leaked a connection")
	}
}

func receiptWithoutGeneratedFields(value TokenReceipt) TokenReceipt {
	value.ReceiptID = ""
	value.CreatedAt = ""
	value.PreviousHash = ""
	value.EventHash = ""
	value.Signature = ""
	return value
}

func TestZiranTokenPaymentsAndSpendingMatchBaseline(t *testing.T) {
	actual, baseline := tokenLedgerStore(t), tokenLedgerStore(t)
	background := context.Background()
	key := tokenLedgerSigner()
	input := tokenLedgerInput()
	for _, action := range []string{"credit", "retry credit", "credit collision", "spend", "retry spend", "spend collision", "insufficient", "invalid event", "invalid signer"} {
		current := input
		if action == "credit collision" {
			current.AmountDelta++
		}
		if strings.Contains(action, "spend") || action == "insufficient" || action == "invalid event" {
			current.EventType = "debit"
			current.AmountDelta = -10
			if action == "spend collision" {
				current.AmountDelta = -11
			}
			id := "spend-one"
			if action == "insufficient" {
				current.AmountDelta = -1000
				id = "insufficient"
			}
			if action == "invalid event" {
				current.EventType = "unknown"
				id = "invalid"
			}
			want, balance, created, err := baseline.baselineSpendTokens(background, key, baselineTokenEventInput(current), id)
			got := TokenLedger_Spend(actual.db, background, key, current, id, errTokenIssuerReadOnly)
			if receiptWithoutGeneratedFields(got.Value) != receiptWithoutGeneratedFields(want) || got.Balance != balance || got.Created != created || websocketErrorText(got.Error) != websocketErrorText(err) {
				t.Fatalf("spend %s changed: %+v, %v", action, got, err)
			}
		} else {
			signer, id := key, "payment-one"
			if action == "invalid signer" {
				signer, id = nil, "invalid-signer"
			}
			want, created, err := baseline.baselineCreditTokenPayment(background, signer, "fixture", id, baselineTokenEventInput(current))
			got := TokenLedger_CreditPayment(actual.db, background, signer, "fixture", id, current, errTokenIssuerReadOnly)
			if receiptWithoutGeneratedFields(got.Value) != receiptWithoutGeneratedFields(want) || got.Created != created || websocketErrorText(got.Error) != websocketErrorText(err) {
				t.Fatalf("credit %s changed: %+v, %v", action, got, err)
			}
			if action == "invalid signer" && got.Error != errTokenIssuerReadOnly {
				t.Fatal("issuer error lost identity")
			}
		}
		want, err := baseline.baselineTokenBalance(background, input.AccountID, "waozi:token")
		balance := TokenLedger_Balance(actual.db, background, input.AccountID, "waozi:token")
		if balance.Value != want || websocketErrorText(balance.Error) != websocketErrorText(err) {
			t.Fatalf("balance after %s changed", action)
		}
		items := TokenLedger_List(actual.db, background, input.AccountID, "waozi:token", 0)
		for index, receipt := range items.Value {
			if !baselineValidTokenReceiptSignature(key.Public().(ed25519.PublicKey), receipt) {
				t.Fatal("generated ledger receipt has invalid canonical signature")
			}
			if index > 0 && receipt.PreviousHash != items.Value[index-1].EventHash {
				t.Fatal("ledger hash chain broken")
			}
		}
		if actual.db.Stats().InUse != 0 || baseline.db.Stats().InUse != 0 {
			t.Fatal("transaction leaked a connection")
		}
	}
}

func TestZiranTokenLedgerWriteFailuresRollback(t *testing.T) {
	for _, stage := range []string{"ledger", "payment", "nonce", "commit"} {
		t.Run(stage, func(t *testing.T) {
			actual, baseline := tokenLedgerStore(t), tokenLedgerStore(t)
			if stage == "nonce" {
				seedMatchingTokenLedgers(t, actual, baseline)
			}
			for _, store := range []*Store{actual, baseline} {
				query := "CREATE TRIGGER fail_ledger BEFORE INSERT ON token_ledger BEGIN SELECT RAISE(ABORT,'ledger failed'); END"
				if stage == "payment" {
					query = "CREATE TRIGGER fail_payment BEFORE INSERT ON token_processed_payments BEGIN SELECT RAISE(ABORT,'payment failed'); END"
				}
				if stage == "nonce" {
					query = "CREATE TRIGGER fail_nonce BEFORE INSERT ON token_spend_nonces BEGIN SELECT RAISE(ABORT,'nonce failed'); END"
				}
				if stage == "commit" {
					query = "CREATE TABLE commit_parent(id INTEGER PRIMARY KEY); CREATE TABLE commit_child(parent INTEGER REFERENCES commit_parent(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER fail_commit AFTER INSERT ON token_ledger BEGIN INSERT INTO commit_child VALUES(1); END"
				}
				if _, err := store.db.Exec(query); err != nil {
					t.Fatal(err)
				}
			}
			background := context.Background()
			input := tokenLedgerInput()
			var actualError, baselineError error
			if stage == "nonce" {
				input.EventType, input.AmountDelta = "debit", -10
				want, balance, created, err := baseline.baselineSpendTokens(background, tokenLedgerSigner(), baselineTokenEventInput(input), "failed")
				got := TokenLedger_Spend(actual.db, background, tokenLedgerSigner(), input, "failed", errTokenIssuerReadOnly)
				actualError, baselineError = got.Error, err
				if receiptWithoutGeneratedFields(got.Value) != receiptWithoutGeneratedFields(want) || got.Balance != balance || got.Created != created {
					t.Fatal("failed nonce write retained receipt or balance")
				}
			} else {
				want, created, err := baseline.baselineCreditTokenPayment(background, tokenLedgerSigner(), "fixture", "failed", baselineTokenEventInput(input))
				got := TokenLedger_CreditPayment(actual.db, background, tokenLedgerSigner(), "fixture", "failed", input, errTokenIssuerReadOnly)
				actualError, baselineError = got.Error, err
				if receiptWithoutGeneratedFields(got.Value) != receiptWithoutGeneratedFields(want) || got.Created != created {
					t.Fatal("failed credit result changed")
				}
			}
			if actualError == nil || websocketErrorText(actualError) != websocketErrorText(baselineError) {
				t.Fatalf("write failure changed: %v, %v", actualError, baselineError)
			}
			for _, table := range []string{"token_ledger", "token_processed_payments", "token_spend_nonces"} {
				var got, want int
				if err := actual.db.QueryRow("SELECT count(*) FROM " + table).Scan(&got); err != nil {
					t.Fatal(err)
				}
				if err := baseline.db.QueryRow("SELECT count(*) FROM " + table).Scan(&want); err != nil {
					t.Fatal(err)
				}
				if got != want || (stage != "nonce" && got != 0) {
					t.Fatalf("failed transaction retained %s rows: %d/%d", table, got, want)
				}
			}
			if actual.db.Stats().InUse != 0 || baseline.db.Stats().InUse != 0 {
				t.Fatal("failed transaction retained a connection")
			}
		})
	}
}

// Keep native SQL cancellation and missing-row identities intact.
func TestZiranTokenLedgerCancellationAndEmptyResults(t *testing.T) {
	store := tokenLedgerStore(t)
	background := context.Background()
	if result := TokenLedger_ByID(store.db, background, "missing"); result.Found || result.Error != nil || result.Value != (TokenReceipt{}) {
		t.Fatal("missing receipt changed")
	}
	if result := TokenCheckpoint_Latest(store.db, background); result.Found || result.Error != nil || result.Value != (TokenCheckpoint{}) {
		t.Fatal("missing checkpoint changed")
	}
	cancelled, cancel := context.WithCancel(background)
	cancel()
	if result := TokenLedger_CreditPayment(store.db, cancelled, tokenLedgerSigner(), "fixture", "cancelled", tokenLedgerInput(), errTokenIssuerReadOnly); !errors.Is(result.Error, context.Canceled) || result.Created || result.Value != (TokenReceipt{}) {
		t.Fatal("cancelled transaction changed")
	}
	tx, err := store.db.BeginTx(background, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if result := TokenLedger_ByIDTx(tx, background, "missing"); !errors.Is(result.Error, sql.ErrTxDone) || result.Found {
		t.Fatal("completed transaction error changed")
	}
	data, _ := json.Marshal(TokenEventInput{})
	want, _ := json.Marshal(baselineTokenEventInput{})
	if !bytes.Equal(data, want) {
		t.Fatal("spend request field names changed")
	}
}
