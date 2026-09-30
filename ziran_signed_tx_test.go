package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type signatureObservation struct {
	key       []byte
	message   []byte
	signature []byte
}

type transactionVerifier struct {
	accept bool
	calls  []signatureObservation
}

func (verifier *transactionVerifier) Verify(key, message, signature []byte) bool {
	verifier.calls = append(verifier.calls, signatureObservation{
		key: append([]byte(nil), key...), message: append([]byte(nil), message...),
		signature: append([]byte(nil), signature...),
	})
	return verifier.accept
}

func equalAuthenticationError(actual, expected error) bool {
	var got, want authError
	gotAuth, wantAuth := errors.As(actual, &got), errors.As(expected, &want)
	if gotAuth || wantAuth {
		return gotAuth && wantAuth && got == want
	}
	return sameIdentityError(actual, expected)
}

func TestZiranSignedTransactionHeaderAgainstBaseline(t *testing.T) {
	values := []string{"", "\u2003\t", "!", "{", "{}", `{"tx_id":42}`, `{"expires_at":9223372036854775808}`,
		`{"tx_id":" first ","tx_id":" second ","account_id":" AA ","method":" post "}`,
		"{\"path\":\"\xff\"}", "{} null"}
	for _, raw := range []string{"null", "{}", "[]", `{"tx_id":" id ","nonce":" nonce ","signature":" sig "}`, "{bad", "{} true"} {
		values = append(values, base64.RawURLEncoding.EncodeToString([]byte(raw)), base64.URLEncoding.EncodeToString([]byte(raw)))
	}
	random := rand.New(rand.NewSource(42))
	for index := 0; index < 500; index++ {
		data := make([]byte, random.Intn(128))
		_, _ = random.Read(data)
		values = append(values, string(data), base64.RawURLEncoding.EncodeToString(data))
	}
	for _, value := range values {
		request := httptest.NewRequest(http.MethodPost, "/signed", nil)
		request.Header.Set("X-Daochi-Tx", value)
		got := SignedTx_ReadHeader(request)
		want, err := baselineReadSignedTxHeader(request)
		if !reflect.DeepEqual(got.Value, want) || !equalAuthenticationError(authenticationError(got.Authentication), err) {
			t.Fatalf("header %q = %#v, baseline = %#v, %v", value, got, want, err)
		}
	}
}

func signedTransactionFixture(t *testing.T) (*Store, *http.Request, SignedTxEnvelope, ed25519.PrivateKey, []byte) {
	t.Helper()
	store := deviceStoreFixture(t)
	accountID := strings.Repeat("a", 64)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	_, err := store.db.Exec(`
ALTER TABLE server_users ADD COLUMN public_key BLOB;
CREATE TABLE server_signed_transactions (
 account_id TEXT NOT NULL, tx_id TEXT NOT NULL, app_id TEXT NOT NULL,
 nonce TEXT NOT NULL, expires_at INTEGER NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(account_id,tx_id), UNIQUE(account_id,app_id,nonce)
);`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("UPDATE server_users SET user_id_hash=?1,public_key=?2", accountID, []byte{0, 1, 255}); err != nil {
		t.Fatal(err)
	}
	device := DeviceKey{AccountID: accountID, AppID: "inbe", KeyID: "device-key", ClientID: "client-test",
		PublicKey: hex.EncodeToString(key.Public().(ed25519.PublicKey))}
	if err := store.baselineRegisterDeviceKey(t.Context(), device, "registered"); err != nil {
		t.Fatal(err)
	}
	body := []byte("\x00\xff日本語")
	request := httptest.NewRequest(http.MethodPost, "http://home.example/a%2Fb", nil)
	tx := SignedTxEnvelope{ProtocolVersion: 6, TxID: "transaction", AccountID: accountID, AppID: "inbe",
		DeviceKeyID: "device-key", Method: request.Method, Path: request.URL.Path, BodySHA256: Signing_SHA256Hex(body),
		Nonce: "nonce-test", ExpiresAt: time.Now().Add(time.Minute).Unix(), SignatureContext: baselineTxContext,
		Signature: hex.EncodeToString(bytes.Repeat([]byte{0x33}, mlDSA44SignatureSize))}
	signDeviceTransaction(&tx, key)
	return store, request, tx, key, body
}

func signDeviceTransaction(tx *SignedTxEnvelope, key ed25519.PrivateKey) {
	tx.DeviceSignature = hex.EncodeToString(ed25519.Sign(key, []byte(Transaction_CanonicalMessage(baselineTxContext, *tx))))
}

func signedTransactionRows(t *testing.T, store *Store) []SignedTxEnvelope {
	t.Helper()
	rows, err := store.db.Query("SELECT account_id,tx_id,app_id,nonce,expires_at FROM server_signed_transactions ORDER BY account_id,tx_id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var result []SignedTxEnvelope
	for rows.Next() {
		var tx SignedTxEnvelope
		if err := rows.Scan(&tx.AccountID, &tx.TxID, &tx.AppID, &tx.Nonce, &tx.ExpiresAt); err != nil {
			t.Fatal(err)
		}
		result = append(result, tx)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestZiranSignedTransactionVerificationAgainstBaseline(t *testing.T) {
	failures := map[string]authError{
		"old protocol":           {400, "signed transaction protocol too old"},
		"wrong context":          {400, "invalid signed transaction context"},
		"bad ID":                 {400, "invalid signed transaction id"},
		"account mismatch":       {401, "signed transaction account mismatch"},
		"app mismatch":           {401, "signed transaction app mismatch"},
		"method":                 {401, "signed transaction route mismatch"},
		"escaped path":           {401, "signed transaction route mismatch"},
		"body":                   {401, "signed transaction body mismatch"},
		"expired":                {401, "signed transaction expired"},
		"future":                 {401, "signed transaction expired"},
		"missing account":        {401, "sync account not found"},
		"short signature":        {400, "invalid signed transaction signature"},
		"rejected account":       {401, "signed transaction rejected"},
		"bad device ID":          {400, "invalid device key id"},
		"missing device":         {401, "device key not registered"},
		"revoked device":         {401, "device key not registered"},
		"bad device key":         {401, "invalid app public key"},
		"short device signature": {400, "invalid device signature"},
		"wrong device signature": {401, "device signature rejected"},
		"replay":                 {409, "signed transaction replay"},
	}
	for _, mode := range []string{"valid", "old protocol", "wrong context", "bad ID", "account mismatch", "app mismatch", "method", "escaped path", "body", "expired", "future", "missing account", "short signature", "rejected account", "bad device ID", "missing device", "revoked device", "bad device key", "short device signature", "wrong device signature", "replay", "cleanup error", "insert error", "touch error", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			actual, request, tx, key, body := signedTransactionFixture(t)
			expected, _, _, _, _ := signedTransactionFixture(t)
			gotVerifier, wantVerifier := &transactionVerifier{accept: true}, &transactionVerifier{accept: true}
			query := ""
			switch mode {
			case "old protocol":
				tx.ProtocolVersion = 5
				tx.TxID = "!"
			case "wrong context":
				tx.SignatureContext = "untrusted"
			case "bad ID":
				tx.Nonce = "!"
			case "account mismatch":
				tx.AccountID = strings.Repeat("b", 64)
			case "app mismatch":
				tx.AppID = "other"
			case "method":
				tx.Method = "post"
			case "escaped path":
				tx.Path = request.URL.EscapedPath()
			case "body":
				tx.BodySHA256 = strings.Repeat("0", 64)
			case "expired":
				tx.ExpiresAt = 0
			case "future":
				tx.ExpiresAt = time.Now().Add(time.Hour).Unix()
			case "missing account":
				query = "DELETE FROM server_users"
			case "short signature":
				tx.Signature = "00"
			case "rejected account":
				gotVerifier.accept, wantVerifier.accept = false, false
			case "bad device ID":
				tx.DeviceKeyID = "!"
			case "missing device":
				query = "DELETE FROM server_device_keys"
			case "revoked device":
				query = "UPDATE server_device_keys SET revoked_at='revoked'"
			case "bad device key":
				query = "UPDATE server_device_keys SET public_key='!'"
			case "replay":
				for _, store := range []*Store{actual, expected} {
					if err := store.baselineRecordSignedTx(t.Context(), tx); err != nil {
						t.Fatal(err)
					}
				}
			case "cleanup error":
				query = "DROP TABLE server_signed_transactions"
			case "insert error":
				query = "CREATE TRIGGER reject_tx BEFORE INSERT ON server_signed_transactions BEGIN SELECT RAISE(ABORT,'insert rejected'); END"
			case "touch error":
				query = "CREATE TRIGGER reject_touch BEFORE UPDATE ON server_device_keys BEGIN SELECT RAISE(ABORT,'touch rejected'); END"
			}
			signDeviceTransaction(&tx, key)
			if mode == "short device signature" {
				tx.DeviceSignature = "00"
			}
			if mode == "wrong device signature" {
				tx.DeviceSignature = hex.EncodeToString(bytes.Repeat([]byte{0x11}, ed25519.SignatureSize))
			}
			if query != "" {
				for _, store := range []*Store{actual, expected} {
					if _, err := store.db.Exec(query); err != nil {
						t.Fatal(err)
					}
				}
			}
			ctx := t.Context()
			if mode == "canceled" {
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			}
			accountID := "\u2003" + strings.ToUpper(strings.Repeat("a", 64)) + "\t"
			got := authenticationError(SignedTx_Verify(actual.db, ctx, request, body, tx, accountID, " inbe ", gotVerifier.Verify, errSignedTxReplay))
			server := &Server{store: expected, verifier: wantVerifier}
			want := server.baselineVerifySignedTx(ctx, request, body, tx, accountID, " inbe ")
			if !equalAuthenticationError(got, want) || !reflect.DeepEqual(gotVerifier.calls, wantVerifier.calls) {
				t.Fatalf("verification = %v, baseline = %v; calls = %#v, baseline = %#v", got, want, gotVerifier.calls, wantVerifier.calls)
			}
			if mode == "valid" && got != nil {
				t.Fatal("valid transaction rejected", got)
			}
			if failure, ok := failures[mode]; ok && !equalAuthenticationError(got, failure) {
				t.Fatalf("validation reached the wrong failure: %v, want %v", got, failure)
			}
			if mode == "canceled" && got != context.Canceled {
				t.Fatal("cancellation error lost identity", got)
			}
			if mode != "cleanup error" && !reflect.DeepEqual(signedTransactionRows(t, actual), signedTransactionRows(t, expected)) {
				t.Fatal("verification changed replay persistence")
			}
		})
	}
}

func TestZiranSignedTransactionConcurrentVerificationIsSingleUse(t *testing.T) {
	store, request, tx, _, body := signedTransactionFixture(t)
	verify := func(key, message, signature []byte) bool {
		return bytes.Equal(key, []byte{0, 1, 255}) &&
			bytes.Equal(message, []byte(Transaction_CanonicalMessage(baselineTxContext, tx))) &&
			len(signature) == mlDSA44SignatureSize
	}
	results := make(chan AuthenticationResult, 16)
	var workers sync.WaitGroup
	for index := 0; index < cap(results); index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			results <- SignedTx_Verify(store.db, context.Background(), request, body, tx, tx.AccountID, tx.AppID, verify, errSignedTxReplay)
		}()
	}
	workers.Wait()
	close(results)
	accepted := 0
	for result := range results {
		if err := authenticationError(result); err == nil {
			accepted++
		} else if !equalAuthenticationError(err, authError{409, "signed transaction replay"}) {
			t.Fatalf("concurrent verification = %v", err)
		}
	}
	if accepted != 1 {
		t.Fatalf("signed transaction verified %d times", accepted)
	}
}

func TestZiranSignedTransactionRecordAndForgetAgainstBaseline(t *testing.T) {
	actual, _, tx, _, _ := signedTransactionFixture(t)
	expected, _, _, _, _ := signedTransactionFixture(t)
	for _, item := range []SignedTxEnvelope{tx, tx, {AccountID: tx.AccountID, AppID: tx.AppID, TxID: "other", Nonce: tx.Nonce, ExpiresAt: tx.ExpiresAt}} {
		got := SignedTx_Record(actual.db, t.Context(), item, errSignedTxReplay)
		want := expected.baselineRecordSignedTx(t.Context(), item)
		if got != want && !sameIdentityError(got, want) {
			t.Fatalf("replay recording = %v, baseline = %v", got, want)
		}
		if !reflect.DeepEqual(signedTransactionRows(t, actual), signedTransactionRows(t, expected)) {
			t.Fatal("recorded replay state differs")
		}
	}
	wrong := tx
	wrong.Nonce = "different"
	for _, item := range []SignedTxEnvelope{wrong, tx, tx} {
		SignedTx_Forget(actual.db, t.Context(), item)
		expected.baselineForgetSignedTx(t.Context(), item)
		if !reflect.DeepEqual(signedTransactionRows(t, actual), signedTransactionRows(t, expected)) {
			t.Fatal("forget removed a mismatched transaction")
		}
	}
	const consumers = 16
	var workers sync.WaitGroup
	results := make(chan error, consumers)
	for index := 0; index < consumers; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			results <- SignedTx_Record(actual.db, context.Background(), tx, errSignedTxReplay)
		}()
	}
	workers.Wait()
	close(results)
	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
		} else if err != errSignedTxReplay {
			t.Fatal("concurrent replay lost sentinel identity", err)
		}
	}
	if accepted != 1 {
		t.Fatalf("transaction accepted %d times", accepted)
	}
}

func TestZiranAccountPublicKeyPreservesNativeSQLResults(t *testing.T) {
	actual, _, tx, _, _ := signedTransactionFixture(t)
	for _, query := range []string{"", "UPDATE server_users SET public_key=x''", "DELETE FROM server_users", "DROP TABLE server_users"} {
		if query != "" {
			if _, err := actual.db.Exec(query); err != nil {
				t.Fatal(err)
			}
		}
		got := AccountKeys_PublicKey(actual.db, t.Context(), tx.AccountID)
		want, found, err := actual.baselineAccountPublicKey(t.Context(), tx.AccountID)
		if !reflect.DeepEqual(got.Value, want) || got.Found != found || !sameIdentityError(got.Error, err) {
			t.Fatalf("account key = %#v, baseline = %v, %v, %v", got, want, found, err)
		}
	}
}

func TestZiranSignedHeaderJSONKeepsReleasedTags(t *testing.T) {
	_, request, tx, _, _ := signedTransactionFixture(t)
	raw, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Daochi-Tx", string(raw))
	got := SignedTx_ReadHeader(request)
	if err := authenticationError(got.Authentication); err != nil || !reflect.DeepEqual(got.Value, tx) {
		t.Fatalf("signed header JSON = %#v, %v", got, err)
	}
}

func TestZiranDeviceSignatureValidationAgainstBaseline(t *testing.T) {
	for _, mode := range []string{"valid", "bad app", "short key ID", "expired", "future", "malformed signature", "short signature", "missing account", "account error", "rejected", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			actual, _, tx, key, _ := signedTransactionFixture(t)
			expected, _, _, _, _ := signedTransactionFixture(t)
			registration := DeviceRegistrationRequest{
				AppID: tx.AppID, KeyID: tx.DeviceKeyID, ClientID: "client-test",
				PublicKey: hex.EncodeToString(key.Public().(ed25519.PublicKey)),
				Nonce:     "registration-nonce", ExpiresAt: tx.ExpiresAt, Signature: tx.Signature,
			}
			query := ""
			gotVerifier, wantVerifier := &transactionVerifier{accept: true}, &transactionVerifier{accept: true}
			switch mode {
			case "bad app":
				registration.AppID = "!"
			case "short key ID":
				registration.KeyID = "short"
			case "expired":
				registration.ExpiresAt = 0
			case "future":
				registration.ExpiresAt = time.Now().Add(time.Hour).Unix()
			case "malformed signature":
				registration.Signature = "!"
			case "short signature":
				registration.Signature = "00"
			case "missing account":
				query = "DELETE FROM server_users"
			case "account error":
				query = "DROP TABLE server_users"
			case "rejected":
				gotVerifier.accept, wantVerifier.accept = false, false
			}
			if query != "" {
				for _, store := range []*Store{actual, expected} {
					if _, err := store.db.Exec(query); err != nil {
						t.Fatal(err)
					}
				}
			}
			ctx := t.Context()
			if mode == "canceled" {
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			}
			server := &Server{store: expected, verifier: wantVerifier}
			got := authenticationError(DeviceKeys_VerifyRegistration(actual.db, ctx, tx.AccountID, registration, gotVerifier.Verify))
			want := server.baselineVerifyDeviceRegistration(ctx, tx.AccountID, registration)
			if !equalAuthenticationError(got, want) || !reflect.DeepEqual(gotVerifier.calls, wantVerifier.calls) {
				t.Fatalf("registration verification = %v, baseline = %v; signature arguments differ = %v", got, want, !reflect.DeepEqual(gotVerifier.calls, wantVerifier.calls))
			}
			if mode == "valid" && (got != nil || len(gotVerifier.calls) != 1) {
				t.Fatal("valid registration did not verify its signature", got)
			}
			gotVerifier.calls, wantVerifier.calls = nil, nil
			revocation := DeviceRevocationRequest{AppID: registration.AppID, KeyID: registration.KeyID,
				Nonce: registration.Nonce, ExpiresAt: registration.ExpiresAt, Signature: registration.Signature}
			got = authenticationError(DeviceKeys_VerifyRevocation(actual.db, ctx, tx.AccountID, revocation, gotVerifier.Verify))
			want = server.baselineVerifyDeviceRevocation(ctx, tx.AccountID, revocation)
			if !equalAuthenticationError(got, want) || !reflect.DeepEqual(gotVerifier.calls, wantVerifier.calls) {
				t.Fatalf("revocation verification = %v, baseline = %v; signature arguments differ = %v", got, want, !reflect.DeepEqual(gotVerifier.calls, wantVerifier.calls))
			}
			if mode == "valid" && (got != nil || len(gotVerifier.calls) != 1) {
				t.Fatal("valid revocation did not verify its signature", got)
			}
			if mode == "canceled" && got != context.Canceled {
				t.Fatal("revocation cancellation lost identity", got)
			}
		})
	}
}
