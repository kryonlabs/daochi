package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	testPasskeyCredential = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testGoogleClient      = "client.apps.googleusercontent.com"
)

func passkeyProof(seed string) (string, string) {
	proof := sha256.Sum256([]byte(seed))
	verifier := sha256.Sum256(proof[:])
	return hex.EncodeToString(proof[:]), hex.EncodeToString(verifier[:])
}

func passkeyWrapper(credential string) string {
	return "waozi-account-passkey-v1\nalgorithm=ML-DSA-44\nkdf=WebAuthn-PRF-SHA-256\ncredential=" + credential + "\nnonce=000000000000000000000000\nciphertext=00"
}

func sendJSON(t *testing.T, target any, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	return serveTestRequest(t, target, request)
}

func storePasskey(t *testing.T, target any, token, credential, verifier string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{
		"credential": credential,
		"label":      "Phone",
		"verifier":   verifier,
		"wrapper":    passkeyWrapper(credential),
	})
	if err != nil {
		t.Fatal(err)
	}
	return sendJSON(t, target, http.MethodPost, "/api/v1/account/passkeys", token, string(body))
}

func openPasskey(t *testing.T, target any, account, credential, proof string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"account":"` + account + `","credential":"` + credential + `","proof":"` + proof + `"}`
	return sendJSON(t, target, http.MethodPost, "/api/v1/account-backup/passkey/open", "", body)
}

func TestPasskeyCopyReleasedOnlyForItsProof(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x21)
	proof, verifier := passkeyProof("right")
	wrongProof, _ := passkeyProof("wrong")

	if response := storePasskey(t, handler, identity.Token, testPasskeyCredential, verifier); response.Code != http.StatusOK {
		t.Fatalf("store: %d %s", response.Code, response.Body)
	}

	// Stored text is the sealed wrapper and the digest; never the proof.
	var stored, storedVerifier string
	if err := server.Store.Database.QueryRow(`SELECT wrapper,verifier FROM server_account_passkeys WHERE user_id_hash=?1`, identity.UserID).Scan(&stored, &storedVerifier); err != nil {
		t.Fatal(err)
	}
	if storedVerifier != verifier || strings.Contains(stored, proof) {
		t.Fatalf("node keeps more than the verifier: %q", storedVerifier)
	}

	opened := openPasskey(t, handler, identity.UserID, testPasskeyCredential, proof)
	if opened.Code != http.StatusOK {
		t.Fatalf("open: %d %s", opened.Code, opened.Body)
	}
	var reply struct {
		Account string `json:"account_id"`
		Wrapper string `json:"wrapper"`
	}
	if err := json.Unmarshal(opened.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	if reply.Account != identity.UserID || reply.Wrapper != passkeyWrapper(testPasskeyCredential) {
		t.Fatalf("wrong reply: %+v", reply)
	}

	// A wrong passkey, an unknown credential and an unknown account look alike.
	wrong := openPasskey(t, handler, identity.UserID, testPasskeyCredential, wrongProof)
	otherCredential := openPasskey(t, handler, identity.UserID, strings.Repeat("b", 64), proof)
	otherAccount := openPasskey(t, handler, strings.Repeat("c", 64), testPasskeyCredential, proof)
	for _, refused := range []*httptest.ResponseRecorder{wrong, otherCredential, otherAccount} {
		if refused.Code != http.StatusForbidden || refused.Body.String() != wrong.Body.String() {
			t.Fatalf("refusal differs: %d %s", refused.Code, refused.Body)
		}
	}
	if malformed := openPasskey(t, handler, identity.UserID, testPasskeyCredential, "not-hex"); malformed.Code != http.StatusBadRequest {
		t.Fatalf("malformed proof: %d", malformed.Code)
	}
}

func TestPasskeyStoreRefusesOtherFormatsAndAnonymous(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x22)
	_, verifier := passkeyProof("right")

	if response := storePasskey(t, handler, "", testPasskeyCredential, verifier); response.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous store: %d", response.Code)
	}
	bad := []map[string]string{
		// A v3 password backup is not a passkey copy.
		{"credential": testPasskeyCredential, "label": "x", "verifier": verifier, "wrapper": "waozi-account-backup-v3\nalgorithm=ML-DSA-44\n"},
		// The credential line must match the credential beside it.
		{"credential": testPasskeyCredential, "label": "x", "verifier": verifier, "wrapper": passkeyWrapper(strings.Repeat("b", 64))},
		{"credential": "short", "label": "x", "verifier": verifier, "wrapper": passkeyWrapper("short")},
		{"credential": testPasskeyCredential, "label": "x", "verifier": "short", "wrapper": passkeyWrapper(testPasskeyCredential)},
		{"credential": testPasskeyCredential, "label": "<script>", "verifier": verifier, "wrapper": passkeyWrapper(testPasskeyCredential)},
	}
	for _, input := range bad {
		body, _ := json.Marshal(input)
		if response := sendJSON(t, handler, http.MethodPost, "/api/v1/account/passkeys", identity.Token, string(body)); response.Code != http.StatusBadRequest {
			t.Fatalf("accepted %v: %d", input, response.Code)
		}
	}
}

func TestPasskeyRemovalIsNeverBlocked(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x23)
	other := newTestIdentity(t, handler, 0x24)
	proof, verifier := passkeyProof("right")
	if response := storePasskey(t, handler, identity.Token, testPasskeyCredential, verifier); response.Code != http.StatusOK {
		t.Fatalf("store: %d %s", response.Code, response.Body)
	}

	list := sendJSON(t, handler, http.MethodGet, "/api/v1/account/passkeys", identity.Token, "")
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"label":"Phone"`) || strings.Contains(list.Body.String(), "wrapper") {
		t.Fatalf("list: %d %s", list.Code, list.Body)
	}

	// Another account cannot remove it.
	body := `{"credential":"` + testPasskeyCredential + `"}`
	if response := sendJSON(t, handler, http.MethodPost, "/api/v1/account/passkeys/remove", other.Token, body); !strings.Contains(response.Body.String(), `"deleted":false`) {
		t.Fatalf("other account removal: %d %s", response.Code, response.Body)
	}
	if response := openPasskey(t, handler, identity.UserID, testPasskeyCredential, proof); response.Code != http.StatusOK {
		t.Fatalf("copy gone after another account's attempt: %d", response.Code)
	}

	// The last passkey goes when asked, with no other way in on the node: the
	// .key file is the master key.
	if response := sendJSON(t, handler, http.MethodPost, "/api/v1/account/passkeys/remove", identity.Token, body); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"deleted":true`) {
		t.Fatalf("removal: %d %s", response.Code, response.Body)
	}
	if response := openPasskey(t, handler, identity.UserID, testPasskeyCredential, proof); response.Code != http.StatusForbidden {
		t.Fatalf("copy released after removal: %d", response.Code)
	}
}

func TestPasskeysPerAccountAreLimited(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x25)
	_, verifier := passkeyProof("right")
	for index := 0; index < 8; index++ {
		credential := strings.Repeat(string("abcdef01"[index]), 64)
		if response := storePasskey(t, handler, identity.Token, credential, verifier); response.Code != http.StatusOK {
			t.Fatalf("store %d: %d %s", index, response.Code, response.Body)
		}
	}
	if response := storePasskey(t, handler, identity.Token, strings.Repeat("9", 64), verifier); response.Code != http.StatusConflict {
		t.Fatalf("ninth passkey: %d", response.Code)
	}
	// Replacing an existing one still works at the limit.
	if response := storePasskey(t, handler, identity.Token, strings.Repeat("a", 64), verifier); response.Code != http.StatusOK {
		t.Fatalf("replace at limit: %d", response.Code)
	}
}

// A fake of Google's certificate address and signing key.
type fakeGoogle struct {
	key    *rsa.PrivateKey
	server *httptest.Server
}

func newFakeGoogle(t *testing.T) *fakeGoogle {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fake google"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	fake := &fakeGoogle{key: key}
	fake.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(writer).Encode(map[string]string{"key-1": string(certificate)})
	}))
	t.Cleanup(fake.server.Close)
	previous := GoogleCertificatesURL
	GoogleCertificatesURL = fake.server.URL
	AccountGoogle_ResetCertificates()
	t.Cleanup(func() {
		GoogleCertificatesURL = previous
		AccountGoogle_ResetCertificates()
	})
	return fake
}

func (fake *fakeGoogle) sign(t *testing.T, header string, claims map[string]any) string {
	t.Helper()
	encoded, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	message := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString(encoded)
	digest := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, fake.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return message + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (fake *fakeGoogle) token(t *testing.T, subject, audience, nonce string, expires time.Time) string {
	t.Helper()
	return fake.sign(t, `{"alg":"RS256","kid":"key-1"}`, map[string]any{
		"iss":   "https://accounts.google.com",
		"aud":   audience,
		"sub":   subject,
		"nonce": nonce,
		"iat":   time.Now().Unix(),
		"exp":   expires.Unix(),
		"email": "someone@example.com",
	})
}

func TestGoogleCertificateOutageIsNotFetchedPerRequest(t *testing.T) {
	hits := 0
	outage := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		hits++
		writer.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer outage.Close()
	previous := GoogleCertificatesURL
	GoogleCertificatesURL = outage.URL
	AccountGoogle_ResetCertificates()
	defer func() {
		GoogleCertificatesURL = previous
		AccountGoogle_ResetCertificates()
	}()
	fake := &fakeGoogle{}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fake.key = key
	server := googleServer(t)
	handler := server.Routes()
	token := fake.token(t, "subject", testGoogleClient, "", time.Now().Add(time.Hour))
	for attempt := 0; attempt < 5; attempt++ {
		response := sendJSON(t, handler, http.MethodPost, "/api/v1/account-backup/google", "", `{"id_token":"`+token+`"}`)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d %s", attempt, response.Code, response.Body)
		}
	}
	if hits != 1 {
		t.Fatalf("five sign-ins fetched certificates %d times", hits)
	}
}

// A client that hangs up must not spend the one certificate refresh a minute.
func TestGoogleCertificateRefreshOutlivesCancelledRequest(t *testing.T) {
	fake := newFakeGoogle(t)
	handler := googleServer(t).Routes()
	token := fake.token(t, "subject", testGoogleClient, "", time.Now().Add(time.Hour))
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/account-backup/google", strings.NewReader(`{"id_token":"`+token+`"}`)).WithContext(cancelled)
	request.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(httptest.NewRecorder(), request)
	response := sendJSON(t, handler, http.MethodPost, "/api/v1/account-backup/google", "", `{"id_token":"`+token+`"}`)
	if response.Code == http.StatusUnauthorized {
		t.Fatalf("the cancelled request lost the refresh: %d %s", response.Code, response.Body)
	}
}

func googleServer(t *testing.T) *Server {
	t.Helper()
	server, _, _ := testServer(t)
	server.Cfg.GoogleSignInClientIDs = []string{testGoogleClient}
	return server
}

func linkNonce(account string) string {
	digest := sha256.Sum256([]byte("waozi-google-link-v1\n" + account))
	return hex.EncodeToString(digest[:])
}

func TestGoogleFindsOnlyTheLinkedAccount(t *testing.T) {
	fake := newFakeGoogle(t)
	server := googleServer(t)
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x31)
	soon := time.Now().Add(time.Hour)

	find := func(token string) *httptest.ResponseRecorder {
		return sendJSON(t, handler, http.MethodPost, "/api/v1/account-backup/google", "", `{"id_token":"`+token+`"}`)
	}
	if response := find(fake.token(t, "subject-1", testGoogleClient, "random-nonce", soon)); response.Code != http.StatusNotFound {
		t.Fatalf("unlinked: %d %s", response.Code, response.Body)
	}
	link := fake.token(t, "subject-1", testGoogleClient, linkNonce(identity.UserID), soon)
	if response := sendJSON(t, handler, http.MethodPost, "/api/v1/account/google", identity.Token, `{"id_token":"`+link+`"}`); response.Code != http.StatusOK {
		t.Fatalf("link: %d %s", response.Code, response.Body)
	}
	// A browser sign-in carries a random nonce, which finding an account ignores.
	found := find(fake.token(t, "subject-1", testGoogleClient, "random-nonce", soon))
	if found.Code != http.StatusOK || !strings.Contains(found.Body.String(), identity.UserID) {
		t.Fatalf("find: %d %s", found.Code, found.Body)
	}
	// It names the account and nothing that could unlock it.
	if strings.Contains(found.Body.String(), "backup") || strings.Contains(found.Body.String(), "wrapper") {
		t.Fatalf("lookup released more than the account: %s", found.Body)
	}

	// The node holds neither the subject nor the email.
	var subject string
	if err := server.Store.Database.QueryRow(`SELECT subject_hash FROM server_account_google WHERE user_id_hash=?1`, identity.UserID).Scan(&subject); err != nil {
		t.Fatal(err)
	}
	if subject == "" || strings.Contains(subject, "subject-1") {
		t.Fatalf("subject stored as %q", subject)
	}

	// Removing the link works with no Google token, for revoked access too.
	if response := sendJSON(t, handler, http.MethodPost, "/api/v1/account/google/remove", identity.Token, ""); response.Code != http.StatusOK {
		t.Fatalf("unlink: %d %s", response.Code, response.Body)
	}
	if response := find(fake.token(t, "subject-1", testGoogleClient, "", soon)); response.Code != http.StatusNotFound {
		t.Fatalf("after unlink: %d", response.Code)
	}
}

func TestGoogleRefusesBadTokens(t *testing.T) {
	fake := newFakeGoogle(t)
	server := googleServer(t)
	handler := server.Routes()
	soon := time.Now().Add(time.Hour)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	stranger := &fakeGoogle{key: other}
	tokens := map[string]string{
		"expired or revoked access": fake.token(t, "subject", testGoogleClient, "", time.Now().Add(-time.Hour)),
		"another app's token":       fake.token(t, "subject", "someone-else", "", soon),
		"not signed by Google":      stranger.token(t, "subject", testGoogleClient, "", soon),
		"no signature algorithm":    fake.sign(t, `{"alg":"none","kid":"key-1"}`, map[string]any{"iss": "https://accounts.google.com", "aud": testGoogleClient, "sub": "s", "exp": soon.Unix()}),
		"unknown signing key":       fake.sign(t, `{"alg":"RS256","kid":"key-2"}`, map[string]any{"iss": "https://accounts.google.com", "aud": testGoogleClient, "sub": "s", "exp": soon.Unix()}),
		"another issuer":            fake.sign(t, `{"alg":"RS256","kid":"key-1"}`, map[string]any{"iss": "https://example.com", "aud": testGoogleClient, "sub": "s", "exp": soon.Unix()}),
		"no subject":                fake.sign(t, `{"alg":"RS256","kid":"key-1"}`, map[string]any{"iss": "https://accounts.google.com", "aud": testGoogleClient, "exp": soon.Unix()}),
		"garbled":                   "a.b",
	}
	for name, token := range tokens {
		response := sendJSON(t, handler, http.MethodPost, "/api/v1/account-backup/google", "", `{"id_token":"`+token+`"}`)
		if response.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d %s", name, response.Code, response.Body)
		}
	}
}

func TestGoogleLinkIsBoundToTheAccount(t *testing.T) {
	fake := newFakeGoogle(t)
	server := googleServer(t)
	handler := server.Routes()
	first := newTestIdentity(t, handler, 0x32)
	second := newTestIdentity(t, handler, 0x33)
	soon := time.Now().Add(time.Hour)
	link := func(identity testIdentity, nonce string) *httptest.ResponseRecorder {
		token := fake.token(t, "subject-shared", testGoogleClient, nonce, soon)
		return sendJSON(t, handler, http.MethodPost, "/api/v1/account/google", identity.Token, `{"id_token":"`+token+`"}`)
	}
	// A token made for one account cannot be replayed to link another.
	if response := link(second, linkNonce(first.UserID)); response.Code != http.StatusUnauthorized {
		t.Fatalf("replayed nonce: %d %s", response.Code, response.Body)
	}
	if response := link(second, ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("missing nonce: %d", response.Code)
	}
	if response := link(first, linkNonce(first.UserID)); response.Code != http.StatusOK {
		t.Fatalf("link: %d %s", response.Code, response.Body)
	}
	// One Google account finds one account.
	if response := link(second, linkNonce(second.UserID)); response.Code != http.StatusConflict {
		t.Fatalf("second link: %d %s", response.Code, response.Body)
	}
	// Signing the same account in again is fine.
	if response := link(first, linkNonce(first.UserID)); response.Code != http.StatusOK {
		t.Fatalf("relink: %d %s", response.Code, response.Body)
	}
}

func TestGoogleIsOffOnANodeWithoutClientIDs(t *testing.T) {
	newFakeGoogle(t)
	server, _, _ := testServer(t)
	handler := server.Routes()
	methods := sendJSON(t, handler, http.MethodGet, "/api/v1/account-backup/methods", "", "")
	if methods.Code != http.StatusOK || strings.Contains(methods.Body.String(), "google_client_id") {
		t.Fatalf("methods: %d %s", methods.Code, methods.Body)
	}
	if response := sendJSON(t, handler, http.MethodPost, "/api/v1/account-backup/google", "", `{"id_token":"a.b.c"}`); response.Code != http.StatusNotFound {
		t.Fatalf("lookup: %d", response.Code)
	}
	configured := googleServer(t).Routes()
	if response := sendJSON(t, configured, http.MethodGet, "/api/v1/account-backup/methods", "", ""); !strings.Contains(response.Body.String(), testGoogleClient) {
		t.Fatalf("configured methods: %s", response.Body)
	}
}

func TestDeletingAnAccountRemovesItsPasskeysAndGoogleLink(t *testing.T) {
	fake := newFakeGoogle(t)
	server := googleServer(t)
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x34)
	proof, verifier := passkeyProof("right")
	if response := storePasskey(t, handler, identity.Token, testPasskeyCredential, verifier); response.Code != http.StatusOK {
		t.Fatalf("store: %d", response.Code)
	}
	link := fake.token(t, "subject-deleted", testGoogleClient, linkNonce(identity.UserID), time.Now().Add(time.Hour))
	if response := sendJSON(t, handler, http.MethodPost, "/api/v1/account/google", identity.Token, `{"id_token":"`+link+`"}`); response.Code != http.StatusOK {
		t.Fatalf("link: %d", response.Code)
	}
	transaction, err := server.Store.Database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := AccountState_DeleteTx(transaction, t.Context(), identity.UserID); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
	if response := openPasskey(t, handler, identity.UserID, testPasskeyCredential, proof); response.Code != http.StatusForbidden {
		t.Fatalf("copy released after account deletion: %d", response.Code)
	}
	if count := holdCount(t, server.Store.Database, "SELECT COUNT(*) FROM server_account_google WHERE user_id_hash=?1", identity.UserID); count != 0 {
		t.Fatalf("google link kept after account deletion: %d", count)
	}
}
