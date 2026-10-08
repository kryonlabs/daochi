package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

type authorizationFixture struct {
	server       *Server
	store        *Store
	handler      http.Handler
	owner        testIdentity
	ownerPrivate []byte
	device       ed25519.PrivateKey
	delegate     ed25519.PrivateKey
	grant        Grant
	credential   SessionCredential
	sequence     int
}

func authorizationSetup(t *testing.T) *authorizationFixture {
	t.Helper()
	server, store, _ := testServer(t)
	server.Verifier = Verifier_New(MlDsa44_Verify)
	owner := MlDsa44_KeyPair()
	if owner.Error != nil {
		t.Fatal(owner.Error)
	}
	id := Signing_SHA256Hex(owner.PublicKey)
	if _, err := store.Database.Exec("INSERT INTO server_users(user_id_hash,public_key) VALUES(?,?)", id, owner.PublicKey); err != nil {
		t.Fatal(err)
	}
	registered := AppStore_OwnsCollection(store.Database, t.Context(), "inbe", "private.inbe.v2.lumi")
	if registered.Error != nil || !registered.Value {
		t.Fatal("built-in Inbe registration does not declare isolated Lumi history")
	}
	// An approved app manifest preserves its declared collections when the
	// node restarts, instead of restoring the legacy unsigned seed inventory.
	if _, err := store.Database.Exec("INSERT INTO server_app_manifests(app_id,manifest_version,manifest_json,manifest_hash,manifest_signature,approval_signature,status) VALUES('inbe',2,'{}','synthetic-fixture','synthetic-fixture','synthetic-fixture','active')"); err != nil {
		t.Fatal(err)
	}
	device := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, 32))
	if err := DeviceKeys_Register(store.Database, t.Context(), DeviceKey{
		AccountID: id, AppID: "inbe", KeyID: "owner-device", ClientID: strings.Repeat("a", 64),
		PublicKey: hex.EncodeToString(device.Public().(ed25519.PublicKey)),
	}, "fixture-registration", errSignedTxReplay); err != nil {
		t.Fatal(err)
	}
	token := Token_IssueAuthToken(server.Cfg.TokenSecret, id, time.Now().Add(time.Hour).Unix())
	if token.Error != "" {
		t.Fatal(token.Error)
	}
	return &authorizationFixture{server: server, store: store, handler: server.Routes(),
		owner:        testIdentity{PublicKey: owner.PublicKey, UserID: id, Token: token.Value},
		ownerPrivate: owner.PrivateKey, device: device,
		delegate: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, 32))}
}

func authorizationCall(t *testing.T, handler http.Handler, path string, input any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("POST", path, bytes.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	result := httptest.NewRecorder()
	handler.ServeHTTP(result, request)
	return result
}

func (fixture *authorizationFixture) ownerCall(t *testing.T, path string, input any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(input)
	fixture.sequence++
	txID := fmt.Sprintf("fixture-tx-%d", fixture.sequence)
	tx := SignedTxEnvelope{ProtocolVersion: 6, TxID: txID, AccountID: fixture.owner.UserID,
		AppID: "inbe", DeviceKeyID: "owner-device", Method: "POST", Path: path,
		BodySHA256: Signing_SHA256Hex(raw), Nonce: txID + "-nonce", ExpiresAt: time.Now().Unix() + 60}
	message := []byte(Transaction_CanonicalMessage(TransactionContext, tx))
	signed := MlDsa44_Sign(message, fixture.ownerPrivate)
	if signed.Error != nil {
		t.Fatal(signed.Error)
	}
	tx.Signature = hex.EncodeToString(signed.Value)
	tx.DeviceSignature = hex.EncodeToString(ed25519.Sign(fixture.device, message))
	header, _ := json.Marshal(tx)
	return authorizationCall(t, fixture.handler, path, input, map[string]string{
		"Authorization": "Bearer " + fixture.owner.Token, "X-Daochi-User": fixture.owner.UserID,
		"X-Daochi-Tx": string(header),
	})
}

func (fixture *authorizationFixture) connect(t *testing.T) {
	t.Helper()
	input := AuthorizationRequest{AppID: "inbe", Scopes: []RequestedScope{{Collection: "private.inbe.v2.lumi", Read: true, Write: true}}}
	created := fixture.ownerCall(t, "/api/v1/authorization/requests", input)
	var pending Rendezvous
	if created.Code != 200 || json.Unmarshal(created.Body.Bytes(), &pending) != nil {
		t.Fatalf("create rendezvous: %d %s", created.Code, created.Body.String())
	}
	claim := RendezvousClaim{RequestID: pending.RequestID, ClientID: strings.Repeat("b", 64),
		SigningKey: hex.EncodeToString(fixture.delegate.Public().(ed25519.PublicKey)), EncryptionKey: strings.Repeat("c", 2368)}
	claim.Proof = hex.EncodeToString(ed25519.Sign(fixture.delegate, []byte(AuthorizationHttp_ClaimMessage(pending, claim, ""))))
	claimed := authorizationCall(t, fixture.handler, "/api/v1/authorization/claim", claim, nil)
	if claimed.Code != 200 {
		t.Fatalf("claim rendezvous: %d %s", claimed.Code, claimed.Body.String())
	}
	now := time.Now().Unix()
	fixture.grant = Grant{Version: 1, AccountID: pending.AccountID, GrantID: strings.Repeat("d", 32),
		RequestID: pending.RequestID, AppID: "inbe", ClientID: claim.ClientID, NodeID: pending.NodeID,
		Audience: pending.Audience, SigningKey: claim.SigningKey, EncryptionKey: claim.EncryptionKey,
		IssuedAt: now, NotBefore: now, ExpiresAt: now + 3600, Nonce: strings.Repeat("e", 32),
		Scopes: []GrantScope{{Collection: "private.inbe.v2.lumi", Visibility: "private", Read: true, Write: true, KeyID: "lumi-key-v2", KeyEnvelope: "opaque-fixture-envelope"}}}
	signature := MlDsa44_Sign([]byte(Authorization_GrantMessage(fixture.grant)), fixture.ownerPrivate)
	if signature.Error != nil {
		t.Fatal(signature.Error)
	}
	fixture.grant.Signature = hex.EncodeToString(signature.Value)
	approved := authorizationCall(t, fixture.handler, "/api/v1/authorization/approve", fixture.grant,
		map[string]string{"Authorization": "Bearer " + fixture.owner.Token})
	if approved.Code != 200 {
		t.Fatalf("approve grant: %d %s", approved.Code, approved.Body.String())
	}
	fixture.renew(t)
}

func (fixture *authorizationFixture) renew(t *testing.T) {
	t.Helper()
	issued := authorizationCall(t, fixture.handler, "/api/v1/authorization/challenge", GrantIDRequest{GrantID: fixture.grant.GrantID}, nil)
	var challenge SessionChallenge
	if issued.Code != 200 || json.Unmarshal(issued.Body.Bytes(), &challenge) != nil {
		t.Fatalf("session challenge: %d %s", issued.Code, issued.Body.String())
	}
	input := SessionRequest{GrantID: fixture.grant.GrantID, Challenge: challenge.Challenge,
		Signature: hex.EncodeToString(ed25519.Sign(fixture.delegate, []byte(Session_ChallengeMessage(challenge))))}
	issued = authorizationCall(t, fixture.handler, "/api/v1/authorization/session", input, nil)
	var answer SessionAnswer
	if issued.Code != 200 || json.Unmarshal(issued.Body.Bytes(), &answer) != nil {
		t.Fatalf("issue session: %d %s", issued.Code, issued.Body.String())
	}
	fixture.credential = answer.Credential
	if answer.Credential.ExpiresAt > time.Now().Unix()+300 {
		t.Fatal("session lifetime exceeded five minutes")
	}
	if replay := authorizationCall(t, fixture.handler, "/api/v1/authorization/session", input, nil); replay.Code != 409 {
		t.Fatal("session challenge reused")
	}
}

func (fixture *authorizationFixture) delegateRequest(t *testing.T, input DelegatedSyncRequest) *http.Request {
	t.Helper()
	raw, _ := json.Marshal(input)
	fixture.sequence++
	proof := RequestProof{Version: 1, GrantID: fixture.grant.GrantID, SessionID: fixture.credential.SessionID,
		AccountID: fixture.owner.UserID, AppID: "inbe", ClientID: fixture.grant.ClientID,
		NodeID: fixture.server.Node.ID, Audience: fixture.server.Cfg.BaseURL, Challenge: fixture.credential.Challenge,
		Method: "POST", Path: "/api/v1/delegated/sync", BodySHA256: Signing_SHA256Hex(raw),
		ExpiresAt: time.Now().Unix() + 30, Nonce: fmt.Sprintf("%032x", fixture.sequence)}
	proof.Signature = hex.EncodeToString(ed25519.Sign(fixture.delegate, []byte(Session_ProofMessage(proof))))
	header, _ := json.Marshal(proof)
	request := httptest.NewRequest("POST", proof.Path, bytes.NewReader(raw))
	request.Header.Set("X-Daochi-Delegate", string(header))
	request.Header.Set("Authorization", "Delegate ds1."+fixture.credential.SessionID)
	return request
}

func (fixture *authorizationFixture) syncInput() DelegatedSyncRequest {
	return DelegatedSyncRequest{Sync: SyncRequest{ProtocolVersion: 6, AppID: "inbe",
		UserIDHash: fixture.owner.UserID, ClientID: fixture.grant.ClientID},
		Collection: "private.inbe.v2.lumi", Read: true, Limit: 10}
}

func TestAuthorizationOwnerGrantAndScopedSession(t *testing.T) {
	fixture := authorizationSetup(t)
	fixture.connect(t)
	input := fixture.syncInput()
	input.Sync.EncryptedRecords = []EncryptedRecord{{Collection: input.Collection, ID: "cell.lumi.message.1",
		KeyID: "lumi-key-v2", Nonce: "nonce", Ciphertext: "opaque-ciphertext", UpdatedAt: "2026-10-08T00:00:00Z"}}
	request := fixture.delegateRequest(t, input)
	result := httptest.NewRecorder()
	fixture.handler.ServeHTTP(result, request)
	var response DelegatedSyncResponse
	if result.Code != 200 || json.Unmarshal(result.Body.Bytes(), &response) != nil || response.Applied != 1 || len(response.Records) != 1 {
		t.Fatalf("scoped sync: %d %s", result.Code, result.Body.String())
	}
	// An identical proof is durable replay state, even after session renewal.
	raw, _ := json.Marshal(input)
	replay := httptest.NewRequest("POST", "/api/v1/delegated/sync", bytes.NewReader(raw))
	replay.Header = request.Header.Clone()
	result = httptest.NewRecorder()
	fixture.handler.ServeHTTP(result, replay)
	if result.Code != 409 {
		t.Fatalf("replay accepted: %d", result.Code)
	}
	for _, route := range []string{"/api/v1/sync", "/api/v1/account/export", "/api/v1/tokens/spend", "/api/v1/lumi/telegram/link"} {
		request := httptest.NewRequest("POST", route, strings.NewReader(`{}`))
		request.Header.Set("Authorization", "Delegate ds1."+fixture.credential.SessionID)
		result = httptest.NewRecorder()
		fixture.handler.ServeHTTP(result, request)
		if result.Code == 200 {
			t.Fatalf("delegate accepted by owner route %s", route)
		}
	}
	for _, mutate := range []func(*DelegatedSyncRequest){
		func(value *DelegatedSyncRequest) { value.Collection = "private.inbe.v1.cells" },
		func(value *DelegatedSyncRequest) { value.Sync.UserIDHash = strings.Repeat("f", 64) },
		func(value *DelegatedSyncRequest) { value.Sync.FullSyncRequested = true },
		func(value *DelegatedSyncRequest) { value.Sync.EncryptedRecords[0].DeletedAt = 1 },
		func(value *DelegatedSyncRequest) { value.Sync.EncryptedRecords[0].KeyID = "other-key" },
	} {
		bad := input
		bad.Sync.EncryptedRecords = append([]EncryptedRecord(nil), input.Sync.EncryptedRecords...)
		mutate(&bad)
		result = httptest.NewRecorder()
		fixture.handler.ServeHTTP(result, fixture.delegateRequest(t, bad))
		if result.Code != 403 {
			t.Fatalf("scope escalation: %d %s", result.Code, result.Body.String())
		}
	}
	if revoked := fixture.ownerCall(t, "/api/v1/authorization/revoke", GrantIDRequest{GrantID: fixture.grant.GrantID, AppID: "inbe"}); revoked.Code != 200 {
		t.Fatalf("revoke: %d %s", revoked.Code, revoked.Body.String())
	}
	result = httptest.NewRecorder()
	fixture.handler.ServeHTTP(result, fixture.delegateRequest(t, fixture.syncInput()))
	if result.Code != 401 {
		t.Fatal("revoked grant accepted")
	}
	challenge := authorizationCall(t, fixture.handler, "/api/v1/authorization/challenge", GrantIDRequest{GrantID: fixture.grant.GrantID}, nil)
	if challenge.Code != 401 {
		t.Fatal("revoked grant renewed")
	}
}

func TestAuthorizationGrantSignatureAndRequestTampering(t *testing.T) {
	fixture := authorizationSetup(t)
	fixture.connect(t)
	for name, mutate := range map[string]func(*Grant){
		"account":  func(value *Grant) { value.AccountID = strings.Repeat("a", 64) },
		"app":      func(value *Grant) { value.AppID = "other" },
		"key":      func(value *Grant) { value.SigningKey = strings.Repeat("1", 64) },
		"node":     func(value *Grant) { value.NodeID = strings.Repeat("2", 64) },
		"expiry":   func(value *Grant) { value.ExpiresAt++ },
		"envelope": func(value *Grant) { value.Scopes[0].KeyEnvelope = "different-envelope" },
		"scope":    func(value *Grant) { value.Scopes[0].Collection = "private.inbe.v1.diary" },
	} {
		t.Run(name, func(t *testing.T) {
			grant := fixture.grant
			grant.Scopes = append([]GrantScope(nil), grant.Scopes...)
			mutate(&grant)
			verified := Authorization_VerifyGrant(fixture.store.Database, t.Context(), grant,
				fixture.owner.UserID, fixture.server.Node.ID, fixture.server.Cfg.BaseURL, MlDsa44_Verify)
			if verified.Status == 0 && verified.Error == nil {
				t.Fatal("tampered grant accepted")
			}
		})
	}
	for _, field := range []string{"signature", "app_id", "node_id", "session_id", "body_sha256", "query", "expires_at"} {
		t.Run("request-"+field, func(t *testing.T) {
			request := fixture.delegateRequest(t, fixture.syncInput())
			var proof map[string]any
			json.Unmarshal([]byte(request.Header.Get("X-Daochi-Delegate")), &proof)
			if field == "expires_at" {
				proof[field] = time.Now().Unix() - 1
			} else {
				proof[field] = "tampered"
			}
			header, _ := json.Marshal(proof)
			request.Header.Set("X-Daochi-Delegate", string(header))
			result := httptest.NewRecorder()
			fixture.handler.ServeHTTP(result, request)
			if result.Code != 401 {
				t.Fatalf("tampered request accepted: %d", result.Code)
			}
		})
	}
	request := fixture.delegateRequest(t, fixture.syncInput())
	request.Header.Del("X-Daochi-Delegate")
	result := httptest.NewRecorder()
	fixture.handler.ServeHTTP(result, request)
	if result.Code != 401 {
		t.Fatal("stolen session without proof accepted")
	}
}

func telegramInitFixture(token string, fields url.Values) string {
	var names []string
	for name := range fields {
		if name != "hash" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	var lines []string
	for _, name := range names {
		lines = append(lines, name+"="+fields.Get(name))
	}
	secret := hmac.New(sha256.New, []byte("WebAppData"))
	secret.Write([]byte(token))
	signature := hmac.New(sha256.New, secret.Sum(nil))
	signature.Write([]byte(strings.Join(lines, "\n")))
	fields.Set("hash", hex.EncodeToString(signature.Sum(nil)))
	return fields.Encode()
}

func TestTelegramInitDataValidationAndStrictJSON(t *testing.T) {
	now := time.Now().Unix()
	token := "123456:synthetic-only"
	fields := url.Values{"auth_date": {strconv.FormatInt(now, 10)}, "query_id": {"synthetic-query"}, "user": {`{"id":1234,"first_name":"Ignored"}`}}
	raw := telegramInitFixture(token, fields)
	verified := TelegramInit_Validate(raw, token, now)
	if !verified.Valid || verified.UserID != 1234 || verified.BotID != 123456 {
		t.Fatal("valid synthetic HMAC vector rejected")
	}
	if TelegramInit_Validate(raw, "654321:wrong-bot", now).Valid || TelegramInit_Validate(raw, token, now+301).Valid || TelegramInit_Validate(raw, token, now-31).Valid {
		t.Fatal("wrong bot, stale or future initData accepted")
	}
	for _, bad := range []string{raw + "&user=%7B%22id%22%3A1234%7D", raw + "&%75ser=x", raw + "&bad=%zz", strings.Replace(raw, "1234", "4321", 1)} {
		if TelegramInit_Validate(bad, token, now).Valid {
			t.Fatal("duplicate, malformed or tampered initData accepted")
		}
	}
	for _, user := range []string{`{"id":1234,"id":4321}`, `{"id":1234,"\u0069d":4321}`, `{"id":1234,"ID":4321}`, `{"ID":1234}`, `{"\u0049d":1234}`, `{"id":"1234"}`, `{"first_name":"1234"}`, `{"id":1.2}`, `{"id":1234,"is_bot":true}`} {
		fields.Set("user", user)
		if TelegramInit_Validate(telegramInitFixture(token, fields), token, now).Valid {
			t.Fatal("malformed numeric identity accepted")
		}
	}
	for _, document := range []string{`{"a":1,"a":2}`, `{"a":[{"b":1,"b":2}]}`, `{"id":1,"\u0069d":2}`, `{"grant_id":"a","GRANT_ID":"b"}`, `{"GRANT_ID":"a"}`, `{"grant_id":"a","\u0047rant_id":"b"}`} {
		if StrictJson_Valid(document) {
			t.Fatal("duplicate JSON accepted")
		}
	}
	if !StrictJson_Valid(`{"a":[{},null,1,"x"],"b":true}`) {
		t.Fatal("valid JSON rejected")
	}
}

func TestAuthorizationRejectsCaseFoldedProtocolFields(t *testing.T) {
	fixture := authorizationSetup(t)
	fixture.connect(t)
	request := fixture.delegateRequest(t, fixture.syncInput())
	proof := request.Header.Get("X-Daochi-Delegate")
	for _, malformed := range []string{
		strings.Replace(proof, `"grant_id":`, `"GRANT_ID":`, 1),
		strings.Replace(proof, `"grant_id":`, `"GRANT_ID":"ignored","grant_id":`, 1),
		strings.Replace(proof, `"grant_id":`, `"\u0047rant_id":`, 1),
	} {
		clone := fixture.delegateRequest(t, fixture.syncInput())
		clone.Header.Set("X-Daochi-Delegate", malformed)
		if result := authorizationServe(fixture, clone); result.Code != 401 {
			t.Fatalf("case-folded request field accepted: %d", result.Code)
		}
	}
}
