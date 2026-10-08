package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func authorizationRecord(t *testing.T, fixture *authorizationFixture, id, key string) {
	t.Helper()
	transaction, err := fixture.store.Database.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	result := SyncWrites_UpsertRecord(transaction, t.Context(), fixture.owner.UserID, EncryptedRecord{
		Collection: "private.inbe.v2.lumi", ID: id, KeyID: key, Nonce: "fixture-nonce",
		Ciphertext: "opaque-fixture", UpdatedAt: "2026-10-08T00:00:00Z",
	})
	if result.Error != nil {
		t.Fatal(result.Error)
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
}

func authorizationServe(fixture *authorizationFixture, request *http.Request) *httptest.ResponseRecorder {
	result := httptest.NewRecorder()
	fixture.handler.ServeHTTP(result, request)
	return result
}

func TestAuthorizationKeyGenerationRotation(t *testing.T) {
	fixture := authorizationSetup(t)
	fixture.connect(t)
	authorizationRecord(t, fixture, "old-history", "lumi-key-v1")
	authorizationRecord(t, fixture, "approved-history", "lumi-key-v2")
	authorizationRecord(t, fixture, "rotated-history", "lumi-key-v3")
	input := fixture.syncInput()
	input.Limit = 1
	result := authorizationServe(fixture, fixture.delegateRequest(t, input))
	var answer DelegatedSyncResponse
	if result.Code != 200 || json.Unmarshal(result.Body.Bytes(), &answer) != nil ||
		len(answer.Records) != 1 || answer.Records[0].ID != "approved-history" || answer.Truncated {
		t.Fatalf("read escaped approved generation: %d %s", result.Code, result.Body.String())
	}
	input.Sync.EncryptedRecords = []EncryptedRecord{{Collection: input.Collection,
		ID: "rotated-history", KeyID: "lumi-key-v2", Nonce: "fixture-nonce", Ciphertext: "overwrite",
		UpdatedAt: "2026-10-09T00:00:00Z"}}
	if result := authorizationServe(fixture, fixture.delegateRequest(t, input)); result.Code != 403 {
		t.Fatalf("delegate overwrote rotated generation: %d", result.Code)
	}
	// Owner rotation replaces the approved ciphertext; both reads and socket
	// versions exclude the replacement until a new owner grant is approved.
	authorizationRecord(t, fixture, "approved-history", "lumi-key-v3")
	input = fixture.syncInput()
	result = authorizationServe(fixture, fixture.delegateRequest(t, input))
	if result.Code != 200 || json.Unmarshal(result.Body.Bytes(), &answer) != nil || len(answer.Records) != 0 {
		t.Fatal("rotated records delivered to prior key generation")
	}
	current := DelegatedWs_Current(Server_Authorizations(fixture.server), t.Context(),
		fixture.credential.SessionID, fixture.grant.GrantID, input.Collection)
	if !current.Active || current.Value != 0 {
		t.Fatal("socket revealed records outside approved key generation")
	}
	if result := fixture.ownerCall(t, "/api/v1/authorization/revoke", GrantIDRequest{
		GrantID: fixture.grant.GrantID, AppID: "inbe"}); result.Code != 200 {
		t.Fatal("old generation revocation failed")
	}
	if result := authorizationServe(fixture, fixture.delegateRequest(t, input)); result.Code != 401 {
		t.Fatal("revoked old generation remained readable")
	}
}

func TestAuthorizationRendezvousPrivacyAndLegacyKeyRefusal(t *testing.T) {
	fixture := authorizationSetup(t)
	for _, collection := range []string{"private.inbe.v1.cells", "private.inbe.v1.sessions", "private.inbe.v1.habits", "private.inbe.v1.habit_days", " private.inbe.v1.sessions", "private.inbe.v2.lumi "} {
		created := fixture.ownerCall(t, "/api/v1/authorization/requests", AuthorizationRequest{AppID: "inbe",
			Scopes: []RequestedScope{{Collection: collection, Read: true}}})
		if created.Code != 400 {
			t.Fatalf("legacy shared-key collection accepted: %s %d", collection, created.Code)
		}
	}
	created := fixture.ownerCall(t, "/api/v1/authorization/requests", AuthorizationRequest{AppID: "inbe",
		Scopes: []RequestedScope{{Collection: "private.inbe.v2.lumi", Read: true}}})
	var pending Rendezvous
	if created.Code != 200 || json.Unmarshal(created.Body.Bytes(), &pending) != nil {
		t.Fatal("owner pending request failed")
	}
	input := RendezvousID{RequestID: pending.RequestID}
	public := authorizationCall(t, fixture.handler, "/api/v1/authorization/rendezvous", input, nil)
	var fields map[string]any
	if public.Code != 200 || json.Unmarshal(public.Body.Bytes(), &fields) != nil || len(fields) != 8 {
		t.Fatalf("minimal challenge unavailable: %d %s", public.Code, public.Body.String())
	}
	for _, private := range []string{"account_id", "telegram_id", "bot_id", "scopes", "client_id", "signing_key", "encryption_key"} {
		if _, exists := fields[private]; exists {
			t.Fatalf("rendezvous leaked %s before sender proof", private)
		}
	}
	owner := authorizationCall(t, fixture.handler, "/api/v1/authorization/rendezvous", input,
		map[string]string{"Authorization": "Bearer " + fixture.owner.Token})
	if owner.Code != 200 || json.Unmarshal(owner.Body.Bytes(), &pending) != nil || pending.AccountID != fixture.owner.UserID || len(pending.Scopes) != 1 {
		t.Fatal("owner authenticated polling lost approval details")
	}
	// A valid bearer belonging to a different account must not get the full
	// details merely by acquiring this rendezvous ID.
	otherKey := MlDsa44_KeyPair()
	if otherKey.Error != nil {
		t.Fatal(otherKey.Error)
	}
	defer clear(otherKey.PrivateKey)
	otherID := Signing_SHA256Hex(otherKey.PublicKey)
	if _, err := fixture.store.Database.Exec("INSERT INTO server_users(user_id_hash,public_key) VALUES(?,?)", otherID, otherKey.PublicKey); err != nil {
		t.Fatal(err)
	}
	otherToken := Token_IssueAuthToken(fixture.server.Cfg.TokenSecret, otherID, time.Now().Unix()+300)
	other := authorizationCall(t, fixture.handler, "/api/v1/authorization/rendezvous", input,
		map[string]string{"Authorization": "Bearer " + otherToken.Value})
	if other.Code != 404 {
		t.Fatal("another owner read private approval metadata")
	}
}

func TestAuthorizationCurrentRegistrationAndExpiry(t *testing.T) {
	for name, change := range map[string]string{
		"visibility":        "UPDATE server_app_collections SET visibility='public' WHERE collection_prefix='private.inbe.v2.lumi'",
		"scope removed":     "DELETE FROM server_app_collections WHERE collection_prefix='private.inbe.v2.lumi'",
		"app disabled":      "UPDATE server_apps SET status='disabled' WHERE app_id='inbe'",
		"manifest disabled": "UPDATE server_app_manifests SET status='disabled' WHERE app_id='inbe'",
		"manifest expired":  "UPDATE server_app_manifests SET expires_at=1 WHERE app_id='inbe'",
		"grant expired":     "UPDATE server_authorization_grants SET expires_at=1",
		"session expired":   "UPDATE server_authorization_sessions SET expires_at=1",
		"client removed":    "DELETE FROM server_clients WHERE client_id='" + strings.Repeat("b", 64) + "'",
	} {
		t.Run(name, func(t *testing.T) {
			fixture := authorizationSetup(t)
			fixture.connect(t)
			if _, err := fixture.store.Database.Exec(change); err != nil {
				t.Fatal(err)
			}
			result := authorizationServe(fixture, fixture.delegateRequest(t, fixture.syncInput()))
			if result.Code != 401 && result.Code != 403 && result.Code != 400 {
				t.Fatalf("changed registration accepted: %d %s", result.Code, result.Body.String())
			}
			if current := DelegatedWs_Current(Server_Authorizations(fixture.server), t.Context(),
				fixture.credential.SessionID, fixture.grant.GrantID, "private.inbe.v2.lumi"); current.Active {
				t.Fatal("socket survived inactive registration or credential")
			}
		})
	}
}

func TestAuthorizationAtomicNonceMutationRacesAndRollback(t *testing.T) {
	fixture := authorizationSetup(t)
	fixture.connect(t)
	fixture.store.Database.SetMaxOpenConns(8)
	input := fixture.syncInput()
	input.Sync.EncryptedRecords = []EncryptedRecord{{Collection: input.Collection, ID: "once",
		KeyID: "lumi-key-v2", Nonce: "fixture", Ciphertext: "opaque", UpdatedAt: "2026-10-08T00:00:00Z"}}
	raw, _ := json.Marshal(input)
	request := fixture.delegateRequest(t, input)
	codes := make(chan int, 24)
	var workers sync.WaitGroup
	for index := 0; index < 24; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			clone := httptest.NewRequest("POST", request.URL.String(), bytes.NewReader(raw))
			clone.Header = request.Header.Clone()
			codes <- authorizationServe(fixture, clone).Code
		}()
	}
	workers.Wait()
	close(codes)
	accepted, replayed := 0, 0
	for code := range codes {
		switch code {
		case 200:
			accepted++
		case 409:
			replayed++
		default:
			t.Fatalf("unexpected raced request status %d", code)
		}
	}
	if accepted != 1 || replayed != 23 {
		t.Fatalf("race winners=%d replays=%d", accepted, replayed)
	}
	var mutations int
	if err := fixture.store.Database.QueryRow("SELECT COUNT(*) FROM server_mesh_changes WHERE record_id='once'").Scan(&mutations); err != nil || mutations != 1 {
		t.Fatalf("mutation executed more than once: %d %v", mutations, err)
	}
	// A storage failure must roll back the claimed nonce as well as every write.
	if _, err := fixture.store.Database.Exec("CREATE TRIGGER fixture_reject_write BEFORE INSERT ON server_encrypted_records BEGIN SELECT RAISE(ABORT,'synthetic storage failure'); END"); err != nil {
		t.Fatal(err)
	}
	input.Sync.EncryptedRecords[0].ID = "retry-after-failure"
	raw, _ = json.Marshal(input)
	request = fixture.delegateRequest(t, input)
	if result := authorizationServe(fixture, request); result.Code != 503 {
		t.Fatalf("storage failure status=%d", result.Code)
	}
	if _, err := fixture.store.Database.Exec("DROP TRIGGER fixture_reject_write"); err != nil {
		t.Fatal(err)
	}
	retry := httptest.NewRequest("POST", request.URL.String(), bytes.NewReader(raw))
	retry.Header = request.Header.Clone()
	if result := authorizationServe(fixture, retry); result.Code != 200 {
		t.Fatalf("rolled back nonce was burned: %d %s", result.Code, result.Body.String())
	}
}

func TestAuthorizationRestartAndIssuingNodePartition(t *testing.T) {
	fixture := authorizationSetup(t)
	fixture.connect(t)
	input := fixture.syncInput()
	raw, _ := json.Marshal(input)
	used := fixture.delegateRequest(t, input)
	if result := authorizationServe(fixture, used); result.Code != 200 {
		t.Fatal("initial read failed")
	}
	configuration := fixture.server.Cfg
	// Production loads this persistent key before creating the node. The
	// ordinary HTTP fixtures intentionally use fresh ephemeral identities.
	configuration.NodeIdentityPrivateKey = fixture.server.Node.PrivateKey
	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	opened, err := OpenStore(configuration.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	fixture.store = opened
	fixture.server = NewServer(configuration, opened, Verifier_New(MlDsa44_Verify))
	fixture.handler = fixture.server.Routes()
	replay := httptest.NewRequest("POST", used.URL.String(), bytes.NewReader(raw))
	replay.Header = used.Header.Clone()
	if result := authorizationServe(fixture, replay); result.Code != 409 {
		t.Fatalf("replay state lost on restart: %d", result.Code)
	}
	if result := authorizationServe(fixture, fixture.delegateRequest(t, input)); result.Code != 200 {
		t.Fatalf("fresh proof failed on issuing-node restart: %d", result.Code)
	}
	// Even with the database copied locally, a different node or audience must
	// reject the credential. It cannot renew through another partition.
	other := *fixture.server
	other.Node = fixture.server.Node
	other.Node.ID = strings.Repeat("f", 64)
	otherHandler := other.Routes()
	request := fixture.delegateRequest(t, input)
	result := httptest.NewRecorder()
	otherHandler.ServeHTTP(result, request)
	if result.Code != 401 {
		t.Fatalf("other node accepted issuing-node proof: %d", result.Code)
	}
	challenge := authorizationCall(t, otherHandler, "/api/v1/authorization/challenge", GrantIDRequest{GrantID: fixture.grant.GrantID}, nil)
	if challenge.Code != 401 {
		t.Fatal("partition accepted session renewal")
	}
	other.Node.ID = fixture.grant.NodeID
	other.Cfg.BaseURL = "https://other-audience.invalid"
	challenge = authorizationCall(t, other.Routes(), "/api/v1/authorization/challenge", GrantIDRequest{GrantID: fixture.grant.GrantID}, nil)
	if challenge.Code != 401 {
		t.Fatal("other audience accepted session renewal")
	}
}

func TestAuthorizationTelegramClaimCancelReplayAndDisconnect(t *testing.T) {
	fixture := authorizationSetup(t)
	fixture.server.Cfg.LumiBotToken = "123456:synthetic-only"
	fixture.handler = fixture.server.Routes()
	if !LumiTelegram_Schema(Server_ChatService(fixture.server), httptest.NewRequest("POST", "/", nil)) {
		t.Fatal("Telegram schema unavailable")
	}
	if _, err := fixture.store.Database.Exec("INSERT INTO server_lumi_telegram(account_id,telegram_id,linked_at) VALUES(?,1234,1)", fixture.owner.UserID); err != nil {
		t.Fatal(err)
	}
	create := func() Rendezvous {
		result := fixture.ownerCall(t, "/api/v1/authorization/requests", AuthorizationRequest{AppID: "inbe", Telegram: true,
			Scopes: []RequestedScope{{Collection: "private.inbe.v2.lumi", Read: true}}})
		var pending Rendezvous
		if result.Code != 200 || json.Unmarshal(result.Body.Bytes(), &pending) != nil {
			t.Fatalf("Telegram request: %d %s", result.Code, result.Body.String())
		}
		return pending
	}
	fields := url.Values{"auth_date": {fmt.Sprint(time.Now().Unix())}, "user": {`{"id":1234}`}, "query_id": {"synthetic-claim"}}
	initData := telegramInitFixture(fixture.server.Cfg.LumiBotToken, fields)
	digest := TelegramInit_Validate(initData, fixture.server.Cfg.LumiBotToken, time.Now().Unix()).Digest
	claimFor := func(pending Rendezvous, data, digest string) RendezvousClaim {
		claim := RendezvousClaim{RequestID: pending.RequestID, ClientID: strings.Repeat("b", 64),
			SigningKey: hex.EncodeToString(fixture.delegate.Public().(ed25519.PublicKey)), EncryptionKey: strings.Repeat("c", 2368), InitData: data}
		claim.Proof = hex.EncodeToString(ed25519.Sign(fixture.delegate, []byte(AuthorizationHttp_ClaimMessage(pending, claim, digest))))
		return claim
	}
	pending := create()
	wrongFields := url.Values{"auth_date": fields["auth_date"], "user": {`{"id":4321}`}}
	wrongData := telegramInitFixture(fixture.server.Cfg.LumiBotToken, wrongFields)
	wrongDigest := TelegramInit_Validate(wrongData, fixture.server.Cfg.LumiBotToken, time.Now().Unix()).Digest
	if result := authorizationCall(t, fixture.handler, "/api/v1/authorization/claim", claimFor(pending, wrongData, wrongDigest), nil); result.Code != 401 {
		t.Fatal("wrong numeric sender claimed account")
	}
	claim := claimFor(pending, initData, digest)
	if result := authorizationCall(t, fixture.handler, "/api/v1/authorization/claim", claim, nil); result.Code != 200 {
		t.Fatalf("verified Telegram claim failed: %d %s", result.Code, result.Body.String())
	}
	if result := authorizationCall(t, fixture.handler, "/api/v1/authorization/claim", claim, nil); result.Code != 409 {
		t.Fatal("rendezvous replay accepted")
	}
	second := create()
	if result := authorizationCall(t, fixture.handler, "/api/v1/authorization/claim", claimFor(second, initData, digest), nil); result.Code != 409 {
		t.Fatal("initData replay crossed rendezvous")
	}
	if result := fixture.ownerCall(t, "/api/v1/authorization/cancel", RendezvousID{RequestID: second.RequestID, AppID: "inbe"}); result.Code != 200 {
		t.Fatal("owner cancellation failed")
	}
	if result := authorizationCall(t, fixture.handler, "/api/v1/authorization/claim", claimFor(second, initData, digest), nil); result.Code != 409 {
		t.Fatal("cancelled rendezvous claimed")
	}
	request := httptest.NewRequest("DELETE", "/api/v1/lumi/telegram/link", nil)
	request.Header.Set("Authorization", "Bearer "+fixture.owner.Token)
	if result := authorizationServe(fixture, request); result.Code != 200 {
		t.Fatalf("disconnect failed: %d %s", result.Code, result.Body.String())
	}
	var status string
	if err := fixture.store.Database.QueryRow("SELECT status FROM server_authorization_requests WHERE request_id=?", pending.RequestID).Scan(&status); err != nil || status != "cancelled" {
		t.Fatal("disconnect left claimed authorization pending")
	}
}

func TestAuthorizationWebSocketRevocation(t *testing.T) {
	fixture := authorizationSetup(t)
	fixture.connect(t)
	target := httptest.NewServer(fixture.handler)
	t.Cleanup(target.Close)
	parsed, _ := url.Parse(target.URL)
	connection, err := net.Dial("tcp", parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	proof := RequestProof{Version: 1, GrantID: fixture.grant.GrantID, SessionID: fixture.credential.SessionID,
		AccountID: fixture.owner.UserID, AppID: "inbe", ClientID: fixture.grant.ClientID,
		NodeID: fixture.grant.NodeID, Audience: fixture.grant.Audience, Challenge: fixture.credential.Challenge,
		Method: "GET", Path: "/api/v1/delegated/ws", Query: "collection=private.inbe.v2.lumi",
		BodySHA256: Signing_SHA256Hex(nil), ExpiresAt: time.Now().Unix() + 30, Nonce: strings.Repeat("9", 32)}
	proof.Signature = hex.EncodeToString(ed25519.Sign(fixture.delegate, []byte(Session_ProofMessage(proof))))
	raw, _ := json.Marshal(proof)
	protocol := "daochi-sync-v1, daochi.delegate." + base64.RawURLEncoding.EncodeToString(raw) + ", daochi.session." + fixture.credential.SessionID
	_, err = fmt.Fprintf(connection, "GET %s?%s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: %s\r\n\r\n", proof.Path, proof.Query, parsed.Host, protocol)
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
	if err != nil || response.StatusCode != 101 {
		t.Fatalf("delegate handshake: %v %v", response, err)
	}
	connection.SetReadDeadline(time.Now().Add(3 * time.Second))
	frame := Websocket_ReadFrame(reader)
	var event CollectionEvent
	if frame.Error != nil || json.Unmarshal(frame.Payload, &event) != nil || event.Collection != "private.inbe.v2.lumi" {
		t.Fatalf("scoped socket event: %v", frame.Error)
	}
	if result := fixture.ownerCall(t, "/api/v1/authorization/revoke", GrantIDRequest{GrantID: fixture.grant.GrantID, AppID: "inbe"}); result.Code != 200 {
		t.Fatal("revoke failed")
	}
	frame = Websocket_ReadFrame(reader)
	if frame.Error == nil {
		t.Fatal("revoked socket emitted another frame")
	}
	if timeout, ok := frame.Error.(net.Error); ok && timeout.Timeout() {
		t.Fatal("revoked socket remained open")
	}
}
