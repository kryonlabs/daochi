package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const entryRendezvousPath = "/api/v1/telegram/entry/rendezvous"

func entryRendezvousSetup(t *testing.T, linked bool) (*entryFixture, EntryIdentity) {
	t.Helper()
	fixture := entrySetup(t)
	fixture.owner.handler = fixture.owner.server.Routes()
	if linked {
		if _, err := fixture.owner.store.Database.Exec(
			"INSERT INTO server_lumi_telegram(account_id,telegram_id,linked_at) VALUES(?,1234,1)", fixture.owner.owner.UserID); err != nil {
			t.Fatal(err)
		}
	}
	info := fixture.issue(t, "connect", 1234)
	result := authorizationCall(t, fixture.owner.handler, "/api/v1/telegram/entry/verify", fixture.proof(info, 1234), nil)
	var entry EntryIdentity
	if result.Code != http.StatusOK || json.Unmarshal(result.Body.Bytes(), &entry) != nil {
		t.Fatalf("production verified entry status=%d", result.Code)
	}
	return fixture, entry
}

func entryRendezvousMinimal(t *testing.T, result *httptest.ResponseRecorder, fixture *entryFixture) EntryRendezvous {
	t.Helper()
	if result.Code != http.StatusOK {
		t.Fatalf("owner rendezvous status=%d", result.Code)
	}
	var answer EntryRendezvous
	var fields map[string]any
	if json.Unmarshal(result.Body.Bytes(), &answer) != nil || json.Unmarshal(result.Body.Bytes(), &fields) != nil {
		t.Fatal("invalid minimal owner rendezvous")
	}
	allowed := map[string]bool{
		"request_id": true, "grant_id": true, "app_id": true, "node_id": true,
		"audience": true, "expires_at": true, "challenge": true, "status": true,
	}
	for field := range fields {
		if !allowed[field] {
			t.Fatalf("owner rendezvous exposes an unlisted field: %s", field)
		}
	}
	if len(fields) != len(allowed) || strings.Contains(result.Body.String(), fixture.owner.owner.UserID) {
		t.Fatal("owner rendezvous response is not minimal")
	}
	return answer
}

func entryRendezvousNonceCount(t *testing.T, fixture *entryFixture, action EntryAction) int {
	t.Helper()
	var count int
	if err := fixture.owner.store.Database.QueryRow(
		"SELECT COUNT(*) FROM server_telegram_entry_nonces WHERE entry_id=? AND nonce=?",
		action.EntryID, action.Nonce).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func entryRendezvousSign(fixture *entryFixture, info EntryChallenge, input EntryAction) EntryAction {
	input.Proof = hex.EncodeToString(ed25519.Sign(fixture.owner.delegate,
		[]byte(TelegramAccountEntry_ActionMessage(info, input, "request"))))
	return input
}

func entryPending(t *testing.T, fixture *entryFixture) Rendezvous {
	t.Helper()
	input := AuthorizationRequest{AppID: "inbe", Telegram: true,
		Scopes: []RequestedScope{{Collection: "private.inbe.v2.lumi", Read: true, Write: true}}}
	result := fixture.owner.ownerCall(t, "/api/v1/authorization/requests", input)
	var pending Rendezvous
	if result.Code != 200 || json.Unmarshal(result.Body.Bytes(), &pending) != nil {
		t.Fatalf("owner pending request failed: %d", result.Code)
	}
	return pending
}

func entryRendezvousClaim(fixture *entryFixture, pending Rendezvous, proof EntryVerify, entryID string) RendezvousClaim {
	claim := RendezvousClaim{EntryID: entryID, RequestID: pending.RequestID,
		ClientID: proof.ClientID, SigningKey: proof.SigningKey, EncryptionKey: proof.EncryptionKey}
	if entryID == "" {
		claim.InitData = proof.InitData
	}
	digest := TelegramInit_Validate(proof.InitData, fixture.service.Configuration.LumiBotToken, time.Now().Unix()).Digest
	claim.Proof = hex.EncodeToString(ed25519.Sign(fixture.owner.delegate,
		[]byte(AuthorizationHttp_ClaimMessage(pending, claim, digest))))
	return claim
}

func TestTelegramAccountEntrySharedReplayAndClaimRollback(t *testing.T) {
	for _, entryFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(entryFirst), func(t *testing.T) {
			fixture := entrySetup(t)
			if _, err := fixture.owner.store.Database.Exec("INSERT INTO server_lumi_telegram(account_id,telegram_id,linked_at) VALUES(?,1234,1)", fixture.owner.owner.UserID); err != nil {
				t.Fatal(err)
			}
			info := fixture.issue(t, "connect", 1234)
			proof := fixture.proof(info, 1234)
			pending := entryPending(t, fixture)
			claim := entryRendezvousClaim(fixture, pending, proof, "")
			verify := func() int {
				return authorizationCall(t, fixture.owner.handler, entryPath+"verify", proof, nil).Code
			}
			claimRaw := func() int {
				return authorizationCall(t, fixture.owner.handler, "/api/v1/authorization/claim", claim, nil).Code
			}
			if !entryFirst {
				if claimRaw() != 200 || verify() != 409 {
					t.Fatal("owner rendezvous replayed through bot entry")
				}
				return
			}
			if verify() != 200 || claimRaw() != 409 {
				t.Fatal("bot entry replayed through owner rendezvous")
			}
			claim = entryRendezvousClaim(fixture, pending, proof, info.EntryID)
			validProof := claim.Proof
			claim.Proof = strings.Repeat("0", 128)
			if result := authorizationCall(t, fixture.owner.handler, "/api/v1/authorization/claim", claim, nil); result.Code != 401 {
				t.Fatalf("tampered claim accepted: %d", result.Code)
			}
			var status string
			if err := fixture.owner.store.Database.QueryRow("SELECT status FROM server_telegram_account_entries WHERE entry_id=?", info.EntryID).Scan(&status); err != nil || status != "verified" {
				t.Fatal("rejected claim consumed verified entry")
			}
			claim.Proof = validProof
			if result := authorizationCall(t, fixture.owner.handler, "/api/v1/authorization/claim", claim, nil); result.Code != 200 {
				t.Fatalf("verified same-key entry could not claim: %d", result.Code)
			}
			if result := authorizationCall(t, fixture.owner.handler, "/api/v1/authorization/claim", claim, nil); result.Code != 409 {
				t.Fatal("entry consumed more than once")
			}
		})
	}
}

func TestTelegramAccountEntryProductionRoutesAndBotMenu(t *testing.T) {
	fixture := entrySetup(t)
	fixture.owner.handler = fixture.owner.server.Routes()
	fixture.owner.server.Cfg.TelegramAccountsEnabled = true
	fixture.owner.server.Cfg.LumiWebhookSecret = "synthetic-entry-webhook"
	fixture.owner.server.Cfg.LumiCanvasURL = "https://inbe.example/telegram/index.html"
	var menu map[string]any
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/bot123456:synthetic-only/sendMessage" {
			t.Error("unexpected synthetic protocol action")
		}
		var value map[string]any
		if json.NewDecoder(request.Body).Decode(&value) != nil {
			t.Error("invalid synthetic menu")
		}
		menu, _ = value["reply_markup"].(map[string]any)
		fmt.Fprint(writer, `{"ok":true}`)
	}))
	defer upstream.Close()
	previous := TelegramAPIBase
	TelegramAPIBase = upstream.URL
	defer func() { TelegramAPIBase = previous }()
	if result := lumiWebhook(fixture.owner.handler, "synthetic-entry-webhook", 801, "private", "/start"); result.Code != 200 {
		t.Fatalf("bot entry menu failed: %d", result.Code)
	}
	rows, ok := menu["inline_keyboard"].([]any)
	if !ok || len(rows) != 3 {
		t.Fatal("Create/Restore/Connect menu not wired")
	}
	for index, mode := range []string{"create", "restore", "connect"} {
		button := rows[index].([]any)[0].(map[string]any)
		url := button["web_app"].(map[string]any)["url"].(string)
		id := strings.TrimPrefix(url, fixture.owner.server.Cfg.LumiCanvasURL+"?r=")
		result := authorizationCall(t, fixture.owner.handler, "/api/v1/telegram/entry", EntryID{EntryID: id}, nil)
		var info EntryChallenge
		if result.Code != 200 || json.Unmarshal(result.Body.Bytes(), &info) != nil || info.Mode != mode {
			t.Fatal("bot menu link is not a live expiring entry")
		}
		proof := fixture.proof(info, 1234)
		verified := authorizationCall(t, fixture.owner.handler, "/api/v1/telegram/entry/verify", proof, nil)
		if verified.Code != 200 {
			t.Fatalf("production verify route failed: %d", verified.Code)
		}
	}
}

func TestTelegramAccountEntryRendezvousWaitsForLateOwnerRequest(t *testing.T) {
	fixture, entry := entryRendezvousSetup(t, true)
	first := fixture.action(entry, "request", "")
	result := authorizationCall(t, fixture.owner.handler, entryRendezvousPath, first, nil)
	if result.Code != http.StatusAccepted || strings.TrimSpace(result.Body.String()) != "true" {
		t.Fatalf("entry without owner approval should wait: status=%d", result.Code)
	}
	if entryRendezvousNonceCount(t, fixture, first) != 1 {
		t.Fatal("waiting response did not consume its fresh proof")
	}
	if result := authorizationCall(t, fixture.owner.handler, entryRendezvousPath, first, nil); result.Code != http.StatusConflict {
		t.Fatalf("waiting proof replay status=%d", result.Code)
	}
	pending := entryPending(t, fixture)
	second := fixture.action(entry, "request", "")
	answer := entryRendezvousMinimal(t, authorizationCall(t, fixture.owner.handler, entryRendezvousPath, second, nil), fixture)
	if answer.RequestID != pending.RequestID || answer.AppID != "inbe" || answer.NodeID != pending.NodeID ||
		answer.Audience != pending.Audience || answer.ExpiresAt != pending.ExpiresAt ||
		answer.Challenge != pending.Challenge || answer.Status != "pending" {
		t.Fatal("late owner request did not match the verified issuing-node entry")
	}
	if result := authorizationCall(t, fixture.owner.handler, entryRendezvousPath, second, nil); result.Code != http.StatusConflict {
		t.Fatalf("successful discovery proof replay status=%d", result.Code)
	}
	public := authorizationCall(t, fixture.owner.handler, "/api/v1/telegram/entry", EntryID{EntryID: entry.Info.EntryID}, nil)
	var publicFields map[string]any
	if public.Code != http.StatusOK || json.Unmarshal(public.Body.Bytes(), &publicFields) != nil || len(publicFields) != 8 {
		t.Fatal("entry public challenge lost its minimal shape")
	}
	for _, field := range []string{"account_id", "telegram_id", "client_id", "signing_key", "encryption_key", "init_digest", "request_id"} {
		if _, exists := publicFields[field]; exists {
			t.Fatalf("public URL-possession polling exposed %s", field)
		}
	}
}

func TestTelegramAccountEntryRendezvousRequiresVerifiedSenderAndKeys(t *testing.T) {
	fixture := entrySetup(t)
	fixture.owner.handler = fixture.owner.server.Routes()
	info := fixture.issue(t, "connect", 1234)
	proof := fixture.proof(info, 4321)
	wrongSender := authorizationCall(t, fixture.owner.handler, "/api/v1/telegram/entry/verify", proof, nil)
	if wrongSender.Code != http.StatusUnauthorized {
		t.Fatalf("wrong numeric sender verified: status=%d", wrongSender.Code)
	}
	unverified := EntryIdentity{Info: info, ClientID: proof.ClientID, SigningKey: proof.SigningKey, EncryptionKey: proof.EncryptionKey}
	if result := authorizationCall(t, fixture.owner.handler, entryRendezvousPath, fixture.action(unverified, "request", ""), nil); result.Code != http.StatusUnauthorized {
		t.Fatalf("unverified entry discovered owner identity: status=%d", result.Code)
	}
	result := authorizationCall(t, fixture.owner.handler, "/api/v1/telegram/entry/verify", fixture.proof(info, 1234), nil)
	var entry EntryIdentity
	if result.Code != http.StatusOK || json.Unmarshal(result.Body.Bytes(), &entry) != nil {
		t.Fatal("wrong-sender rejection consumed the legitimate verification")
	}
	good := fixture.action(entry, "request", "")
	mutations := []struct {
		name string
		edit func(*EntryAction)
	}{
		{"client", func(input *EntryAction) { input.ClientID = strings.Repeat("d", 64) }},
		{"signing-key", func(input *EntryAction) { input.SigningKey = strings.Repeat("d", 64) }},
		{"encryption-key", func(input *EntryAction) { input.EncryptionKey = strings.Repeat("d", 2368) }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			input := good
			mutation.edit(&input)
			input = entryRendezvousSign(fixture, entry.Info, input)
			if result := authorizationCall(t, fixture.owner.handler, entryRendezvousPath, input, nil); result.Code != http.StatusUnauthorized {
				t.Fatalf("entry key binding mismatch status=%d", result.Code)
			}
		})
	}
	for _, field := range []string{"node", "audience", "challenge", "mode"} {
		badInfo := entry.Info
		switch field {
		case "node":
			badInfo.NodeID = strings.Repeat("d", 64)
		case "audience":
			badInfo.Audience += "/other"
		case "challenge":
			badInfo.Challenge = strings.Repeat("d", 32)
		case "mode":
			badInfo.Mode = "create"
		}
		input := entryRendezvousSign(fixture, badInfo, good)
		if result := authorizationCall(t, fixture.owner.handler, entryRendezvousPath, input, nil); result.Code != http.StatusUnauthorized {
			t.Fatalf("proof did not bind %s: status=%d", field, result.Code)
		}
	}
	if entryRendezvousNonceCount(t, fixture, good) != 0 {
		t.Fatal("rejected identity/key proofs consumed the valid nonce")
	}
	if result := authorizationCall(t, fixture.owner.handler, entryRendezvousPath, good, nil); result.Code != http.StatusAccepted {
		t.Fatalf("valid proof failed after identity/key rejection: status=%d", result.Code)
	}
}

func TestTelegramAccountEntryRendezvousCurrentAccountConflict(t *testing.T) {
	fixture, entry := entryRendezvousSetup(t, true)
	pending := entryPending(t, fixture)
	other := MlDsa44_KeyPair()
	if other.Error != nil {
		t.Fatal(other.Error)
	}
	defer clear(other.PrivateKey)
	otherAccount := Signing_SHA256Hex(other.PublicKey)
	if _, err := fixture.owner.store.Database.Exec(
		"INSERT INTO server_users(user_id_hash,public_key) VALUES(?,?)", otherAccount, other.PublicKey); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.owner.store.Database.Exec(
		"UPDATE server_lumi_telegram SET account_id=? WHERE telegram_id=1234", otherAccount); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.owner.store.Database.Exec(
		"UPDATE server_authorization_requests SET account_id=? WHERE request_id=?", otherAccount, pending.RequestID); err != nil {
		t.Fatal(err)
	}
	action := fixture.action(entry, "request", "")
	result := authorizationCall(t, fixture.owner.handler, entryRendezvousPath, action, nil)
	if result.Code != http.StatusConflict || strings.Contains(result.Body.String(), pending.RequestID) ||
		strings.Contains(result.Body.String(), otherAccount) || strings.Contains(result.Body.String(), fixture.owner.owner.UserID) {
		t.Fatal("changed chat binding exposed another account's owner request")
	}
	if entryRendezvousNonceCount(t, fixture, action) != 0 {
		t.Fatal("account conflict consumed the valid discovery proof")
	}
	if _, err := fixture.owner.store.Database.Exec(
		"UPDATE server_lumi_telegram SET account_id=? WHERE telegram_id=1234", fixture.owner.owner.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.owner.store.Database.Exec(
		"UPDATE server_authorization_requests SET account_id=? WHERE request_id=?", fixture.owner.owner.UserID, pending.RequestID); err != nil {
		t.Fatal(err)
	}
	answer := entryRendezvousMinimal(t, authorizationCall(t, fixture.owner.handler, entryRendezvousPath, action, nil), fixture)
	if answer.RequestID != pending.RequestID {
		t.Fatal("unchanged proof could not retry after restoring the exact account binding")
	}
}

func TestTelegramAccountEntryRendezvousExpiryAndTransactionRollback(t *testing.T) {
	t.Run("fresh action expiry", func(t *testing.T) {
		fixture, entry := entryRendezvousSetup(t, true)
		for _, expires := range []int64{time.Now().Unix() - 1, time.Now().Unix() + 120} {
			input := fixture.action(entry, "request", "")
			input.ExpiresAt = expires
			input = entryRendezvousSign(fixture, entry.Info, input)
			if result := authorizationCall(t, fixture.owner.handler, entryRendezvousPath, input, nil); result.Code != http.StatusUnauthorized {
				t.Fatalf("stale/future discovery proof status=%d", result.Code)
			}
			if entryRendezvousNonceCount(t, fixture, input) != 0 {
				t.Fatal("expired discovery proof consumed a nonce")
			}
		}
		input := fixture.action(entry, "request", "")
		if _, err := fixture.owner.store.Database.Exec(
			"UPDATE server_telegram_account_entries SET expires_at=1 WHERE entry_id=?", entry.Info.EntryID); err != nil {
			t.Fatal(err)
		}
		if result := authorizationCall(t, fixture.owner.handler, entryRendezvousPath, input, nil); result.Code != http.StatusUnauthorized {
			t.Fatalf("expired entry discovery status=%d", result.Code)
		}
	})
	t.Run("SQL rollback", func(t *testing.T) {
		fixture, entry := entryRendezvousSetup(t, false)
		if entry.AccountID != "" {
			t.Fatal("unlinked verification fabricated account ownership")
		}
		if _, err := fixture.owner.store.Database.Exec(
			"INSERT INTO server_lumi_telegram(account_id,telegram_id,linked_at) VALUES(?,1234,1)", fixture.owner.owner.UserID); err != nil {
			t.Fatal(err)
		}
		pending := entryPending(t, fixture)
		if _, err := fixture.owner.store.Database.Exec(
			"UPDATE server_authorization_requests SET expires_at='synthetic-invalid-expiry' WHERE request_id=?", pending.RequestID); err != nil {
			t.Fatal(err)
		}
		input := fixture.action(entry, "request", "")
		if result := authorizationCall(t, fixture.owner.handler, entryRendezvousPath, input, nil); result.Code != http.StatusServiceUnavailable {
			t.Fatalf("owner request SQL failure status=%d", result.Code)
		}
		var account string
		if err := fixture.owner.store.Database.QueryRow(
			"SELECT account_id FROM server_telegram_account_entries WHERE entry_id=?", entry.Info.EntryID).Scan(&account); err != nil || account != "" {
			t.Fatal("failed discovery committed its late account binding")
		}
		if entryRendezvousNonceCount(t, fixture, input) != 0 {
			t.Fatal("failed SQL transaction consumed the discovery proof")
		}
		if _, err := fixture.owner.store.Database.Exec(
			"UPDATE server_authorization_requests SET expires_at=? WHERE request_id=?", pending.ExpiresAt, pending.RequestID); err != nil {
			t.Fatal(err)
		}
		answer := entryRendezvousMinimal(t, authorizationCall(t, fixture.owner.handler, entryRendezvousPath, input, nil), fixture)
		if answer.RequestID != pending.RequestID || entryRendezvousNonceCount(t, fixture, input) != 1 {
			t.Fatal("repaired owner request could not atomically retry the same proof")
		}
		if err := fixture.owner.store.Database.QueryRow(
			"SELECT account_id FROM server_telegram_account_entries WHERE entry_id=?", entry.Info.EntryID).Scan(&account); err != nil || account != fixture.owner.owner.UserID {
			t.Fatal("successful discovery did not freeze the verified chat's exact account")
		}
	})
}
