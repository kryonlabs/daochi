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
