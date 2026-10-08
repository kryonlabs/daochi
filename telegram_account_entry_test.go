package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const entryPath = "/fixture/telegram-entry/"

type entryFixture struct {
	owner   *authorizationFixture
	service AccountEntries
	query   int
}

func entrySetup(t *testing.T) *entryFixture {
	t.Helper()
	owner := authorizationSetup(t)
	owner.server.Cfg.LumiBotToken = "123456:synthetic-only"
	if !LumiTelegram_Schema(Server_ChatService(owner.server), httptest.NewRequest("POST", "/", nil)) {
		t.Fatal("Telegram binding schema unavailable")
	}
	if _, err := owner.store.Database.Exec(TelegramAccountEntry_SchemaSQL()); err != nil {
		t.Fatal(err)
	}
	fixture := &entryFixture{owner: owner, service: AccountEntries{
		Database: owner.store.Database, Configuration: &owner.server.Cfg,
		Counters: owner.server.Metrics, Verify: MlDsa44_Verify,
		Replay: errSignedTxReplay, NodeID: owner.server.Node.ID,
	}}
	fixture.installHandler()
	return fixture
}

func (fixture *entryFixture) installHandler() {
	fallback := fixture.owner.server.Routes()
	fixture.owner.handler = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case entryPath + "environment":
			TelegramAccountEntry_Environment(fixture.service, writer, request)
		case entryPath + "info":
			TelegramAccountEntry_EntryInfo(fixture.service, writer, request)
		case entryPath + "verify":
			TelegramAccountEntry_Verify(fixture.service, writer, request)
		case entryPath + "status":
			TelegramAccountEntry_Status(fixture.service, writer, request)
		case entryPath + "cancel":
			TelegramAccountEntry_Cancel(fixture.service, writer, request)
		case entryPath + "bind":
			TelegramAccountEntry_Bind(fixture.service, writer, request)
		default:
			fallback.ServeHTTP(writer, request)
		}
	})
}

func (fixture *entryFixture) issue(t *testing.T, mode string, sender int64) EntryChallenge {
	t.Helper()
	issued := TelegramAccountEntry_Issue(fixture.service, t.Context(), mode, sender)
	if issued.Error != nil {
		t.Fatal(issued.Error)
	}
	return issued.Info
}

func (fixture *entryFixture) proof(info EntryChallenge, sender int64) EntryVerify {
	fixture.query++
	fields := url.Values{"auth_date": {strconv.FormatInt(time.Now().Unix(), 10)},
		"user":     {fmt.Sprintf(`{"id":%d,"first_name":"Ignored"}`, sender)},
		"query_id": {fmt.Sprintf("synthetic-entry-%d", fixture.query)}}
	data := telegramInitFixture(fixture.service.Configuration.LumiBotToken, fields)
	digest := TelegramInit_Validate(data, fixture.service.Configuration.LumiBotToken, time.Now().Unix()).Digest
	input := EntryVerify{EntryID: info.EntryID, ClientID: strings.Repeat("b", 64),
		SigningKey:    hex.EncodeToString(fixture.owner.delegate.Public().(ed25519.PublicKey)),
		EncryptionKey: strings.Repeat("c", 2368), InitData: data}
	input.Proof = hex.EncodeToString(ed25519.Sign(fixture.owner.delegate,
		[]byte(TelegramAccountEntry_VerifyMessage(info, input, digest))))
	return input
}

func (fixture *entryFixture) verify(t *testing.T, info EntryChallenge, sender int64) EntryIdentity {
	t.Helper()
	result := authorizationCall(t, fixture.owner.handler, entryPath+"verify", fixture.proof(info, sender), nil)
	var entry EntryIdentity
	if result.Code != 200 || json.Unmarshal(result.Body.Bytes(), &entry) != nil {
		t.Fatalf("verify entry: %d %s", result.Code, result.Body.String())
	}
	return entry
}

func (fixture *entryFixture) action(entry EntryIdentity, action, account string) EntryAction {
	fixture.query++
	input := EntryAction{EntryID: entry.Info.EntryID, ClientID: entry.ClientID,
		SigningKey: entry.SigningKey, EncryptionKey: entry.EncryptionKey,
		ExpiresAt: time.Now().Unix() + 30, Nonce: fmt.Sprintf("%032x", fixture.query)}
	message := TelegramAccountEntry_ActionMessage(entry.Info, input, action)
	if action == "bind" {
		message = TelegramAccountEntry_BindMessage(entry, input, account)
	}
	input.Proof = hex.EncodeToString(ed25519.Sign(fixture.owner.delegate, []byte(message)))
	return input
}

func (fixture *entryFixture) bind(t *testing.T, entry EntryIdentity) EntryIdentity {
	t.Helper()
	input := fixture.action(entry, "bind", fixture.owner.owner.UserID)
	result := fixture.owner.ownerCall(t, entryPath+"bind", input)
	var bound EntryIdentity
	if result.Code != 200 || json.Unmarshal(result.Body.Bytes(), &bound) != nil {
		t.Fatalf("bind entry: %d %s", result.Code, result.Body.String())
	}
	return bound
}

func entryClaim(transaction *sql.Tx, entry EntryIdentity, now int64) bool {
	return TelegramAccountEntry_ClaimTx(transaction, context.Background(), entry.Info.EntryID,
		entry.AccountID, entry.Info.BotID, entry.TelegramID, entry.ClientID, entry.SigningKey,
		entry.EncryptionKey, entry.Info.NodeID, entry.Info.Audience, now)
}

func TestTelegramAccountEntryMenuAndPublicMetadata(t *testing.T) {
	fixture := entrySetup(t)
	if _, err := fixture.owner.store.Database.Exec(
		"INSERT INTO server_lumi_telegram(account_id,telegram_id,linked_at) VALUES(?,1234,1)", fixture.owner.owner.UserID); err != nil {
		t.Fatal(err)
	}
	menu := TelegramAccountEntry_Create(fixture.service, t.Context(), 1234)
	if menu.Error != nil {
		t.Fatal(menu.Error)
	}
	infos := []EntryChallenge{menu.Create, menu.Restore, menu.Connect}
	seen := make(map[string]bool)
	for index, info := range infos {
		if info.Mode != []string{"create", "restore", "connect"}[index] ||
			info.ExpiresAt > time.Now().Unix()+600 || info.ExpiresAt <= time.Now().Unix() || seen[info.EntryID] {
			t.Fatal("menu entry mode, lifetime or uniqueness failed")
		}
		seen[info.EntryID] = true
		result := authorizationCall(t, fixture.owner.handler, entryPath+"info", EntryID{EntryID: info.EntryID}, nil)
		var fields map[string]any
		if result.Code != 200 || json.Unmarshal(result.Body.Bytes(), &fields) != nil || len(fields) != 8 {
			t.Fatalf("public entry metadata: %d %s", result.Code, result.Body.String())
		}
		for _, field := range []string{"account_id", "telegram_id", "client_id", "signing_key", "encryption_key", "init_digest"} {
			if _, exists := fields[field]; exists {
				t.Fatalf("public entry leaked %s", field)
			}
		}
	}
	entry := fixture.verify(t, menu.Connect, 1234)
	if entry.AccountID != fixture.owner.owner.UserID || entry.TelegramID != 1234 || entry.Status != "verified" {
		t.Fatal("verified identity did not use current numeric chat binding")
	}
	public := authorizationCall(t, fixture.owner.handler, entryPath+"info", EntryID{EntryID: menu.Connect.EntryID}, nil)
	if public.Code != 200 || strings.Contains(public.Body.String(), fixture.owner.owner.UserID) ||
		strings.Contains(public.Body.String(), "telegram_id") || strings.Contains(public.Body.String(), "client_id") {
		t.Fatal("verified identity leaked through public polling")
	}
	environment := httptest.NewRecorder()
	fixture.owner.handler.ServeHTTP(environment, httptest.NewRequest("GET", entryPath+"environment", nil))
	var fields map[string]any
	if environment.Code != 200 || json.Unmarshal(environment.Body.Bytes(), &fields) != nil ||
		len(fields) != 5 || fields["environment"] != "production" || fields["bot_id"] != float64(123456) {
		t.Fatal("environment metadata is incorrect or excessive")
	}
	for _, issue := range []EntryIssue{
		TelegramAccountEntry_Issue(fixture.service, t.Context(), "arbitrary", 1234),
		TelegramAccountEntry_Issue(fixture.service, t.Context(), "create", 0),
		TelegramAccountEntry_Issue(fixture.service, t.Context(), "restore", 4503599627370496),
	} {
		if issue.Error == nil {
			t.Fatal("invalid trusted entry input accepted")
		}
	}
}

func TestTelegramAccountEntryVerifyRejectsTamperingAndReplay(t *testing.T) {
	fixture := entrySetup(t)
	info := fixture.issue(t, "connect", 1234)
	good := fixture.proof(info, 1234)
	mutations := []struct {
		name string
		edit func(*EntryVerify)
		code int
	}{
		{"client", func(input *EntryVerify) { input.ClientID = strings.Repeat("d", 64) }, 401},
		{"signing-key", func(input *EntryVerify) { input.SigningKey = strings.Repeat("d", 64) }, 401},
		{"encryption-key", func(input *EntryVerify) { input.EncryptionKey = strings.Repeat("d", 2368) }, 401},
		{"signature", func(input *EntryVerify) { input.Proof = strings.Repeat("0", 128) }, 401},
		{"malformed-key", func(input *EntryVerify) { input.EncryptionKey = "invalid" }, 400},
		{"duplicate-init", func(input *EntryVerify) { input.InitData += "&%75ser=x" }, 401},
		{"sender", func(input *EntryVerify) { *input = fixture.proof(info, 4321) }, 401},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			input := good
			test.edit(&input)
			result := authorizationCall(t, fixture.owner.handler, entryPath+"verify", input, nil)
			if result.Code != test.code {
				t.Fatalf("got %d, want %d", result.Code, test.code)
			}
		})
	}
	for _, field := range []string{"mode", "node", "audience", "challenge", "expiry"} {
		badInfo := info
		switch field {
		case "mode":
			badInfo.Mode = "create"
		case "node":
			badInfo.NodeID = strings.Repeat("d", 64)
		case "audience":
			badInfo.Audience += "/other"
		case "challenge":
			badInfo.Challenge = strings.Repeat("d", 32)
		case "expiry":
			badInfo.ExpiresAt++
		}
		input := good
		digest := TelegramInit_Validate(input.InitData, fixture.service.Configuration.LumiBotToken, time.Now().Unix()).Digest
		input.Proof = hex.EncodeToString(ed25519.Sign(fixture.owner.delegate,
			[]byte(TelegramAccountEntry_VerifyMessage(badInfo, input, digest))))
		if result := authorizationCall(t, fixture.owner.handler, entryPath+"verify", input, nil); result.Code != 401 {
			t.Fatalf("proof did not bind %s", field)
		}
	}
	result := authorizationCall(t, fixture.owner.handler, entryPath+"verify", good, nil)
	if result.Code != 200 {
		t.Fatalf("failed proofs consumed valid entry or initData: %d %s", result.Code, result.Body.String())
	}
	if result := authorizationCall(t, fixture.owner.handler, entryPath+"verify", good, nil); result.Code != 409 {
		t.Fatal("entry reused")
	}
	second := fixture.issue(t, "restore", 1234)
	replay := good
	replay.EntryID = second.EntryID
	digest := TelegramInit_Validate(good.InitData, fixture.service.Configuration.LumiBotToken, time.Now().Unix()).Digest
	replay.Proof = hex.EncodeToString(ed25519.Sign(fixture.owner.delegate,
		[]byte(TelegramAccountEntry_VerifyMessage(second, replay, digest))))
	if result := authorizationCall(t, fixture.owner.handler, entryPath+"verify", replay, nil); result.Code != 409 {
		t.Fatal("global initData replay crossed entries")
	}
	var grants, sessions int
	if err := fixture.owner.store.Database.QueryRow("SELECT COUNT(*) FROM server_authorization_grants").Scan(&grants); err != nil {
		t.Fatal(err)
	}
	if err := fixture.owner.store.Database.QueryRow("SELECT COUNT(*) FROM server_authorization_sessions").Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if grants != 0 || sessions != 0 {
		t.Fatal("entry verification created grant authority")
	}
}

func TestTelegramAccountEntryExpiryWrongBotAndPartition(t *testing.T) {
	fixture := entrySetup(t)
	info := fixture.issue(t, "create", 1234)
	input := fixture.proof(info, 1234)
	for _, change := range []func(){
		func() { fixture.service.NodeID = strings.Repeat("d", 64) },
		func() { fixture.service.Configuration.BaseURL += "/partition" },
		func() { fixture.service.Configuration.LumiBotToken = "654321:wrong-bot" },
	} {
		node, audience, token := fixture.service.NodeID, fixture.service.Configuration.BaseURL, fixture.service.Configuration.LumiBotToken
		change()
		if result := authorizationCall(t, fixture.owner.handler, entryPath+"verify", input, nil); result.Code != 409 {
			t.Fatal("entry authorized at another node, audience or bot")
		}
		fixture.service.NodeID, fixture.service.Configuration.BaseURL, fixture.service.Configuration.LumiBotToken = node, audience, token
	}
	if _, err := fixture.owner.store.Database.Exec("UPDATE server_telegram_account_entries SET expires_at=? WHERE entry_id=?", time.Now().Unix(), info.EntryID); err != nil {
		t.Fatal(err)
	}
	if result := authorizationCall(t, fixture.owner.handler, entryPath+"verify", input, nil); result.Code != 409 {
		t.Fatal("expired entry verified")
	}
	if result := authorizationCall(t, fixture.owner.handler, entryPath+"info", EntryID{EntryID: info.EntryID}, nil); result.Code != 404 {
		t.Fatal("expired public entry remained usable")
	}
}

func TestTelegramAccountEntryOwnerBindAndExactConsumption(t *testing.T) {
	fixture := entrySetup(t)
	info := fixture.issue(t, "create", 1234)
	pending := EntryIdentity{Info: info, TelegramID: 1234, AccountID: fixture.owner.owner.UserID,
		ClientID: strings.Repeat("b", 64), SigningKey: hex.EncodeToString(fixture.owner.delegate.Public().(ed25519.PublicKey)),
		EncryptionKey: strings.Repeat("c", 2368)}
	transaction, err := fixture.owner.store.Database.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if entryClaim(transaction, pending, time.Now().Unix()) {
		t.Fatal("URL possession consumed unverified entry")
	}
	transaction.Rollback()
	entry := fixture.verify(t, info, 1234)
	if entry.AccountID != "" {
		t.Fatal("unlinked sender fabricated an account")
	}
	input := fixture.action(entry, "bind", fixture.owner.owner.UserID)
	if result := authorizationCall(t, fixture.owner.handler, entryPath+"bind", input, nil); result.Code != 401 {
		t.Fatal("bind without owner authentication accepted")
	}
	if result := authorizationCall(t, fixture.owner.handler, entryPath+"bind", input,
		map[string]string{"Authorization": "Bearer " + fixture.owner.owner.Token}); result.Code != 401 {
		t.Fatal("bind without owner/device signature accepted")
	}
	wrong := input
	wrong.Proof = strings.Repeat("0", 128)
	if result := fixture.owner.ownerCall(t, entryPath+"bind", wrong); result.Code != 401 {
		t.Fatal("owner signature alone substituted for delegate binding proof")
	}
	bound := fixture.bind(t, entry)
	if bound.AccountID != fixture.owner.owner.UserID || bound.Status != "bound" {
		t.Fatal("owner account was not frozen into entry")
	}
	if result := fixture.owner.ownerCall(t, entryPath+"bind", fixture.action(bound, "bind", bound.AccountID)); result.Code != 409 {
		t.Fatal("bound entry rebound")
	}
	now := time.Now().Unix()
	mutations := []func(*EntryIdentity){
		func(entry *EntryIdentity) { entry.AccountID = strings.Repeat("d", 64) },
		func(entry *EntryIdentity) { entry.Info.BotID++ },
		func(entry *EntryIdentity) { entry.TelegramID++ },
		func(entry *EntryIdentity) { entry.ClientID = strings.Repeat("d", 64) },
		func(entry *EntryIdentity) { entry.SigningKey = strings.Repeat("d", 64) },
		func(entry *EntryIdentity) { entry.EncryptionKey = strings.Repeat("d", 2368) },
		func(entry *EntryIdentity) { entry.Info.NodeID = strings.Repeat("d", 64) },
		func(entry *EntryIdentity) { entry.Info.Audience += "/other" },
	}
	for _, mutate := range mutations {
		bad := bound
		mutate(&bad)
		transaction, err := fixture.owner.store.Database.BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		accepted := entryClaim(transaction, bad, now)
		transaction.Rollback()
		if accepted {
			t.Fatal("entry consumption escaped exact verified identity or keys")
		}
	}
	transaction, err = fixture.owner.store.Database.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !entryClaim(transaction, bound, now) {
		t.Fatal("exact bound entry failed consumption")
	}
	transaction.Rollback()
	transaction, err = fixture.owner.store.Database.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !entryClaim(transaction, bound, now) || transaction.Commit() != nil {
		t.Fatal("failed caller transaction burned entry")
	}
	transaction, err = fixture.owner.store.Database.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if entryClaim(transaction, bound, now) {
		t.Fatal("entry consumed twice")
	}
	transaction.Rollback()
}

func TestTelegramAccountEntryBindRequiresExactV6OwnerAndDevice(t *testing.T) {
	fixture := entrySetup(t)
	entry := fixture.verify(t, fixture.issue(t, "create", 1234), 1234)
	input := fixture.action(entry, "bind", fixture.owner.owner.UserID)
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		protocol  int
		app       string
		badOwner  bool
		badDevice bool
	}{
		{name: "older-protocol", protocol: 5, app: "inbe"},
		{name: "future-protocol", protocol: 7, app: "inbe"},
		{name: "wrong-app", protocol: 6, app: "another"},
		{name: "invalid-owner", protocol: 6, app: "inbe", badOwner: true},
		{name: "invalid-device", protocol: 6, app: "inbe", badDevice: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx := SignedTxEnvelope{ProtocolVersion: test.protocol, TxID: "synthetic-entry-" + test.name,
				AccountID: fixture.owner.owner.UserID, AppID: test.app, DeviceKeyID: "owner-device",
				Method: "POST", Path: entryPath + "bind", BodySHA256: Signing_SHA256Hex(raw),
				Nonce: "synthetic-entry-" + test.name, ExpiresAt: time.Now().Unix() + 60}
			message := []byte(Transaction_CanonicalMessage(TransactionContext, tx))
			signature := MlDsa44_Sign(message, fixture.owner.ownerPrivate)
			if signature.Error != nil {
				t.Fatal(signature.Error)
			}
			tx.Signature = hex.EncodeToString(signature.Value)
			tx.DeviceSignature = hex.EncodeToString(ed25519.Sign(fixture.owner.device, message))
			if test.badOwner {
				tx.Signature = strings.Repeat("0", 4840)
			}
			if test.badDevice {
				tx.DeviceSignature = strings.Repeat("0", 128)
			}
			header, err := json.Marshal(tx)
			if err != nil {
				t.Fatal(err)
			}
			result := authorizationCall(t, fixture.owner.handler, entryPath+"bind", input,
				map[string]string{"Authorization": "Bearer " + fixture.owner.owner.Token,
					"X-Daochi-User": fixture.owner.owner.UserID, "X-Daochi-Tx": string(header)})
			if result.Code == 200 {
				t.Fatal("invalid owner/device authorization bound entry")
			}
		})
	}
	fixture.bind(t, entry)
}

func TestTelegramAccountEntryFreshStatusAndKeyBoundCancel(t *testing.T) {
	fixture := entrySetup(t)
	entry := fixture.verify(t, fixture.issue(t, "restore", 1234), 1234)
	status := fixture.action(entry, "status", "")
	result := authorizationCall(t, fixture.owner.handler, entryPath+"status", status, nil)
	if result.Code != 200 {
		t.Fatalf("fresh status: %d %s", result.Code, result.Body.String())
	}
	if result := authorizationCall(t, fixture.owner.handler, entryPath+"status", status, nil); result.Code != 409 {
		t.Fatal("captured status proof replayed")
	}
	for _, change := range []func(*EntryAction){
		func(input *EntryAction) { input.ExpiresAt = time.Now().Unix() },
		func(input *EntryAction) { input.ExpiresAt = time.Now().Unix() + 61 },
		func(input *EntryAction) { input.Nonce = "invalid" },
		func(input *EntryAction) { input.ClientID = strings.Repeat("d", 64) },
		func(input *EntryAction) { input.EncryptionKey = strings.Repeat("d", 2368) },
	} {
		input := fixture.action(entry, "status", "")
		change(&input)
		input.Proof = hex.EncodeToString(ed25519.Sign(fixture.owner.delegate,
			[]byte(TelegramAccountEntry_ActionMessage(entry.Info, input, "status"))))
		if result := authorizationCall(t, fixture.owner.handler, entryPath+"status", input, nil); result.Code != 401 {
			t.Fatal("status accepted stale, malformed or mismatched signed action")
		}
	}
	if result := authorizationCall(t, fixture.owner.handler, entryPath+"cancel", EntryID{EntryID: entry.Info.EntryID}, nil); result.Code != 400 {
		t.Fatal("URL possession cancelled verified entry")
	}
	fresh := fixture.action(entry, "status", "")
	if result := authorizationCall(t, fixture.owner.handler, entryPath+"cancel", fresh, nil); result.Code != 401 {
		t.Fatal("status proof became cancellation proof")
	}
	cancel := fixture.action(entry, "cancel", "")
	if result := authorizationCall(t, fixture.owner.handler, entryPath+"cancel", cancel, nil); result.Code != 200 {
		t.Fatalf("cancel: %d %s", result.Code, result.Body.String())
	}
	if result := fixture.owner.ownerCall(t, entryPath+"bind", fixture.action(entry, "bind", fixture.owner.owner.UserID)); result.Code != 409 {
		t.Fatal("cancelled entry bound")
	}
	transaction, err := fixture.owner.store.Database.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if entryClaim(transaction, entry, time.Now().Unix()) {
		t.Fatal("cancelled entry consumed")
	}
	transaction.Rollback()
}

func TestTelegramAccountEntryVerifyAndGlobalReplayRaces(t *testing.T) {
	for _, separate := range []bool{false, true} {
		t.Run(fmt.Sprintf("separate-entries-%v", separate), func(t *testing.T) {
			fixture := entrySetup(t)
			fixture.owner.store.Database.SetMaxOpenConns(8)
			first := fixture.issue(t, "connect", 1234)
			input := fixture.proof(first, 1234)
			digest := TelegramInit_Validate(input.InitData, fixture.service.Configuration.LumiBotToken, time.Now().Unix()).Digest
			inputs := make([]EntryVerify, 16)
			for index := range inputs {
				info := first
				if separate {
					info = fixture.issue(t, "connect", 1234)
				}
				inputs[index] = input
				inputs[index].EntryID = info.EntryID
				inputs[index].Proof = hex.EncodeToString(ed25519.Sign(fixture.owner.delegate,
					[]byte(TelegramAccountEntry_VerifyMessage(info, inputs[index], digest))))
			}
			start := make(chan struct{})
			codes := make(chan int, len(inputs))
			for _, input := range inputs {
				go func(input EntryVerify) {
					<-start
					result := authorizationCall(t, fixture.owner.handler, entryPath+"verify", input, nil)
					codes <- result.Code
				}(input)
			}
			close(start)
			winners := 0
			for range inputs {
				code := <-codes
				if code == 200 {
					winners++
				} else if code != 409 {
					t.Fatalf("unexpected verification race outcome: %d", code)
				}
			}
			if winners != 1 {
				t.Fatalf("verification race winners: %d", winners)
			}
			var verified, replays int
			if err := fixture.owner.store.Database.QueryRow("SELECT COUNT(*) FROM server_telegram_account_entries WHERE status='verified'").Scan(&verified); err != nil {
				t.Fatal(err)
			}
			if err := fixture.owner.store.Database.QueryRow("SELECT COUNT(*) FROM server_telegram_init_replays").Scan(&replays); err != nil {
				t.Fatal(err)
			}
			if verified != 1 || replays != 1 {
				t.Fatal("entry and global initData claim did not commit atomically")
			}
		})
	}
}

func TestTelegramAccountEntryConsumptionRacesAndBindingRecheck(t *testing.T) {
	fixture := entrySetup(t)
	entry := fixture.bind(t, fixture.verify(t, fixture.issue(t, "create", 1234), 1234))
	if _, err := fixture.owner.store.Database.Exec("DELETE FROM server_lumi_telegram WHERE account_id=?", entry.AccountID); err != nil {
		t.Fatal(err)
	}
	transaction, err := fixture.owner.store.Database.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if entryClaim(transaction, entry, time.Now().Unix()) {
		t.Fatal("disconnected chat retained entry authority")
	}
	transaction.Rollback()
	if _, err := fixture.owner.store.Database.Exec("INSERT INTO server_lumi_telegram(account_id,telegram_id,linked_at) VALUES(?,1234,1)", entry.AccountID); err != nil {
		t.Fatal(err)
	}
	fixture.owner.store.Database.SetMaxOpenConns(8)
	start := make(chan struct{})
	results := make(chan bool, 16)
	errors := make(chan error, 16)
	var workers sync.WaitGroup
	for index := 0; index < 16; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			transaction, err := fixture.owner.store.Database.BeginTx(context.Background(), nil)
			if err != nil {
				errors <- err
				return
			}
			accepted := entryClaim(transaction, entry, time.Now().Unix())
			if accepted {
				err = transaction.Commit()
			} else {
				err = transaction.Rollback()
			}
			if err != nil {
				errors <- err
				return
			}
			results <- accepted
		}()
	}
	close(start)
	workers.Wait()
	close(errors)
	close(results)
	for err := range errors {
		t.Fatal(err)
	}
	winners := 0
	for accepted := range results {
		if accepted {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("entry consumption race winners: %d", winners)
	}
}

func TestTelegramAccountEntryRestartKeepsProofAndConsumption(t *testing.T) {
	fixture := entrySetup(t)
	info := fixture.issue(t, "create", 1234)
	input := fixture.proof(info, 1234)
	var entry EntryIdentity
	verified := authorizationCall(t, fixture.owner.handler, entryPath+"verify", input, nil)
	if verified.Code != 200 || json.Unmarshal(verified.Body.Bytes(), &entry) != nil {
		t.Fatal("initial verification failed")
	}
	entry = fixture.bind(t, entry)
	status := fixture.action(entry, "status", "")
	if result := authorizationCall(t, fixture.owner.handler, entryPath+"status", status, nil); result.Code != 200 {
		t.Fatal("initial status failed")
	}
	if err := fixture.owner.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(fixture.owner.store.Path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	fixture.service.Database = reopened.Database
	fixture.owner.server.Store = reopened
	fixture.installHandler()
	if result := authorizationCall(t, fixture.owner.handler, entryPath+"verify", input, nil); result.Code != 409 {
		t.Fatal("verification replay survived restart")
	}
	if result := authorizationCall(t, fixture.owner.handler, entryPath+"status", status, nil); result.Code != 409 {
		t.Fatal("status replay survived restart")
	}
	transaction, err := reopened.Database.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !entryClaim(transaction, entry, time.Now().Unix()) || transaction.Commit() != nil {
		t.Fatal("verified bound entry did not survive restart")
	}
	transaction, err = reopened.Database.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if entryClaim(transaction, entry, time.Now().Unix()) {
		t.Fatal("consumed entry replayed after restart")
	}
	transaction.Rollback()
}

func TestTelegramAccountEntryRejectsMalformedJSON(t *testing.T) {
	fixture := entrySetup(t)
	info := fixture.issue(t, "connect", 1234)
	input := fixture.proof(info, 1234)
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, document := range []string{
		strings.Replace(string(raw), `"entry_id":`, `"ENTRY_ID":`, 1),
		strings.Replace(string(raw), `"entry_id":`, `"entry_id":"ignored","entry_id":`, 1),
		strings.Replace(string(raw), `"entry_id":`, `"unknown":"ignored","entry_id":`, 1),
	} {
		request := httptest.NewRequest("POST", entryPath+"verify", bytes.NewBufferString(document))
		result := httptest.NewRecorder()
		fixture.owner.handler.ServeHTTP(result, request)
		if result.Code != 400 {
			t.Fatal("malformed protocol fields accepted")
		}
	}
}

func entryOtherOwner(t *testing.T, fixture *entryFixture) *authorizationFixture {
	t.Helper()
	other := *fixture.owner
	keys := MlDsa44_KeyPair()
	if keys.Error != nil {
		t.Fatal(keys.Error)
	}
	id := Signing_SHA256Hex(keys.PublicKey)
	if _, err := fixture.owner.store.Database.Exec("INSERT INTO server_users(user_id_hash,public_key) VALUES(?,?)", id, keys.PublicKey); err != nil {
		t.Fatal(err)
	}
	token := Token_IssueAuthToken(fixture.owner.server.Cfg.TokenSecret, id, time.Now().Add(time.Hour).Unix())
	if token.Error != "" {
		t.Fatal(token.Error)
	}
	other.owner = testIdentity{PublicKey: keys.PublicKey, UserID: id, Token: token.Value}
	other.ownerPrivate = keys.PrivateKey
	if err := DeviceKeys_Register(fixture.owner.store.Database, t.Context(), DeviceKey{
		AccountID: id, AppID: "inbe", KeyID: "owner-device", ClientID: strings.Repeat("a", 64),
		PublicKey: hex.EncodeToString(other.device.Public().(ed25519.PublicKey)),
	}, "synthetic-other-owner", errSignedTxReplay); err != nil {
		t.Fatal(err)
	}
	return &other
}

func TestTelegramAccountEntryMultipleAccountBindRace(t *testing.T) {
	fixture := entrySetup(t)
	other := entryOtherOwner(t, fixture)
	first := fixture.verify(t, fixture.issue(t, "create", 1234), 1234)
	second := fixture.verify(t, fixture.issue(t, "restore", 1234), 1234)
	inputs := []EntryAction{
		fixture.action(first, "bind", fixture.owner.owner.UserID),
		fixture.action(second, "bind", other.owner.UserID),
	}
	owners := []*authorizationFixture{fixture.owner, other}
	fixture.owner.store.Database.SetMaxOpenConns(8)
	start := make(chan struct{})
	codes := make(chan int, 2)
	for index, owner := range owners {
		go func(owner *authorizationFixture, input EntryAction) {
			<-start
			codes <- owner.ownerCall(t, entryPath+"bind", input).Code
		}(owner, inputs[index])
	}
	close(start)
	winners, conflicts := 0, 0
	for index := 0; index < 2; index++ {
		switch code := <-codes; code {
		case 200:
			winners++
		case 409:
			conflicts++
		default:
			t.Fatalf("unexpected account binding race outcome: %d", code)
		}
	}
	if winners != 1 || conflicts != 1 {
		t.Fatal("numeric sender bound to multiple accounts")
	}
	var bindings, boundEntries int
	if err := fixture.owner.store.Database.QueryRow("SELECT COUNT(*) FROM server_lumi_telegram WHERE telegram_id=1234").Scan(&bindings); err != nil {
		t.Fatal(err)
	}
	if err := fixture.owner.store.Database.QueryRow("SELECT COUNT(*) FROM server_telegram_account_entries e JOIN server_lumi_telegram b ON b.account_id=e.account_id AND b.telegram_id=e.telegram_id WHERE e.status='bound'").Scan(&boundEntries); err != nil {
		t.Fatal(err)
	}
	if bindings != 1 || boundEntries != 1 {
		t.Fatal("account binding and frozen entry did not commit together")
	}
	// A separately verified entry for the already linked sender must freeze
	// the real current account; another owner cannot substitute itself.
	linked := fixture.verify(t, fixture.issue(t, "connect", 1234), 1234)
	loser := fixture.owner
	if linked.AccountID == loser.owner.UserID {
		loser = other
	}
	input := fixture.action(linked, "bind", loser.owner.UserID)
	if result := loser.ownerCall(t, entryPath+"bind", input); result.Code != 409 {
		t.Fatal("different owner substituted for verified current Telegram account")
	}
}

func TestTelegramAccountEntryCancelConsumptionRace(t *testing.T) {
	fixture := entrySetup(t)
	entry := fixture.bind(t, fixture.verify(t, fixture.issue(t, "create", 1234), 1234))
	fixture.owner.store.Database.SetMaxOpenConns(8)
	cancel := fixture.action(entry, "cancel", "")
	start := make(chan struct{})
	cancelled := make(chan int, 1)
	consumed := make(chan bool, 1)
	errors := make(chan error, 1)
	go func() {
		<-start
		cancelled <- authorizationCall(t, fixture.owner.handler, entryPath+"cancel", cancel, nil).Code
	}()
	go func() {
		<-start
		transaction, err := fixture.owner.store.Database.BeginTx(context.Background(), nil)
		if err != nil {
			errors <- err
			consumed <- false
			return
		}
		accepted := entryClaim(transaction, entry, time.Now().Unix())
		if accepted {
			err = transaction.Commit()
		} else {
			err = transaction.Rollback()
		}
		if err != nil {
			errors <- err
		}
		consumed <- accepted
	}()
	close(start)
	code, accepted := <-cancelled, <-consumed
	select {
	case err := <-errors:
		t.Fatal(err)
	default:
	}
	var status string
	if err := fixture.owner.store.Database.QueryRow("SELECT status FROM server_telegram_account_entries WHERE entry_id=?", entry.Info.EntryID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if accepted {
		if code != 409 || status != "consumed" {
			t.Fatal("consumption and cancellation both succeeded")
		}
	} else if code != 200 || status != "cancelled" {
		t.Fatal("cancellation did not atomically block entry consumption")
	}
}

func TestTelegramAccountEntryStatusReplayRace(t *testing.T) {
	fixture := entrySetup(t)
	entry := fixture.verify(t, fixture.issue(t, "restore", 1234), 1234)
	fixture.owner.store.Database.SetMaxOpenConns(8)
	input := fixture.action(entry, "status", "")
	start := make(chan struct{})
	codes := make(chan int, 16)
	for index := 0; index < 16; index++ {
		go func() {
			<-start
			codes <- authorizationCall(t, fixture.owner.handler, entryPath+"status", input, nil).Code
		}()
	}
	close(start)
	winners := 0
	for index := 0; index < 16; index++ {
		code := <-codes
		if code == 200 {
			winners++
		} else if code != 409 {
			t.Fatalf("unexpected status race result: %d", code)
		}
	}
	if winners != 1 {
		t.Fatal("status proof disclosed identity more than once")
	}
}

func TestTelegramAccountEntryRejectsHistoricalInitReplay(t *testing.T) {
	fixture := entrySetup(t)
	pending := fixture.owner.ownerCall(t, "/api/v1/authorization/requests", AuthorizationRequest{
		AppID: "inbe", Scopes: []RequestedScope{{Collection: "private.inbe.v2.lumi", Read: true}},
	})
	var rendezvous Rendezvous
	if pending.Code != 200 || json.Unmarshal(pending.Body.Bytes(), &rendezvous) != nil {
		t.Fatal("owner rendezvous fixture failed")
	}
	info := fixture.issue(t, "connect", 1234)
	input := fixture.proof(info, 1234)
	digest := TelegramInit_Validate(input.InitData, fixture.service.Configuration.LumiBotToken, time.Now().Unix()).Digest
	if _, err := fixture.owner.store.Database.Exec("INSERT INTO server_telegram_init_claims(digest,request_id,expires_at) VALUES(?,?,?)", digest, rendezvous.RequestID, time.Now().Unix()+300); err != nil {
		t.Fatal(err)
	}
	if result := authorizationCall(t, fixture.owner.handler, entryPath+"verify", input, nil); result.Code != 409 {
		t.Fatal("historical owner rendezvous initData replayed through entry")
	}
}

func TestTelegramAccountEntryTelegramEd25519Vector(t *testing.T) {
	// Synthetic verification keys exercise the third-party branch. Production
	// Validate remains pinned and must reject these substitute/test keys.
	now := time.Now().Unix()
	production := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, 32))
	testEnvironment := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x61}, 32))
	fields := url.Values{"auth_date": {strconv.FormatInt(now, 10)},
		"query_id": {"synthetic-ed-vector"}, "user": {`{"id":1234}`}}
	message := "123456:WebAppData\n" + "auth_date=" + fields.Get("auth_date") +
		"\nquery_id=" + fields.Get("query_id") + "\nuser=" + fields.Get("user")
	fields.Set("signature", base64.RawURLEncoding.EncodeToString(ed25519.Sign(production, []byte(message))))
	raw := telegramInitFixture("123456:synthetic-only", fields)
	key := hex.EncodeToString(production.Public().(ed25519.PublicKey))
	if !TelegramInit_ValidateWithKey(raw, "123456:synthetic-only", now, key).Valid {
		t.Fatal("valid synthetic Telegram Ed25519 vector rejected")
	}
	wrongKey := hex.EncodeToString(testEnvironment.Public().(ed25519.PublicKey))
	if TelegramInit_ValidateWithKey(raw, "123456:synthetic-only", now, wrongKey).Valid ||
		TelegramInit_Validate(raw, "123456:synthetic-only", now).Valid {
		t.Fatal("wrong environment or substitute production key accepted")
	}
	fields.Set("signature", base64.RawURLEncoding.EncodeToString(ed25519.Sign(production, []byte(message+"tampered"))))
	if TelegramInit_ValidateWithKey(telegramInitFixture("123456:synthetic-only", fields), "123456:synthetic-only", now, key).Valid {
		t.Fatal("Ed25519 tamper accepted despite valid HMAC")
	}
	fields.Set("signature", "malformed")
	if TelegramInit_ValidateWithKey(telegramInitFixture("123456:synthetic-only", fields), "123456:synthetic-only", now, key).Valid {
		t.Fatal("malformed third-party signature accepted")
	}
}
