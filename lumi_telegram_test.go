package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLumiTelegramAtomicLinkOutcomes(t *testing.T) {
	server, store, _ := testServer(t)
	server.Cfg.LumiBotToken = "fixture-token"
	handler := server.Routes()
	owner := newTestIdentity(t, handler, 0xa1)
	other := newTestIdentity(t, handler, 0xa2)
	now := time.Now().Unix()
	code := lumiLink(t, handler, owner)
	assertOutcome := func(code string, sender int64, want string) {
		t.Helper()
		result := LumiTelegram_ConsumeLink(store.Database, context.Background(), code, sender, now)
		if result.Error != nil || result.Status != want {
			t.Fatalf("link outcome: got %q error %v, want %q", result.Status, result.Error, want)
		}
	}
	assertOutcome(code, 1001, "connected")
	assertOutcome(code, 1001, "reused")
	assertOutcome(code, 1002, "reused")
	assertOutcome(strings.Repeat("z", 32), 1001, "invalid")
	assertOutcome(code, 0, "invalid")
	conflict := lumiLink(t, handler, other)
	assertOutcome(conflict, 1001, "conflicting_account")
	// A rejected account switch must not burn the intended owner's code.
	assertOutcome(conflict, 1002, "connected")
	accountConflict := lumiLink(t, handler, owner)
	assertOutcome(accountConflict, 1003, "conflicting_account")
	assertOutcome(accountConflict, 1001, "connected")
	expired := lumiLink(t, handler, owner)
	if _, err := store.Database.Exec("UPDATE server_lumi_link_codes SET expires=? WHERE code=?", now, expired); err != nil {
		t.Fatal(err)
	}
	assertOutcome(expired, 1001, "expired")
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(store.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	result := LumiTelegram_ConsumeLink(reopened.Database, context.Background(), code, 1001, now)
	if result.Error != nil || result.Status != "reused" {
		t.Fatal("consumed link did not survive restart")
	}
}

func TestLumiTelegramLinkRaces(t *testing.T) {
	server, store, _ := testServer(t)
	server.Cfg.LumiBotToken = "fixture-token"
	handler := server.Routes()
	owner := newTestIdentity(t, handler, 0xb1)
	code := lumiLink(t, handler, owner)
	// Exercise SQLite locking with multiple connections, not only the default
	// one-connection pool. The first statement must acquire the write lock.
	store.Database.SetMaxOpenConns(8)
	start := make(chan struct{})
	results := make(chan LinkResult, 32)
	for i := 0; i < 32; i++ {
		go func(sender int64) {
			<-start
			results <- LumiTelegram_ConsumeLink(store.Database, context.Background(), code, sender, time.Now().Unix())
		}(int64(2000 + i))
	}
	close(start)
	connected := 0
	for i := 0; i < 32; i++ {
		result := <-results
		if result.Error != nil {
			t.Fatalf("concurrent link failed: %v", result.Error)
		}
		if result.Status == "connected" {
			connected++
		} else if result.Status != "reused" {
			t.Fatalf("unexpected concurrent outcome: %s", result.Status)
		}
	}
	if connected != 1 {
		t.Fatalf("connected %d times, want exactly once", connected)
	}
	var bound, consumed int
	if err := store.Database.QueryRow("SELECT COUNT(*) FROM server_lumi_telegram WHERE account_id=?", owner.UserID).Scan(&bound); err != nil {
		t.Fatal(err)
	}
	if err := store.Database.QueryRow("SELECT COUNT(*) FROM server_lumi_link_codes WHERE code=? AND consumed_at>0 AND telegram_id=(SELECT telegram_id FROM server_lumi_telegram WHERE account_id=?)", code, owner.UserID).Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if bound != 1 || consumed != 1 {
		t.Fatal("binding and consumption did not commit together")
	}
}

func lumiRequest(handler http.Handler, identity testIdentity, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+identity.Token)
	req.Header.Set("X-Daochi-User", identity.UserID)
	req.Header.Set("Content-Type", "application/json")
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, req)
	return out
}

func lumiWebhook(handler http.Handler, secret string, id int, chatType, text string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]any{
		"update_id": id,
		"message": map[string]any{
			"message_id": id,
			"from":       map[string]any{"id": 1234},
			"chat":       map[string]any{"id": 1234, "type": chatType},
			"text":       text,
		},
	})
	req := httptest.NewRequest("POST", "/api/v1/lumi/telegram/webhook", strings.NewReader(string(body)))
	req.Header.Set("X-Telegram-Bot-Api-Secret-Token", secret)
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, req)
	return out
}

func lumiLink(t *testing.T, handler http.Handler, identity testIdentity) string {
	t.Helper()
	out := lumiRequest(handler, identity, "POST", "/api/v1/lumi/telegram/link", `{}`)
	if out.Code != 200 {
		t.Fatalf("link status %d: %s", out.Code, out.Body.String())
	}
	var result struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(out.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	code := strings.TrimPrefix(result.URL, "https://t.me/inlumi_bot?start=")
	if len(code) != 32 {
		t.Fatal("invalid bot deep link")
	}
	return code
}

func TestLumiTelegramAccountLinkQueueConsentAndDelivery(t *testing.T) {
	server, _, _ := testServer(t)
	server.Cfg.LumiBotToken = "fixture-token"
	server.Cfg.LumiWebhookSecret = "fixture-secret"
	server.Cfg.LumiCanvasURL = "https://inbe.example/canvas"
	var mu sync.Mutex
	var messages []map[string]any
	typing := 0
	failDelivery := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/botfixture-token/sendChatAction" {
			mu.Lock()
			typing++
			mu.Unlock()
			fmt.Fprint(w, `{"ok":true}`)
			return
		}
		if r.URL.Path != "/botfixture-token/sendMessage" && r.URL.Path != "/botfixture-token/answerCallbackQuery" {
			t.Error("unexpected Telegram method")
		}
		var value map[string]any
		if err := json.NewDecoder(r.Body).Decode(&value); err != nil {
			t.Error(err)
		}
		mu.Lock()
		messages = append(messages, value)
		fail := failDelivery
		mu.Unlock()
		fmt.Fprintf(w, `{"ok":%t}`, !fail)
	}))
	defer upstream.Close()
	original := TelegramAPIBase
	TelegramAPIBase = upstream.URL
	defer func() { TelegramAPIBase = original }()
	handler := server.Routes()
	owner := newTestIdentity(t, handler, 0x91)
	other := newTestIdentity(t, handler, 0x92)
	server.Cfg.LumiOwnerID = owner.UserID
	client := strings.Repeat("a", 64)
	secondClient := strings.Repeat("b", 64)
	poll := "/api/v1/lumi/telegram/updates?client=" + client
	if out := lumiRequest(handler, testIdentity{}, "POST", "/api/v1/lumi/telegram/link", `{}`); out.Code != 401 {
		t.Fatalf("unauthenticated link: %d", out.Code)
	}
	code := lumiLink(t, handler, owner)
	if out := lumiWebhook(handler, "wrong-secret", 1, "private", "/start "+code); out.Code != 401 {
		t.Fatal("untrusted webhook accepted")
	}
	lumiWebhook(handler, "fixture-secret", 1, "group", "/start "+code)
	mu.Lock()
	if len(messages) != 0 {
		t.Error("group update sent a response")
	}
	mu.Unlock()
	lumiWebhook(handler, "fixture-secret", 2, "private", "/start "+code)
	mu.Lock()
	markup := messages[0]["reply_markup"].(map[string]any)["inline_keyboard"].([]any)[0].([]any)[0].(map[string]any)
	if markup["web_app"].(map[string]any)["url"] != server.Cfg.LumiCanvasURL {
		t.Error("bot did not open its Inbe canvas")
	}
	mu.Unlock()
	// The same numeric Telegram identity cannot silently switch accounts.
	otherCode := lumiLink(t, handler, other)
	lumiWebhook(handler, "fixture-secret", 3, "private", "/start "+otherCode)
	lumiWebhook(handler, "fixture-secret", 4, "private", "/todo From Telegram")
	lumiWebhook(handler, "fixture-secret", 4, "private", "/todo From Telegram")
	mu.Lock()
	if typing == 0 {
		t.Error("queued message did not show that Lumi is typing")
	}
	mu.Unlock()
	out := lumiRequest(handler, owner, "GET", poll, "")
	var result LumiPoll
	if out.Code != 200 || json.Unmarshal(out.Body.Bytes(), &result) != nil || result.Update.ID != 4 || result.Update.Text != "/todo From Telegram" || !result.Linked {
		t.Fatalf("linked owner queue: %d %s", out.Code, out.Body.String())
	}
	out = lumiRequest(handler, owner, "GET", "/api/v1/lumi/telegram/updates?client="+secondClient, "")
	if json.Unmarshal(out.Body.Bytes(), &result) != nil || result.Update.ID != 0 {
		t.Fatal("two app clients claimed one action")
	}
	out = lumiRequest(handler, other, "GET", poll, "")
	if json.Unmarshal(out.Body.Bytes(), &result) != nil || result.Update.ID != 0 || result.Linked {
		t.Fatal("account link or action leaked")
	}
	lumiRequest(handler, owner, "POST", "/api/v1/lumi/telegram/ack", `{"id":4,"client":"`+secondClient+`"}`)
	out = lumiRequest(handler, owner, "GET", poll, "")
	if json.Unmarshal(out.Body.Bytes(), &result) != nil || result.Update.ID != 4 {
		t.Fatal("foreign executor acknowledged action")
	}
	lumiRequest(handler, owner, "POST", "/api/v1/lumi/telegram/ack", `{"id":4,"client":"`+client+`"}`)
	out = lumiRequest(handler, owner, "GET", poll, "")
	if json.Unmarshal(out.Body.Bytes(), &result) != nil || result.Update.ID != 0 {
		t.Fatal("duplicate webhook action was retained")
	}
	// Feedback from users is visible only to the immutable owner account.
	report := `{"id":"` + strings.Repeat("f", 64) + `","app_id":"inbe","title":"Lag","message":"Slow view","context":"view=lumi"}`
	if out := chatRequest(handler, other, "/api/v1/feedback", report); out.Code != 200 {
		t.Fatalf("feedback submit: %d", out.Code)
	}
	out = lumiRequest(handler, owner, "GET", poll, "")
	if json.Unmarshal(out.Body.Bytes(), &result) != nil || result.Update.ID >= 0 || result.Update.Kind != "feedback" || !strings.Contains(result.Update.Text, "Slow view") {
		t.Fatalf("owner feedback missing: %s", out.Body.String())
	}
	lumiRequest(handler, owner, "POST", "/api/v1/lumi/telegram/ack", fmt.Sprintf(`{"id":%d,"client":"%s"}`, result.Update.ID, client))
	out = lumiRequest(handler, other, "GET", poll, "")
	if json.Unmarshal(out.Body.Bytes(), &result) != nil || result.Update.ID != 0 {
		t.Fatal("owner feedback leaked to another account")
	}
	// Messages are idempotent; consent remains an explicit Yes/No callback.
	body := fmt.Sprintf(`{"id":"cell.lumi.message.new","text":"Send this feedback?","draft":"%s","time":%d}`, strings.Repeat("d", 32), time.Now().UnixMicro()+1000000)
	for i := 0; i < 2; i++ {
		if out := lumiRequest(handler, owner, "POST", "/api/v1/lumi/telegram/messages", body); out.Code != 200 {
			t.Fatalf("publish: %d %s", out.Code, out.Body.String())
		}
	}
	mu.Lock()
	last := messages[len(messages)-1]
	buttons := last["reply_markup"].(map[string]any)["inline_keyboard"].([]any)[0].([]any)
	if len(buttons) != 2 || buttons[0].(map[string]any)["callback_data"] != "Y"+strings.Repeat("d", 32) || buttons[1].(map[string]any)["callback_data"] != "N"+strings.Repeat("d", 32) {
		t.Error("consent buttons missing")
	}
	before := len(messages)
	failDelivery = true
	mu.Unlock()
	body = strings.Replace(body, "message.new", "message.uncertain", 1)
	if out := lumiRequest(handler, owner, "POST", "/api/v1/lumi/telegram/messages", body); out.Code != 502 {
		t.Fatalf("failed Telegram send: %d", out.Code)
	}
	if out := lumiRequest(handler, owner, "POST", "/api/v1/lumi/telegram/messages", body); out.Code != 409 {
		t.Fatalf("uncertain send was retried: %d", out.Code)
	}
	mu.Lock()
	if len(messages) != before+1 {
		t.Error("uncertain delivery sent twice")
	}
	mu.Unlock()
	if out := lumiRequest(handler, owner, "DELETE", "/api/v1/lumi/telegram/link", ""); out.Code != 200 {
		t.Fatal("unlink failed")
	}
	if out := lumiRequest(handler, owner, "POST", "/api/v1/lumi/telegram/messages", body); out.Code != 409 {
		t.Fatal("unlinked account could publish")
	}
}
