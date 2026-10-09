package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLumiTelegramAppHistoryNeverSends(t *testing.T) {
	server, store, _ := testServer(t)
	server.Cfg.LumiBotToken = "input-fixture-token"
	server.Cfg.LumiWebhookSecret = "input-fixture-secret"
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer upstream.Close()
	original := TelegramAPIBase
	TelegramAPIBase = upstream.URL
	defer func() { TelegramAPIBase = original }()
	handler := server.Routes()
	owner := newTestIdentity(t, handler, 0xd5)
	code := lumiLink(t, handler, owner)
	if out := lumiWebhook(handler, "input-fixture-secret", 200, "private", "/start "+code); out.Code != 200 {
		t.Fatal(out.Body.String())
	}
	before := calls
	if before == 0 {
		t.Fatal("direct Telegram link acknowledgement was lost")
	}
	// Prior delivery receipts remain audit data, including uncertain sends.
	for _, state := range []string{"sending", "sent"} {
		if _, err := store.Database.Exec("INSERT INTO server_lumi_deliveries(account_id,id,state) VALUES(?,?,?)", owner.UserID, "cell.lumi.message."+state, state); err != nil {
			t.Fatal(err)
		}
	}
	path := "/api/v1/lumi/telegram/messages"
	for _, id := range []string{"app-user", "app-reply", "activity", "telegram-reply", "stale", "sending", "sent", "feedback"} {
		stamp := time.Now().UnixMicro() + 1000000
		if id == "stale" {
			stamp = 1
		}
		body := fmt.Sprintf(`{"id":%q,"text":"Saved conversation","draft":%q,"time":%d}`, "cell.lumi.message."+id, strings.Repeat("d", 32), stamp)
		for repeat := 0; repeat < 2; repeat++ {
			out := lumiRequest(handler, owner, "POST", path, body)
			if calls != before {
				t.Fatalf("app activity made %d outbound Telegram calls (text, action or notification)", calls-before)
			}
			if out.Code != 200 || strings.TrimSpace(out.Body.String()) != "true" {
				t.Fatalf("old client upload %s: %d %s", id, out.Code, out.Body.String())
			}
		}
	}
	if calls != before {
		t.Fatalf("app activity made %d outbound Telegram calls (text, action or notification)", calls-before)
	}
	var deliveries int
	if err := store.Database.QueryRow("SELECT COUNT(*) FROM server_lumi_deliveries").Scan(&deliveries); err != nil || deliveries != 2 {
		t.Fatalf("silence changed delivery receipts: %d %v", deliveries, err)
	}
	// Incoming messages still have one app executor and retain their exact text.
	if out := lumiWebhook(handler, "input-fixture-secret", 201, "private", "A quiet morning 水"); out.Code != 200 {
		t.Fatal(out.Body.String())
	}
	client := strings.Repeat("a", 64)
	poll := "/api/v1/lumi/telegram/updates?client=" + client
	out := lumiRequest(handler, owner, "GET", poll, "")
	var result LumiPoll
	if out.Code != 200 || json.Unmarshal(out.Body.Bytes(), &result) != nil || result.Update.ID != 201 || result.Update.Text != "A quiet morning 水" {
		t.Fatalf("incoming conversation lost: %s", out.Body.String())
	}
	if out := lumiRequest(handler, owner, "POST", "/api/v1/lumi/telegram/ack", fmt.Sprintf(`{"id":201,"client":%q}`, client)); out.Code != 200 {
		t.Fatal(out.Body.String())
	}
	// Existing explicit feedback approval callbacks keep their input path.
	callback := fmt.Sprintf(`{"update_id":202,"callback_query":{"id":"fixture-callback","from":{"id":1234},"message":{"chat":{"id":1234,"type":"private"}},"data":%q}}`, "Y"+strings.Repeat("d", 32))
	request := httptest.NewRequest("POST", "/api/v1/lumi/telegram/webhook", strings.NewReader(callback))
	request.Header.Set("X-Telegram-Bot-Api-Secret-Token", "input-fixture-secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	out = lumiRequest(handler, owner, "GET", poll, "")
	if response.Code != 200 || json.Unmarshal(out.Body.Bytes(), &result) != nil || result.Update.ID != 202 || result.Update.Kind != "confirmation" || result.Update.Choice != 1 {
		t.Fatalf("explicit Telegram feedback choice lost: %s", out.Body.String())
	}
	if out := lumiRequest(handler, testIdentity{}, "POST", path, `{}`); out.Code != 401 {
		t.Fatalf("unauthenticated upload accepted: %d", out.Code)
	}
	if out := lumiRequest(handler, owner, "POST", path, `{"id":"invalid","text":""}`); out.Code != 400 {
		t.Fatalf("malformed upload accepted: %d", out.Code)
	}
	if out := lumiRequest(handler, owner, "DELETE", "/api/v1/lumi/telegram/link", ""); out.Code != 200 {
		t.Fatal("unlink failed")
	}
	before = calls
	out = lumiRequest(handler, owner, "POST", path, `{"id":"queued-before-unlink","text":"Saved reply","time":1}`)
	if out.Code != 200 || calls != before {
		t.Fatalf("unlinked old-client queue did not drain silently: %d", out.Code)
	}
}

func TestLumiTelegramInputAPIDocumentation(t *testing.T) {
	fixture, err := os.ReadFile("testdata/telegram_paths.json")
	if err != nil {
		t.Fatal(err)
	}
	var expected map[string]any
	if err := json.Unmarshal(fixture, &expected); err != nil {
		t.Fatal(err)
	}
	actual := TelegramPaths_Paths()
	if !reflect.DeepEqual(actual, expected) {
		a, _ := json.Marshal(actual)
		b, _ := json.Marshal(expected)
		t.Fatalf("Telegram paths differ: actual=%s expected=%s", a, b)
	}
}
