package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLumiGroupRouteAndDeliveryReceipts(t *testing.T) {
	server, store, _ := testServer(t)
	server.Cfg.LumiBotToken = "8967366018:fixture"
	server.Cfg.LumiWebhookSecret = "group-secret"
	server.Cfg.LumiGroupID = -1001234
	server.Cfg.ChatAPIKey = "fixture-model-key"
	server.Cfg.ChatDailyLimit = 20
	server.Cfg.ChatGlobalDailyLimit = 100
	var models, sends atomic.Int32
	failSend := false
	rejectSend := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/model":
			models.Add(1)
			var input struct {
				Messages []ChatMessage `json:"messages"`
				Tools    []ChatTool    `json:"tools"`
			}
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
			}
			if len(input.Messages) != 2 || len(input.Tools) != 0 || strings.Contains(input.Messages[0].Content, "Current app context") {
				t.Error("group request included personal context or tools")
			}
			fmt.Fprint(w, `{"choices":[{"message":{"role":"assistant","content":"Hello from Lumi."}}]}`)
		case "/bot8967366018:fixture/sendChatAction":
			fmt.Fprint(w, `{"ok":true}`)
		case "/bot8967366018:fixture/sendMessage":
			sends.Add(1)
			var input struct {
				ChatID int64  `json:"chat_id"`
				Thread int64  `json:"message_thread_id"`
				Text   string `json:"text"`
				Reply  struct {
					MessageID int64 `json:"message_id"`
				} `json:"reply_parameters"`
			}
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
			}
			if input.ChatID != -1001234 || input.Thread != 22 || input.Reply.MessageID <= 0 || input.Text != "Hello from Lumi." {
				t.Errorf("wrong group, topic, reply or text: %+v", input)
			}
			if failSend {
				http.Error(w, "uncertain", 503)
				return
			}
			if rejectSend {
				w.WriteHeader(400)
				fmt.Fprint(w, `{"ok":false,"error_code":400,"description":"fixture rejection"}`)
				return
			}
			fmt.Fprint(w, `{"ok":true,"result":{"message_id":777}}`)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
		}
	}))
	defer upstream.Close()
	server.Cfg.ChatAPIEndpoint = upstream.URL + "/model"
	original := TelegramAPIBase
	TelegramAPIBase = upstream.URL
	defer func() { TelegramAPIBase = original }()
	handler := server.Routes()
	send := func(id int, group, owner int64, bot bool, text string, reply int64, secret string) {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"update_id": id, "message": map[string]any{
			"message_id": id, "message_thread_id": 22,
			"chat": map[string]any{"id": group, "type": "supergroup"},
			"from": map[string]any{"id": owner, "is_bot": bot}, "text": text,
			"reply_to_message": map[string]any{"from": map[string]any{"id": reply}},
		}})
		r := httptest.NewRequest("POST", "/api/v1/lumi/telegram/webhook", strings.NewReader(string(body)))
		r.Header.Set("X-Telegram-Bot-Api-Secret-Token", secret)
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, r)
		want := 200
		if secret != "group-secret" {
			want = 401
		}
		if out.Code != want {
			t.Fatalf("webhook %d: %s", out.Code, out.Body.String())
		}
	}
	// Neither untrusted transport, another group, missing senders, bots nor ambient chat
	// can make a provider request or send a group message.
	send(1, -1001234, 1234, false, "@inlumi_bot hi", 0, "wrong")
	send(2, -999, 1234, false, "@inlumi_bot hi", 0, "group-secret")
	send(3, -1001234, 0, false, "@inlumi_bot hi", 0, "group-secret")
	send(4, -1001234, 1234, true, "@inlumi_bot hi", 0, "group-secret")
	send(5, -1001234, 1234, false, "ordinary group chat", 0, "group-secret")
	send(6, -1001234, 1234, false, "@inlumi_bot_fake hi", 0, "group-secret")
	send(7, -1001234, 1234, false, "/help@another_bot @inlumi_bot", 0, "group-secret")
	if models.Load() != 0 || sends.Load() != 0 {
		t.Fatal("unaddressed or unauthorized message caused work")
	}
	server.Cfg.LumiGroupID = 0
	send(8, -1001234, 1234, false, "@inlumi_bot hi", 0, "group-secret")
	server.Cfg.LumiGroupID = -1001234
	if models.Load() != 0 {
		t.Fatal("disabled route called provider")
	}
	for _, id := range []int{10, 10} {
		send(id, -1001234, 1234, false, "@inlumi_bot hi", 0, "group-secret")
	}
	if models.Load() != 1 || sends.Load() != 1 {
		t.Fatal("duplicate update replayed")
	}
	var state string
	var delivery int64
	if err := store.Database.QueryRow("SELECT state,message_id FROM server_lumi_group_deliveries WHERE update_id=10").Scan(&state, &delivery); err != nil || state != "delivered" || delivery != 777 {
		t.Fatalf("missing delivery receipt: %s %d %v", state, delivery, err)
	}
	send(11, -1001234, 1234, false, "and how are you?", 8967366018, "group-secret")
	send(12, -1001234, 5555, false, "/help@INLUMI_BOT", 0, "group-secret")
	if sends.Load() != 3 {
		t.Fatal("Lumi reply or addressed command did not respond")
	}
	failSend = true
	send(13, -1001234, 1234, false, "@inlumi_bot hello", 0, "group-secret")
	send(13, -1001234, 1234, false, "@inlumi_bot hello", 0, "group-secret")
	if sends.Load() != 4 || models.Load() != 4 {
		t.Fatal("uncertain delivery replayed")
	}
	if err := store.Database.QueryRow("SELECT state FROM server_lumi_group_deliveries WHERE update_id=13").Scan(&state); err != nil || state != "uncertain" {
		t.Fatalf("missing uncertain receipt: %s %v", state, err)
	}
	retentionPrune(t, store, time.Now())
	if retentionCount(t, store, "SELECT used FROM server_chat_usage WHERE account_id='lumi-group'") != 4 {
		t.Fatal("retention reset the group's daily allowance")
	}
	failSend = false
	rejectSend = true
	send(14, -1001234, 1234, false, "@inlumi_bot hello again", 0, "group-secret")
	send(14, -1001234, 1234, false, "@inlumi_bot hello again", 0, "group-secret")
	if sends.Load() != 5 || models.Load() != 5 {
		t.Fatal("rejected delivery replayed")
	}
	if err := store.Database.QueryRow("SELECT state FROM server_lumi_group_deliveries WHERE update_id=14").Scan(&state); err != nil || state != "rejected" {
		t.Fatalf("explicit rejection was not recorded: %s %v", state, err)
	}
}

func TestLumiGroupMentionBoundaries(t *testing.T) {
	for _, input := range []string{"@inlumi_bot hi", "Hi\n@inlumi_bot!", "Hi\t@INLUMI_BOT", "/help@inlumi_bot"} {
		if !Address.MatchString(input) {
			t.Errorf("missed mention %q", input)
		}
	}
	for _, input := range []string{"n@inlumi_bot", "@inlumi_bot_fake", "someone@inlumi_bot", "/help@another_bot"} {
		if Address.MatchString(input) {
			t.Errorf("accepted false mention %q", input)
		}
	}
}
