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
			_, _ = fmt.Fprint(w, `{"choices":[{"message":{"role":"assistant","content":"Hello from Lumi."}}]}`)
		case "/bot8967366018:fixture/sendChatAction":
			_, _ = fmt.Fprint(w, `{"ok":true}`)
		case "/bot8967366018:fixture/sendMessage":
			sends.Add(1)
			var input struct {
				ChatID int64  `json:"chat_id"`
				Thread int64  `json:"message_thread_id"`
				Text   string `json:"text"`
				Reply  struct {
					MessageID         int64 `json:"message_id"`
					AllowWithoutReply bool  `json:"allow_sending_without_reply"`
				} `json:"reply_parameters"`
			}
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
			}
			if input.ChatID != -1001234 || input.Thread != 22 || input.Reply.MessageID <= 0 || !input.Reply.AllowWithoutReply || input.Text != "Hello from Lumi." {
				t.Errorf("wrong group, topic, reply or text: %+v", input)
			}
			if failSend {
				http.Error(w, "uncertain", http.StatusServiceUnavailable)
				return
			}
			if rejectSend {
				w.WriteHeader(400)
				_, _ = fmt.Fprint(w, `{"ok":false,"error_code":400,"description":"fixture rejection"}`)
				return
			}
			_, _ = fmt.Fprint(w, `{"ok":true,"result":{"message_id":777}}`)
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
		send(id, -1001234, 1234, false, "@inlumi_bot how does Inner Breeze work?", 0, "group-secret")
	}
	if models.Load() != 1 || sends.Load() != 1 {
		t.Fatal("duplicate update replayed")
	}
	var state string
	var delivery int64
	if err := store.Database.QueryRow("SELECT state,message_id FROM server_lumi_group_deliveries WHERE update_id=10").Scan(&state, &delivery); err != nil || state != "delivered" || delivery != 777 {
		t.Fatalf("missing delivery receipt: %s %d %v", state, delivery, err)
	}
	send(11, -1001234, 1234, false, "How do breathing practices work?", 8967366018, "group-secret")
	send(12, -1001234, 5555, false, "Lumi, how do habits work in Inner Breeze?", 0, "group-secret")
	if sends.Load() != 3 {
		t.Fatal("Lumi reply or addressed command did not respond")
	}
	failSend = true
	send(13, -1001234, 1234, false, "@inlumi_bot explain Inner Breeze breathing", 0, "group-secret")
	send(13, -1001234, 1234, false, "@inlumi_bot explain Inner Breeze breathing", 0, "group-secret")
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
	send(14, -1001234, 1234, false, "@inlumi_bot explain Inner Breeze meditation", 0, "group-secret")
	send(14, -1001234, 1234, false, "@inlumi_bot explain Inner Breeze meditation", 0, "group-secret")
	if sends.Load() != 5 || models.Load() != 5 {
		t.Fatal("rejected delivery replayed")
	}
	if err := store.Database.QueryRow("SELECT state FROM server_lumi_group_deliveries WHERE update_id=14").Scan(&state); err != nil || state != "rejected" {
		t.Fatalf("explicit rejection was not recorded: %s %v", state, err)
	}
}

func TestLumiGroupMentionBoundaries(t *testing.T) {
	for _, input := range []string{"@inlumi_bot hi", "Hi\n@inlumi_bot!", "Hi\t@INLUMI_BOT", "/help@inlumi_bot", "Lumi, hello", "hi Lumi", "where do you live lumi?", "what can you do, Lumi?"} {
		if !Address.MatchString(input) {
			t.Errorf("missed mention %q", input)
		}
	}
	for _, input := range []string{"n@inlumi_bot", "@inlumi_bot_fake", "someone@inlumi_bot", "/help@another_bot", "luminous", "I spoke to Lumi yesterday", "Lumi_bot_fake hello"} {
		if Address.MatchString(input) {
			t.Errorf("accepted false mention %q", input)
		}
	}
}

func TestLumiGroupRelevanceBeforeModel(t *testing.T) {
	cases := []struct {
		text  string
		reply bool
		model bool
		local string
	}{
		{"doing well, it's a pleasure", false, false, ""},
		{"where do you live?", false, false, ""},
		{"we have many work tasks to do", false, false, ""},
		{"the weather is nice", false, false, ""},
		{"luminous colors", false, false, ""},
		{"I spoke to Lumi yesterday", false, false, ""},
		{"where do you live lumi?", false, false, "don't have a physical home"},
		{"where do you live in Inner Breeze, Lumi?", false, false, "don't have a physical home"},
		{"Lumi, where are you from?", false, false, "don't have a physical home"},
		{"@inlumi_bot where do you live?", false, false, "don't have a physical home"},
		{"where do you live?", true, false, "don't have a physical home"},
		{"hi Lumi", false, false, "Inner Breeze companion"},
		{"doing well, it's a pleasure", true, false, "Inner Breeze companion"},
		{"/help@inlumi_bot", false, false, "Inner Breeze companion"},
		{"Lumi, write me a crypto trading bot", false, false, "leave other topics"},
		{"@inlumi_bot solve this algebra problem", false, false, "leave other topics"},
		{"tell me a joke", true, false, "leave other topics"},
		{"Lumi, show my Inner Breeze diary", false, false, "can't access"},
		{"@inlumi_bot add a task to buy tea", false, false, "can't access"},
		{"/todo@inlumi_bot buy tea", false, false, "can't access"},
		{"show my habits", true, false, "can't access"},
		{"/help@another_bot Inner Breeze", false, false, ""},
		{"How do I use Inner Breeze?", false, true, ""},
		{"Lumi, how do breathing practices work?", false, true, ""},
		{"how do habits work?", true, true, ""},
		{"how do habits work?", false, false, ""},
		{"How do I change settings in Inner Breeze?", false, true, ""},
		{"Lumi, how can I improve my habits?", false, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.text, func(t *testing.T) {
			got := LumiGroup_Decide(tc.text, tc.reply)
			if got.Model != tc.model || (tc.local == "" && got.Reply != "") || (tc.local != "" && !strings.Contains(got.Reply, tc.local)) {
				t.Fatalf("decision: model=%v reply=%q; want model=%v containing %q", got.Model, got.Reply, tc.model, tc.local)
			}
		})
	}
}

func TestLumiGroupLocalRepliesNeverUseLinkedAccountOrTokens(t *testing.T) {
	server, store, _ := testServer(t)
	server.Cfg.LumiBotToken = "8967366018:fixture"
	server.Cfg.LumiWebhookSecret = "group-secret"
	server.Cfg.LumiGroupID = -1009876543210
	server.Cfg.ChatAPIKey = "fixture-model-key"
	server.Cfg.ChatDailyLimit = 20
	server.Cfg.ChatGlobalDailyLimit = 100
	var models, sends, typing atomic.Int32
	var linkedAccount string
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
			if len(input.Messages) != 2 || len(input.Tools) != 0 || !strings.Contains(input.Messages[0].Content, "no account access") {
				t.Error("group account boundary missing")
			}
			body, _ := json.Marshal(input)
			if linkedAccount != "" && strings.Contains(string(body), linkedAccount) {
				t.Error("linked account leaked into group prompt")
			}
			_, _ = fmt.Fprint(w, `{"choices":[{"message":{"role":"assistant","content":"Inner Breeze explanation."}}]}`)
		case "/bot8967366018:fixture/sendMessage":
			sends.Add(1)
			_, _ = fmt.Fprint(w, `{"ok":true,"result":{"message_id":777}}`)
		case "/bot8967366018:fixture/sendChatAction":
			typing.Add(1)
			_, _ = fmt.Fprint(w, `{"ok":true}`)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
		}
	}))
	defer upstream.Close()
	original := TelegramAPIBase
	TelegramAPIBase = upstream.URL
	defer func() { TelegramAPIBase = original }()
	server.Cfg.ChatAPIEndpoint = upstream.URL + "/model"
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0xb4)
	linkedAccount = identity.UserID
	code := lumiLink(t, handler, identity)
	if out := lumiWebhook(handler, "group-secret", 100, "private", "/start "+code); out.Code != 200 {
		t.Fatal("private account link failed")
	}
	baselineSends := sends.Load()
	group := func(id int, text string, reply bool) {
		t.Helper()
		bot := int64(0)
		if reply {
			bot = 8967366018
		}
		body, _ := json.Marshal(map[string]any{"update_id": id, "message": map[string]any{
			"message_id": id, "chat": map[string]any{"id": server.Cfg.LumiGroupID, "type": "supergroup"},
			"from": map[string]any{"id": 1234}, "text": text, "reply_to_message": map[string]any{"from": map[string]any{"id": bot}},
		}})
		r := httptest.NewRequest("POST", "/api/v1/lumi/telegram/webhook", strings.NewReader(string(body)))
		r.Header.Set("X-Telegram-Bot-Api-Secret-Token", "group-secret")
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, r)
		if out.Code != 200 {
			t.Fatalf("group status %d", out.Code)
		}
	}
	group(101, "doing well, it's a pleasure", false)
	group(102, "where do you live?", false)
	group(103, "where do you live lumi?", false)
	group(104, "Lumi, show my Inner Breeze diary", false)
	group(105, "Lumi, write me a trading bot", false)
	group(106, "/help@inlumi_bot", false)
	if models.Load() != 0 || typing.Load() != 0 || sends.Load() != baselineSends+4 {
		t.Fatal("unrelated/local messages used provider, typing, or wrong response count")
	}
	if retentionCount(t, store, "SELECT COUNT(*) FROM server_chat_usage") != 0 {
		t.Fatal("local replies spent model allowance")
	}
	group(107, "Lumi, how do breathing practices work in Inner Breeze?", false)
	if models.Load() != 1 || typing.Load() != 1 {
		t.Fatal("Inner Breeze question did not use the scoped model")
	}
	if retentionCount(t, store, "SELECT used FROM server_chat_usage WHERE account_id='lumi-group'") != 1 {
		t.Fatal("wrong group model accounting")
	}
	if out := lumiWebhook(handler, "group-secret", 108, "private", "/todo Buy tea"); out.Code != 200 {
		t.Fatal("connected private input failed")
	}
	poll := lumiRequest(handler, identity, "GET", "/api/v1/lumi/telegram/updates?client="+strings.Repeat("c", 64), "")
	var queued LumiPoll
	if poll.Code != 200 || json.Unmarshal(poll.Body.Bytes(), &queued) != nil || queued.Update.Text != "/todo Buy tea" || !queued.Linked {
		t.Fatal("group filter broke private account actions")
	}
}
