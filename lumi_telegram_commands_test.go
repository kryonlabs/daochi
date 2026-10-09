package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLumiTelegramHelpUsageAndCommandQueue(t *testing.T) {
	server, _, _ := testServer(t)
	server.Cfg.LumiBotToken = "command-fixture-token"
	server.Cfg.LumiWebhookSecret = "command-fixture-secret"
	server.Cfg.LumiCanvasURL = "https://inbe.example/canvas"
	var messages []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/botcommand-fixture-token/sendChatAction" {
			fmt.Fprint(w, `{"ok":true}`)
			return
		}
		if r.URL.Path != "/botcommand-fixture-token/sendMessage" {
			t.Error("unexpected Telegram method")
		}
		var message struct {
			Text string `json:"text"`
		}
		if err := json.NewDecoder(r.Body).Decode(&message); err != nil {
			t.Error(err)
		}
		messages = append(messages, message.Text)
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer upstream.Close()
	original := TelegramAPIBase
	TelegramAPIBase = upstream.URL
	defer func() { TelegramAPIBase = original }()
	handler := server.Routes()
	owner := newTestIdentity(t, handler, 0xa5)
	send := func(id int, input string) {
		t.Helper()
		if got := lumiWebhook(handler, "command-fixture-secret", id, "private", input); got.Code != 200 {
			t.Fatalf("webhook status %d: %s", got.Code, got.Body.String())
		}
	}
	send(101, "/help@inlumi_bot")
	if len(messages) != 1 || !strings.Contains(messages[0], "sign in") || !strings.Contains(messages[0], "/journal") {
		t.Fatal("unlinked help did not explain commands and account linking")
	}
	code := lumiLink(t, handler, owner)
	send(102, "/start@inlumi_bot "+code)
	send(103, "/help")
	if !strings.Contains(messages[len(messages)-1], "while Inner Breeze is open") {
		t.Fatal("linked help omitted the app execution requirement")
	}
	for i, input := range []string{"/todo", "/todo \t\n", "/feedback", "/destroy_everything", "/"} {
		before := len(messages)
		send(110+i, input)
		if len(messages) != before+1 {
			t.Fatalf("command %q did not receive a help response", input)
		}
	}
	before := len(messages)
	send(120, "/todo@other_bot Private task")
	if len(messages) != before {
		t.Fatal("responded to a command for another bot")
	}
	const journal = "/journal  A calm morning\n水を飲む  "
	send(121, "/journal@inlumi_bot  A calm morning\n水を飲む  ")
	send(121, "/journal@inlumi_bot  A calm morning\n水を飲む  ")
	client := strings.Repeat("c", 64)
	out := lumiRequest(handler, owner, "GET", "/api/v1/lumi/telegram/updates?client="+client, "")
	var result LumiPoll
	if out.Code != 200 || json.Unmarshal(out.Body.Bytes(), &result) != nil || result.Update.ID != 121 || result.Update.Text != journal {
		t.Fatalf("help or invalid command entered the queue, or journal changed: %s", out.Body.String())
	}
	ack := lumiRequest(handler, owner, "POST", "/api/v1/lumi/telegram/ack", fmt.Sprintf(`{"id":121,"client":%q}`, client))
	if ack.Code != 200 {
		t.Fatal("could not acknowledge journal")
	}
	out = lumiRequest(handler, owner, "GET", "/api/v1/lumi/telegram/updates?client="+client, "")
	if json.Unmarshal(out.Body.Bytes(), &result) != nil || result.Update.ID != 0 {
		t.Fatal("duplicate command was queued twice")
	}
}
