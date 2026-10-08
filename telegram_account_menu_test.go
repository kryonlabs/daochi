package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func accountMenuURLs() [3]string {
	return [3]string{
		"https://inbe.example/build/telegram/?r=" + strings.Repeat("a", 32),
		"https://inbe.example/build/telegram/?r=" + strings.Repeat("b", 32),
		"https://inbe.example/build/telegram/?r=" + strings.Repeat("c", 32),
	}
}

func checkAccountMenu(t *testing.T, raw json.RawMessage, urls [3]string) {
	t.Helper()
	var keyboard struct {
		Rows [][]struct {
			Text     string            `json:"text"`
			WebApp   map[string]string `json:"web_app"`
			Callback string            `json:"callback_data"`
		} `json:"inline_keyboard"`
	}
	if err := json.Unmarshal(raw, &keyboard); err != nil {
		t.Fatal(err)
	}
	labels := [3]string{"Create account", "Restore account", "Connect existing account"}
	if len(keyboard.Rows) != 3 {
		t.Fatalf("want three stacked rows, got %d", len(keyboard.Rows))
	}
	for i, row := range keyboard.Rows {
		if len(row) != 1 || row[0].Text != labels[i] || row[0].Callback != "" ||
			len(row[0].WebApp) != 1 || row[0].WebApp["url"] != urls[i] {
			t.Fatalf("unexpected account menu row %d", i)
		}
	}
}

func TestTelegramAccountMenuBuild(t *testing.T) {
	urls := accountMenuURLs()
	checkAccountMenu(t, TelegramAccountMenu_Build(urls[0], urls[1], urls[2]), urls)
}

func TestTelegramAccountMenuValidHostsAndPorts(t *testing.T) {
	for _, authority := range []string{
		"inbe.example", "INBE.example", "inbe.example.", "inbe.example:443",
		"inbe.example:1", "inbe.example:65535", "127.0.0.1:8443", "[::1]",
		"[2001:db8::1]:443",
	} {
		urls := accountMenuURLs()
		urls[0] = "https://" + authority + "/telegram/?r=" + strings.Repeat("a", 32)
		checkAccountMenu(t, TelegramAccountMenu_Build(urls[0], urls[1], urls[2]), urls)
	}
}

func TestTelegramAccountMenuRejectsUnsafeURLs(t *testing.T) {
	valid := accountMenuURLs()
	id := strings.Repeat("a", 32)
	invalid := []string{
		"", "http://inbe.example/?r=" + id, "HTTPS://inbe.example/?r=" + id,
		"//inbe.example/?r=" + id, "https:///app?r=" + id,
		"https://user:password@inbe.example/?r=" + id,
		"https://user@inbe.example/?r=" + id, "https://inbe.example/",
		"https://inbe.example/?r=", "https://inbe.example/?r=" + id[:31],
		"https://inbe.example/?r=" + id + "a", "https://inbe.example/?r=" + strings.Repeat("A", 32),
		"https://inbe.example/?r=" + strings.Repeat("g", 32),
		"https://inbe.example/?r=" + id + "&private_key=synthetic-only",
		"https://inbe.example/?r=" + id + "&r=" + id,
		"https://inbe.example/?token=" + id, "https://inbe.example/?%72=" + id,
		"https://inbe.example/?r=%61" + id[1:], "https://inbe.example/?r=" + id + "#",
		"https://inbe.example/?r=" + id + "#passphrase=synthetic-only",
		"https://inbe.example/\\bad?r=" + id, "https://inbe.example/%3fkey?r=" + id,
		"https://inbe.example:bad/?r=" + id, "https://inbe.example/\n?r=" + id,
		"https://inbe.example/\x00?r=" + id, " https://inbe.example/?r=" + id,
		"https://inbe.example/?r=" + id + " ", "https://inbe.example/é?r=" + id,
		"https://inbe.example/" + strings.Repeat("a", 2048) + "?r=" + id,
	}
	for _, authority := range []string{
		":443", ".", "inbe..example", ".inbe.example", "-inbe.example",
		"inbe-.example", "inbe.example-", "inbe_example", "[bad]", "[127.0.0.1]",
		"::1", "inbe.example:", "inbe.example:0", "inbe.example:65536",
		"inbe.example:99999999999999999999", "inbe.example:+443",
		strings.Repeat("a", 64) + ".example", strings.Repeat("a.", 127) + "a",
	} {
		invalid = append(invalid, "https://"+authority+"/?r="+id)
	}
	for _, bad := range invalid {
		for position := range valid {
			urls := valid
			urls[position] = bad
			if got := TelegramAccountMenu_Build(urls[0], urls[1], urls[2]); len(got) != 0 {
				t.Errorf("unsafe URL accepted in position %d: %q", position, bad)
			}
		}
	}
}

func TestTelegramAccountMenuSend(t *testing.T) {
	urls := accountMenuURLs()
	requests := 0
	status, answer := http.StatusOK, `{"ok":true}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodPost || r.URL.Path != "/botsynthetic-menu-token/sendMessage" ||
			r.Header.Get("Content-Type") != "application/json" {
			t.Error("unexpected synthetic transport request")
		}
		var message struct {
			ChatID   int64           `json:"chat_id"`
			Text     string          `json:"text"`
			Keyboard json.RawMessage `json:"reply_markup"`
		}
		if err := json.NewDecoder(r.Body).Decode(&message); err != nil {
			t.Error(err)
		} else {
			if message.ChatID != 1234 {
				t.Error("account menu sent to wrong numeric sender")
			}
			for _, phrase := range []string{"on your device", "private owner key stays there", "approving access in Inbe",
				"Never send private keys or recovery passphrases", "active Inbe session", "handled by Inbe"} {
				if !strings.Contains(message.Text, phrase) {
					t.Errorf("missing account explanation %q", phrase)
				}
			}
			checkAccountMenu(t, message.Keyboard, urls)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, answer)
	}))
	defer server.Close()
	originalBase := TelegramAPIBase
	originalClient := TelegramHTTPClient
	TelegramAPIBase = server.URL
	TelegramHTTPClient = server.Client()
	t.Cleanup(func() {
		TelegramAPIBase = originalBase
		TelegramHTTPClient = originalClient
	})
	send := func(token string, sender int64, given [3]string) bool {
		return TelegramAccountMenu_Send(token, sender, given[0], given[1], given[2])
	}
	if !send("synthetic-menu-token", 1234, urls) || requests != 1 {
		t.Fatal("valid account menu was not sent exactly once")
	}
	bad := urls
	bad[1] += "&private_key=synthetic-only"
	if send("", 1234, urls) || send("synthetic-menu-token", 0, urls) ||
		send("synthetic-menu-token", -1234, urls) || send("synthetic-menu-token", 1234, bad) || requests != 1 {
		t.Fatal("invalid menu attempted a transport request")
	}
	for _, failure := range []struct {
		status int
		answer string
	}{{200, `{"ok":false}`}, {200, "invalid JSON"}, {403, `{"ok":true}`},
		{200, `{"ok":true,"padding":"` + strings.Repeat("a", 65536) + `"}`}} {
		status, answer = failure.status, failure.answer
		if send("synthetic-menu-token", 1234, urls) {
			t.Errorf("failed transport reported success (status %d)", status)
		}
	}
	server.Close()
	if send("synthetic-menu-token", 1234, urls) {
		t.Fatal("connection failure reported success")
	}
}
