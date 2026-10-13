package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func chatRequest(handler http.Handler, identity testIdentity, path, data string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+identity.Token)
	req.Header.Set("X-Daochi-User", identity.UserID)
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, req)
	return out
}

func TestChatAppearanceToolsAndBoundedContinuations(t *testing.T) {
	request := ChatRequest{Context: json.RawMessage(`{}`), Messages: []ChatMessage{{Role: "user", Content: "Make the buttons rounder"}}}
	for index := 0; index < 24; index++ {
		request.Tools = append(request.Tools, ChatTool{Type: "function", Function: ChatFunction{
			Name: "app_tool_" + strconv.Itoa(index), Description: "App action", Parameters: json.RawMessage(`{"type":"object"}`),
		}})
	}
	if len(request.Tools) < 24 || !Chat_ValidRequest(request) {
		t.Fatal("Inbe's full tool catalog was rejected")
	}
	request.Messages = append(request.Messages,
		ChatMessage{Role: "assistant", ToolCalls: []ChatToolCall{{ID: "style-read", Type: "function", Function: ChatFunction{Name: "read_style", Arguments: `{"scope":"all"}`}}}},
		ChatMessage{Role: "tool", ToolCallId: "style-read", Content: strings.Repeat("x", 98304)},
		ChatMessage{Role: "assistant", ToolCalls: []ChatToolCall{{ID: "style-preview", Type: "function", Function: ChatFunction{Name: "preview_style", Arguments: strings.Repeat("x", 8191)}}}},
	)
	if !Chat_ValidRequest(request) {
		t.Fatal("Bounded appearance continuation was rejected")
	}
	server, _, _ := testServer(t)
	server.Cfg.ChatAPIKey = "private-test-key"
	server.Cfg.ChatDailyLimit = 20
	server.Cfg.ChatGlobalDailyLimit = 100
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var received struct {
			Messages []ChatMessage `json:"messages"`
			Tools    []ChatTool    `json:"tools"`
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Error(err)
		}
		if len(received.Tools) != 24 || len(received.Messages[3].Content) != 98304 {
			t.Error("Appearance tools or results were truncated")
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"Preview ready"}}]}`))
	}))
	defer upstream.Close()
	original := ChatEndpoint
	ChatEndpoint = upstream.URL
	defer func() { ChatEndpoint = original }()
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x79)
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if out := chatRequest(handler, identity, "/api/v1/chat/completions", string(encoded)); out.Code != 200 {
		t.Fatalf("Appearance continuation: %d %s", out.Code, out.Body.String())
	}
	request.Messages[2].Content += "x"
	if Chat_ValidRequest(request) {
		t.Fatal("Oversize tool result was accepted")
	}
	request.Messages[2].Content = "{}"
	request.Messages[3].ToolCalls[0].Function.Arguments = strings.Repeat("x", 65537)
	if Chat_ValidRequest(request) {
		t.Fatal("Oversize tool arguments were accepted")
	}
	request.Messages = request.Messages[:1]
	request.Tools = append(request.Tools, make([]ChatTool, 33-len(request.Tools))...)
	if Chat_ValidRequest(request) {
		t.Fatal("Oversize tool catalog was accepted")
	}
}

func TestChatAccountAuthenticationToolsAndPersistentQuota(t *testing.T) {
	server, store, _ := testServer(t)
	server.Cfg.ChatAPIKey = "server-only-key"
	server.Cfg.ChatModel = "glm-4.7-flash"
	server.Cfg.ChatDailyLimit = 2
	server.Cfg.ChatGlobalDailyLimit = 3
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer server-only-key" {
			t.Error("provider did not receive server credential")
		}
		var data map[string]any
		if json.NewDecoder(r.Body).Decode(&data) != nil {
			t.Error("invalid provider JSON")
		}
		if data["model"] != "glm-4.7-flash" || data["max_tokens"] != float64(512) {
			t.Error("provider budget or model changed")
		}
		messages := data["messages"].([]any)
		if !strings.Contains(messages[0].(map[string]any)["content"].(string), "report_feedback") {
			t.Error("feedback instructions missing")
		}
		if !strings.Contains(messages[0].(map[string]any)["content"].(string), "done_last_14_days") {
			t.Error("coaching instructions missing")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"call-1","type":"function","function":{"name":"report_feedback","arguments":"{\"title\":\"Lag\",\"message\":\"Lumi freezes\"}"}}]}}]}`))
	}))
	defer upstream.Close()
	original := ChatEndpoint
	ChatEndpoint = upstream.URL
	defer func() { ChatEndpoint = original }()
	handler := server.Routes()
	first := newTestIdentity(t, handler, 0x73)
	second := newTestIdentity(t, handler, 0x74)
	data := `{"messages":[{"role":"user","content":"fix the lag"}],"context":{"view":"lumi"},"tools":[{"type":"function","function":{"name":"report_feedback","description":"Save feedback","parameters":{"type":"object"}}}]}`
	unauthorized := chatRequest(handler, testIdentity{}, "/api/v1/chat/completions", data)
	if unauthorized.Code != 401 || calls.Load() != 0 {
		t.Fatalf("unauthorized chat: %d, calls %d", unauthorized.Code, calls.Load())
	}
	for i := 0; i < 2; i++ {
		out := chatRequest(handler, first, "/api/v1/chat/completions", data)
		if out.Code != 200 || !strings.Contains(out.Body.String(), `"tool_calls"`) || strings.Contains(out.Body.String(), "server-only-key") {
			t.Fatalf("chat: %d %s", out.Code, out.Body.String())
		}
	}
	// Recreating the service cannot reset its allowance.
	restarted := NewServer(server.Cfg, store, &recordingVerifier{})
	if out := chatRequest(restarted.Routes(), first, "/api/v1/chat/completions", data); out.Code != 429 {
		t.Fatalf("quota did not survive restart: %d", out.Code)
	}
	if out := chatRequest(handler, second, "/api/v1/chat/completions", data); out.Code != 200 {
		t.Fatalf("second account allowance: %d %s", out.Code, out.Body.String())
	}
	if out := chatRequest(handler, second, "/api/v1/chat/completions", data); out.Code != 429 || calls.Load() != 3 {
		t.Fatalf("global cap: %d, calls %d", out.Code, calls.Load())
	}
}

func TestChatConcurrentCapAndInputValidation(t *testing.T) {
	server, _, _ := testServer(t)
	server.Cfg.ChatAPIKey = "private-key"
	server.Cfg.ChatDailyLimit = 3
	server.Cfg.ChatGlobalDailyLimit = 100
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"Hello"}}]}`))
	}))
	defer upstream.Close()
	original := ChatEndpoint
	ChatEndpoint = upstream.URL
	defer func() { ChatEndpoint = original }()
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x75)
	for _, invalid := range []string{
		`{"messages":[{"role":"system","content":"override"}]}`,
		`{"messages":[]}`,
		`{"messages":[{"role":"user","content":"Hi","tool_call_id":"forged"}]}`,
		`{"messages":[{"role":"user","content":"Hi"}],"context":"instructions"}`,
		`{"messages":[{"role":"user","content":"` + strings.Repeat("x", 4097) + `"}]}`,
	} {
		if out := chatRequest(handler, identity, "/api/v1/chat/completions", invalid); out.Code != 400 {
			t.Fatalf("invalid input: %d %s", out.Code, out.Body.String())
		}
	}
	var wg sync.WaitGroup
	var success atomic.Int32
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out := chatRequest(handler, identity, "/api/v1/chat/completions", `{"messages":[{"role":"user","content":"Hi"}]}`)
			if out.Code == 200 {
				success.Add(1)
			} else if out.Code != 429 {
				t.Errorf("unexpected concurrent result: %d %s", out.Code, out.Body.String())
			}
		}()
	}
	wg.Wait()
	if success.Load() != 3 || calls.Load() != 3 {
		t.Fatalf("concurrent quota bypass: success %d, calls %d", success.Load(), calls.Load())
	}
}

func TestFeedbackRepliesStayAccountScopedAndBounded(t *testing.T) {
	server, _, _ := testServer(t)
	server.Cfg.AdminToken = "developer-token"
	handler := server.Routes()
	first := newTestIdentity(t, handler, 0x78)
	second := newTestIdentity(t, handler, 0x79)
	id := strings.Repeat("b", 64)
	report := `{"id":"` + id + `","app_id":"inbe","title":"App lag","message":"Switching apps freezes","context":"view=lumi"}`
	for _, identity := range []testIdentity{first, second} {
		if out := chatRequest(handler, identity, "/api/v1/feedback", report); out.Code != 200 {
			t.Fatalf("report: %d %s", out.Code, out.Body.String())
		}
	}
	reply := httptest.NewRequest(http.MethodPost, "/api/v1/admin/feedback/reply", strings.NewReader(`{"account_id":"`+first.UserID+`","id":"`+id+`","reply":"Thanks, I will investigate."}`))
	reply.Header.Set("X-Daochi-Admin", "developer-token")
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, reply)
	if out.Code != 200 {
		t.Fatalf("reply: %d %s", out.Code, out.Body.String())
	}
	for _, identity := range []testIdentity{first, second} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/feedback?replies=1&offset=0", nil)
		req.Header.Set("Authorization", "Bearer "+identity.Token)
		req.Header.Set("X-Daochi-User", identity.UserID)
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		if out.Code != 200 || strings.Contains(out.Body.String(), "Switching apps freezes") {
			t.Fatalf("bounded replies: %d %s", out.Code, out.Body.String())
		}
		hasReply := strings.Contains(out.Body.String(), "I will investigate")
		if hasReply != (identity.UserID == first.UserID) {
			t.Fatalf("reply crossed account boundary: %s", out.Body.String())
		}
	}
	for _, offset := range []string{"invalid", "-1", "1000000"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/feedback?replies=1&offset="+offset, nil)
		req.Header.Set("Authorization", "Bearer "+first.Token)
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		if out.Code != 400 {
			t.Fatalf("invalid offset %q: %d", offset, out.Code)
		}
	}
}

func TestChatCodingProviderUsesConfiguredEndpointAndBoundedThinking(t *testing.T) {
	server, _, _ := testServer(t)
	server.Cfg.ChatAPIKey = "coding-key"
	server.Cfg.ChatModel = "glm-5.3-flash"
	server.Cfg.ChatDailyLimit = 20
	server.Cfg.ChatGlobalDailyLimit = 1000
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Model           string `json:"model"`
			MaxTokens       int    `json:"max_tokens"`
			ReasoningEffort string `json:"reasoning_effort"`
			Thinking        struct {
				Type string `json:"type"`
			} `json:"thinking"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload.Model != "glm-5.3-flash" || payload.Thinking.Type != "enabled" || payload.MaxTokens != 2048 || payload.ReasoningEffort != "low" {
			t.Errorf("unexpected coding request: %+v", payload)
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"Hello"}}]}`))
	}))
	defer upstream.Close()
	server.Cfg.ChatAPIEndpoint = upstream.URL
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x7a)
	response := chatRequest(handler, identity, "/api/v1/chat/completions", `{"messages":[{"role":"user","content":"Hi"}]}`)
	if response.Code != 200 || !strings.Contains(response.Body.String(), "Hello") {
		t.Fatalf("coding completion: %d %s", response.Code, response.Body.String())
	}
}

func TestFeedbackAdministrationIsDisabledWithoutToken(t *testing.T) {
	server, _, _ := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/feedback", nil)
	req.RemoteAddr = "127.0.0.1:8080"
	out := httptest.NewRecorder()
	server.Routes().ServeHTTP(out, req)
	if out.Code != 403 {
		t.Fatalf("unconfigured operator inbox exposed to proxy: %d %s", out.Code, out.Body.String())
	}
}

func TestFeedbackRetryPrivacyAndDeveloperReply(t *testing.T) {
	server, _, _ := testServer(t)
	server.Cfg.AdminToken = "developer-token"
	handler := server.Routes()
	first := newTestIdentity(t, handler, 0x76)
	second := newTestIdentity(t, handler, 0x77)
	id := strings.Repeat("a", 64)
	report := `{"id":"` + id + `","app_id":"inbe","title":"Lag","message":"Lumi freezes","context":"view=lumi"}`
	for i := 0; i < 2; i++ {
		if out := chatRequest(handler, first, "/api/v1/feedback", report); out.Code != 200 {
			t.Fatalf("submit/retry: %d %s", out.Code, out.Body.String())
		}
	}
	read := func(identity testIdentity, admin bool) *httptest.ResponseRecorder {
		path := "/api/v1/feedback"
		if admin {
			path = "/api/v1/admin/feedback"
		}
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+identity.Token)
		req.Header.Set("X-Daochi-User", identity.UserID)
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		return out
	}
	if out := read(second, false); out.Code != 200 || strings.Contains(out.Body.String(), "freezes") {
		t.Fatalf("another account read private feedback: %d %s", out.Code, out.Body.String())
	}
	if out := read(first, true); out.Code != 401 {
		t.Fatalf("non-developer inbox: %d", out.Code)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/feedback/reply", bytes.NewBufferString(`{"account_id":"`+first.UserID+`","id":"`+id+`","reply":"Fixed in the next update"}`))
	req.Header.Set("X-Daochi-Admin", "developer-token")
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, req)
	if out.Code != 200 {
		t.Fatalf("developer reply: %d %s", out.Code, out.Body.String())
	}
	out = read(first, false)
	if strings.Count(out.Body.String(), "freezes") != 1 || !strings.Contains(out.Body.String(), "Fixed in the next update") {
		t.Fatalf("feedback lost or duplicated: %s", out.Body.String())
	}
	alias := httptest.NewRequest(http.MethodPost, "/api/v1/account/alias", strings.NewReader(`{"user_id_hash":"`+first.UserID+`","alias":"@reporter"}`))
	alias.Header.Set("Content-Type", "application/json")
	alias.Header.Set("X-Daochi-User", first.UserID)
	alias.Header.Set("Authorization", "Bearer "+first.Token)
	out = httptest.NewRecorder()
	handler.ServeHTTP(out, alias)
	if out.Code != 200 {
		t.Fatalf("reporter alias: %d %s", out.Code, out.Body.String())
	}
	inbox := httptest.NewRequest(http.MethodGet, "/api/v1/admin/feedback", nil)
	inbox.Header.Set("X-Daochi-Admin", "developer-token")
	out = httptest.NewRecorder()
	handler.ServeHTTP(out, inbox)
	if out.Code != 200 || !strings.Contains(out.Body.String(), `"account_id":"`+first.UserID+`","account_alias":"reporter"`) {
		t.Fatalf("operator inbox does not name the reporting account: %d %s", out.Code, out.Body.String())
	}
}

func TestSpellingCorrectsTextAndSharesChatAllowance(t *testing.T) {
	server, _, _ := testServer(t)
	server.Cfg.ChatAPIKey = "server-only-key"
	server.Cfg.ChatModel = "glm-4.7-flash"
	server.Cfg.ChatDailyLimit = 2
	server.Cfg.ChatGlobalDailyLimit = 10
	var calls atomic.Int32
	failUpstream := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var payload struct {
			Model     string `json:"model"`
			MaxTokens int    `json:"max_tokens"`
			Thinking  struct {
				Type string `json:"type"`
			} `json:"thinking"`
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
			Tools []any `json:"tools"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		if payload.Model != "glm-4.7-flash" || payload.MaxTokens != 6144 || payload.Thinking.Type != "disabled" || len(payload.Tools) != 0 {
			t.Errorf("unexpected spelling request: %+v", payload)
		}
		if len(payload.Messages) != 2 || payload.Messages[0].Role != "system" || !strings.Contains(payload.Messages[0].Content, "spelling") {
			t.Errorf("spelling instructions missing: %+v", payload.Messages)
		}
		if payload.Messages[1].Role != "user" || payload.Messages[1].Content != "I wnet **home**.\nIt was nice." {
			t.Errorf("entry was not sent without its surrounding blank space: %q", payload.Messages[1].Content)
		}
		if failUpstream {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"\n I went **home**.\nIt was nice.  "}}]}`))
	}))
	defer upstream.Close()
	server.Cfg.ChatAPIEndpoint = upstream.URL
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x7c)
	entry := `{"text":"\n\n  I wnet **home**.\nIt was nice. \n"}`

	if out := chatRequest(handler, testIdentity{}, "/api/v1/chat/spelling", entry); out.Code != 401 || calls.Load() != 0 {
		t.Fatalf("unauthorized spelling: %d, calls %d", out.Code, calls.Load())
	}
	for _, invalid := range []string{`{"text":"  \n "}`, `{"text":""}`, `{}`, `{"text":"` + strings.Repeat("a", 8193) + `"}`} {
		if out := chatRequest(handler, identity, "/api/v1/chat/spelling", invalid); out.Code != 400 {
			t.Fatalf("invalid spelling request %.40q: %d", invalid, out.Code)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid requests reached the provider: %d", calls.Load())
	}

	out := chatRequest(handler, identity, "/api/v1/chat/spelling", entry)
	var corrected struct {
		Text      string `json:"text"`
		Remaining int64  `json:"remaining"`
	}
	if out.Code != 200 || json.Unmarshal(out.Body.Bytes(), &corrected) != nil {
		t.Fatalf("spelling: %d %s", out.Code, out.Body.String())
	}
	if corrected.Text != "\n\n  I went **home**.\nIt was nice. \n" || corrected.Remaining != 1 {
		t.Fatalf("corrected entry: %q, remaining %d", corrected.Text, corrected.Remaining)
	}

	failUpstream = true
	if out := chatRequest(handler, identity, "/api/v1/chat/spelling", entry); out.Code != 503 {
		t.Fatalf("provider failure: %d %s", out.Code, out.Body.String())
	}
	// Spelling uses the same daily allowance as online chat.
	data := `{"messages":[{"role":"user","content":"Hi"}]}`
	if out := chatRequest(handler, identity, "/api/v1/chat/completions", data); out.Code != 429 {
		t.Fatalf("spelling did not use the chat allowance: %d", out.Code)
	}
	if out := chatRequest(handler, identity, "/api/v1/chat/spelling", entry); out.Code != 429 || calls.Load() != 2 {
		t.Fatalf("spelling allowance: %d, calls %d", out.Code, calls.Load())
	}
}

func TestHabitIconsChooseOfferedIconsAndShareChatAllowance(t *testing.T) {
	boundary := HabitIconRequest{}
	for index := 0; index < 64; index++ {
		boundary.Icons = append(boundary.Icons, strings.Repeat("a", 30)+strconv.Itoa(index+10))
	}
	for index := 0; index < 32; index++ {
		boundary.Habits = append(boundary.Habits, HabitIconHabit{Name: strings.Repeat("h", 64), Description: strings.Repeat("d", 256)})
	}
	if len(boundary.Icons[63]) != 32 || !Chat_ValidHabitIconRequest(boundary) {
		t.Fatal("the largest valid habit icon request was rejected")
	}

	server, _, _ := testServer(t)
	server.Cfg.ChatAPIKey = "server-only-key"
	server.Cfg.ChatModel = "glm-4.7-flash"
	server.Cfg.ChatDailyLimit = 3
	server.Cfg.ChatGlobalDailyLimit = 10
	const (
		answerChoices = iota
		answerFailure
		answerWrongLength
	)
	var calls atomic.Int32
	var answer atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var payload struct {
			Model     string `json:"model"`
			MaxTokens int    `json:"max_tokens"`
			Thinking  struct {
				Type string `json:"type"`
			} `json:"thinking"`
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
			Tools []any `json:"tools"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		if payload.Model != "glm-4.7-flash" || payload.MaxTokens != 1024 || payload.Thinking.Type != "disabled" || len(payload.Tools) != 0 {
			t.Errorf("unexpected habit icon request: %+v", payload)
		}
		if len(payload.Messages) != 2 || payload.Messages[0].Role != "system" || !strings.Contains(payload.Messages[0].Content, "icon") {
			t.Errorf("habit icon instructions missing: %+v", payload.Messages)
		}
		if len(payload.Messages) == 2 {
			sent := payload.Messages[1].Content
			for _, expected := range []string{`"lotus"`, `"fork_knife"`, `"Meditate"`, `"Cook dinner"`, `"Call grandma"`, `"Ten quiet minutes"`} {
				if payload.Messages[1].Role != "user" || !strings.Contains(sent, expected) {
					t.Errorf("habit icon document misses %s: %q", expected, sent)
				}
			}
		}
		switch answer.Load() {
		case answerFailure:
			w.WriteHeader(http.StatusInternalServerError)
			return
		case answerWrongLength:
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"[\"lotus\"]"}}]}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"\n` + "```json" + `\n[\"lotus\", \"\", \"telephone\"]\n` + "```" + `\n"}}]}`))
	}))
	defer upstream.Close()
	server.Cfg.ChatAPIEndpoint = upstream.URL
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x7d)
	path := "/api/v1/chat/habit-icons"
	habits := `{"icons":["lotus","fork_knife","book"],"habits":[{"name":"Meditate","description":"Ten quiet minutes"},{"name":"Cook dinner"},{"name":"Call grandma","description":""}]}`

	if out := chatRequest(handler, testIdentity{}, path, habits); out.Code != 401 || calls.Load() != 0 {
		t.Fatalf("unauthorized habit icons: %d, calls %d", out.Code, calls.Load())
	}
	distinctIcons := []string{}
	for index := 0; index < 65; index++ {
		distinctIcons = append(distinctIcons, "icon_"+strconv.Itoa(index))
	}
	manyIcons := `{"icons":["` + strings.Join(distinctIcons, `","`) + `"],"habits":[{"name":"Run"}]}`
	manyHabits := `{"icons":["run"],"habits":[{"name":"Run"}` + strings.Repeat(`,{"name":"Run"}`, 32) + `]}`
	invalid := []string{
		`{}`,
		`not json`,
		`{"icons":[],"habits":[{"name":"Run"}]}`,
		`{"icons":["run"],"habits":[]}`,
		`{"icons":["run"]}`,
		`{"habits":[{"name":"Run"}]}`,
		`{"icons":"run","habits":[{"name":"Run"}]}`,
		`{"icons":["run"],"habits":[1]}`,
		`{"icons":[""],"habits":[{"name":"Run"}]}`,
		`{"icons":[null],"habits":[{"name":"Run"}]}`,
		`{"icons":["Run"],"habits":[{"name":"Run"}]}`,
		`{"icons":["fork-knife"],"habits":[{"name":"Run"}]}`,
		`{"icons":["` + strings.Repeat("a", 33) + `"],"habits":[{"name":"Run"}]}`,
		`{"icons":["run","run"],"habits":[{"name":"Run"}]}`,
		manyIcons,
		manyHabits,
		`{"icons":["run"],"habits":[{"name":" \n "}]}`,
		`{"icons":["run"],"habits":[{"description":"Run every day"}]}`,
		`{"icons":["run"],"habits":[{"name":"` + strings.Repeat("r", 65) + `"}]}`,
		`{"icons":["run"],"habits":[{"name":"Run","description":"` + strings.Repeat("d", 257) + `"}]}`,
	}
	for _, request := range invalid {
		out := chatRequest(handler, identity, path, request)
		if out.Code != 400 || !strings.Contains(out.Body.String(), "invalid habit icon request") {
			t.Fatalf("invalid habit icon request %.60q: %d %s", request, out.Code, out.Body.String())
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid requests reached the provider: %d", calls.Load())
	}

	out := chatRequest(handler, identity, path, habits)
	var chosen struct {
		Icons     []string `json:"icons"`
		Remaining int64    `json:"remaining"`
	}
	if out.Code != 200 || json.Unmarshal(out.Body.Bytes(), &chosen) != nil {
		t.Fatalf("habit icons: %d %s", out.Code, out.Body.String())
	}
	if len(chosen.Icons) != 3 || chosen.Icons[0] != "lotus" || chosen.Icons[1] != "" || chosen.Icons[2] != "" || chosen.Remaining != 2 {
		t.Fatalf("chosen icons: %q, remaining %d", chosen.Icons, chosen.Remaining)
	}

	answer.Store(answerFailure)
	if out := chatRequest(handler, identity, path, habits); out.Code != 503 || !strings.Contains(out.Body.String(), "online chat unavailable") {
		t.Fatalf("provider failure: %d %s", out.Code, out.Body.String())
	}
	answer.Store(answerWrongLength)
	if out := chatRequest(handler, identity, path, habits); out.Code != 503 || !strings.Contains(out.Body.String(), "invalid model response") {
		t.Fatalf("wrong-length answer: %d %s", out.Code, out.Body.String())
	}
	// Habit icons use the same daily allowance as online chat.
	data := `{"messages":[{"role":"user","content":"Hi"}]}`
	if out := chatRequest(handler, identity, "/api/v1/chat/completions", data); out.Code != 429 {
		t.Fatalf("habit icons did not use the chat allowance: %d", out.Code)
	}
	if out := chatRequest(handler, identity, path, habits); out.Code != 429 || calls.Load() != 3 {
		t.Fatalf("habit icon allowance: %d, calls %d", out.Code, calls.Load())
	}
}

func TestHabitIconAnswersAreReadStrictly(t *testing.T) {
	request := HabitIconRequest{
		Icons:  []string{"lotus", "book"},
		Habits: []HabitIconHabit{{Name: "Meditate"}, {Name: "Read"}},
	}
	cases := []struct {
		reply string
		icons []string
	}{
		{`["lotus","book"]`, []string{"lotus", "book"}},
		{" ```JSON\n[\"book\", \"lotus\"]\n``` ", []string{"book", "lotus"}},
		{"```\n[\"lotus\",null]\n```", []string{"lotus", ""}},
		{`["Lotus", 3]`, []string{"", ""}},
		{`[" lotus", "books"]`, []string{"", ""}},
	}
	for _, test := range cases {
		parsed := Chat_ParseHabitIcons(test.reply, request)
		if !parsed.Valid || len(parsed.Icons) != len(test.icons) {
			t.Fatalf("reply %q: %+v", test.reply, parsed)
		}
		for index := range test.icons {
			if parsed.Icons[index] != test.icons[index] {
				t.Fatalf("reply %q: %q", test.reply, parsed.Icons)
			}
		}
	}
	for _, reply := range []string{``, `lotus`, `null`, `{"icons":["lotus","book"]}`, `["lotus"]`, `["lotus","book","lotus"]`, "```json\n[\"lotus\",\n```"} {
		if parsed := Chat_ParseHabitIcons(reply, request); parsed.Valid {
			t.Fatalf("unusable reply %q was accepted: %+v", reply, parsed)
		}
	}
}
