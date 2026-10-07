package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		if data["model"] != "glm-4.7-flash" || data["max_tokens"] != float64(256) {
			t.Error("provider budget or model changed")
		}
		messages := data["messages"].([]any)
		if !strings.Contains(messages[0].(map[string]any)["content"].(string), "report_feedback") {
			t.Error("feedback instructions missing")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"call-1","type":"function","function":{"name":"report_feedback","arguments":"{\"title\":\"Lag\",\"message\":\"Lumi freezes\"}"}}]}}]}`))
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
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"Hello"}}]}`))
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
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"Hello"}}]}`))
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
}
