package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// One offered icon name is also a valid chat reply and spelling correction.
const chatAnswerReply = `{"choices":[{"message":{"role":"assistant","content":"[\"lotus\"]"}}]}`

var chatAnswerRoutes = []struct {
	path string
	body string
	wait time.Duration
}{
	{"/api/v1/chat/completions", `{"messages":[{"role":"user","content":"Hi"}]}`, ChatWait},
	{"/api/v1/chat/spelling", `{"text":"Helo"}`, SpellingWait},
	{"/api/v1/chat/habit-icons", `{"icons":["lotus"],"habits":[{"name":"Meditate"}]}`, ChatWait},
}

func chatAnswerServer(t *testing.T, delay time.Duration) (*Server, http.Handler, *atomic.Int32) {
	t.Helper()
	server, _, _ := testServer(t)
	server.Cfg.ChatAPIKey = "private-test-key"
	server.Cfg.ChatDailyLimit = 20
	server.Cfg.ChatGlobalDailyLimit = 100
	calls := &atomic.Int32{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		time.Sleep(delay)
		_, _ = w.Write([]byte(chatAnswerReply))
	}))
	t.Cleanup(upstream.Close)
	original := ChatEndpoint
	ChatEndpoint = upstream.URL
	t.Cleanup(func() { ChatEndpoint = original })
	return server, server.Routes(), calls
}

func postSlowly(t *testing.T, client *http.Client, url string, identity testIdentity, body string) (int, string, error) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+identity.Token)
	request.Header.Set("X-Daochi-User", identity.UserID)
	response, err := client.Do(request)
	if err != nil {
		return 0, "", err
	}
	defer ignoreCleanupError(response.Body.Close)
	data, err := io.ReadAll(response.Body)
	return response.StatusCode, string(data), err
}

func TestChatSlowAnswerOutlivesServerWriteTimeout(t *testing.T) {
	const delay = time.Second
	// Far shorter than the model's wait, like the node's 15 s in production.
	const writeTimeout = 300 * time.Millisecond
	_, handler, calls := chatAnswerServer(t, delay)
	identity := newTestIdentity(t, handler, 0x7b)
	node := httptest.NewUnstartedServer(handler)
	node.Config.ReadTimeout = writeTimeout
	node.Config.WriteTimeout = writeTimeout
	node.Start()
	defer node.Close()
	for _, route := range chatAnswerRoutes {
		status, body, err := postSlowly(t, node.Client(), node.URL+route.path, identity, route.body)
		if err != nil || status != http.StatusOK || !strings.Contains(body, "lotus") {
			t.Fatalf("%s: slow answer did not arrive: %d %q %v", route.path, status, body, err)
		}
	}
	if calls.Load() != int32(len(chatAnswerRoutes)) {
		t.Fatalf("provider calls: %d", calls.Load())
	}
	// The same timeouts cut off a handler that keeps the server's deadline,
	// so the answers above arrived only because the chat routes moved it.
	control := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		_, _ = w.Write([]byte("late"))
	}))
	control.Config.ReadTimeout = writeTimeout
	control.Config.WriteTimeout = writeTimeout
	control.Start()
	defer control.Close()
	if status, body, err := postSlowly(t, control.Client(), control.URL, identity, "{}"); err == nil {
		t.Fatalf("control answer outlived the write timeout: %d %q", status, body)
	}
}

// Records write deadlines that http.ResponseController reaches through the
// node's middleware.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (writer *deadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	writer.deadlines = append(writer.deadlines, deadline)
	return nil
}

func serveWithDeadlines(handler http.Handler, method, path string, identity testIdentity, body string) *deadlineRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if identity.Token != "" {
		request.Header.Set("Authorization", "Bearer "+identity.Token)
		request.Header.Set("X-Daochi-User", identity.UserID)
	}
	writer := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	handler.ServeHTTP(writer, request)
	return writer
}

func TestChatWriteDeadlineCoversModelWaitOnly(t *testing.T) {
	server, handler, _ := chatAnswerServer(t, 0)
	identity := newTestIdentity(t, handler, 0x7c)
	for _, route := range chatAnswerRoutes {
		before := time.Now()
		writer := serveWithDeadlines(handler, http.MethodPost, route.path, identity, route.body)
		after := time.Now()
		if writer.Code != http.StatusOK || len(writer.deadlines) != 1 {
			t.Fatalf("%s: %d with deadlines %v", route.path, writer.Code, writer.deadlines)
		}
		margin := time.Duration(AnswerMargin)
		if writer.deadlines[0].Before(before.Add(route.wait+margin)) || writer.deadlines[0].After(after.Add(route.wait+margin)) {
			t.Fatalf("%s: deadline %v is not the model wait %v plus %v", route.path, writer.deadlines[0].Sub(before), route.wait, margin)
		}
	}
	// Requests that never wait for the model keep the server's write timeout.
	unauthenticated := serveWithDeadlines(handler, http.MethodPost, chatAnswerRoutes[0].path, testIdentity{}, chatAnswerRoutes[0].body)
	invalid := serveWithDeadlines(handler, http.MethodPost, chatAnswerRoutes[0].path, identity, `{"messages":[]}`)
	health := serveWithDeadlines(handler, http.MethodGet, "/healthz", testIdentity{}, "")
	for name, writer := range map[string]*deadlineRecorder{"unauthenticated": unauthenticated, "invalid": invalid, "health": health} {
		if len(writer.deadlines) != 0 {
			t.Fatalf("%s request moved its write deadline: %d %v", name, writer.Code, writer.deadlines)
		}
	}
	server.Cfg.ChatDailyLimit = 3
	exhausted := serveWithDeadlines(handler, http.MethodPost, chatAnswerRoutes[0].path, identity, chatAnswerRoutes[0].body)
	if exhausted.Code != http.StatusTooManyRequests || len(exhausted.deadlines) != 0 {
		t.Fatalf("exhausted allowance: %d with deadlines %v", exhausted.Code, exhausted.deadlines)
	}
}

func chatToolRequest(count int) string {
	request := ChatRequest{Context: json.RawMessage(`{}`), Messages: []ChatMessage{{Role: "user", Content: "Add tea to my list"}}}
	for index := 0; index < count; index++ {
		request.Tools = append(request.Tools, ChatTool{Type: "function", Function: ChatFunction{
			Name: "app_tool_" + strconv.Itoa(index), Description: "App action", Parameters: json.RawMessage(`{"type":"object"}`),
		}})
	}
	encoded, _ := json.Marshal(request)
	return string(encoded)
}

func TestChatAcceptsSixtyFourTools(t *testing.T) {
	server, _, _ := testServer(t)
	server.Cfg.ChatAPIKey = "private-test-key"
	server.Cfg.ChatDailyLimit = 20
	server.Cfg.ChatGlobalDailyLimit = 100
	var received atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Tools []ChatTool `json:"tools"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		received.Store(int32(len(payload.Tools)))
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"Done"}}]}`))
	}))
	defer upstream.Close()
	original := ChatEndpoint
	ChatEndpoint = upstream.URL
	defer func() { ChatEndpoint = original }()
	handler := server.Routes()
	identity := newTestIdentity(t, handler, 0x7d)
	if ToolCountLimit != 64 {
		t.Fatalf("tool limit: %d", ToolCountLimit)
	}
	if out := chatRequest(handler, identity, "/api/v1/chat/completions", chatToolRequest(64)); out.Code != 200 || received.Load() != 64 {
		t.Fatalf("64 tools: %d %s, provider saw %d", out.Code, out.Body.String(), received.Load())
	}
	received.Store(0)
	if out := chatRequest(handler, identity, "/api/v1/chat/completions", chatToolRequest(65)); out.Code != 400 || received.Load() != 0 {
		t.Fatalf("65 tools: %d %s, provider saw %d", out.Code, out.Body.String(), received.Load())
	}
}
