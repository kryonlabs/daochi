package main

import (
	"bufio"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

var _ http.ResponseWriter = (*CapturedWriter)(nil)
var _ http.Hijacker = (*CapturedWriter)(nil)
var _ http.Handler = (*Middleware)(nil)

type middlewareWriter struct {
	recorder *httptest.ResponseRecorder
	events   []string
	fail     string
	panic    any
	error    error
}

func (writer *middlewareWriter) Header() http.Header {
	writer.events = append(writer.events, "header")
	if writer.fail == "header" {
		panic(writer.panic)
	}
	return writer.recorder.Header()
}

func (writer *middlewareWriter) WriteHeader(status int) {
	writer.events = append(writer.events, fmt.Sprintf("status:%d", status))
	if writer.fail == "status" {
		panic(writer.panic)
	}
	writer.recorder.WriteHeader(status)
}

func (writer *middlewareWriter) Write(data []byte) (int, error) {
	writer.events = append(writer.events, fmt.Sprintf("write:%x", data))
	if writer.fail == "write" {
		panic(writer.panic)
	}
	if writer.error != nil {
		return 7, writer.error
	}
	return writer.recorder.Write(data)
}

type middlewareHijacker struct {
	*middlewareWriter
	connection net.Conn
	buffer     *bufio.ReadWriter
}

func (writer *middlewareHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	writer.events = append(writer.events, "hijack")
	if writer.fail == "hijack" {
		panic(writer.panic)
	}
	return writer.connection, writer.buffer, writer.error
}

func TestZiranMiddlewareBaseline(t *testing.T) {
	for _, mode := range []string{
		"empty", "body", "empty body", "status", "repeated status", "write error",
		"panic", "header panic", "status panic", "write panic", "options",
		"unsupported hijack", "hijack", "hijack error", "hijack panic",
		"hijack after status", "request mutation", "metrics replacement",
	} {
		t.Run(mode, func(t *testing.T) {
			marker := &struct{ mode string }{mode}
			sentinel := errors.New("middleware native error")
			connection, peer := net.Pipe()
			defer connection.Close()
			defer peer.Close()
			buffer := bufio.NewReadWriter(bufio.NewReader(strings.NewReader("")), bufio.NewWriter(peer))
			type observation struct {
				status   int
				headers  http.Header
				body     string
				events   []string
				panic    any
				requests map[string]uint64
			}
			var observations [2]observation
			for index := range observations {
				counters := &ServerMetrics{}
				baseline := &middlewareBaseline{metrics: counters}
				recorder := httptest.NewRecorder()
				writer := &middlewareWriter{recorder: recorder, panic: marker}
				var output http.ResponseWriter = writer
				if strings.HasPrefix(mode, "hijack") {
					output = &middlewareHijacker{middlewareWriter: writer, connection: connection, buffer: buffer}
				}
				switch mode {
				case "header panic":
					writer.fail = "header"
				case "status panic":
					writer.fail = "status"
				case "write panic":
					writer.fail = "write"
				case "hijack panic":
					writer.fail = "hijack"
				case "write error", "hijack error":
					writer.error = sentinel
				}
				called := false
				next := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
					called = true
					if w.Header() != nil {
						w.Header().Set("Handler", "reached")
					}
					switch mode {
					case "body", "write error", "write panic":
						count, err := w.Write([]byte{0, 255, 42})
						if mode == "write error" && (count != 7 || err != sentinel) {
							t.Fatalf("native Write result: %d %v", count, err)
						}
					case "empty body":
						_, _ = w.Write(nil)
					case "status", "status panic":
						w.WriteHeader(http.StatusAccepted)
					case "repeated status":
						w.WriteHeader(http.StatusCreated)
						w.WriteHeader(http.StatusTeapot)
						_, _ = w.Write([]byte("repeat"))
					case "panic":
						panic(marker)
					case "unsupported hijack", "hijack", "hijack error", "hijack panic", "hijack after status":
						if mode == "hijack after status" {
							w.WriteHeader(http.StatusAccepted)
						}
						conn, reader, err := w.(http.Hijacker).Hijack()
						if mode == "unsupported hijack" {
							if conn != nil || reader != nil || err == nil || err.Error() != "hijack unsupported" {
								t.Fatalf("unsupported hijack: %v %v %v", conn, reader, err)
							}
						} else if conn != connection || reader != buffer || err != writer.error {
							t.Fatalf("native Hijack identity: %v %v %v", conn, reader, err)
						}
					case "request mutation":
						request.Method = "PATCH"
						request.URL.Path = "/api/v1/friends/target"
						w.WriteHeader(http.StatusNoContent)
					case "metrics replacement":
						counters = &ServerMetrics{}
						baseline.metrics = counters
					}
				})
				var handler http.Handler
				if index == 0 {
					handler = baseline.withCommonHeaders(next)
				} else {
					handler = Middleware_New(&counters, next)
				}
				method := http.MethodGet
				if mode == "options" {
					method = http.MethodOptions
				}
				request := httptest.NewRequest(method, "/api/v1/friends", nil)
				request.Header.Set("Origin", "https://daochi.net")
				func() {
					defer func() { observations[index].panic = recover() }()
					handler.ServeHTTP(output, request)
				}()
				if mode == "options" && called {
					t.Fatal("preflight reached downstream handler")
				}
				observations[index].status = recorder.Code
				observations[index].headers = recorder.Header().Clone()
				observations[index].body = recorder.Body.String()
				observations[index].events = writer.events
				observations[index].requests = counters.HttpRequests
				if len(counters.HttpRequests) != 1 || len(counters.HttpLatencyMS) != 1 {
					t.Fatalf("completion counters: %#v %#v", counters.HttpRequests, counters.HttpLatencyMS)
				}
				for key, elapsed := range counters.HttpLatencyMS {
					if counters.HttpRequests[key] != 1 || elapsed > 60000 {
						t.Fatalf("invalid completion timing/count: %q %d", key, elapsed)
					}
				}
			}
			if !reflect.DeepEqual(observations[0], observations[1]) {
				t.Fatalf("baseline: %#v\nZiran: %#v", observations[0], observations[1])
			}
		})
	}
}

func TestZiranMiddlewareOriginBaseline(t *testing.T) {
	origins := []string{
		"", "https://daochi.net", "https://www.daochi.net", "https://daochi.pages.dev",
		"https://daochi.kryonlabs.com", "https://inbe.waozi.xyz", "https://uku.waozi.xyz",
	}
	for _, scheme := range []string{"http", "https", "HTTP", "chrome-extension", "ftp", ""} {
		for _, host := range []string{
			"localhost", "LOCALHOST", "127.0.0.1", "0.0.0.0", "[::1]", "[::ffff:127.0.0.1]",
			"daochi.net", "daochi.net.evil", strings.Repeat("a", 32), strings.Repeat("p", 32),
			strings.Repeat("q", 32), strings.Repeat("é", 16), "evil", "",
		} {
			for _, suffix := range []string{"", ":8080", ":bad", "/", "/path", "?", "?x=1", "#", "#x", "\n", "\x00", "%ff"} {
				origins = append(origins, scheme+"://"+host+suffix)
				origins = append(origins, scheme+"://user@"+host+suffix)
			}
		}
	}
	random := rand.New(rand.NewSource(83124))
	for index := 0; index < 2048; index++ {
		value := make([]byte, random.Intn(100))
		_, _ = random.Read(value)
		origins = append(origins, string(value))
	}
	for _, origin := range origins {
		if got, expected := Middleware_AllowedOrigin(origin), baselineAllowedOrigin(origin); got != expected {
			t.Fatalf("origin %q: got %q, expected %q", origin, got, expected)
		}
		if got, expected := Middleware_ValidExtensionID(origin), baselineValidExtensionID(origin); got != expected {
			t.Fatalf("extension %q: got %v, expected %v", origin, got, expected)
		}
	}
}

func TestZiranMiddlewareConcurrentRequests(t *testing.T) {
	counters := &ServerMetrics{}
	handler := Middleware_New(&counters, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	var workers sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for request := 0; request < 100; request++ {
				handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/v1/sync", nil))
			}
		}()
	}
	workers.Wait()
	if len(counters.HttpRequests) != 1 || counters.HttpRequests["GET|/api/v1/sync|204"] != 1600 {
		t.Fatalf("concurrent completion counts: %#v", counters.HttpRequests)
	}
}
