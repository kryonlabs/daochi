package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

// This opt-in fixture serves the production API against a disposable database.
// Its control endpoints exist only in a Go test and only on loopback. Browser
// tests proxy the fixed production audience to it; no real Telegram is used.
func TestTelegramBrowserFixture(t *testing.T) {
	reportPath := os.Getenv("DAOCHI_BROWSER_FIXTURE_REPORT")
	if reportPath == "" {
		t.Skip("browser fixture is opt-in")
	}
	if !filepath.IsAbs(reportPath) {
		t.Fatal("browser fixture report must use an absolute private path")
	}
	fixture := entrySetup(t)
	fixture.owner.server.Cfg.BaseURL = "https://api.waozi.xyz"
	fixture.owner.server.Cfg.TelegramAccountsEnabled = true
	fixture.owner.server.Cfg.LumiCanvasURL = "https://inbe.waozi.xyz/build/telegram/index.html"
	fixture.owner.handler = fixture.owner.server.Routes()
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		// Every protocol delivery stays in this process. Unexpected actions fail.
		http.Error(writer, "synthetic delivery unavailable", http.StatusServiceUnavailable)
	}))
	defer upstream.Close()
	previousAPI := TelegramAPIBase
	TelegramAPIBase = upstream.URL
	defer func() { TelegramAPIBase = previousAPI }()
	var controlBytes [32]byte
	if _, err := rand.Read(controlBytes[:]); err != nil {
		t.Fatal("synthetic fixture control key unavailable")
	}
	control := hex.EncodeToString(controlBytes[:])
	var mutex sync.Mutex
	sequence := 0
	stopped := make(chan struct{})
	var stopOnce sync.Once
	mux := http.NewServeMux()
	mux.HandleFunc("/fixture/", func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Fixture-Key") != control {
			http.Error(writer, "fixture control denied", http.StatusUnauthorized)
			return
		}
		mutex.Lock()
		defer mutex.Unlock()
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/fixture/entry":
			var input struct {
				Mode string `json:"mode"`
				User int64  `json:"user"`
			}
			decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, 1024))
			decoder.DisallowUnknownFields()
			if request.Method != "POST" || decoder.Decode(&input) != nil || input.User <= 0 ||
				input.User > 4503599627370495 || (input.Mode != "create" && input.Mode != "restore" && input.Mode != "connect") {
				http.Error(writer, "invalid fixture entry", http.StatusBadRequest)
				return
			}
			issued := TelegramAccountEntry_Issue(fixture.service, request.Context(), input.Mode, input.User)
			if issued.Error != nil {
				http.Error(writer, "fixture entry unavailable", http.StatusServiceUnavailable)
				return
			}
			sequence++
			fields := url.Values{
				"auth_date": {strconv.FormatInt(time.Now().Unix(), 10)},
				"user":      {fmt.Sprintf(`{"id":%d,"first_name":"Synthetic"}`, input.User)},
				"query_id":  {fmt.Sprintf("browser-fixture-%d", sequence)},
			}
			json.NewEncoder(writer).Encode(map[string]any{
				"url":       fixture.owner.server.Cfg.LumiCanvasURL + "?r=" + issued.Info.EntryID,
				"init_data": telegramInitFixture(fixture.owner.server.Cfg.LumiBotToken, fields),
				"entry_id":  issued.Info.EntryID,
				"bot_id":    issued.Info.BotID,
				"node_id":   issued.Info.NodeID,
			})
		case "/fixture/state":
			if request.Method != "GET" {
				http.Error(writer, "invalid fixture method", http.StatusMethodNotAllowed)
				return
			}
			counts := make(map[string]int)
			for _, table := range []string{"server_lumi_telegram", "server_authorization_requests", "server_authorization_grants", "server_authorization_sessions"} {
				var count int
				if err := fixture.owner.store.Database.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
					http.Error(writer, "fixture state unavailable", http.StatusServiceUnavailable)
					return
				}
				counts[table] = count
			}
			json.NewEncoder(writer).Encode(counts)
		case "/fixture/revoke":
			if request.Method != "POST" {
				http.Error(writer, "invalid fixture method", http.StatusMethodNotAllowed)
				return
			}
			if _, err := fixture.owner.store.Database.Exec("UPDATE server_authorization_grants SET revoked_at=? WHERE revoked_at=0", time.Now().Unix()); err != nil {
				http.Error(writer, "fixture revoke unavailable", http.StatusServiceUnavailable)
				return
			}
			json.NewEncoder(writer).Encode(true)
		case "/fixture/stop":
			if request.Method != "POST" {
				http.Error(writer, "invalid fixture method", http.StatusMethodNotAllowed)
				return
			}
			json.NewEncoder(writer).Encode(true)
			stopOnce.Do(func() { close(stopped) })
		default:
			http.NotFound(writer, request)
		}
	})
	mux.Handle("/", fixture.owner.handler)
	server := httptest.NewServer(mux)
	defer server.Close()
	metadata, err := json.Marshal(map[string]any{
		"url": server.URL, "control_key": control, "audience": fixture.owner.server.Cfg.BaseURL,
		"synthetic": true, "bot_id": int64(123456), "node_id": fixture.owner.server.Node.ID,
	})
	if err != nil || os.WriteFile(reportPath, metadata, 0600) != nil {
		t.Fatal("private browser fixture report unavailable")
	}
	t.Log("synthetic browser fixture ready; metadata saved privately")
	select {
	case <-stopped:
	case <-t.Context().Done():
	case <-time.After(20 * time.Minute):
		t.Error("synthetic browser fixture deadline exceeded")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Config.Shutdown(ctx); err != nil {
		t.Error("synthetic browser fixture shutdown failed")
	}
}
