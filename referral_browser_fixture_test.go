package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Opt-in loopback fixture: real ML-DSA auth and production referral routes.
// Synthetic control endpoints exist only in this test, never in the server.
func TestReferralBrowserFixture(t *testing.T) {
	report := os.Getenv("DAOCHI_REFERRAL_FIXTURE_REPORT")
	if report == "" {
		t.Skip("opt-in referral browser fixture")
	}
	if !filepath.IsAbs(report) {
		t.Fatal("fixture report must be private absolute path")
	}
	server, _ := referralFixture(t)
	verifier := MlDsa44_New()
	if verifier.Error != nil {
		t.Fatal(verifier.Error)
	}
	server.Verifier = verifier.Value
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	control := hex.EncodeToString(secret[:])
	stopped := make(chan struct{})
	var once sync.Once
	mux := http.NewServeMux()
	mux.Handle("/", server.Routes())
	mux.HandleFunc("/fixture/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Fixture-Key") != control {
			http.Error(w, "denied", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/fixture/seed":
			var input struct {
				AccountID string `json:"account_id"`
				Count     int    `json:"count"`
			}
			decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
			decoder.DisallowUnknownFields()
			if r.Method != "POST" || decoder.Decode(&input) != nil || !Identity_ValidUserID(input.AccountID) || input.Count < 0 || input.Count > 150 {
				http.Error(w, "invalid seed", 400)
				return
			}
			code := Referral_Code(server.Store.Database, r.Context(), input.AccountID, "")
			if code.Error != nil {
				http.Error(w, "code unavailable", http.StatusServiceUnavailable)
				return
			}
			for index := 0; index < input.Count; index++ {
				user := fmt.Sprintf("%064x", 100000+index)
				if _, err := server.Store.Database.ExecContext(r.Context(), "INSERT OR IGNORE INTO server_users(user_id_hash,public_key,alias) VALUES(?,?,?)", user, []byte{1}, fmt.Sprintf("fixture-referral-%03d", index)); err != nil {
					http.Error(w, err.Error(), 500)
					return
				}
				claimed := Referral_Claim(server.Store.Database, r.Context(), server.Cfg.WaoziIssuerPrivateKey, user, code.Code, fmt.Sprintf("fixture-claim-%03d", index), "")
				if claimed.Error != nil {
					http.Error(w, claimed.Error.Error(), 500)
					return
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"code": code.Code, "count": input.Count})
		case "/fixture/stop":
			if r.Method != "POST" {
				http.Error(w, "method", http.StatusMethodNotAllowed)
				return
			}
			once.Do(func() { close(stopped) })
			_ = json.NewEncoder(w).Encode(true)
		default:
			http.NotFound(w, r)
		}
	})
	wire := httptest.NewServer(mux)
	defer wire.Close()
	bytes, err := json.Marshal(map[string]any{"url": wire.URL, "authority": server.Cfg.BaseURL, "control_key": control, "synthetic": true, "real_mldsa": true})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeTelegramBrowserFixtureReport(report, bytes); err != nil {
		t.Fatal(err)
	}
	t.Log("referral browser fixture ready; metadata saved privately")
	select {
	case <-stopped:
	case <-t.Context().Done():
	case <-time.After(25 * time.Minute):
		t.Error("referral fixture deadline")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := wire.Config.Shutdown(ctx); err != nil {
		t.Error(err)
	}
}
