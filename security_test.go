package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMetricsAdminGate(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()

	server.cfg.AdminToken = "admin-secret"
	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("metrics without admin token: status=%d, want 401", unauthorized.Code)
	}

	wrongToken := httptest.NewRecorder()
	wrongReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	wrongReq.Header.Set("X-Daochi-Admin", "wrong")
	handler.ServeHTTP(wrongToken, wrongReq)
	if wrongToken.Code != http.StatusUnauthorized {
		t.Fatalf("metrics with wrong admin token: status=%d, want 401", wrongToken.Code)
	}

	authorized := httptest.NewRecorder()
	authReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	authReq.Header.Set("X-Daochi-Admin", "admin-secret")
	handler.ServeHTTP(authorized, authReq)
	if authorized.Code != http.StatusOK || authorized.Body.Len() == 0 {
		t.Fatalf("metrics with admin token: status=%d body=%d bytes, want 200 with payload", authorized.Code, authorized.Body.Len())
	}

	// Without a configured admin token the endpoint stays public, matching
	// the historical behavior for tokenless self-hosted deployments.
	server.cfg.AdminToken = ""
	public := httptest.NewRecorder()
	handler.ServeHTTP(public, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if public.Code != http.StatusOK {
		t.Fatalf("public metrics without configured token: status=%d, want 200", public.Code)
	}
}

func TestTokenReceiptRateLimited(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	for i := 0; i < 60; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/tokens/receipts/receipt-probe-0001", nil))
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("rate limit hit early at request %d", i+1)
		}
	}
	limited := httptest.NewRecorder()
	handler.ServeHTTP(limited, httptest.NewRequest(http.MethodGet, "/api/v1/tokens/receipts/receipt-probe-0001", nil))
	if limited.Code != http.StatusTooManyRequests {
		t.Fatalf("61st receipt request: status=%d, want 429", limited.Code)
	}
}
