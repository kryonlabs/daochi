package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// X-Forwarded-For is only trusted when the direct peer is loopback
// (the documented reverse-proxy deployment); a remote peer must never
// let a client choose its own rate-limit bucket.
func TestClientAddressForwardedForTrust(t *testing.T) {
	request := func(remoteAddr, forwarded string) string {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		req.RemoteAddr = remoteAddr
		if forwarded != "" {
			req.Header.Set("X-Forwarded-For", forwarded)
		}
		return clientAddress(req)
	}
	cases := []struct {
		name       string
		remoteAddr string
		forwarded  string
		want       string
	}{
		{"loopback trusts proxy header", "127.0.0.1:8080", "203.0.113.9", "203.0.113.9"},
		{"loopback uses first hop only", "127.0.0.1:8080", "203.0.113.9, 198.51.100.7", "203.0.113.9"},
		{"loopback ignores garbage header", "127.0.0.1:8080", "not-an-ip", "127.0.0.1"},
		{"loopback without header", "[::1]:9000", "", "::1"},
		{"remote peer ignores header", "203.0.113.50:5555", "198.51.100.7", "203.0.113.50"},
		{"no port", "203.0.113.50", "", "203.0.113.50"},
		{"empty address", "", "", "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := request(tc.remoteAddr, tc.forwarded); got != tc.want {
				t.Fatalf("clientAddress(%q, %q) = %q, want %q", tc.remoteAddr, tc.forwarded, got, tc.want)
			}
		})
	}
}

func TestRateLimiterWindow(t *testing.T) {
	limiter := NewRateLimiter()
	for i := 0; i < 3; i++ {
		if !limiter.Allow("bucket", 3, time.Hour) {
			t.Fatalf("request %d denied inside limit", i+1)
		}
	}
	if limiter.Allow("bucket", 3, time.Hour) {
		t.Fatal("4th request allowed past limit")
	}
	if !limiter.Allow("other-bucket", 3, time.Hour) {
		t.Fatal("unrelated bucket denied")
	}
	// Invalid parameters disable limiting rather than block everything.
	if !limiter.Allow("", 3, time.Hour) || !limiter.Allow("bucket", 0, time.Hour) {
		t.Fatal("degenerate parameters should bypass limiting")
	}
}
