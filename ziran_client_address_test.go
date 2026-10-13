package main

import (
	"math/rand"
	"net"
	"net/http"
	"strings"
	"testing"
)

// Since the 2026-10-13 security fix a loopback peer is a proxy: Cloudflare's
// CF-Connecting-IP wins, then the last X-Forwarded-For entry, which the proxy
// itself appended. The client-chosen first entry never selects the bucket.
func baselineClientAddress(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		host = request.RemoteAddr
	}
	host = strings.TrimSpace(host)
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if cloudflare := net.ParseIP(strings.TrimSpace(request.Header.Get("CF-Connecting-IP"))); cloudflare != nil {
			return cloudflare.String()
		}
		if values := request.Header.Values("X-Forwarded-For"); len(values) > 0 {
			parts := strings.Split(values[len(values)-1], ",")
			last := strings.TrimSpace(parts[len(parts)-1])
			if forwarded := net.ParseIP(last); forwarded != nil {
				return forwarded.String()
			}
		}
	}
	if host == "" {
		return "unknown"
	}
	return host
}

func TestZiranClientAddressBaselinePolicy(t *testing.T) {
	addresses := []string{
		"127.0.0.1:80", "127.99.88.77:80", "127.0.0.1:", "127.0.0.1",
		"[::1]:80", "::1", "[::ffff:127.0.0.1]:80", "[::1%lo]:80",
		"203.0.113.1:80", "[2001:db8::1]:443", "example.com:80",
		"", " \t\r\n", "\u00a0\u2003", "\u00a0127.0.0.1\u00a0",
		"invalid:extra:colons", "[broken", "127.0.0.01:80", "\xff127.0.0.1:80",
	}
	headers := []string{
		"", "203.0.113.9", "203.0.113.9, 198.51.100.7",
		" , 203.0.113.9", "invalid, 203.0.113.9", "2001:DB8:0:0::1",
		"::ffff:203.0.113.9", "\u00a02001:DB8::1\u2003, ignored",
		"127.0.0.01", "203.0.113.9:80", "[2001:db8::1]", "::1%lo", "\xff",
	}
	for _, remote := range addresses {
		for _, forwarded := range headers {
			request := &http.Request{RemoteAddr: remote, Header: make(http.Header)}
			request.Header.Set("X-Forwarded-For", forwarded)
			want := baselineClientAddress(request)
			if got := ClientAddress_FromRequest(request); got != want {
				t.Errorf("address(%q, %q) = %q, want %q", remote, forwarded, got, want)
			}
		}
	}
	request := &http.Request{RemoteAddr: "127.0.0.1:80"}
	if got := ClientAddress_FromRequest(request); got != "127.0.0.1" {
		t.Fatalf("nil headers changed behavior: %q", got)
	}
	request.Header = http.Header{"X-Forwarded-For": {"203.0.113.9", "198.51.100.7"}}
	if got := ClientAddress_FromRequest(request); got != "198.51.100.7" {
		t.Fatalf("multiple header lines did not select the proxy's hop: %q", got)
	}
}

// A client cannot choose its rate-limit bucket by sending its own forwarding
// headers through Cloudflare or a reverse proxy.
func TestClientAddressIgnoresClientChosenForwarding(t *testing.T) {
	tests := []struct {
		name       string
		remote     string
		cloudflare string
		forwarded  string
		want       string
	}{
		{"Cloudflare address wins", "127.0.0.1:8080", "203.0.113.9", "198.51.100.1, 192.0.2.10", "203.0.113.9"},
		{"spoofed first hop ignored", "127.0.0.1:8080", "", "198.51.100.1, 203.0.113.9", "203.0.113.9"},
		{"invalid Cloudflare address", "127.0.0.1:8080", "not-an-ip", "203.0.113.9", "203.0.113.9"},
		{"IPv6 Cloudflare address", "[::1]:8080", "2001:DB8::1", "", "2001:db8::1"},
		{"remote peer ignores both", "203.0.113.50:5555", "198.51.100.1", "198.51.100.2", "203.0.113.50"},
		{"no forwarding", "127.0.0.1:8080", "", "", "127.0.0.1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := &http.Request{RemoteAddr: test.remote, Header: make(http.Header)}
			if test.cloudflare != "" {
				request.Header.Set("CF-Connecting-IP", test.cloudflare)
			}
			if test.forwarded != "" {
				request.Header.Set("X-Forwarded-For", test.forwarded)
			}
			if got := ClientAddress_FromRequest(request); got != test.want {
				t.Fatalf("address = %q, want %q", got, test.want)
			}
		})
	}
}

func TestZiranForwardedAddressArbitraryBytes(t *testing.T) {
	random := rand.New(rand.NewSource(1984))
	for i := 0; i < 1000; i++ {
		data := make([]byte, random.Intn(64))
		if _, err := random.Read(data); err != nil {
			t.Fatal(err)
		}
		header := string(data)
		if i%3 == 0 {
			header = header + ",\u20032001:DB8::1\u00a0"
		}
		parts := strings.Split(header, ",")
		last := strings.TrimSpace(parts[len(parts)-1])
		want := ""
		if parsed := net.ParseIP(last); parsed != nil {
			want = parsed.String()
		}
		if got := ClientAddress_LastForwardedFor([]string{header}); got != want {
			t.Fatalf("forwarded address(%q) = %q, want %q", header, got, want)
		}
	}
}
