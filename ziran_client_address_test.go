package main

import (
	"math/rand"
	"net"
	"net/http"
	"strings"
	"testing"
)

// This keeps the baseline's Go policy as a regression oracle while production
// address selection runs through the Ziran module and native HTTP/IP bindings.
func baselineClientAddress(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		host = request.RemoteAddr
	}
	host = strings.TrimSpace(host)
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		header := request.Header.Get("X-Forwarded-For")
		first := strings.TrimSpace(strings.Split(header, ",")[0])
		if forwarded := net.ParseIP(first); forwarded != nil {
			return forwarded.String()
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
	if got := ClientAddress_FromRequest(request); got != "203.0.113.9" {
		t.Fatalf("multiple header lines changed first-hop selection: %q", got)
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
			header = "\u20032001:DB8::1\u00a0," + header
		}
		first := strings.TrimSpace(strings.Split(header, ",")[0])
		want := ""
		if parsed := net.ParseIP(first); parsed != nil {
			want = parsed.String()
		}
		if got := ClientAddress_FirstForwardedFor(header); got != want {
			t.Fatalf("forwarded address(%q) = %q, want %q", header, got, want)
		}
	}
}
