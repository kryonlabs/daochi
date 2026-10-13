package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestZiranAdminAuthenticationAgainstBaseline(t *testing.T) {
	tests := []struct {
		name       string
		expected   string
		current    string
		legacy     string
		allowed    bool
		statusCode int
	}{
		{"disabled", "", "", "", false, http.StatusForbidden},
		{"disabled with header", "", "secret", "", false, http.StatusForbidden},
		{"current", "secret", "secret", "", true, http.StatusOK},
		{"legacy", "secret", "", "secret", true, http.StatusOK},
		{"header whitespace", "secret", "\u2003secret\t", "", true, http.StatusOK},
		{"blank current", "secret", "\u2003\t", "secret", true, http.StatusOK},
		{"current precedence", "secret", "wrong", "secret", false, http.StatusUnauthorized},
		{"current wins", "secret", "secret", "wrong", true, http.StatusOK},
		{"missing", "secret", "", "", false, http.StatusUnauthorized},
		{"short", "secret", "secre", "", false, http.StatusUnauthorized},
		{"long", "secret", "secretX", "", false, http.StatusUnauthorized},
		{"case", "secret", "SECRET", "", false, http.StatusUnauthorized},
		{"configured whitespace", " secret ", " secret ", "", false, http.StatusUnauthorized},
		{"Unicode bytes", "秘密", "秘密", "", true, http.StatusOK},
		{"arbitrary bytes", "\x00\xff", "\x00\xff", "", true, http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := &Server{Cfg: Config{AdminToken: test.expected}, Signer: signAccountProof}
			request := httptest.NewRequest(http.MethodPost, "/api/v1/admin/tokens/manual-credit", nil)
			request.Header.Set("X-Daochi-Admin", test.current)
			request.Header.Set("X-Ksync-Admin", test.legacy)
			actual, expected := httptest.NewRecorder(), httptest.NewRecorder()
			got := HttpAuth_RequireAdmin(actual, request, test.expected)
			want := server.baselineRequireAdmin(expected, request)
			if got != want || got != test.allowed || actual.Code != test.statusCode {
				t.Fatalf("admin guard = %v/%d, baseline = %v; expected %v/%d", got, actual.Code, want, test.allowed, test.statusCode)
			}
			compareHTTPResponse(t, actual, expected)
		})
	}
}

func TestZiranLocalOperatorAuthenticationAgainstBaseline(t *testing.T) {
	addresses := []struct {
		value    string
		loopback bool
	}{
		{"127.0.0.1:9000", true},
		{"127.9.8.7:0", true},
		{"127.0.0.1", true},
		{"127.0.0.1:bad", true},
		{"[::1]:9000", true},
		{"::1", true},
		{"[::ffff:127.0.0.1]:9000", true},
		{"[::1]", false},
		{"[::1%lo]:9000", false},
		{"localhost:9000", false},
		{"0.0.0.0:9000", false},
		{"192.0.2.1:9000", false},
		{"[2001:db8::1]:9000", false},
		{"::", false},
		{" 127.0.0.1:9000", false},
		{"", false},
		{"broken:address:port", false},
	}
	for _, address := range addresses {
		for _, mode := range []string{"no token", "correct token", "wrong token", "missing token"} {
			t.Run(address.value+"/"+mode, func(t *testing.T) {
				server := &Server{Signer: signAccountProof}
				request := httptest.NewRequest(http.MethodPost, "/api/v1/node/pairing/invite", nil)
				request.RemoteAddr = address.value
				request.Host = "127.0.0.1:8080"
				allowed := address.loopback
				status := http.StatusOK
				if mode != "no token" {
					server.Cfg.AdminToken = "operator-secret"
					allowed = mode == "correct token"
					if mode == "correct token" {
						request.Header.Set("X-Daochi-Admin", "operator-secret")
					} else if mode == "wrong token" {
						request.Header.Set("X-Daochi-Admin", "wrong-secret")
					}
					if !allowed {
						status = http.StatusUnauthorized
					}
				} else if !allowed {
					status = http.StatusForbidden
				}
				actual, expected := httptest.NewRecorder(), httptest.NewRecorder()
				got := HttpAuth_RequireLocalOperator(actual, request, server.Cfg.AdminToken)
				want := server.baselineRequireLocalOperator(expected, request)
				if got != want || got != allowed || actual.Code != status {
					t.Fatalf("operator guard = %v/%d, baseline = %v; expected %v/%d", got, actual.Code, want, allowed, status)
				}
				compareHTTPResponse(t, actual, expected)
			})
		}
	}
}

// Behind a reverse proxy on the same host every internet request arrives from
// loopback, so without an admin token only a direct local request is the
// operator: no forwarding header, a local Host, and no cross-site Origin.
func TestLocalOperatorRejectsProxiedAndCrossSiteRequests(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		header  string
		value   string
		allowed bool
	}{
		{"direct IPv4", "127.0.0.1:8080", "", "", true},
		{"direct localhost", "localhost:8080", "", "", true},
		{"direct IPv6", "[::1]:8080", "", "", true},
		{"direct without port", "localhost", "", "", true},
		{"local origin", "127.0.0.1:8080", "Origin", "http://localhost:3000", true},
		{"forwarded for", "127.0.0.1:8080", "X-Forwarded-For", "203.0.113.9", false},
		{"forwarded loopback", "127.0.0.1:8080", "X-Forwarded-For", "127.0.0.1", false},
		{"forwarded host", "127.0.0.1:8080", "X-Forwarded-Host", "api.example", false},
		{"forwarded proto", "127.0.0.1:8080", "X-Forwarded-Proto", "https", false},
		{"real IP", "127.0.0.1:8080", "X-Real-IP", "203.0.113.9", false},
		{"standard forwarded", "127.0.0.1:8080", "Forwarded", "for=203.0.113.9", false},
		{"Cloudflare", "127.0.0.1:8080", "CF-Connecting-IP", "203.0.113.9", false},
		{"true client", "127.0.0.1:8080", "True-Client-IP", "203.0.113.9", false},
		{"via", "127.0.0.1:8080", "Via", "1.1 proxy", false},
		{"public host", "api.example", "", "", false},
		{"rebinding host", "attacker.example:8080", "", "", false},
		{"empty host", "", "", "", false},
		{"cross-site origin", "127.0.0.1:8080", "Origin", "https://attacker.example", false},
		{"opaque origin", "127.0.0.1:8080", "Origin", "null", false},
		{"origin with loopback prefix", "127.0.0.1:8080", "Origin", "http://localhost.attacker.example", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/v1/node/pairing/invites", nil)
			request.RemoteAddr = "127.0.0.1:40000"
			request.Host = test.host
			if test.header != "" {
				request.Header.Set(test.header, test.value)
			}
			recorder := httptest.NewRecorder()
			got := HttpAuth_RequireLocalOperator(recorder, request, "")
			if got != test.allowed {
				t.Fatalf("operator guard = %v/%d; expected %v", got, recorder.Code, test.allowed)
			}
			if !got && recorder.Code != http.StatusForbidden {
				t.Fatalf("rejected status = %d; expected %d", recorder.Code, http.StatusForbidden)
			}
			// With an admin token, the token alone decides, even through a proxy.
			withToken := httptest.NewRecorder()
			request.Header.Set("X-Daochi-Admin", "operator-secret")
			if !HttpAuth_RequireLocalOperator(withToken, request, "operator-secret") {
				t.Fatalf("admin token rejected: %d", withToken.Code)
			}
		})
	}
}
