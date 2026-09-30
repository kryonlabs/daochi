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
			server := &Server{cfg: Config{AdminToken: test.expected}}
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
				server := &Server{}
				request := httptest.NewRequest(http.MethodPost, "/api/v1/node/pairing/invite", nil)
				request.RemoteAddr = address.value
				request.Header.Set("X-Forwarded-For", "127.0.0.1")
				request.Header.Set("X-Real-IP", "::1")
				request.Header.Set("Forwarded", "for=127.0.0.1")
				allowed := address.loopback
				status := http.StatusOK
				if mode != "no token" {
					server.cfg.AdminToken = "operator-secret"
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
				got := HttpAuth_RequireLocalOperator(actual, request, server.cfg.AdminToken)
				want := server.baselineRequireLocalOperator(expected, request)
				if got != want || got != allowed || actual.Code != status {
					t.Fatalf("operator guard = %v/%d, baseline = %v; expected %v/%d", got, actual.Code, want, allowed, status)
				}
				compareHTTPResponse(t, actual, expected)
			})
		}
	}
}
