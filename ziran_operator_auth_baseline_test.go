package main

// Original administrative guards retained as independent migration oracles.
import (
	"crypto/subtle"
	"net"
	"net/http"
)

func (s *Server) baselineRequireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if s.Cfg.AdminToken == "" {
		Response_Error(w, http.StatusForbidden, "admin disabled")
		return false
	}
	provided := HttpAuth_HeaderAlias(r, []string{"X-Daochi-Admin", "X-Ksync-Admin"})
	if subtle.ConstantTimeCompare([]byte(provided), []byte(s.Cfg.AdminToken)) != 1 {
		Response_Error(w, http.StatusUnauthorized, "admin token required")
		return false
	}
	return true
}

func (s *Server) baselineRequireLocalOperator(w http.ResponseWriter, r *http.Request) bool {
	if s.Cfg.AdminToken != "" {
		return s.baselineRequireAdmin(w, r)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		Response_Error(w, http.StatusForbidden,
			"administration requires loopback access or DAOCHI_ADMIN_TOKEN")
		return false
	}
	return true
}
