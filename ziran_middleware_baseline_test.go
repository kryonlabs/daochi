// Original middleware from d28d7db. Names only are changed for an independent
// oracle during the Ziran port; retain its native Go control flow.
package main

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"
)

type middlewareBaseline struct{ metrics *ServerMetrics }

type baselineMetricsWriter struct {
	http.ResponseWriter
	status int
}

func (w *baselineMetricsWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *baselineMetricsWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(data)
}

func (w *baselineMetricsWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("hijack unsupported")
	}
	if w.status == 0 {
		w.status = http.StatusSwitchingProtocols
	}
	return hijacker.Hijack()
}

func (s *middlewareBaseline) withCommonHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		mw := &baselineMetricsWriter{ResponseWriter: w}
		defer func() {
			status := mw.status
			if status == 0 {
				status = http.StatusOK
			}
			Metrics_RecordHTTP(s.metrics, r.Method, r.URL.Path, status, time.Since(start))
		}()
		w = mw
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		if origin := baselineAllowedOrigin(r.Header.Get("Origin")); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Daochi-User, X-Daochi-Signature, X-Daochi-Client, X-Daochi-Since-Version, X-Daochi-Limit, X-Daochi-Admin, X-Ksync-User, X-Ksync-Signature, X-Ksync-Client, X-Ksync-Since-Version, X-Ksync-Limit, X-Ksync-Admin, X-Inbe-User, X-Inbe-Signature")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func baselineAllowedOrigin(origin string) string {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Path != "" ||
		u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return ""
	}
	if origin == "https://daochi.pages.dev" ||
		origin == "https://daochi.kryonlabs.com" ||
		origin == "https://daochi.net" ||
		origin == "https://www.daochi.net" ||
		origin == "https://inbe.waozi.xyz" ||
		origin == "https://uku.waozi.xyz" {
		return origin
	}
	if u.Scheme == "chrome-extension" && baselineValidExtensionID(u.Host) {
		return origin
	}
	if u.Scheme != "http" {
		return ""
	}
	switch u.Hostname() {
	case "localhost", "127.0.0.1", "0.0.0.0", "::1":
		return origin
	default:
		return ""
	}
}

func baselineValidExtensionID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, r := range id {
		if r < 'a' || r > 'p' {
			return false
		}
	}
	return true
}
