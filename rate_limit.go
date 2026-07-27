package main

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type rateWindow struct {
	ResetAt time.Time
	Count   int
}

type RateLimiter struct {
	mu      sync.Mutex
	windows map[string]rateWindow
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{windows: make(map[string]rateWindow)}
}

func (l *RateLimiter) Allow(key string, limit int, window time.Duration) bool {
	if key == "" || limit <= 0 || window <= 0 {
		return true
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	item := l.windows[key]
	if now.After(item.ResetAt) {
		item = rateWindow{ResetAt: now.Add(window)}
	}
	item.Count++
	l.windows[key] = item
	if len(l.windows) > 8192 {
		l.pruneLocked(now)
	}
	return item.Count <= limit
}

func (l *RateLimiter) pruneLocked(now time.Time) {
	for key, item := range l.windows {
		if now.After(item.ResetAt) {
			delete(l.windows, key)
		}
	}
}

func clientAddress(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	host = strings.TrimSpace(host)
	if isLoopbackHost(host) {
		if forwarded := firstForwardedFor(r.Header.Get("X-Forwarded-For")); forwarded != "" {
			return forwarded
		}
	}
	if host == "" {
		return "unknown"
	}
	return host
}

func firstForwardedFor(header string) string {
	if header == "" {
		return ""
	}
	first := strings.TrimSpace(strings.Split(header, ",")[0])
	if ip := net.ParseIP(first); ip != nil {
		return ip.String()
	}
	return ""
}

func isLoopbackHost(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
