package main

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ServerMetrics struct {
	syncRequests          atomic.Uint64
	syncFailures          atomic.Uint64
	syncFullSnapshots     atomic.Uint64
	syncEncryptedRecords  atomic.Uint64
	syncEncryptedPayloads atomic.Uint64
	rateLimitedRequests   atomic.Uint64
	webSocketAccepted     atomic.Uint64
	webSocketRejected     atomic.Uint64
	authFailures          atomic.Uint64
	legacyClientHints     atomic.Uint64

	mu               sync.Mutex
	httpRequests     map[string]uint64
	httpLatencyMS    map[string]uint64
	authFailuresBy   map[string]uint64
	fullSnapshotsBy  map[string]uint64
	webSocketRejects map[string]uint64
}

func (m *ServerMetrics) ensureMaps() {
	if m.httpRequests == nil {
		m.httpRequests = make(map[string]uint64)
		m.httpLatencyMS = make(map[string]uint64)
		m.authFailuresBy = make(map[string]uint64)
		m.fullSnapshotsBy = make(map[string]uint64)
		m.webSocketRejects = make(map[string]uint64)
	}
}

func (m *ServerMetrics) recordHTTP(method, path string, status int, elapsed time.Duration) {
	route := metricRoute(path)
	key := method + "|" + route + "|" + fmt.Sprint(status)
	m.mu.Lock()
	m.ensureMaps()
	m.httpRequests[key]++
	m.httpLatencyMS[key] += uint64(elapsed / time.Millisecond)
	m.mu.Unlock()
}

func (m *ServerMetrics) recordAuthFailure(status int, message string) {
	m.authFailures.Add(1)
	reason := metricReason(message)
	key := fmt.Sprintf("%d|%s", status, reason)
	m.mu.Lock()
	m.ensureMaps()
	m.authFailuresBy[key]++
	m.mu.Unlock()
}

func (m *ServerMetrics) recordFullSnapshot(reason string) {
	m.syncFullSnapshots.Add(1)
	reason = metricReason(reason)
	if reason == "" {
		reason = "unspecified"
	}
	m.mu.Lock()
	m.ensureMaps()
	m.fullSnapshotsBy[reason]++
	m.mu.Unlock()
}

func (m *ServerMetrics) recordWebSocketReject(reason string) {
	m.webSocketRejected.Add(1)
	reason = metricReason(reason)
	if reason == "" {
		reason = "rejected"
	}
	m.mu.Lock()
	m.ensureMaps()
	m.webSocketRejects[reason]++
	m.mu.Unlock()
}

func (m *ServerMetrics) writePrometheus(w http.ResponseWriter, activeWebSockets int) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(w, "# TYPE ksync_sync_requests_total counter\nksync_sync_requests_total %d\n", m.syncRequests.Load())
	fmt.Fprintf(w, "# TYPE ksync_sync_failures_total counter\nksync_sync_failures_total %d\n", m.syncFailures.Load())
	fmt.Fprintf(w, "# TYPE ksync_sync_full_snapshots_total counter\nksync_sync_full_snapshots_total %d\n", m.syncFullSnapshots.Load())
	fmt.Fprintf(w, "# TYPE ksync_sync_encrypted_records_applied_total counter\nksync_sync_encrypted_records_applied_total %d\n", m.syncEncryptedRecords.Load())
	fmt.Fprintf(w, "# TYPE ksync_sync_encrypted_payloads_applied_total counter\nksync_sync_encrypted_payloads_applied_total %d\n", m.syncEncryptedPayloads.Load())
	fmt.Fprintf(w, "# TYPE ksync_rate_limited_requests_total counter\nksync_rate_limited_requests_total %d\n", m.rateLimitedRequests.Load())
	fmt.Fprintf(w, "# TYPE ksync_auth_failures_total counter\nksync_auth_failures_total %d\n", m.authFailures.Load())
	fmt.Fprintf(w, "# TYPE ksync_legacy_client_hints_total counter\nksync_legacy_client_hints_total %d\n", m.legacyClientHints.Load())
	fmt.Fprintf(w, "# TYPE ksync_websocket_accepted_total counter\nksync_websocket_accepted_total %d\n", m.webSocketAccepted.Load())
	fmt.Fprintf(w, "# TYPE ksync_websocket_rejected_total counter\nksync_websocket_rejected_total %d\n", m.webSocketRejected.Load())
	fmt.Fprintf(w, "# TYPE ksync_websocket_active gauge\nksync_websocket_active %d\n", activeWebSockets)
	m.writeMapMetrics(w)
}

func (m *ServerMetrics) writeMapMetrics(w http.ResponseWriter) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureMaps()
	writeLabelMap(w, "ksync_http_requests_total", "counter", "method,route,status", m.httpRequests)
	writeLabelMap(w, "ksync_http_request_duration_milliseconds_total", "counter", "method,route,status", m.httpLatencyMS)
	writeLabelMap(w, "ksync_auth_failures_by_reason_total", "counter", "status,reason", m.authFailuresBy)
	writeSingleLabelMap(w, "ksync_sync_full_snapshots_by_reason_total", "counter", "reason", m.fullSnapshotsBy)
	writeSingleLabelMap(w, "ksync_websocket_rejected_by_reason_total", "counter", "reason", m.webSocketRejects)
}

func writeLabelMap(w http.ResponseWriter, name, typ, labels string, values map[string]uint64) {
	fmt.Fprintf(w, "# TYPE %s %s\n", name, typ)
	keys := sortedMetricKeys(values)
	names := strings.Split(labels, ",")
	for _, key := range keys {
		parts := strings.Split(key, "|")
		fmt.Fprintf(w, "%s{", name)
		for i, label := range names {
			if i > 0 {
				fmt.Fprint(w, ",")
			}
			value := ""
			if i < len(parts) {
				value = parts[i]
			}
			fmt.Fprintf(w, `%s="%s"`, label, escapeMetricLabel(value))
		}
		fmt.Fprintf(w, "} %d\n", values[key])
	}
}

func writeSingleLabelMap(w http.ResponseWriter, name, typ, label string, values map[string]uint64) {
	fmt.Fprintf(w, "# TYPE %s %s\n", name, typ)
	keys := sortedMetricKeys(values)
	for _, key := range keys {
		fmt.Fprintf(w, `%s{%s="%s"} %d`+"\n", name, label, escapeMetricLabel(key), values[key])
	}
}

func sortedMetricKeys(values map[string]uint64) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func metricRoute(path string) string {
	if path == "" {
		return "/"
	}
	if strings.HasPrefix(path, "/api/v1/friends/requests/") {
		return "/api/v1/friends/requests/{id}"
	}
	if strings.HasPrefix(path, "/api/v1/friends/") {
		return "/api/v1/friends/{user_id_hash}"
	}
	if strings.HasPrefix(path, "/api/v1/apps/") {
		if strings.HasSuffix(path, "/collections") {
			return "/api/v1/apps/{app_id}/collections"
		}
		return "/api/v1/apps/{app_id}"
	}
	if strings.HasPrefix(path, "/api/v1/account/app-grants/") {
		return "/api/v1/account/app-grants/{id}"
	}
	if strings.HasPrefix(path, "/api/v1/tokens/purchases/monero/invoices/") {
		return "/api/v1/tokens/purchases/monero/invoices/{id}"
	}
	if strings.HasPrefix(path, "/api/v1/tokens/receipts/") {
		return "/api/v1/tokens/receipts/{receipt_id}"
	}
	if strings.HasPrefix(path, "/api/v1/processes/") {
		rest := strings.TrimPrefix(path, "/api/v1/processes/")
		switch {
		case strings.HasSuffix(rest, "/proposals"):
			return "/api/v1/processes/{id}/proposals"
		case strings.Contains(rest, "/proposals/"):
			return "/api/v1/processes/{id}/proposals/{proposal_id}"
		case strings.HasSuffix(rest, "/votes"):
			return "/api/v1/processes/{id}/votes"
		default:
			return "/api/v1/processes/{id}"
		}
	}
	return path
}

func metricReason(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	var out strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			out.WriteRune(r)
		case r == '_' || r == '-' || r == '.':
			out.WriteRune(r)
		default:
			out.WriteByte('_')
		}
	}
	return strings.Trim(out.String(), "_")
}

func escapeMetricLabel(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	return strings.ReplaceAll(value, `"`, `\"`)
}
