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

func (m *ServerMetrics) writePrometheus(w http.ResponseWriter, usage NodeUsage) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	writeScalarMetric(w, "daochi_sync_requests_total", "counter", m.syncRequests.Load())
	writeScalarMetric(w, "daochi_sync_failures_total", "counter", m.syncFailures.Load())
	writeScalarMetric(w, "daochi_sync_full_snapshots_total", "counter", m.syncFullSnapshots.Load())
	writeScalarMetric(w, "daochi_sync_encrypted_records_applied_total", "counter", m.syncEncryptedRecords.Load())
	writeScalarMetric(w, "daochi_sync_encrypted_payloads_applied_total", "counter", m.syncEncryptedPayloads.Load())
	writeScalarMetric(w, "daochi_rate_limited_requests_total", "counter", m.rateLimitedRequests.Load())
	writeScalarMetric(w, "daochi_auth_failures_total", "counter", m.authFailures.Load())
	writeScalarMetric(w, "daochi_legacy_client_hints_total", "counter", m.legacyClientHints.Load())
	writeScalarMetric(w, "daochi_websocket_accepted_total", "counter", m.webSocketAccepted.Load())
	writeScalarMetric(w, "daochi_websocket_rejected_total", "counter", m.webSocketRejected.Load())
	writeScalarMetric(w, "daochi_websocket_active", "gauge", uint64(usage.ConnectedWebSocketClients))
	writeScalarMetric(w, "daochi_connected_users", "gauge", uint64(usage.ConnectedUsers))
	writeScalarMetric(w, "daochi_registered_users", "gauge", uint64(usage.RegisteredUsers))
	writeScalarMetric(w, "daochi_active_users_30d", "gauge", uint64(usage.ActiveUsers30d))
	writeScalarMetric(w, "daochi_registered_clients", "gauge", uint64(usage.RegisteredClients))
	writeScalarMetric(w, "daochi_active_clients_30d", "gauge", uint64(usage.ActiveClients30d))
	writeScalarMetric(w, "daochi_websocket_connection_limit_per_user", "gauge", uint64(usage.WebSocketConnectionLimitPerUser))
	writeScalarMetric(w, "ksync_sync_requests_total", "counter", m.syncRequests.Load())
	writeScalarMetric(w, "ksync_sync_failures_total", "counter", m.syncFailures.Load())
	writeScalarMetric(w, "ksync_sync_full_snapshots_total", "counter", m.syncFullSnapshots.Load())
	writeScalarMetric(w, "ksync_sync_encrypted_records_applied_total", "counter", m.syncEncryptedRecords.Load())
	writeScalarMetric(w, "ksync_sync_encrypted_payloads_applied_total", "counter", m.syncEncryptedPayloads.Load())
	writeScalarMetric(w, "ksync_rate_limited_requests_total", "counter", m.rateLimitedRequests.Load())
	writeScalarMetric(w, "ksync_auth_failures_total", "counter", m.authFailures.Load())
	writeScalarMetric(w, "ksync_legacy_client_hints_total", "counter", m.legacyClientHints.Load())
	writeScalarMetric(w, "ksync_websocket_accepted_total", "counter", m.webSocketAccepted.Load())
	writeScalarMetric(w, "ksync_websocket_rejected_total", "counter", m.webSocketRejected.Load())
	writeScalarMetric(w, "ksync_websocket_active", "gauge", uint64(usage.ConnectedWebSocketClients))
	m.writeMapMetrics(w)
}

func (m *ServerMetrics) writeMapMetrics(w http.ResponseWriter) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureMaps()
	writeLabelMap(w, "daochi_http_requests_total", "counter", "method,route,status", m.httpRequests)
	writeLabelMap(w, "daochi_http_request_duration_milliseconds_total", "counter", "method,route,status", m.httpLatencyMS)
	writeLabelMap(w, "daochi_auth_failures_by_reason_total", "counter", "status,reason", m.authFailuresBy)
	writeSingleLabelMap(w, "daochi_sync_full_snapshots_by_reason_total", "counter", "reason", m.fullSnapshotsBy)
	writeSingleLabelMap(w, "daochi_websocket_rejected_by_reason_total", "counter", "reason", m.webSocketRejects)
	writeLabelMap(w, "ksync_http_requests_total", "counter", "method,route,status", m.httpRequests)
	writeLabelMap(w, "ksync_http_request_duration_milliseconds_total", "counter", "method,route,status", m.httpLatencyMS)
	writeLabelMap(w, "ksync_auth_failures_by_reason_total", "counter", "status,reason", m.authFailuresBy)
	writeSingleLabelMap(w, "ksync_sync_full_snapshots_by_reason_total", "counter", "reason", m.fullSnapshotsBy)
	writeSingleLabelMap(w, "ksync_websocket_rejected_by_reason_total", "counter", "reason", m.webSocketRejects)
}

func writeScalarMetric(w http.ResponseWriter, name, typ string, value uint64) {
	fmt.Fprintf(w, "# TYPE %s %s\n%s %d\n", name, typ, name, value)
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
