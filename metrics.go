package main

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

type ServerMetrics struct {
	syncRequests         atomic.Uint64
	syncFailures         atomic.Uint64
	syncFullSnapshots    atomic.Uint64
	syncEncryptedRecords atomic.Uint64
	rateLimitedRequests  atomic.Uint64
	webSocketAccepted    atomic.Uint64
	webSocketRejected    atomic.Uint64
}

func (m *ServerMetrics) writePrometheus(w http.ResponseWriter, activeWebSockets int) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(w, "# TYPE ksync_sync_requests_total counter\nksync_sync_requests_total %d\n", m.syncRequests.Load())
	fmt.Fprintf(w, "# TYPE ksync_sync_failures_total counter\nksync_sync_failures_total %d\n", m.syncFailures.Load())
	fmt.Fprintf(w, "# TYPE ksync_sync_full_snapshots_total counter\nksync_sync_full_snapshots_total %d\n", m.syncFullSnapshots.Load())
	fmt.Fprintf(w, "# TYPE ksync_sync_encrypted_records_applied_total counter\nksync_sync_encrypted_records_applied_total %d\n", m.syncEncryptedRecords.Load())
	fmt.Fprintf(w, "# TYPE ksync_rate_limited_requests_total counter\nksync_rate_limited_requests_total %d\n", m.rateLimitedRequests.Load())
	fmt.Fprintf(w, "# TYPE ksync_websocket_accepted_total counter\nksync_websocket_accepted_total %d\n", m.webSocketAccepted.Load())
	fmt.Fprintf(w, "# TYPE ksync_websocket_rejected_total counter\nksync_websocket_rejected_total %d\n", m.webSocketRejected.Load())
	fmt.Fprintf(w, "# TYPE ksync_websocket_active gauge\nksync_websocket_active %d\n", activeWebSockets)
}
