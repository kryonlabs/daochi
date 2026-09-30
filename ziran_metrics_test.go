package main

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Baseline metrics implementation from 8514299, retained only as a regression oracle.
type BaselineServerMetrics struct {
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
	moneroStuckInvoices   atomic.Uint64

	mu               sync.Mutex
	httpRequests     map[string]uint64
	httpLatencyMS    map[string]uint64
	authFailuresBy   map[string]uint64
	fullSnapshotsBy  map[string]uint64
	webSocketRejects map[string]uint64
}

func (m *BaselineServerMetrics) ensureMaps() {
	if m.httpRequests == nil {
		m.httpRequests = make(map[string]uint64)
		m.httpLatencyMS = make(map[string]uint64)
		m.authFailuresBy = make(map[string]uint64)
		m.fullSnapshotsBy = make(map[string]uint64)
		m.webSocketRejects = make(map[string]uint64)
	}
}

func (m *BaselineServerMetrics) recordHTTP(method, path string, status int, elapsed time.Duration) {
	route := baselineMetricRoute(path)
	key := method + "|" + route + "|" + fmt.Sprint(status)
	m.mu.Lock()
	m.ensureMaps()
	m.httpRequests[key]++
	m.httpLatencyMS[key] += uint64(elapsed / time.Millisecond)
	m.mu.Unlock()
}

func (m *BaselineServerMetrics) recordAuthFailure(status int, message string) {
	m.authFailures.Add(1)
	reason := baselineMetricReason(message)
	key := fmt.Sprintf("%d|%s", status, reason)
	m.mu.Lock()
	m.ensureMaps()
	m.authFailuresBy[key]++
	m.mu.Unlock()
}

func (m *BaselineServerMetrics) recordFullSnapshot(reason string) {
	m.syncFullSnapshots.Add(1)
	reason = baselineMetricReason(reason)
	if reason == "" {
		reason = "unspecified"
	}
	m.mu.Lock()
	m.ensureMaps()
	m.fullSnapshotsBy[reason]++
	m.mu.Unlock()
}

func (m *BaselineServerMetrics) recordWebSocketReject(reason string) {
	m.webSocketRejected.Add(1)
	reason = baselineMetricReason(reason)
	if reason == "" {
		reason = "rejected"
	}
	m.mu.Lock()
	m.ensureMaps()
	m.webSocketRejects[reason]++
	m.mu.Unlock()
}

func (m *BaselineServerMetrics) writePrometheus(w http.ResponseWriter, usage NodeUsage, storage NodeStorageUsage, buildVersion string) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(w, "# TYPE daochi_build_info gauge\ndaochi_build_info{version=%q} 1\n", buildVersion)
	baselineWriteScalarMetric(w, "daochi_sync_requests_total", "counter", m.syncRequests.Load())
	baselineWriteScalarMetric(w, "daochi_sync_failures_total", "counter", m.syncFailures.Load())
	baselineWriteScalarMetric(w, "daochi_sync_full_snapshots_total", "counter", m.syncFullSnapshots.Load())
	baselineWriteScalarMetric(w, "daochi_sync_encrypted_records_applied_total", "counter", m.syncEncryptedRecords.Load())
	baselineWriteScalarMetric(w, "daochi_sync_encrypted_payloads_applied_total", "counter", m.syncEncryptedPayloads.Load())
	baselineWriteScalarMetric(w, "daochi_rate_limited_requests_total", "counter", m.rateLimitedRequests.Load())
	baselineWriteScalarMetric(w, "daochi_auth_failures_total", "counter", m.authFailures.Load())
	baselineWriteScalarMetric(w, "daochi_legacy_client_hints_total", "counter", m.legacyClientHints.Load())
	baselineWriteScalarMetric(w, "daochi_websocket_accepted_total", "counter", m.webSocketAccepted.Load())
	baselineWriteScalarMetric(w, "daochi_websocket_rejected_total", "counter", m.webSocketRejected.Load())
	baselineWriteScalarMetric(w, "daochi_monero_stuck_invoices_total", "counter", m.moneroStuckInvoices.Load())
	baselineWriteScalarMetric(w, "daochi_websocket_active", "gauge", uint64(usage.ConnectedWebSocketClients))
	baselineWriteScalarMetric(w, "daochi_connected_users", "gauge", uint64(usage.ConnectedUsers))
	baselineWriteScalarMetric(w, "daochi_registered_users", "gauge", uint64(usage.RegisteredUsers))
	baselineWriteScalarMetric(w, "daochi_active_users_30d", "gauge", uint64(usage.ActiveUsers30d))
	baselineWriteScalarMetric(w, "daochi_registered_clients", "gauge", uint64(usage.RegisteredClients))
	baselineWriteScalarMetric(w, "daochi_active_clients_30d", "gauge", uint64(usage.ActiveClients30d))
	baselineWriteScalarMetric(w, "daochi_websocket_connection_limit_per_user", "gauge", uint64(usage.WebSocketConnectionLimitPerUser))
	baselineWriteScalarMetric(w, "daochi_storage_database_total_bytes", "gauge", uint64(baselineNonNegativeInt64(storage.DatabaseTotalBytes)))
	baselineWriteScalarMetric(w, "daochi_storage_sqlite_page_bytes", "gauge", uint64(baselineNonNegativeInt64(storage.SQLitePageBytes)))
	baselineWriteScalarMetric(w, "daochi_storage_logical_bytes", "gauge", uint64(baselineNonNegativeInt64(storage.LogicalBytes)))
	baselineWriteScalarMetric(w, "daochi_storage_encrypted_record_bytes", "gauge", uint64(baselineNonNegativeInt64(storage.EncryptedRecordBytes)))
	baselineWriteScalarMetric(w, "daochi_storage_encrypted_payload_bytes", "gauge", uint64(baselineNonNegativeInt64(storage.EncryptedPayloadBytes)))
	baselineWriteAppStorageMetrics(w, "daochi_storage_app_logical_bytes", "gauge", storage.Apps)
	baselineWriteCollectionStorageMetrics(w, "daochi_storage_collection_logical_bytes", "gauge", storage.Apps)
	baselineWriteScalarMetric(w, "ksync_sync_requests_total", "counter", m.syncRequests.Load())
	baselineWriteScalarMetric(w, "ksync_sync_failures_total", "counter", m.syncFailures.Load())
	baselineWriteScalarMetric(w, "ksync_sync_full_snapshots_total", "counter", m.syncFullSnapshots.Load())
	baselineWriteScalarMetric(w, "ksync_sync_encrypted_records_applied_total", "counter", m.syncEncryptedRecords.Load())
	baselineWriteScalarMetric(w, "ksync_sync_encrypted_payloads_applied_total", "counter", m.syncEncryptedPayloads.Load())
	baselineWriteScalarMetric(w, "ksync_rate_limited_requests_total", "counter", m.rateLimitedRequests.Load())
	baselineWriteScalarMetric(w, "ksync_auth_failures_total", "counter", m.authFailures.Load())
	baselineWriteScalarMetric(w, "ksync_legacy_client_hints_total", "counter", m.legacyClientHints.Load())
	baselineWriteScalarMetric(w, "ksync_websocket_accepted_total", "counter", m.webSocketAccepted.Load())
	baselineWriteScalarMetric(w, "ksync_websocket_rejected_total", "counter", m.webSocketRejected.Load())
	baselineWriteScalarMetric(w, "ksync_websocket_active", "gauge", uint64(usage.ConnectedWebSocketClients))
	m.writeMapMetrics(w)
}

func baselineNonNegativeInt64(value int64) int64 {
	if value < 0 {
		return 0
	}
	return value
}

func baselineWriteAppStorageMetrics(w http.ResponseWriter, name, typ string, apps []AppStorageUsage) {
	fmt.Fprintf(w, "# TYPE %s %s\n", name, typ)
	for _, app := range apps {
		fmt.Fprintf(w, `%s{app_id="%s"} %d`+"\n",
			name, baselineEscapeMetricLabel(app.AppID), baselineNonNegativeInt64(app.LogicalBytes))
	}
}

func baselineWriteCollectionStorageMetrics(w http.ResponseWriter, name, typ string, apps []AppStorageUsage) {
	fmt.Fprintf(w, "# TYPE %s %s\n", name, typ)
	for _, app := range apps {
		for _, collection := range app.Collections {
			fmt.Fprintf(w, `%s{app_id="%s",collection="%s"} %d`+"\n",
				name, baselineEscapeMetricLabel(app.AppID), baselineEscapeMetricLabel(collection.Collection),
				baselineNonNegativeInt64(collection.LogicalBytes))
		}
	}
}

func (m *BaselineServerMetrics) writeMapMetrics(w http.ResponseWriter) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureMaps()
	baselineWriteLabelMap(w, "daochi_http_requests_total", "counter", "method,route,status", m.httpRequests)
	baselineWriteLabelMap(w, "daochi_http_request_duration_milliseconds_total", "counter", "method,route,status", m.httpLatencyMS)
	baselineWriteLabelMap(w, "daochi_auth_failures_by_reason_total", "counter", "status,reason", m.authFailuresBy)
	baselineWriteSingleLabelMap(w, "daochi_sync_full_snapshots_by_reason_total", "counter", "reason", m.fullSnapshotsBy)
	baselineWriteSingleLabelMap(w, "daochi_websocket_rejected_by_reason_total", "counter", "reason", m.webSocketRejects)
	baselineWriteLabelMap(w, "ksync_http_requests_total", "counter", "method,route,status", m.httpRequests)
	baselineWriteLabelMap(w, "ksync_http_request_duration_milliseconds_total", "counter", "method,route,status", m.httpLatencyMS)
	baselineWriteLabelMap(w, "ksync_auth_failures_by_reason_total", "counter", "status,reason", m.authFailuresBy)
	baselineWriteSingleLabelMap(w, "ksync_sync_full_snapshots_by_reason_total", "counter", "reason", m.fullSnapshotsBy)
	baselineWriteSingleLabelMap(w, "ksync_websocket_rejected_by_reason_total", "counter", "reason", m.webSocketRejects)
}

func baselineWriteScalarMetric(w http.ResponseWriter, name, typ string, value uint64) {
	fmt.Fprintf(w, "# TYPE %s %s\n%s %d\n", name, typ, name, value)
}

func baselineWriteLabelMap(w http.ResponseWriter, name, typ, labels string, values map[string]uint64) {
	fmt.Fprintf(w, "# TYPE %s %s\n", name, typ)
	keys := baselineSortedMetricKeys(values)
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
			fmt.Fprintf(w, `%s="%s"`, label, baselineEscapeMetricLabel(value))
		}
		fmt.Fprintf(w, "} %d\n", values[key])
	}
}

func baselineWriteSingleLabelMap(w http.ResponseWriter, name, typ, label string, values map[string]uint64) {
	fmt.Fprintf(w, "# TYPE %s %s\n", name, typ)
	keys := baselineSortedMetricKeys(values)
	for _, key := range keys {
		fmt.Fprintf(w, `%s{%s="%s"} %d`+"\n", name, label, baselineEscapeMetricLabel(key), values[key])
	}
}

func baselineSortedMetricKeys(values map[string]uint64) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func baselineMetricRoute(path string) string {
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
	if strings.HasPrefix(path, "/api/v1/tokens/purchases/monero/address/") {
		return "/api/v1/tokens/purchases/monero/address/{recipient}"
	}
	if strings.HasPrefix(path, "/api/v1/tokens/receipts/") {
		return "/api/v1/tokens/receipts/{receipt_id}"
	}
	return path
}

func baselineMetricReason(value string) string {
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

func baselineEscapeMetricLabel(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	return strings.ReplaceAll(value, `"`, `\"`)
}

func TestZiranMetricsTextAgainstBaseline(t *testing.T) {
	paths := []string{
		"", "/", "/metrics", "/api/v1/friends/requests/x",
		"/api/v1/friends/requests/", "/api/v1/friends/x", "/api/v1/apps/x",
		"/api/v1/apps/x/collections", "/api/v1/apps/x/collections/",
		"/api/v1/account/app-grants/x", "/api/v1/tokens/purchases/monero/invoices/x",
		"/api/v1/tokens/purchases/monero/address/x", "/api/v1/tokens/receipts/x",
		"/api/v1/friends", "/api/v1/apps", "/api/v1/appsx/x", "/未知\xff",
	}
	for _, path := range paths {
		if got, want := Metrics_Route(path), baselineMetricRoute(path); got != want {
			t.Fatalf("route %q: got %q, want %q", path, got, want)
		}
	}
	values := []string{
		"", "___", " AUTH Failed! ", "İΣK A", "a😀é中z", "\xff\xfea\xffb",
		" \t\r\nvalue \u2000", "A.Z_0-9", "back\\slash\n\"quote\"\r", "\x00a\x00",
	}
	random := rand.New(rand.NewSource(823))
	for i := 0; i < 1000; i++ {
		data := make([]byte, random.Intn(160))
		if _, err := random.Read(data); err != nil {
			t.Fatal(err)
		}
		values = append(values, string(data))
	}
	for _, value := range values {
		if got, want := Metrics_Reason(value), baselineMetricReason(value); got != want {
			t.Fatalf("reason %q: got %q, want %q", value, got, want)
		}
		if got, want := Metrics_EscapeLabel(value), baselineEscapeMetricLabel(value); got != want {
			t.Fatalf("label %q: got %q, want %q", value, got, want)
		}
	}
	for _, value := range []int64{math.MinInt64, -1, 0, 1, math.MaxInt64} {
		if got, want := Metrics_NonNegative(value), baselineNonNegativeInt64(value); got != want {
			t.Fatalf("nonnegative %d: got %d, want %d", value, got, want)
		}
	}
	for _, values := range []map[string]uint64{nil, {}, {"z": 0, "a": math.MaxUint64, "\xff": 2}} {
		if got, want := Metrics_SortedKeys(values), baselineSortedMetricKeys(values); !reflect.DeepEqual(got, want) {
			t.Fatalf("sorted keys: got %#v, want %#v", got, want)
		}
	}
}

func assertMetricsState(t *testing.T, actual *ServerMetrics, expected *BaselineServerMetrics) {
	t.Helper()
	actualMaps := []map[string]uint64{
		actual.HttpRequests, actual.HttpLatencyMS, actual.AuthFailuresBy,
		actual.FullSnapshotsBy, actual.WebSocketRejects,
	}
	expectedMaps := []map[string]uint64{
		expected.httpRequests, expected.httpLatencyMS, expected.authFailuresBy,
		expected.fullSnapshotsBy, expected.webSocketRejects,
	}
	for i := range actualMaps {
		if !reflect.DeepEqual(actualMaps[i], expectedMaps[i]) {
			t.Fatalf("metric map %d: got %#v, want %#v", i, actualMaps[i], expectedMaps[i])
		}
	}
	actualCounters := []uint64{
		actual.AuthFailures.Load(), actual.SyncFullSnapshots.Load(), actual.WebSocketRejected.Load(),
	}
	expectedCounters := []uint64{
		expected.authFailures.Load(), expected.syncFullSnapshots.Load(), expected.webSocketRejected.Load(),
	}
	if !reflect.DeepEqual(actualCounters, expectedCounters) {
		t.Fatalf("metric counters: got %#v, want %#v", actualCounters, expectedCounters)
	}
}

func TestZiranMetricsRecordingAndPrometheusAgainstBaseline(t *testing.T) {
	actual := &ServerMetrics{}
	expected := &BaselineServerMetrics{}
	durations := []time.Duration{
		math.MinInt64, -time.Millisecond - 1, -time.Millisecond + 1, -1,
		0, time.Millisecond - 1, time.Millisecond, math.MaxInt64,
	}
	for i, elapsed := range durations {
		method := []string{"GET", "POST", "METHOD|split"}[i%3]
		path := []string{"/api/v1/apps/app/collections", "/metrics", "/raw|path\n\"\\"}[i%3]
		status := []int{math.MinInt, -1, 0, 200, math.MaxInt}[i%5]
		Metrics_RecordHTTP(actual, method, path, status, elapsed)
		expected.recordHTTP(method, path, status, elapsed)
	}
	for _, reason := range []string{"", "___", " No TOKEN! ", "Δ İ A", "\xffA\xff"} {
		Metrics_RecordAuthFailure(actual, 401, reason)
		expected.recordAuthFailure(401, reason)
		Metrics_RecordFullSnapshot(actual, reason)
		expected.recordFullSnapshot(reason)
		Metrics_RecordWebSocketReject(actual, reason)
		expected.recordWebSocketReject(reason)
	}
	actual.HttpRequests["missing"] = math.MaxUint64
	expected.httpRequests["missing"] = math.MaxUint64
	actual.HttpRequests["GET|/wrap|200"] = math.MaxUint64
	expected.httpRequests["GET|/wrap|200"] = math.MaxUint64
	Metrics_RecordHTTP(actual, "GET", "/wrap", 200, time.Millisecond)
	expected.recordHTTP("GET", "/wrap", 200, time.Millisecond)
	actualCounters := []*Uint64{
		&actual.SyncRequests, &actual.SyncFailures, &actual.SyncEncryptedRecords,
		&actual.SyncEncryptedPayloads, &actual.RateLimitedRequests,
		&actual.WebSocketAccepted, &actual.LegacyClientHints, &actual.MoneroStuckInvoices,
	}
	expectedCounters := []*atomic.Uint64{
		&expected.syncRequests, &expected.syncFailures, &expected.syncEncryptedRecords,
		&expected.syncEncryptedPayloads, &expected.rateLimitedRequests,
		&expected.webSocketAccepted, &expected.legacyClientHints, &expected.moneroStuckInvoices,
	}
	for i := range actualCounters {
		value := uint64(math.MaxUint64) - uint64(i)
		actualCounters[i].Store(value)
		expectedCounters[i].Store(value)
	}
	assertMetricsState(t, actual, expected)
	usage := NodeUsage{
		RegisteredUsers: -1, ActiveUsers30d: 2, RegisteredClients: 3,
		ActiveClients30d: 4, ConnectedUsers: 5, ConnectedWebSocketClients: 6,
		WebSocketConnectionLimitPerUser: math.MaxInt,
	}
	storage := NodeStorageUsage{
		DatabaseTotalBytes: -1, SQLitePageBytes: math.MaxInt64, LogicalBytes: 9,
		EncryptedRecordBytes: -10, EncryptedPayloadBytes: 11,
		Apps: []AppStorageUsage{
			{AppID: "z\n\"\\\xff", LogicalBytes: -1, Collections: []CollectionStorageUsage{
				{Collection: "private\n\"\\", LogicalBytes: -2},
				{Collection: "public", LogicalBytes: math.MaxInt64},
			}},
			{AppID: "a", LogicalBytes: 7},
			{AppID: "a", LogicalBytes: 8},
		},
	}
	for _, buildVersion := range []string{"", "1.2.3", "v\n\"\\\xff😀"} {
		got := httptest.NewRecorder()
		want := httptest.NewRecorder()
		Metrics_Prometheus(actual, got, usage, storage, buildVersion)
		expected.writePrometheus(want, usage, storage, buildVersion)
		if got.Body.String() != want.Body.String() {
			t.Fatalf("Prometheus output differs\ngot:\n%s\nwant:\n%s", got.Body, want.Body)
		}
		if !reflect.DeepEqual(got.Header(), want.Header()) {
			t.Fatalf("Prometheus headers: got %#v, want %#v", got.Header(), want.Header())
		}
	}
	assertMetricsState(t, actual, expected)
}

type metricsWriter struct {
	header  http.Header
	body    bytes.Buffer
	panicAt string
	err     error
}

func (writer *metricsWriter) Header() http.Header {
	return writer.header
}

func (writer *metricsWriter) WriteHeader(int) {}

func (writer *metricsWriter) Write(data []byte) (int, error) {
	if writer.panicAt != "" && bytes.Contains(data, []byte(writer.panicAt)) {
		panic("metrics writer failure")
	}
	writer.body.Write(data)
	if writer.err != nil {
		return 0, writer.err
	}
	return len(data), nil
}

func TestZiranMetricsWriterFailuresAndMapInitialization(t *testing.T) {
	actual := &ServerMetrics{HttpLatencyMS: map[string]uint64{"old": 3}}
	expected := &BaselineServerMetrics{httpLatencyMS: map[string]uint64{"old": 3}}
	oldMap := actual.HttpLatencyMS
	got := &metricsWriter{header: make(http.Header), err: errors.New("write failed")}
	want := &metricsWriter{header: make(http.Header), err: errors.New("write failed")}
	Metrics_Prometheus(actual, got, NodeUsage{}, NodeStorageUsage{}, "test")
	expected.writePrometheus(want, NodeUsage{}, NodeStorageUsage{}, "test")
	if got.body.String() != want.body.String() || !reflect.DeepEqual(got.header, want.header) {
		t.Fatal("write errors changed scrape attempts")
	}
	assertMetricsState(t, actual, expected)
	if oldMap["old"] != 3 || len(actual.HttpLatencyMS) != 0 {
		t.Fatal("initialization changed old map storage or retained stale entries")
	}
	panics := func(write func()) {
		t.Helper()
		defer func() {
			if value := recover(); value != "metrics writer failure" {
				t.Fatalf("scrape panic: got %#v", value)
			}
		}()
		write()
	}
	panics(func() {
		Metrics_Prometheus(actual, &metricsWriter{header: make(http.Header), panicAt: "daochi_http_requests_total"}, NodeUsage{}, NodeStorageUsage{}, "test")
	})
	if !actual.Mu.TryLock() {
		t.Fatal("metrics mutex remained locked after a writer panic")
	}
	actual.Mu.Unlock()
	panics(func() {
		expected.writePrometheus(&metricsWriter{header: make(http.Header), panicAt: "daochi_http_requests_total"}, NodeUsage{}, NodeStorageUsage{}, "test")
	})
	if !expected.mu.TryLock() {
		t.Fatal("baseline metrics mutex remained locked")
	}
	expected.mu.Unlock()
	Metrics_RecordHTTP(actual, "GET", "/after-panic", 200, time.Millisecond)
	expected.recordHTTP("GET", "/after-panic", 200, time.Millisecond)
	assertMetricsState(t, actual, expected)
}

func TestZiranMetricsConcurrentRecordingAndScraping(t *testing.T) {
	actual := &ServerMetrics{}
	expected := &BaselineServerMetrics{}
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 100; j++ {
				Metrics_RecordHTTP(actual, "GET", "/api/v1/apps/a", 200, time.Millisecond)
				expected.recordHTTP("GET", "/api/v1/apps/a", 200, time.Millisecond)
				Metrics_RecordAuthFailure(actual, 403, "No access!")
				expected.recordAuthFailure(403, "No access!")
				Metrics_RecordFullSnapshot(actual, "Reconnect")
				expected.recordFullSnapshot("Reconnect")
				Metrics_RecordWebSocketReject(actual, "Connection limit")
				expected.recordWebSocketReject("Connection limit")
			}
		}()
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		for i := 0; i < 25; i++ {
			Metrics_Prometheus(actual, httptest.NewRecorder(), NodeUsage{}, NodeStorageUsage{}, "test")
			expected.writePrometheus(httptest.NewRecorder(), NodeUsage{}, NodeStorageUsage{}, "test")
		}
	}()
	workers.Wait()
	assertMetricsState(t, actual, expected)
	if actual.AuthFailures.Load() != 1600 || actual.HttpRequests["GET|/api/v1/apps/{app_id}|200"] != 1600 {
		t.Fatal("concurrent metric updates lost counts")
	}
}
