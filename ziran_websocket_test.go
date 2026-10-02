package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func websocketErrorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestZiranWebSocketFramesMatchBaseline(t *testing.T) {
	compare := func(data []byte, mask bool) {
		t.Helper()
		opcode, payload, err := baselineReadWebSocketFrameMasked(bufio.NewReader(bytes.NewReader(data)), mask)
		actual := Websocket_ReadMaskedFrame(bufio.NewReader(bytes.NewReader(data)), mask)
		if actual.Opcode != opcode || !reflect.DeepEqual(actual.Payload, payload) || websocketErrorText(actual.Error) != websocketErrorText(err) {
			t.Fatalf("frame %x mask=%v: got (%d,%x,%v), want (%d,%x,%v)", data[:min(len(data), 20)], mask, actual.Opcode, actual.Payload, actual.Error, opcode, payload, err)
		}
		if errors.Is(actual.Error, io.EOF) != errors.Is(err, io.EOF) || errors.Is(actual.Error, io.ErrUnexpectedEOF) != errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("read error identity changed: %v, %v", actual.Error, err)
		}
	}
	for first := 0; first < 256; first++ {
		for second := 0; second < 256; second++ {
			data := []byte{byte(first), byte(second), 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4}
			compare(data, false)
			compare(data, true)
		}
	}
	random := rand.New(rand.NewSource(20260930))
	for index := 0; index < 2000; index++ {
		data := make([]byte, random.Intn(256))
		_, _ = random.Read(data)
		compare(data, index%2 == 0)
	}
	for _, size := range []int{0, 1, 125, 126, 127, 255, 65535, 65536, 1 << 20, (1 << 20) + 1} {
		for _, opcode := range []byte{0, 1, 2, 8, 9, 10} {
			payload := bytes.Repeat([]byte{0xa7}, size)
			for _, masked := range []bool{false, true} {
				data := []byte{0x80 | opcode}
				maskBit := byte(0)
				if masked {
					maskBit = 0x80
				}
				if size < 126 {
					data = append(data, maskBit|byte(size))
				} else if size <= 65535 {
					data = append(data, maskBit|126, byte(size>>8), byte(size))
				} else {
					data = append(data, maskBit|127)
					data = binary.BigEndian.AppendUint64(data, uint64(size))
				}
				if masked {
					mask := [4]byte{0, 0xff, 0x55, 0xaa}
					data = append(data, mask[:]...)
					for index := range payload {
						payload[index] ^= mask[index%4]
					}
				}
				data = append(data, payload...)
				compare(data, masked)
				compare(data[:min(len(data), 17)], masked)
			}
		}
	}
}

type websocketMemoryConnection struct {
	bytes.Buffer
	failAt     int
	err        error
	writes     int
	closed     int
	panicAt    int
	panicValue any
}

func (connection *websocketMemoryConnection) Read(data []byte) (int, error) {
	return 0, io.EOF
}

func (connection *websocketMemoryConnection) Write(data []byte) (int, error) {
	connection.writes++
	if connection.panicAt == connection.writes {
		panic(connection.panicValue)
	}
	if connection.failAt == connection.writes {
		return 0, connection.err
	}
	return connection.Buffer.Write(data)
}

func (connection *websocketMemoryConnection) Close() error {
	connection.closed++
	return nil
}

func (connection *websocketMemoryConnection) LocalAddr() net.Addr {
	return &net.TCPAddr{}
}

func (connection *websocketMemoryConnection) RemoteAddr() net.Addr {
	return &net.TCPAddr{}
}

func (connection *websocketMemoryConnection) SetDeadline(time.Time) error {
	return nil
}

func (connection *websocketMemoryConnection) SetReadDeadline(time.Time) error {
	return nil
}

func (connection *websocketMemoryConnection) SetWriteDeadline(time.Time) error {
	return nil
}

func TestZiranWebSocketWritesMatchBaseline(t *testing.T) {
	failure := errors.New("socket write failed")
	for _, size := range []int{0, 1, 125, 126, 65535, 65536, 1 << 20} {
		for _, opcode := range []byte{0, 1, 2, 8, 9, 10, 255} {
			for _, failAt := range []int{0, 1, 2} {
				baseline := &websocketMemoryConnection{failAt: failAt, err: failure}
				actual := &websocketMemoryConnection{failAt: failAt, err: failure}
				payload := bytes.Repeat([]byte{0xa6}, size)
				err := baselineWriteWebSocketFrame(baseline, opcode, payload)
				got := Websocket_WriteFrame(actual, opcode, payload)
				if got != err || actual.writes != baseline.writes || !bytes.Equal(actual.Bytes(), baseline.Bytes()) {
					t.Fatalf("write size=%d opcode=%d fail=%d changed bytes, calls or error identity", size, opcode, failAt)
				}
			}
		}
	}
	for _, value := range []any{nil, SyncEvent{Type: "sync_changed", UserIDHash: "日本語\n", ServerVersion: -1}, make(chan int)} {
		baseline := &websocketMemoryConnection{}
		actual := &websocketMemoryConnection{}
		err := baselineWriteWebSocketJSON(baseline, value)
		got := Websocket_WriteJSON(actual, value)
		if websocketErrorText(got) != websocketErrorText(err) || !bytes.Equal(actual.Bytes(), baseline.Bytes()) {
			t.Fatalf("JSON write %T changed: %v, %v", value, got, err)
		}
	}
}

type websocketHijackWriter struct {
	*httptest.ResponseRecorder
	connection *websocketMemoryConnection
	err        error
	bufferSize int
}

func (writer *websocketHijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if writer.err != nil {
		return nil, nil, writer.err
	}
	return writer.connection, bufio.NewReadWriter(bufio.NewReader(writer.connection), bufio.NewWriterSize(writer.connection, writer.bufferSize)), nil
}

func websocketHandshakeRequest() *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/api/v1/sync/ws", nil)
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Connection", "keep-alive, UpGrAdE")
	request.Header.Set("Sec-WebSocket-Version", "13")
	request.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	return request
}

func TestZiranWebSocketHandshakeMatchesBaseline(t *testing.T) {
	for _, protocol := range []string{"", "unknown", "daochi-sync-v1", "ksync-sync-v1", "inbe-sync-v1", "bearer.secret, inbe-sync-v1, ksync-sync-v1, daochi-sync-v1"} {
		for _, failure := range []string{"", "upgrade", "key", "version", "unsupported", "hijack", "flush", "write"} {
			request := websocketHandshakeRequest()
			request.Header.Set("Sec-WebSocket-Protocol", protocol)
			if failure == "upgrade" {
				request.Header.Set("Connection", "x-upgrade")
			}
			if failure == "key" {
				request.Header.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString(make([]byte, 15)))
			}
			if failure == "version" {
				request.Header.Set("Sec-WebSocket-Version", " 13")
			}
			baseline := &websocketHijackWriter{ResponseRecorder: httptest.NewRecorder(), connection: &websocketMemoryConnection{}}
			actual := &websocketHijackWriter{ResponseRecorder: httptest.NewRecorder(), connection: &websocketMemoryConnection{}}
			if failure == "hijack" {
				baseline.err = errors.New("hijack failed")
				actual.err = baseline.err
			}
			if failure == "flush" || failure == "write" {
				baseline.connection.failAt = 1
				actual.connection.failAt = 1
				baseline.connection.err = errors.New("flush failed")
				actual.connection.err = baseline.connection.err
				if failure == "write" {
					baseline.bufferSize = 16
					actual.bufferSize = 16
				}
			}
			var oldWriter, newWriter http.ResponseWriter = baseline, actual
			if failure == "unsupported" {
				oldWriter, newWriter = baseline.ResponseRecorder, actual.ResponseRecorder
			}
			connection, _, err := baselineAcceptWebSocket(oldWriter, request)
			got := Websocket_Accept(newWriter, request)
			if websocketErrorText(got.Error) != websocketErrorText(err) || (got.Connection == nil) != (connection == nil) || !reflect.DeepEqual(baseline.Header(), actual.Header()) || baseline.Code != actual.Code || baseline.Body.String() != actual.Body.String() || !bytes.Equal(baseline.connection.Bytes(), actual.connection.Bytes()) || baseline.connection.closed != actual.connection.closed {
				t.Fatalf("handshake %q/%s changed: %v, %v", protocol, failure, got.Error, err)
			}
		}
	}
}

func TestZiranWebSocketHeaderHelpersMatchBaseline(t *testing.T) {
	random := rand.New(rand.NewSource(417))
	values := []string{"", "bearer.", " bearer.secret ", "bearer.first,bearer.second", "Bearer.secret", "\u2003bearer.日本語\u2003, daochi-sync-v1", "keep-alive, UpGrAdE", "dGhlIHNhbXBsZSBub25jZQ=="}
	for index := 0; index < 1000; index++ {
		data := make([]byte, random.Intn(90))
		_, _ = random.Read(data)
		values = append(values, string(data))
	}
	for _, value := range values {
		if Websocket_BearerToken(value) != baselineBearerTokenFromWebSocketProtocol(value) || Websocket_ValidKey(value) != baselineValidWebSocketKey(value) || Websocket_AcceptKey(value) != baselineWebsocketAccept(value) {
			t.Fatalf("header helper changed for %q", value)
		}
		for _, token := range []string{"", "upgrade", "daochi-sync-v1", "inbe-sync-v1", value} {
			if Websocket_ProtocolRequested(value, token) != baselineWebsocketProtocolRequested(value, token) || Websocket_HeaderContainsToken(value, token) != baselineHeaderContainsToken(value, token) {
				t.Fatalf("header token helper changed for %q/%q", value, token)
			}
		}
	}
}

func TestZiranSyncHubPreservesDeliveryAndCleanup(t *testing.T) {
	actual := SyncHub_New()
	baseline := baselineNewSyncHub()
	var subscriptions []*Subscription
	var oldSubscriptions []chan baselineSyncEvent
	for index := 0; index < 12; index++ {
		user := fmt.Sprintf("user-%d", index%3)
		subscriptions = append(subscriptions, SyncHub_Subscribe(actual, user))
		oldSubscriptions = append(oldSubscriptions, baseline.subscribe(user))
	}
	if got, want := SyncHub_Stats(actual), baseline.stats(); got.Connections != want.Connections || got.Users != want.Users || SyncHub_Total(actual) != baseline.total() {
		t.Fatalf("hub statistics changed: %v, %v", got, want)
	}
	for version := int64(0); version < 16; version++ {
		for index := 0; index < 3; index++ {
			user := fmt.Sprintf("user-%d", index)
			SyncHub_Publish(actual, user, version)
			baseline.publish(user, version)
		}
	}
	for index, subscription := range subscriptions {
		channel := subscription.Channel.Interface().(chan SyncEvent)
		if len(channel) != 8 {
			t.Fatalf("slow subscriber queue length=%d", len(channel))
		}
		for count := 0; count < 8; count++ {
			got, want := <-channel, <-oldSubscriptions[index]
			if got.Type != want.Type || got.UserIDHash != want.UserIDHash || got.ServerVersion != want.ServerVersion {
				t.Fatalf("event changed: %v, %v", got, want)
			}
		}
		user := fmt.Sprintf("user-%d", index%3)
		SyncHub_Unsubscribe(actual, user, subscription)
		baseline.unsubscribe(user, oldSubscriptions[index])
		if _, open := <-channel; open {
			t.Fatal("unsubscribed channel remained open")
		}
		if SyncHub_Count(actual, user) != baseline.count(user) {
			t.Fatal("subscription count changed")
		}
	}
	if SyncHub_Total(actual) != 0 || SyncHub_Stats(actual).Users != 0 {
		t.Fatal("unsubscribed hub retained accounts")
	}
	// Publishing, subscribing and removal share one lock; a removed channel
	// must never be sent to, even with concurrent publishers.
	var workers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := 0; index < 100; index++ {
				subscription := SyncHub_Subscribe(actual, "concurrent")
				SyncHub_Publish(actual, "concurrent", int64(index))
				SyncHub_Unsubscribe(actual, "concurrent", subscription)
			}
		}()
	}
	workers.Wait()
	if SyncHub_Total(actual) != 0 {
		t.Fatal("concurrent removal leaked subscriptions")
	}
}

func TestZiranWebSocketAuthenticationMatchesBaseline(t *testing.T) {
	server, store, _ := testServer(t)
	user := strings.Repeat("b", 64)
	issued := Token_IssueAuthToken(server.cfg.TokenSecret, user, time.Now().Add(time.Hour).Unix())
	if issued.Error != "" {
		t.Fatal(issued.Error)
	}
	for _, cancelled := range []bool{false, true} {
		if cancelled {
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
		}
		for _, query := range []string{"", "?token=secret", "?token=", "?token=&token=secret"} {
			for _, protocol := range []string{"", "bearer.", "bearer.bad", "bearer." + issued.Value, "daochi-sync-v1, bearer." + issued.Value} {
				for _, authorization := range []string{"", "Bearer bad", "Bearer " + issued.Value} {
					request := httptest.NewRequest(http.MethodGet, "/api/v1/sync/ws"+query, nil)
					request.Header.Set("Sec-WebSocket-Protocol", protocol)
					request.Header.Set("Authorization", authorization)
					want, err := server.baselineAuthenticateWebSocket(request)
					got := SyncWs_Authenticate(server.syncSocket(), request)
					if got.Value != want || websocketErrorText(AuthenticationError_Convert(got.Authentication)) != websocketErrorText(err) {
						t.Fatalf("auth closed=%v query=%q protocol=%q header=%q changed", cancelled, query, protocol, authorization)
					}
				}
			}
		}
	}
}

func TestZiranWebSocketHandlerMatchesBaseline(t *testing.T) {
	for _, scenario := range []string{"closed", "write error", "write panic", "method", "auth", "query token", "handshake", "connection limit", "ip rate limit", "user rate limit"} {
		t.Run(scenario, func(t *testing.T) {
			actual, _, _ := testServer(t)
			baseline, _, _ := testServer(t)
			oldHub := baselineNewSyncHub()
			user := strings.Repeat("c", 64)
			issued := Token_IssueAuthToken(actual.cfg.TokenSecret, user, time.Now().Add(time.Hour).Unix())
			request := websocketHandshakeRequest()
			request.Header.Set("Sec-WebSocket-Protocol", "daochi-sync-v1, bearer."+issued.Value)
			if scenario == "method" {
				request.Method = http.MethodPost
			}
			if scenario == "auth" {
				request.Header.Set("Sec-WebSocket-Protocol", "bearer.bad")
			}
			if scenario == "query token" {
				request.URL.RawQuery = "token=secret"
			}
			if scenario == "handshake" {
				request.Header.Del("Upgrade")
			}
			var subscriptions []*Subscription
			var oldSubscriptions []chan baselineSyncEvent
			if scenario == "connection limit" {
				for index := 0; index < 8; index++ {
					subscriptions = append(subscriptions, SyncHub_Subscribe(actual.syncHub, user))
					oldSubscriptions = append(oldSubscriptions, oldHub.subscribe(user))
				}
			}
			if scenario == "ip rate limit" || scenario == "user rate limit" {
				key, limit := "ws:ip:"+ClientAddress_FromRequest(request), 120
				if scenario == "user rate limit" {
					key, limit = "ws:user:"+user, 40
				}
				for index := 0; index < limit; index++ {
					RateLimit_Allow(actual.limiter, key, limit, time.Minute)
					RateLimit_Allow(baseline.limiter, key, limit, time.Minute)
				}
			}
			newWriter := &websocketHijackWriter{ResponseRecorder: httptest.NewRecorder(), connection: &websocketMemoryConnection{}}
			oldWriter := &websocketHijackWriter{ResponseRecorder: httptest.NewRecorder(), connection: &websocketMemoryConnection{}}
			if scenario == "write error" {
				failure := errors.New("ready write failed")
				newWriter.connection.failAt, oldWriter.connection.failAt = 2, 2
				newWriter.connection.err, oldWriter.connection.err = failure, failure
			}
			if scenario == "write panic" {
				marker := &struct{ name string }{"ready write panic"}
				newWriter.connection.panicAt, oldWriter.connection.panicAt = 2, 2
				newWriter.connection.panicValue, oldWriter.connection.panicValue = marker, marker
			}
			invoke := func(run func()) (caught any) {
				defer func() { caught = recover() }()
				run()
				return nil
			}
			want := invoke(func() { baseline.baselineHandleSyncWebSocket(oldWriter, request, oldHub) })
			got := invoke(func() { SyncWs_Handle(actual.syncSocket(), newWriter, request) })
			if got != want || newWriter.Code != oldWriter.Code || !reflect.DeepEqual(newWriter.Header(), oldWriter.Header()) || newWriter.Body.String() != oldWriter.Body.String() || !bytes.Equal(newWriter.connection.Bytes(), oldWriter.connection.Bytes()) || newWriter.connection.closed != oldWriter.connection.closed {
				t.Fatalf("handler output, error or cleanup changed: panic %v/%v, closes %d/%d", got, want, newWriter.connection.closed, oldWriter.connection.closed)
			}
			if SyncHub_Count(actual.syncHub, user) != oldHub.count(user) || !reflect.DeepEqual(actual.metrics.WebSocketRejects, baseline.metrics.WebSocketRejects) || actual.metrics.WebSocketAccepted.Load() != baseline.metrics.WebSocketAccepted.Load() || actual.metrics.WebSocketRejected.Load() != baseline.metrics.WebSocketRejected.Load() || actual.metrics.RateLimitedRequests.Load() != baseline.metrics.RateLimitedRequests.Load() {
				t.Fatal("handler subscription or metrics changed")
			}
			for index, subscription := range subscriptions {
				SyncHub_Unsubscribe(actual.syncHub, user, subscription)
				oldHub.unsubscribe(user, oldSubscriptions[index])
			}
		})
	}
}
