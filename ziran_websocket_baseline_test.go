// WebSocket implementation from de2774a, retained as an independent regression oracle.
package main

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const baselineWebsocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

type baselineSyncEvent struct {
	Type          string `json:"type"`
	UserIDHash    string `json:"user_id_hash"`
	ServerVersion int64  `json:"server_version"`
}

type baselineSyncHub struct {
	mu   sync.Mutex
	subs map[string]map[chan baselineSyncEvent]struct{}
}

type baselineSyncHubStats struct {
	Connections int
	Users       int
}

func baselineNewSyncHub() *baselineSyncHub {
	return &baselineSyncHub{subs: make(map[string]map[chan baselineSyncEvent]struct{})}
}

func (h *baselineSyncHub) subscribe(userID string) chan baselineSyncEvent {
	ch := make(chan baselineSyncEvent, 8)
	h.mu.Lock()
	if h.subs[userID] == nil {
		h.subs[userID] = make(map[chan baselineSyncEvent]struct{})
	}
	h.subs[userID][ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *baselineSyncHub) unsubscribe(userID string, ch chan baselineSyncEvent) {
	h.mu.Lock()
	if subs := h.subs[userID]; subs != nil {
		delete(subs, ch)
		if len(subs) == 0 {
			delete(h.subs, userID)
		}
	}
	h.mu.Unlock()
	close(ch)
}

func (h *baselineSyncHub) publish(userID string, version int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs[userID] {
		select {
		case ch <- baselineSyncEvent{Type: "sync_changed", UserIDHash: userID, ServerVersion: version}:
		default:
		}
	}
}

func (h *baselineSyncHub) count(userID string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs[userID])
}

func (h *baselineSyncHub) total() int {
	return h.stats().Connections
}

func (h *baselineSyncHub) stats() baselineSyncHubStats {
	h.mu.Lock()
	defer h.mu.Unlock()
	stats := baselineSyncHubStats{}
	for _, subs := range h.subs {
		if len(subs) == 0 {
			continue
		}
		stats.Users++
		stats.Connections += len(subs)
	}
	return stats
}

func (s *Server) baselineHandleSyncWebSocket(w http.ResponseWriter, r *http.Request, hub *baselineSyncHub) {
	if r.Method != http.MethodGet {
		Response_Error(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	userID, err := s.baselineAuthenticateWebSocket(r)
	if err != nil {
		Metrics_RecordWebSocketReject(s.metrics, "auth")
		s.writeAuthError(w, err)
		return
	}
	if !s.allowRequest(r, "ws:ip:"+ClientAddress_FromRequest(r), 120, time.Minute) ||
		!s.allowRequest(r, "ws:user:"+userID, 40, time.Minute) {
		Metrics_RecordWebSocketReject(s.metrics, "rate_limited")
		Response_Error(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}
	if hub.count(userID) >= 8 {
		Metrics_RecordWebSocketReject(s.metrics, "too_many_connections")
		Response_Error(w, http.StatusTooManyRequests, "too many websocket connections")
		return
	}
	conn, rw, err := baselineAcceptWebSocket(w, r)
	if err != nil {
		Metrics_RecordWebSocketReject(s.metrics, "handshake")
		return
	}
	s.metrics.WebSocketAccepted.Add(1)
	defer conn.Close()

	events := hub.subscribe(userID)
	defer hub.unsubscribe(userID, events)

	if version, err := s.store.currentUserVersion(r.Context(), userID); err == nil {
		_ = baselineWriteWebSocketJSON(conn, baselineSyncEvent{Type: "sync_ready", UserIDHash: userID, ServerVersion: version})
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	go func() {
		for {
			_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
			if _, _, err := baselineReadClientWebSocketFrame(rw.Reader); err != nil {
				cancel()
				return
			}
		}
	}()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-events:
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := baselineWriteWebSocketJSON(conn, event); err != nil {
				return
			}
		case <-ticker.C:
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := baselineWriteWebSocketFrame(conn, 0x9, nil); err != nil {
				return
			}
		}
	}
}

func (s *Server) baselineAuthenticateWebSocket(r *http.Request) (string, error) {
	if r.URL.Query().Get("token") != "" {
		return "", authError{status: http.StatusUnauthorized, message: "websocket query tokens are not accepted"}
	}
	if token := baselineBearerTokenFromWebSocketProtocol(r.Header.Get("Sec-WebSocket-Protocol")); token != "" {
		verified := Token_VerifyAuthToken(s.cfg.TokenSecret, token, time.Now().Unix())
		if verified.Error != "" {
			return "", authError{status: http.StatusUnauthorized, message: "invalid bearer token"}
		}
		return verified.Value, nil
	}
	return s.authenticateToken(r)
}

func baselineAcceptWebSocket(w http.ResponseWriter, r *http.Request) (net.Conn, *bufio.ReadWriter, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
		!baselineHeaderContainsToken(r.Header.Get("Connection"), "upgrade") {
		Response_Error(w, http.StatusBadRequest, "websocket upgrade required")
		return nil, nil, errors.New("missing upgrade")
	}
	key := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	if !baselineValidWebSocketKey(key) || r.Header.Get("Sec-WebSocket-Version") != "13" {
		Response_Error(w, http.StatusBadRequest, "invalid websocket handshake")
		return nil, nil, errors.New("invalid handshake")
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		Response_Error(w, http.StatusInternalServerError, "websocket unsupported")
		return nil, nil, errors.New("hijack unsupported")
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return nil, nil, err
	}
	accept := baselineWebsocketAccept(key)
	response := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n"
	if baselineWebsocketProtocolRequested(r.Header.Get("Sec-WebSocket-Protocol"), "daochi-sync-v1") {
		response += "Sec-WebSocket-Protocol: daochi-sync-v1\r\n"
	} else if baselineWebsocketProtocolRequested(r.Header.Get("Sec-WebSocket-Protocol"), "ksync-sync-v1") {
		response += "Sec-WebSocket-Protocol: ksync-sync-v1\r\n"
	} else if baselineWebsocketProtocolRequested(r.Header.Get("Sec-WebSocket-Protocol"), "inbe-sync-v1") {
		response += "Sec-WebSocket-Protocol: inbe-sync-v1\r\n"
	}
	response += "\r\n"
	if _, err := rw.WriteString(response); err != nil {
		conn.Close()
		return nil, nil, err
	}
	if err := rw.Flush(); err != nil {
		conn.Close()
		return nil, nil, err
	}
	return conn, rw, nil
}

func baselineBearerTokenFromWebSocketProtocol(header string) string {
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if token, ok := strings.CutPrefix(part, "bearer."); ok && token != "" {
			return token
		}
	}
	return ""
}

func baselineWebsocketProtocolRequested(header, protocol string) bool {
	for _, part := range strings.Split(header, ",") {
		if strings.TrimSpace(part) == protocol {
			return true
		}
	}
	return false
}

func baselineValidWebSocketKey(key string) bool {
	decoded, err := base64.StdEncoding.DecodeString(key)
	return err == nil && len(decoded) == 16
}

func baselineHeaderContainsToken(header, token string) bool {
	for _, part := range strings.Split(header, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

func baselineWebsocketAccept(key string) string {
	sum := sha1.Sum([]byte(key + baselineWebsocketGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func baselineWriteWebSocketJSON(conn net.Conn, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return baselineWriteWebSocketFrame(conn, 0x1, data)
}

func baselineWriteWebSocketFrame(conn net.Conn, opcode byte, payload []byte) error {
	header := []byte{0x80 | opcode, 0}
	if len(payload) < 126 {
		header[1] = byte(len(payload))
	} else if len(payload) <= 0xffff {
		header[1] = 126
		header = append(header, byte(len(payload)>>8), byte(len(payload)))
	} else {
		header[1] = 127
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(payload)))
		header = append(header, size[:]...)
	}
	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(payload)
	return err
}

func baselineReadWebSocketFrame(r *bufio.Reader) (byte, []byte, error) {
	return baselineReadWebSocketFrameMasked(r, false)
}

func baselineReadClientWebSocketFrame(r *bufio.Reader) (byte, []byte, error) {
	return baselineReadWebSocketFrameMasked(r, true)
}

func baselineReadWebSocketFrameMasked(r *bufio.Reader, requireMask bool) (byte, []byte, error) {
	var first [2]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return 0, nil, err
	}
	fin := first[0]&0x80 != 0
	if first[0]&0x70 != 0 {
		return 0, nil, errors.New("websocket reserved bits set")
	}
	opcode := first[0] & 0x0f
	if !baselineValidWebSocketOpcode(opcode) {
		return 0, nil, errors.New("websocket unsupported opcode")
	}
	masked := first[1]&0x80 != 0
	if requireMask && !masked {
		return 0, nil, errors.New("websocket client frame not masked")
	}
	length := uint64(first[1] & 0x7f)
	if length == 126 {
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	} else if length == 127 {
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
		if length&(1<<63) != 0 {
			return 0, nil, errors.New("websocket invalid length")
		}
	}
	if opcode >= 0x8 && (!fin || length > 125) {
		return 0, nil, errors.New("websocket invalid control frame")
	}
	if !fin {
		return 0, nil, errors.New("websocket fragmented frames unsupported")
	}
	if length > 1<<20 {
		return 0, nil, errors.New("websocket frame too large")
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(r, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	if opcode == 0x8 {
		return opcode, payload, io.EOF
	}
	return opcode, payload, nil
}

func baselineValidWebSocketOpcode(opcode byte) bool {
	switch opcode {
	case 0x0, 0x1, 0x2, 0x8, 0x9, 0xa:
		return true
	default:
		return false
	}
}
