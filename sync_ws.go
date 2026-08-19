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

const websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

type syncEvent struct {
	Type          string `json:"type"`
	UserIDHash    string `json:"user_id_hash"`
	ServerVersion int64  `json:"server_version"`
}

type syncHub struct {
	mu   sync.Mutex
	subs map[string]map[chan syncEvent]struct{}
}

func newSyncHub() *syncHub {
	return &syncHub{subs: make(map[string]map[chan syncEvent]struct{})}
}

func (h *syncHub) subscribe(userID string) chan syncEvent {
	ch := make(chan syncEvent, 8)
	h.mu.Lock()
	if h.subs[userID] == nil {
		h.subs[userID] = make(map[chan syncEvent]struct{})
	}
	h.subs[userID][ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *syncHub) unsubscribe(userID string, ch chan syncEvent) {
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

func (h *syncHub) publish(userID string, version int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs[userID] {
		select {
		case ch <- syncEvent{Type: "sync_changed", UserIDHash: userID, ServerVersion: version}:
		default:
		}
	}
}

func (h *syncHub) count(userID string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs[userID])
}

func (h *syncHub) total() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, subs := range h.subs {
		n += len(subs)
	}
	return n
}

func (s *Server) handleSyncWebSocket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	userID, err := s.authenticateWebSocket(r)
	if err != nil {
		s.metrics.webSocketRejected.Add(1)
		writeAuthError(w, err)
		return
	}
	if !s.allowRequest(r, "ws:ip:"+clientAddress(r), 120, time.Minute) ||
		!s.allowRequest(r, "ws:user:"+userID, 40, time.Minute) {
		s.metrics.webSocketRejected.Add(1)
		writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}
	if s.syncHub.count(userID) >= 8 {
		s.metrics.webSocketRejected.Add(1)
		writeError(w, http.StatusTooManyRequests, "too many websocket connections")
		return
	}
	conn, rw, err := acceptWebSocket(w, r)
	if err != nil {
		s.metrics.webSocketRejected.Add(1)
		return
	}
	s.metrics.webSocketAccepted.Add(1)
	defer conn.Close()

	events := s.syncHub.subscribe(userID)
	defer s.syncHub.unsubscribe(userID, events)

	if version, err := s.store.currentUserVersion(r.Context(), userID); err == nil {
		_ = writeWebSocketJSON(conn, syncEvent{Type: "sync_ready", UserIDHash: userID, ServerVersion: version})
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	go func() {
		for {
			_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
			if _, _, err := readClientWebSocketFrame(rw.Reader); err != nil {
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
			if err := writeWebSocketJSON(conn, event); err != nil {
				return
			}
		case <-ticker.C:
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := writeWebSocketFrame(conn, 0x9, nil); err != nil {
				return
			}
		}
	}
}

func (s *Server) authenticateWebSocket(r *http.Request) (string, error) {
	if r.URL.Query().Get("token") != "" {
		return "", authError{status: http.StatusUnauthorized, message: "websocket query tokens are not accepted"}
	}
	if token := bearerTokenFromWebSocketProtocol(r.Header.Get("Sec-WebSocket-Protocol")); token != "" {
		userID, err := verifyAuthToken(s.cfg.TokenSecret, token)
		if err != nil {
			return "", authError{status: http.StatusUnauthorized, message: "invalid bearer token"}
		}
		return userID, nil
	}
	return s.authenticateToken(r)
}

func acceptWebSocket(w http.ResponseWriter, r *http.Request) (net.Conn, *bufio.ReadWriter, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
		!headerContainsToken(r.Header.Get("Connection"), "upgrade") {
		writeError(w, http.StatusBadRequest, "websocket upgrade required")
		return nil, nil, errors.New("missing upgrade")
	}
	key := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	if !validWebSocketKey(key) || r.Header.Get("Sec-WebSocket-Version") != "13" {
		writeError(w, http.StatusBadRequest, "invalid websocket handshake")
		return nil, nil, errors.New("invalid handshake")
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		writeError(w, http.StatusInternalServerError, "websocket unsupported")
		return nil, nil, errors.New("hijack unsupported")
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return nil, nil, err
	}
	accept := websocketAccept(key)
	response := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n"
	if websocketProtocolRequested(r.Header.Get("Sec-WebSocket-Protocol"), "ksync-sync-v1") {
		response += "Sec-WebSocket-Protocol: ksync-sync-v1\r\n"
	} else if websocketProtocolRequested(r.Header.Get("Sec-WebSocket-Protocol"), "inbe-sync-v1") {
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

func bearerTokenFromWebSocketProtocol(header string) string {
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if token, ok := strings.CutPrefix(part, "bearer."); ok && token != "" {
			return token
		}
	}
	return ""
}

func websocketProtocolRequested(header, protocol string) bool {
	for _, part := range strings.Split(header, ",") {
		if strings.TrimSpace(part) == protocol {
			return true
		}
	}
	return false
}

func validWebSocketKey(key string) bool {
	decoded, err := base64.StdEncoding.DecodeString(key)
	return err == nil && len(decoded) == 16
}

func headerContainsToken(header, token string) bool {
	for _, part := range strings.Split(header, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

func websocketAccept(key string) string {
	sum := sha1.Sum([]byte(key + websocketGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func writeWebSocketJSON(conn net.Conn, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return writeWebSocketFrame(conn, 0x1, data)
}

func writeWebSocketFrame(conn net.Conn, opcode byte, payload []byte) error {
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

func readWebSocketFrame(r *bufio.Reader) (byte, []byte, error) {
	return readWebSocketFrameMasked(r, false)
}

func readClientWebSocketFrame(r *bufio.Reader) (byte, []byte, error) {
	return readWebSocketFrameMasked(r, true)
}

func readWebSocketFrameMasked(r *bufio.Reader, requireMask bool) (byte, []byte, error) {
	var first [2]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return 0, nil, err
	}
	opcode := first[0] & 0x0f
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
