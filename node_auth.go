package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const nodeAuthenticationWindow = 5 * time.Minute

func randomHex(bytes int) string {
	data := make([]byte, bytes)
	if _, err := rand.Read(data); err != nil {
		panic(err)
	}
	return hex.EncodeToString(data)
}

func (s *Server) signNodeRequest(req *http.Request, body []byte) {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := randomHex(16)
	message := []byte(Signing_NodeRequestMessage(nodeRequestContext, s.node.ID, timestamp, nonce,
		req.Method, req.URL.EscapedPath(), body))
	signature := ed25519.Sign(s.node.PrivateKey, message)

	req.Header.Set("X-Daochi-Node-ID", s.node.ID)
	req.Header.Set("X-Daochi-Node-Time", timestamp)
	req.Header.Set("X-Daochi-Node-Nonce", nonce)
	req.Header.Set("X-Daochi-Node-Signature",
		base64.RawURLEncoding.EncodeToString(signature))
}

func (s *Server) verifyNodeRequest(ctx context.Context, req *http.Request, body []byte) error {
	nodeID := strings.TrimSpace(req.Header.Get("X-Daochi-Node-ID"))
	timestampText := strings.TrimSpace(req.Header.Get("X-Daochi-Node-Time"))
	nonce := strings.TrimSpace(req.Header.Get("X-Daochi-Node-Nonce"))
	if !Identity_ValidUserID(nodeID) || nonce == "" || len(nonce) > 128 {
		return errors.New("invalid node authentication")
	}
	timestamp, err := strconv.ParseInt(timestampText, 10, 64)
	if err != nil {
		return errors.New("invalid node authentication time")
	}
	now := time.Now().Unix()
	windowSeconds := int64(nodeAuthenticationWindow / time.Second)
	if timestamp < now-windowSeconds || timestamp > now+windowSeconds {
		return errors.New("expired node authentication")
	}
	publicKey, found, err := s.store.TrustedPeerPublicKey(ctx, nodeID)
	if err != nil {
		return err
	}
	if !found {
		return errors.New("node is not paired")
	}
	signature, err := base64.RawURLEncoding.DecodeString(
		req.Header.Get("X-Daochi-Node-Signature"))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("invalid node signature")
	}
	message := []byte(Signing_NodeRequestMessage(nodeRequestContext, nodeID, timestampText, nonce,
		req.Method, req.URL.EscapedPath(), body))
	if !ed25519.Verify(publicKey, message, signature) {
		return errors.New("invalid node signature")
	}
	return s.store.ConsumeNodeRequestNonce(ctx, nodeID, nonce, timestamp+windowSeconds)
}
