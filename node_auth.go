package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const nodeAuthenticationWindow = 5 * time.Minute

func nodeRequestMessage(nodeID, timestamp, nonce, method, path string, body []byte) []byte {
	sum := sha256.Sum256(body)
	return []byte(fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s\n%s\n", nodeRequestContext,
		nodeID, timestamp, nonce, strings.ToUpper(method), path, hex.EncodeToString(sum[:])))
}

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
	message := nodeRequestMessage(s.node.ID, timestamp, nonce,
		req.Method, req.URL.EscapedPath(), body)
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
	if !validUserID(nodeID) || nonce == "" || len(nonce) > 128 {
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
	message := nodeRequestMessage(nodeID, timestampText, nonce,
		req.Method, req.URL.EscapedPath(), body)
	if !ed25519.Verify(publicKey, message, signature) {
		return errors.New("invalid node signature")
	}
	return s.store.ConsumeNodeRequestNonce(ctx, nodeID, nonce, timestamp+windowSeconds)
}
