package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

func canonicalMessage(nonce []byte, method, path string, signedPayload []byte) []byte {
	sum := sha256.Sum256(signedPayload)
	var b strings.Builder
	b.WriteString("inbe-sync-v1\n")
	b.WriteString(strings.ToUpper(method))
	b.WriteByte('\n')
	b.WriteString(path)
	b.WriteByte('\n')
	b.WriteString(hex.EncodeToString(sum[:]))
	b.WriteByte('\n')
	b.WriteString(hex.EncodeToString(nonce))
	b.WriteByte('\n')
	return []byte(b.String())
}

func signedPayload(body []byte) ([]byte, error) {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	if _, ok := payload["signature"]; !ok {
		return nil, errors.New("missing signature field")
	}
	delete(payload, "signature")
	return json.Marshal(payload)
}
