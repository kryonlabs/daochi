package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

func canonicalMessage(nonce []byte, method, path string, signedPayload []byte) []byte {
	return canonicalMessageWithContext("ksync-sync-v1", nonce, method, path, signedPayload)
}

func canonicalMessageWithContext(context string, nonce []byte, method, path string, signedPayload []byte) []byte {
	sum := sha256.Sum256(signedPayload)
	var b strings.Builder
	b.WriteString(context)
	b.WriteByte('\n')
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
