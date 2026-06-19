package main

import (
	"crypto/sha256"
	"encoding/hex"
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
