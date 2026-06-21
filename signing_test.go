package main

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestCanonicalMessageSignsRawBodyHash(t *testing.T) {
	nonce := []byte("01234567890123456789012345678901")
	body := []byte(`{"user_id_hash":"u","habits":[{"id":"habit-1","name":"Meditate"}]}`)
	bodyHash := sha256.Sum256(body)
	got := string(canonicalMessage(nonce, "post", "/api/v1/sync", body))
	want := "inbe-sync-v1\nPOST\n/api/v1/sync\n" +
		hex.EncodeToString(bodyHash[:]) + "\n" +
		hex.EncodeToString(nonce) + "\n"
	if got != want {
		t.Fatalf("message mismatch\n got: %q\nwant: %q", got, want)
	}
}
