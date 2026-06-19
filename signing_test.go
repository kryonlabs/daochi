package main

import (
	"bytes"
	"testing"
)

func TestSignedPayloadRemovesSignature(t *testing.T) {
	got, err := signedPayload([]byte(`{"signature":"abc","user_id_hash":"u","preferences":[{"key":"theme","value":"dark"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(got, []byte("signature")) {
		t.Fatalf("signed payload still contains signature: %s", got)
	}
	want := []byte(`{"preferences":[{"key":"theme","value":"dark"}],"user_id_hash":"u"}`)
	if !bytes.Equal(got, want) {
		t.Fatalf("payload mismatch\n got: %s\nwant: %s", got, want)
	}
}
