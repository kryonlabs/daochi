package main

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"testing"
)

// nonceVerifier accepts signatures only over one challenge.
type nonceVerifier struct {
	nonce string
}

func (verifier *nonceVerifier) Verify(key, message, signature []byte) bool {
	return bytes.Contains(message, []byte("\n"+verifier.nonce+"\n"))
}

// Two sign-ins of one account overlap, as an app's sync and live updates do
// right after the account is attached: the second challenge must not make the
// first login fail, and the used challenge must not sign in again.
func TestZiranOverlappingSignInsKeepTheirChallenges(t *testing.T) {
	user, key, signature := accessIdentity()
	server, _, _ := testServer(t)
	if err := server.Store.RegisterUser(t.Context(), user, key); err != nil {
		t.Fatal(err)
	}
	first := Challenge_Issue(server.Challenges, user)
	second := Challenge_Issue(server.Challenges, user)
	if first.Error != nil || second.Error != nil {
		t.Fatal(first.Error, second.Error)
	}
	server.Verifier = testVerifier(&nonceVerifier{nonce: hex.EncodeToString(first.Nonce)})
	if _, err := server.authenticateSignature(t.Context(), user, "", signature, "daochi-sync-v1", "POST", "/login", nil); err != nil {
		t.Fatal("the first sign-in failed after a second challenge", err)
	}
	pending := Challenge_Outstanding(server.Challenges, user)
	if len(pending) != 1 || !bytes.Equal(pending[0].Nonce, second.Nonce) {
		t.Fatal("the second sign-in lost its challenge", pending)
	}
	_, replay := server.authenticateSignature(t.Context(), user, "", signature, "daochi-sync-v1", "POST", "/login", nil)
	if !equalAuthenticationError(replay, authError{http.StatusUnauthorized, "signature rejected"}) {
		t.Fatal("a used challenge signed in again", replay)
	}
	server.Verifier = testVerifier(&nonceVerifier{nonce: hex.EncodeToString(second.Nonce)})
	if _, err := server.authenticateSignature(t.Context(), user, "", signature, "daochi-sync-v1", "POST", "/login", nil); err != nil {
		t.Fatal("the second sign-in failed", err)
	}
}
