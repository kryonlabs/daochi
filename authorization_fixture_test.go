package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Shared with the independent Ziran protocol package. This file contains only
// synthetic public identities, signatures and opaque ciphertext, never keys.
type authorizationProtocolFixture struct {
	Answer           SessionAnswer       `json:"answer"`
	Proof            RequestProof        `json:"proof"`
	Challenge        SessionChallenge    `json:"challenge"`
	Pending          Rendezvous          `json:"pending"`
	PublicPending    RendezvousChallenge `json:"public_pending"`
	Claim            RendezvousClaim     `json:"claim"`
	GrantMessage     string              `json:"grant_message"`
	ProofMessage     string              `json:"proof_message"`
	ChallengeMessage string              `json:"challenge_message"`
	ClaimMessage     string              `json:"claim_message"`
}

func TestAuthorizationSharedProtocolFixture(t *testing.T) {
	const path = "testdata/authorization_v1.json"
	if os.Getenv("UPDATE_AUTHORIZATION_FIXTURE") == "1" {
		owner := MlDsa44_KeyPair()
		if owner.Error != nil {
			t.Fatal(owner.Error)
		}
		defer clear(owner.PrivateKey)
		delegate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, 32))
		defer clear(delegate)
		grant := Grant{Version: 1, AccountID: Signing_SHA256Hex(owner.PublicKey),
			GrantID: strings.Repeat("1", 32), RequestID: strings.Repeat("2", 32),
			AppID: "inbe", ClientID: strings.Repeat("3", 64), NodeID: strings.Repeat("4", 64),
			Audience: "https://synthetic-node.invalid", SigningKey: hex.EncodeToString(delegate.Public().(ed25519.PublicKey)),
			EncryptionKey: strings.Repeat("5", 2368), IssuedAt: 1791400000,
			NotBefore: 1791400000, ExpiresAt: 1791403600, Nonce: strings.Repeat("6", 32),
			Scopes: []GrantScope{{Collection: "private.inbe.v2.lumi",
				Visibility: "private", Read: true, Write: true, KeyID: "inbe-lumi-1", KeyEnvelope: "opaque synthetic envelope"}}}
		fixture := authorizationProtocolFixture{}
		fixture.GrantMessage = Authorization_GrantMessage(grant)
		signature := MlDsa44_Sign([]byte(fixture.GrantMessage), owner.PrivateKey)
		if signature.Error != nil {
			t.Fatal(signature.Error)
		}
		grant.Signature = hex.EncodeToString(signature.Value)
		fixture.Answer = SessionAnswer{Grant: grant, OwnerPublicKey: hex.EncodeToString(owner.PublicKey),
			Credential: SessionCredential{SessionID: strings.Repeat("7", 32), GrantID: grant.GrantID,
				Challenge: strings.Repeat("8", 32), ExpiresAt: 1791400300}}
		fixture.Proof = RequestProof{Version: 1, GrantID: grant.GrantID,
			SessionID: fixture.Answer.Credential.SessionID, AccountID: grant.AccountID,
			AppID: grant.AppID, ClientID: grant.ClientID, NodeID: grant.NodeID, Audience: grant.Audience,
			Challenge: fixture.Answer.Credential.Challenge, Method: "POST", Path: "/api/v1/delegated/sync",
			BodySHA256: Signing_SHA256Hex([]byte("{}")), ExpiresAt: 1791400030, Nonce: strings.Repeat("9", 32)}
		fixture.ProofMessage = Session_ProofMessage(fixture.Proof)
		fixture.Proof.Signature = hex.EncodeToString(ed25519.Sign(delegate, []byte(fixture.ProofMessage)))
		fixture.Challenge = SessionChallenge{GrantID: grant.GrantID, Challenge: strings.Repeat("a", 32),
			NodeID: grant.NodeID, Audience: grant.Audience, ExpiresAt: 1791400090}
		fixture.ChallengeMessage = Session_ChallengeMessage(fixture.Challenge)
		fixture.Pending = Rendezvous{RequestID: grant.RequestID, AccountID: grant.AccountID,
			AppID: grant.AppID, NodeID: grant.NodeID, Audience: grant.Audience, ExpiresAt: 1791400600,
			Challenge: strings.Repeat("b", 32), Status: "pending",
			Scopes: []RequestedScope{{Collection: grant.Scopes[0].Collection, Read: true, Write: true}}}
		fixture.PublicPending = RendezvousChallenge{RequestID: fixture.Pending.RequestID,
			AppID: fixture.Pending.AppID, NodeID: fixture.Pending.NodeID, Audience: fixture.Pending.Audience,
			ExpiresAt: fixture.Pending.ExpiresAt, Challenge: fixture.Pending.Challenge, Status: fixture.Pending.Status}
		fixture.Claim = RendezvousClaim{RequestID: grant.RequestID, ClientID: grant.ClientID,
			SigningKey: grant.SigningKey, EncryptionKey: grant.EncryptionKey}
		fixture.ClaimMessage = AuthorizationHttp_ClaimMessage(fixture.Pending, fixture.Claim, "")
		fixture.Claim.Proof = hex.EncodeToString(ed25519.Sign(delegate, []byte(fixture.ClaimMessage)))
		raw, err := json.MarshalIndent(fixture, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(raw, '\n'), 0644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture authorizationProtocolFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if Authorization_GrantMessage(fixture.Answer.Grant) != fixture.GrantMessage ||
		Session_ProofMessage(fixture.Proof) != fixture.ProofMessage ||
		Session_ChallengeMessage(fixture.Challenge) != fixture.ChallengeMessage ||
		AuthorizationHttp_ClaimMessage(fixture.Pending, fixture.Claim, "") != fixture.ClaimMessage {
		t.Fatal("shared canonical wire message changed")
	}
	owner, _ := hex.DecodeString(fixture.Answer.OwnerPublicKey)
	signature, _ := hex.DecodeString(fixture.Answer.Grant.Signature)
	if Signing_SHA256Hex(owner) != fixture.Answer.Grant.AccountID ||
		!MlDsa44_Verify(owner, []byte(fixture.GrantMessage), signature) ||
		!Session_VerifyKeyProof(fixture.Answer.Grant.SigningKey, fixture.ProofMessage, fixture.Proof.Signature) ||
		!Session_VerifyKeyProof(fixture.Claim.SigningKey, fixture.ClaimMessage, fixture.Claim.Proof) {
		t.Fatal("shared owner or delegate signature fixture failed")
	}
}
