package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	nodeRequestContext   = "daochi-node-request-v1"
	pairingInviteContext = "daochi-pairing-invite-v1"
	nameClaimContext     = "daochi-name-claim-v1"
)

var namePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

type NodeIdentity struct {
	ID         string
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

func newNodeIdentity(private ed25519.PrivateKey) (NodeIdentity, error) {
	if len(private) == 0 {
		_, generated, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return NodeIdentity{}, err
		}
		private = generated
	}
	if len(private) != ed25519.PrivateKeySize {
		return NodeIdentity{}, errors.New("invalid Ed25519 node identity key")
	}
	public := append(ed25519.PublicKey(nil), private.Public().(ed25519.PublicKey)...)
	sum := sha256.Sum256(public)
	return NodeIdentity{
		ID:         hex.EncodeToString(sum[:]),
		PublicKey:  public,
		PrivateKey: append(ed25519.PrivateKey(nil), private...),
	}, nil
}

func loadOrCreateNodeIdentityKey(path string) (ed25519.PrivateKey, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("empty node identity key path")
	}
	if data, err := os.ReadFile(path); err == nil {
		decoded, err := hex.DecodeString(strings.TrimSpace(string(data)))
		if err != nil {
			return nil, fmt.Errorf("decode %s: %w", path, err)
		}
		if len(decoded) == ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(decoded), nil
		}
		if len(decoded) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("%s has invalid key length", path)
		}
		return ed25519.PrivateKey(decoded), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, []byte(hex.EncodeToString(private)+"\n"), 0600); err != nil {
		return nil, err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return nil, err
	}
	return private, nil
}

type PairingInvite struct {
	Version     int            `json:"version"`
	InviteID    string         `json:"invite_id"`
	NodeID      string         `json:"node_id"`
	PublicKey   string         `json:"public_key"`
	DisplayName string         `json:"display_name"`
	Addresses   []string       `json:"addresses"`
	SpaceID     string         `json:"space_id,omitempty"`
	ExpiresAt   int64          `json:"expires_at"`
	Nonce       string         `json:"nonce"`
	Policy      NodeSyncPolicy `json:"policy"`
	Signature   string         `json:"signature"`
}

type PairingAcceptance struct {
	Version     int      `json:"version"`
	InviteID    string   `json:"invite_id"`
	NodeID      string   `json:"node_id"`
	PublicKey   string   `json:"public_key"`
	DisplayName string   `json:"display_name"`
	Addresses   []string `json:"addresses"`
	AcceptedAt  int64    `json:"accepted_at"`
	Nonce       string   `json:"nonce"`
	Signature   string   `json:"signature"`
}

func pairingInviteMessage(invite PairingInvite) []byte {
	addresses := append([]string(nil), invite.Addresses...)
	sort.Strings(addresses)
	policy, _ := canonicalJSON(invite.Policy)
	return []byte(fmt.Sprintf("%s\n%d\n%s\n%s\n%s\n%s\n%s\n%s\n%d\n%s\n%s\n",
		pairingInviteContext, invite.Version, invite.InviteID, invite.NodeID,
		invite.PublicKey, invite.DisplayName, strings.Join(addresses, ","), invite.SpaceID,
		invite.ExpiresAt, invite.Nonce, sha256Hex(policy)))
}

func (n NodeIdentity) signInvite(invite *PairingInvite) {
	signature := ed25519.Sign(n.PrivateKey, pairingInviteMessage(*invite))
	invite.Signature = base64.RawURLEncoding.EncodeToString(signature)
}

func pairingAcceptanceMessage(invite PairingInvite, acceptance PairingAcceptance) []byte {
	addresses := append([]string(nil), acceptance.Addresses...)
	sort.Strings(addresses)
	inviteDigest := sha256.Sum256([]byte(invite.Signature))
	return []byte(fmt.Sprintf("%s-acceptance\n%d\n%s\n%s\n%s\n%s\n%s\n%d\n%s\n%s\n",
		pairingInviteContext,
		acceptance.Version,
		acceptance.InviteID,
		acceptance.NodeID,
		acceptance.PublicKey,
		acceptance.DisplayName,
		strings.Join(addresses, ","),
		acceptance.AcceptedAt,
		acceptance.Nonce,
		hex.EncodeToString(inviteDigest[:]),
	))
}

func (n NodeIdentity) signAcceptance(invite PairingInvite, acceptance *PairingAcceptance) {
	signature := ed25519.Sign(n.PrivateKey, pairingAcceptanceMessage(invite, *acceptance))
	acceptance.Signature = base64.RawURLEncoding.EncodeToString(signature)
}

func validatePairingAcceptance(
	invite PairingInvite,
	acceptance PairingAcceptance,
	now time.Time,
) (ed25519.PublicKey, error) {
	if acceptance.Version != 1 || acceptance.InviteID != invite.InviteID ||
		!validUserID(acceptance.NodeID) || acceptance.Nonce == "" {
		return nil, errors.New("invalid pairing acceptance")
	}
	if acceptance.AcceptedAt < now.Add(-nodeAuthenticationWindow).Unix() ||
		acceptance.AcceptedAt > now.Add(nodeAuthenticationWindow).Unix() {
		return nil, errors.New("pairing acceptance time is outside the allowed window")
	}
	if err := validateHTTPAddresses(acceptance.Addresses); err != nil {
		return nil, err
	}
	publicBytes, err := hex.DecodeString(acceptance.PublicKey)
	if err != nil || len(publicBytes) != ed25519.PublicKeySize {
		return nil, errors.New("invalid pairing acceptance public key")
	}
	publicKey := ed25519.PublicKey(publicBytes)
	digest := sha256.Sum256(publicKey)
	if hex.EncodeToString(digest[:]) != acceptance.NodeID {
		return nil, errors.New("pairing acceptance node ID does not match public key")
	}
	signature, err := base64.RawURLEncoding.DecodeString(acceptance.Signature)
	if err != nil || !ed25519.Verify(
		publicKey,
		pairingAcceptanceMessage(invite, acceptance),
		signature,
	) {
		return nil, errors.New("invalid pairing acceptance signature")
	}
	return publicKey, nil
}

func validatePairingInvite(invite PairingInvite, now time.Time) (ed25519.PublicKey, error) {
	if invite.Version != 1 || !validUserID(invite.NodeID) ||
		invite.InviteID == "" || invite.Nonce == "" {
		return nil, errors.New("invalid pairing invite")
	}
	if invite.ExpiresAt <= now.Unix() || invite.ExpiresAt > now.Add(maximumInviteLifetime).Unix() {
		return nil, errors.New("pairing invite expired or too far in the future")
	}
	publicBytes, err := hex.DecodeString(invite.PublicKey)
	if err != nil || len(publicBytes) != ed25519.PublicKeySize {
		return nil, errors.New("invalid pairing public key")
	}
	public := ed25519.PublicKey(publicBytes)
	sum := sha256.Sum256(public)
	if hex.EncodeToString(sum[:]) != invite.NodeID {
		return nil, errors.New("pairing node ID does not match public key")
	}
	signature, err := base64.RawURLEncoding.DecodeString(invite.Signature)
	if err != nil || !ed25519.Verify(public, pairingInviteMessage(invite), signature) {
		return nil, errors.New("invalid pairing signature")
	}
	if err := validateHTTPAddresses(invite.Addresses); err != nil {
		return nil, err
	}
	return public, nil
}

type ServiceRecord struct {
	Service      string   `json:"service"`
	Endpoints    []string `json:"endpoints"`
	Capabilities []string `json:"capabilities,omitempty"`
}

type NameClaim struct {
	Version   int             `json:"version"`
	SpaceID   string          `json:"space_id"`
	Name      string          `json:"name"`
	NodeID    string          `json:"node_id"`
	Sequence  int64           `json:"sequence"`
	ExpiresAt int64           `json:"expires_at"`
	Services  []ServiceRecord `json:"services,omitempty"`
	Signature string          `json:"signature"`
}

type MeshTrustSpace struct {
	SpaceID            string `json:"space_id"`
	DisplayName        string `json:"display_name"`
	AuthorityPublicKey string `json:"authority_public_key"`
}

func normalizeName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func nameClaimMessage(claim NameClaim) []byte {
	services, _ := canonicalJSON(claim.Services)
	return []byte(fmt.Sprintf("%s\n%d\n%s\n%s\n%s\n%d\n%d\n%s\n",
		nameClaimContext, claim.Version, claim.SpaceID, claim.Name, claim.NodeID,
		claim.Sequence, claim.ExpiresAt, sha256Hex(services)))
}
