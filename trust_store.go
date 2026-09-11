package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type TrustedNodePeer struct {
	NodeID      string         `json:"node_id"`
	PublicKey   string         `json:"public_key"`
	DisplayName string         `json:"display_name"`
	Addresses   []string       `json:"addresses"`
	SpaceID     string         `json:"space_id,omitempty"`
	Policy      NodeSyncPolicy `json:"policy"`
	TrustedAt   string         `json:"trusted_at"`
}

func (s *Store) ensureMeshTrustSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS trusted_node_peers (
    node_id TEXT PRIMARY KEY,
    public_key BLOB NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    addresses_json TEXT NOT NULL DEFAULT '[]',
    space_id TEXT NOT NULL DEFAULT '',
    policy_json TEXT NOT NULL DEFAULT '{}',
    trusted_at TEXT NOT NULL,
    revoked_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS consumed_pairing_invites (
    invite_id TEXT PRIMARY KEY,
    consumed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS issued_pairing_invites (
    invite_id TEXT PRIMARY KEY,
    signature TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    completed_node_id TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS node_request_nonces (
    node_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY(node_id, nonce)
);
CREATE TABLE IF NOT EXISTS trust_spaces (
    space_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    authority_public_key BLOB NOT NULL,
    authority_private_key BLOB NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS name_claims (
    space_id TEXT NOT NULL,
    name TEXT NOT NULL,
    node_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    services_json TEXT NOT NULL DEFAULT '[]',
    signature TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(space_id, name)
);
CREATE INDEX IF NOT EXISTS node_request_nonces_expiry
    ON node_request_nonces(expires_at);
`)
	return err
}

func (s *Store) TrustPeer(ctx context.Context, invite PairingInvite, publicKey ed25519.PublicKey) error {
	return withTx(ctx, s.db, func(tx *sql.Tx) error {
		var consumed int
		if err := tx.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM consumed_pairing_invites WHERE invite_id=?1)`,
			invite.InviteID).Scan(&consumed); err != nil {
			return err
		}
		if consumed != 0 {
			return errors.New("pairing invite already consumed")
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO consumed_pairing_invites(invite_id,consumed_at) VALUES(?1,?2)`,
			invite.InviteID, canonicalNow()); err != nil {
			return err
		}
		return upsertTrustedPeerTx(ctx, tx, invite, publicKey)
	})
}

func upsertTrustedPeerTx(
	ctx context.Context,
	tx *sql.Tx,
	invite PairingInvite,
	publicKey ed25519.PublicKey,
) error {
	addresses, err := json.Marshal(invite.Addresses)
	if err != nil {
		return err
	}
	policy, err := json.Marshal(invite.Policy)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO trusted_node_peers(
    node_id,public_key,display_name,addresses_json,space_id,policy_json,trusted_at
) VALUES(?1,?2,?3,?4,?5,?6,?7)
ON CONFLICT(node_id) DO UPDATE SET
    public_key=excluded.public_key,
    display_name=excluded.display_name,
    addresses_json=excluded.addresses_json,
    space_id=excluded.space_id,
    policy_json=excluded.policy_json,
    trusted_at=excluded.trusted_at,
    revoked_at=''`, invite.NodeID, []byte(publicKey), invite.DisplayName,
		string(addresses), invite.SpaceID, string(policy), canonicalNow())
	return err
}

func (s *Store) RecordIssuedPairingInvite(ctx context.Context, invite PairingInvite) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO issued_pairing_invites(invite_id,signature,expires_at,created_at)
VALUES(?1,?2,?3,?4)`, invite.InviteID, invite.Signature, invite.ExpiresAt, canonicalNow())
	return err
}

func (s *Store) CompleteIssuedPairing(
	ctx context.Context,
	invite PairingInvite,
	acceptance PairingAcceptance,
	publicKey ed25519.PublicKey,
) error {
	return withTx(ctx, s.db, func(tx *sql.Tx) error {
		var storedSignature string
		var expiresAt int64
		var completedNodeID string
		err := tx.QueryRowContext(ctx, `
SELECT signature,expires_at,completed_node_id
FROM issued_pairing_invites
WHERE invite_id=?1`, invite.InviteID).Scan(
			&storedSignature,
			&expiresAt,
			&completedNodeID,
		)
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("pairing invite was not issued by this node")
		}
		if err != nil {
			return err
		}
		if storedSignature != invite.Signature || expiresAt != invite.ExpiresAt {
			return errors.New("pairing invite does not match the issued invite")
		}
		if expiresAt <= time.Now().Unix() {
			return errors.New("pairing invite expired")
		}
		if completedNodeID != "" {
			if completedNodeID == acceptance.NodeID {
				return nil
			}
			return errors.New("pairing invite already completed by another node")
		}

		result, err := tx.ExecContext(ctx, `
UPDATE issued_pairing_invites
SET completed_node_id=?1
WHERE invite_id=?2 AND completed_node_id=''`, acceptance.NodeID, invite.InviteID)
		if err != nil {
			return err
		}
		updated, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if updated != 1 {
			return errors.New("pairing invite was completed concurrently")
		}

		peer := PairingInvite{
			NodeID:      acceptance.NodeID,
			PublicKey:   acceptance.PublicKey,
			DisplayName: acceptance.DisplayName,
			Addresses:   acceptance.Addresses,
			SpaceID:     invite.SpaceID,
			Policy:      inverseNodeSyncPolicy(invite.Policy),
		}
		return upsertTrustedPeerTx(ctx, tx, peer, publicKey)
	})
}

func inverseNodeSyncPolicy(policy NodeSyncPolicy) NodeSyncPolicy {
	inverse := policy
	switch normalizeNodeSyncDirection(policy.Direction) {
	case "pull":
		inverse.Direction = "push"
	case "push":
		inverse.Direction = "pull"
	default:
		inverse.Direction = normalizeNodeSyncDirection(policy.Direction)
	}
	return inverse
}

func withTx(ctx context.Context, db *sql.DB, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) TrustedPeerPublicKey(ctx context.Context, nodeID string) (ed25519.PublicKey, bool, error) {
	var publicKey []byte
	err := s.db.QueryRowContext(ctx, `
SELECT public_key FROM trusted_node_peers
WHERE node_id=?1 AND revoked_at=''`, nodeID).Scan(&publicKey)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, false, errors.New("stored peer key is invalid")
	}
	return ed25519.PublicKey(publicKey), true, nil
}

func (s *Store) TrustedPeerPolicy(ctx context.Context, nodeID string) (NodeSyncPolicy, bool, error) {
	var policyJSON string
	err := s.db.QueryRowContext(ctx, `
SELECT policy_json FROM trusted_node_peers
WHERE node_id=?1 AND revoked_at=''`, nodeID).Scan(&policyJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return NodeSyncPolicy{}, false, nil
	}
	if err != nil {
		return NodeSyncPolicy{}, false, err
	}
	var policy NodeSyncPolicy
	if err := json.Unmarshal([]byte(policyJSON), &policy); err != nil {
		return NodeSyncPolicy{}, false, err
	}
	return policy, true, nil
}

func (s *Store) ConsumeNodeRequestNonce(ctx context.Context, nodeID, nonce string, expiresAt int64) error {
	return withTx(ctx, s.db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM node_request_nonces WHERE expires_at<?1`, time.Now().Unix()); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO node_request_nonces(node_id,nonce,expires_at)
VALUES(?1,?2,?3)`, nodeID, nonce, expiresAt); err != nil {
			return errors.New("node request replayed")
		}
		return nil
	})
}

func (s *Store) ListTrustedPeers(ctx context.Context) ([]TrustedNodePeer, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT node_id,public_key,display_name,addresses_json,space_id,policy_json,trusted_at
FROM trusted_node_peers
WHERE revoked_at=''
ORDER BY display_name,node_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	peers := []TrustedNodePeer{}
	for rows.Next() {
		var peer TrustedNodePeer
		var publicKey []byte
		var addressesJSON string
		var policyJSON string
		if err := rows.Scan(&peer.NodeID, &publicKey, &peer.DisplayName,
			&addressesJSON, &peer.SpaceID, &policyJSON, &peer.TrustedAt); err != nil {
			return nil, err
		}
		peer.PublicKey = hex.EncodeToString(publicKey)
		if err := json.Unmarshal([]byte(addressesJSON), &peer.Addresses); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(policyJSON), &peer.Policy); err != nil {
			return nil, err
		}
		peers = append(peers, peer)
	}
	return peers, rows.Err()
}

func (s *Store) CreateTrustSpace(ctx context.Context, displayName string) (string, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(publicKey)
	spaceID := hex.EncodeToString(digest[:])
	_, err = s.db.ExecContext(ctx, `
INSERT INTO trust_spaces(
    space_id,display_name,authority_public_key,authority_private_key,created_at
) VALUES(?1,?2,?3,?4,?5)`, spaceID, displayName, []byte(publicKey),
		[]byte(privateKey), canonicalNow())
	return spaceID, err
}

func (s *Store) SignAndStoreNameClaim(ctx context.Context, claim NameClaim) (NameClaim, error) {
	var privateKey []byte
	if err := s.db.QueryRowContext(ctx, `
SELECT authority_private_key FROM trust_spaces
WHERE space_id=?1`, claim.SpaceID).Scan(&privateKey); err != nil {
		return claim, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return claim, errors.New("namespace authority is not available on this node")
	}

	var currentSequence int64
	err := s.db.QueryRowContext(ctx, `
SELECT sequence FROM name_claims
WHERE space_id=?1 AND name=?2`, claim.SpaceID, claim.Name).Scan(&currentSequence)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return claim, err
	}
	claim.Version = 1
	claim.Sequence = currentSequence + 1
	services, err := json.Marshal(claim.Services)
	if err != nil {
		return claim, err
	}
	claim.Signature = base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(ed25519.PrivateKey(privateKey), nameClaimMessage(claim)))
	_, err = s.db.ExecContext(ctx, `
INSERT INTO name_claims(
    space_id,name,node_id,sequence,expires_at,services_json,signature,updated_at
) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)
ON CONFLICT(space_id,name) DO UPDATE SET
    node_id=excluded.node_id,
    sequence=excluded.sequence,
    expires_at=excluded.expires_at,
    services_json=excluded.services_json,
    signature=excluded.signature,
    updated_at=excluded.updated_at`, claim.SpaceID, claim.Name, claim.NodeID,
		claim.Sequence, claim.ExpiresAt, string(services), claim.Signature, canonicalNow())
	return claim, err
}

func (s *Store) ResolveNameClaim(ctx context.Context, spaceID, name string) (NameClaim, bool, error) {
	var claim NameClaim
	var servicesJSON string
	err := s.db.QueryRowContext(ctx, `
SELECT space_id,name,node_id,sequence,expires_at,services_json,signature
FROM name_claims
WHERE space_id=?1 AND name=?2`, spaceID, name).Scan(&claim.SpaceID, &claim.Name,
		&claim.NodeID, &claim.Sequence, &claim.ExpiresAt, &servicesJSON, &claim.Signature)
	if errors.Is(err, sql.ErrNoRows) {
		return claim, false, nil
	}
	if err != nil {
		return claim, false, err
	}
	claim.Version = 1
	if err := json.Unmarshal([]byte(servicesJSON), &claim.Services); err != nil {
		return claim, false, err
	}
	if claim.ExpiresAt <= time.Now().Unix() {
		return claim, false, nil
	}

	var publicKey []byte
	if err := s.db.QueryRowContext(ctx, `
SELECT authority_public_key FROM trust_spaces
WHERE space_id=?1`, spaceID).Scan(&publicKey); err != nil {
		return claim, false, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(claim.Signature)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(publicKey), nameClaimMessage(claim), signature) {
		return claim, false, fmt.Errorf("invalid stored name claim signature")
	}
	return claim, true, nil
}

func (s *Store) ExportMeshNames(
	ctx context.Context,
	policy NodeSyncPolicy,
) ([]MeshTrustSpace, []NameClaim, error) {
	if !nodePolicyIncludesData(&policy, "names") || len(policy.Spaces) == 0 {
		return nil, nil, nil
	}
	spaces := make([]MeshTrustSpace, 0, len(policy.Spaces))
	names := []NameClaim{}
	for _, spaceID := range policy.Spaces {
		var space MeshTrustSpace
		var publicKey []byte
		err := s.db.QueryRowContext(ctx, `
SELECT space_id,display_name,authority_public_key
FROM trust_spaces
WHERE space_id=?1`, spaceID).Scan(&space.SpaceID, &space.DisplayName, &publicKey)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		space.AuthorityPublicKey = hex.EncodeToString(publicKey)
		spaces = append(spaces, space)

		rows, err := s.db.QueryContext(ctx, `
SELECT space_id,name,node_id,sequence,expires_at,services_json,signature
FROM name_claims
WHERE space_id=?1
ORDER BY name`, spaceID)
		if err != nil {
			return nil, nil, err
		}
		for rows.Next() {
			var claim NameClaim
			var servicesJSON string
			if err := rows.Scan(&claim.SpaceID, &claim.Name, &claim.NodeID,
				&claim.Sequence, &claim.ExpiresAt, &servicesJSON, &claim.Signature); err != nil {
				rows.Close()
				return nil, nil, err
			}
			claim.Version = 1
			if err := json.Unmarshal([]byte(servicesJSON), &claim.Services); err != nil {
				rows.Close()
				return nil, nil, err
			}
			names = append(names, claim)
		}
		if err := rows.Close(); err != nil {
			return nil, nil, err
		}
	}
	return spaces, names, nil
}

func (s *Store) ImportMeshNames(
	ctx context.Context,
	policy NodeSyncPolicy,
	spaces []MeshTrustSpace,
	claims []NameClaim,
) (int, error) {
	if !nodePolicyIncludesData(&policy, "names") {
		return 0, nil
	}
	allowedSpaces := make(map[string]bool, len(policy.Spaces))
	for _, spaceID := range policy.Spaces {
		allowedSpaces[spaceID] = true
	}
	returnValue := 0
	err := withTx(ctx, s.db, func(tx *sql.Tx) error {
		for _, space := range spaces {
			if !allowedSpaces[space.SpaceID] {
				continue
			}
			publicKey, err := validateMeshTrustSpace(space)
			if err != nil {
				return err
			}
			if err := importTrustSpace(ctx, tx, space, publicKey); err != nil {
				return err
			}
		}
		for _, claim := range claims {
			if !allowedSpaces[claim.SpaceID] {
				continue
			}
			applied, err := importNameClaim(ctx, tx, claim)
			if err != nil {
				return err
			}
			returnValue += applied
		}
		return nil
	})
	return returnValue, err
}

func validateMeshTrustSpace(space MeshTrustSpace) (ed25519.PublicKey, error) {
	publicKey, err := hex.DecodeString(space.AuthorityPublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("invalid mesh trust-space public key")
	}
	digest := sha256.Sum256(publicKey)
	if hex.EncodeToString(digest[:]) != space.SpaceID {
		return nil, errors.New("mesh trust-space ID does not match authority key")
	}
	return ed25519.PublicKey(publicKey), nil
}

func importTrustSpace(
	ctx context.Context,
	tx *sql.Tx,
	space MeshTrustSpace,
	publicKey ed25519.PublicKey,
) error {
	var existing []byte
	err := tx.QueryRowContext(ctx, `
SELECT authority_public_key FROM trust_spaces
WHERE space_id=?1`, space.SpaceID).Scan(&existing)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && !ed25519.PublicKey(existing).Equal(publicKey) {
		return errors.New("trust-space authority fork detected")
	}
	_, err = tx.ExecContext(ctx, `
INSERT OR IGNORE INTO trust_spaces(
    space_id,display_name,authority_public_key,authority_private_key,created_at
) VALUES(?1,?2,?3,'',?4)`, space.SpaceID, space.DisplayName,
		[]byte(publicKey), canonicalNow())
	return err
}

func importNameClaim(ctx context.Context, tx *sql.Tx, claim NameClaim) (int, error) {
	if claim.Version != 1 || !validUserID(claim.SpaceID) ||
		!validUserID(claim.NodeID) || !namePattern.MatchString(claim.Name) ||
		claim.Sequence <= 0 {
		return 0, errors.New("invalid mesh name claim")
	}
	if err := validateServices(claim.Services); err != nil {
		return 0, err
	}
	var publicKey []byte
	if err := tx.QueryRowContext(ctx, `
SELECT authority_public_key FROM trust_spaces
WHERE space_id=?1`, claim.SpaceID).Scan(&publicKey); err != nil {
		return 0, errors.New("mesh name claim has no trusted authority")
	}
	signature, err := base64.RawURLEncoding.DecodeString(claim.Signature)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(publicKey),
		nameClaimMessage(claim), signature) {
		return 0, errors.New("invalid mesh name claim signature")
	}

	var currentSequence int64
	var currentSignature string
	err = tx.QueryRowContext(ctx, `
SELECT sequence,signature FROM name_claims
WHERE space_id=?1 AND name=?2`, claim.SpaceID, claim.Name).
		Scan(&currentSequence, &currentSignature)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if err == nil {
		if currentSequence > claim.Sequence {
			return 0, nil
		}
		if currentSequence == claim.Sequence {
			if currentSignature != claim.Signature {
				return 0, errors.New("namespace history fork detected")
			}
			return 0, nil
		}
	}
	servicesJSON, err := json.Marshal(claim.Services)
	if err != nil {
		return 0, err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO name_claims(
    space_id,name,node_id,sequence,expires_at,services_json,signature,updated_at
) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)
ON CONFLICT(space_id,name) DO UPDATE SET
    node_id=excluded.node_id,
    sequence=excluded.sequence,
    expires_at=excluded.expires_at,
    services_json=excluded.services_json,
    signature=excluded.signature,
    updated_at=excluded.updated_at`, claim.SpaceID, claim.Name, claim.NodeID,
		claim.Sequence, claim.ExpiresAt, string(servicesJSON), claim.Signature, canonicalNow())
	if err != nil {
		return 0, err
	}
	return 1, nil
}
