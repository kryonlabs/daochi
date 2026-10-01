// Original HTTP handlers retained only as regression oracles.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	defaultInviteLifetime = 10 * time.Minute
	maximumInviteLifetime = time.Duration(MaximumInviteLifetimeSeconds) * time.Second
	defaultNameLifetime   = 365 * 24 * time.Hour
	maximumNameLifetime   = 366 * 24 * time.Hour
)

type createInviteRequest struct {
	DisplayName string         `json:"display_name"`
	Addresses   []string       `json:"addresses"`
	SpaceID     string         `json:"space_id"`
	ExpiresIn   int64          `json:"expires_in_seconds"`
	Policy      NodeSyncPolicy `json:"policy"`
}

type completePairingRequest struct {
	Invite     PairingInvite     `json:"invite"`
	Acceptance PairingAcceptance `json:"acceptance"`
}

func (s *Server) baselineTrustCreateInvite(w http.ResponseWriter, r *http.Request) {
	if !HttpAuth_RequireLocalOperator(w, r, s.cfg.AdminToken) {
		return
	}
	bodyResult := HttpBody_ReadJSON(w, r, s.cfg.MaxBodyBytes)
	body, err := bodyResult.Value, bodyResult.Error
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	var req createInviteRequest
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			Response_Error(w, http.StatusBadRequest, "invalid pairing invite request")
			return
		}
	}

	lifetime := defaultInviteLifetime
	if req.ExpiresIn > 0 {
		lifetime = time.Duration(req.ExpiresIn) * time.Second
	}
	if lifetime > maximumInviteLifetime {
		Response_Error(w, http.StatusBadRequest, "pairing invite expiry exceeds 24 hours")
		return
	}
	req.Policy.Direction = ConfigValues_SyncDirection(req.Policy.Direction)
	if !baselineTrustPairingPolicy(req.Policy) {
		Response_Error(w, http.StatusBadRequest, "explicit pairing policy required")
		return
	}
	addresses := req.Addresses
	if len(addresses) == 0 && strings.TrimSpace(s.cfg.BaseURL) != "" {
		addresses = []string{strings.TrimRight(s.cfg.BaseURL, "/")}
	}
	if err := NodeIdentity_ValidateAddresses(addresses); err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}

	invite := PairingInvite{
		Version:     1,
		InviteID:    NodeAuth_RandomHex(16),
		NodeID:      s.node.ID,
		PublicKey:   hex.EncodeToString(s.node.PublicKey),
		DisplayName: Manifest_DefaultString(strings.TrimSpace(req.DisplayName), s.cfg.NodeDisplayName),
		Addresses:   addresses,
		SpaceID:     strings.TrimSpace(req.SpaceID),
		ExpiresAt:   time.Now().Add(lifetime).Unix(),
		Nonce:       NodeAuth_RandomHex(16),
		Policy:      req.Policy,
	}
	NodeIdentity_SignInvite(s.node, &invite)
	if err := TrustStore_RecordIssuedPairingInvite(s.store.Database, r.Context(), invite); err != nil {
		Response_Error(w, http.StatusInternalServerError, "pairing invite creation failed")
		return
	}
	Response_JSON(w, http.StatusOK, invite)
}

func baselineTrustPairingPolicy(policy NodeSyncPolicy) bool {
	switch strings.ToLower(strings.TrimSpace(policy.Direction)) {
	case "pull", "push", "bidirectional":
		return baselineTrustInboundPolicy(policy)
	default:
		return false
	}
}

func (s *Server) baselineTrustAcceptInvite(w http.ResponseWriter, r *http.Request) {
	if !HttpAuth_RequireLocalOperator(w, r, s.cfg.AdminToken) {
		return
	}
	bodyResult := HttpBody_ReadJSON(w, r, s.cfg.MaxBodyBytes)
	body, err := bodyResult.Value, bodyResult.Error
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	var invite PairingInvite
	if err := json.Unmarshal(body, &invite); err != nil {
		Response_Error(w, http.StatusBadRequest, "invalid pairing invite")
		return
	}
	publicKey := NodeIdentity_ValidateInvite(invite, time.Now())
	if publicKey.Error != nil {
		Response_Error(w, http.StatusBadRequest, publicKey.Error.Error())
		return
	}
	if invite.NodeID == s.node.ID {
		Response_Error(w, http.StatusBadRequest, "cannot pair a node with itself")
		return
	}
	acceptance, err := s.baselineTrustAcceptance(invite)
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := baselineTrustCompleteRemote(r.Context(), invite, acceptance); err != nil {
		Response_Error(w, http.StatusBadGateway, err.Error())
		return
	}
	if err := TrustStore_TrustPeer(s.store.Database, r.Context(), invite, publicKey.Value); err != nil {
		Response_Error(w, http.StatusConflict, err.Error())
		return
	}
	Response_JSON(w, http.StatusOK, map[string]any{
		"status":  "paired",
		"node_id": invite.NodeID,
	})
}

func (s *Server) baselineTrustAcceptance(invite PairingInvite) (PairingAcceptance, error) {
	addresses := []string{strings.TrimRight(strings.TrimSpace(s.cfg.BaseURL), "/")}
	if err := NodeIdentity_ValidateAddresses(addresses); err != nil {
		return PairingAcceptance{}, errors.New("this node needs a reachable DAOCHI_BASE_URL")
	}
	acceptance := PairingAcceptance{
		Version:     1,
		InviteID:    invite.InviteID,
		NodeID:      s.node.ID,
		PublicKey:   hex.EncodeToString(s.node.PublicKey),
		DisplayName: s.cfg.NodeDisplayName,
		Addresses:   addresses,
		AcceptedAt:  time.Now().Unix(),
		Nonce:       NodeAuth_RandomHex(16),
	}
	NodeIdentity_SignAcceptance(s.node, invite, &acceptance)
	return acceptance, nil
}

func baselineTrustCompleteRemote(
	ctx context.Context,
	invite PairingInvite,
	acceptance PairingAcceptance,
) error {
	body, err := json.Marshal(completePairingRequest{
		Invite:     invite,
		Acceptance: acceptance,
	})
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	var lastError error
	for _, address := range invite.Addresses {
		target := strings.TrimRight(address, "/") + "/api/v1/node/pairing/complete"
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
		if err != nil {
			lastError = err
			continue
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			lastError = err
			continue
		}
		responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, 2048))
		response.Body.Close()
		if readErr != nil {
			lastError = readErr
			continue
		}
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			return nil
		}
		lastError = fmt.Errorf(
			"pairing completion failed: %s %s",
			response.Status,
			strings.TrimSpace(string(responseBody)),
		)
	}
	if lastError == nil {
		lastError = errors.New("invite has no reachable address")
	}
	return fmt.Errorf("could not complete pairing with inviter: %w", lastError)
}

func (s *Server) baselineTrustCompletePairing(w http.ResponseWriter, r *http.Request) {
	bodyResult := HttpBody_ReadJSON(w, r, s.cfg.MaxBodyBytes)
	body, err := bodyResult.Value, bodyResult.Error
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	var request completePairingRequest
	if err := json.Unmarshal(body, &request); err != nil {
		Response_Error(w, http.StatusBadRequest, "invalid pairing completion")
		return
	}
	if validated := NodeIdentity_ValidateInvite(request.Invite, time.Now()); validated.Error != nil {
		Response_Error(w, http.StatusBadRequest, validated.Error.Error())
		return
	}
	if request.Invite.NodeID != s.node.ID {
		Response_Error(w, http.StatusBadRequest, "pairing invite belongs to another node")
		return
	}
	publicKey := NodeIdentity_ValidateAcceptance(request.Invite, request.Acceptance, time.Now())
	if publicKey.Error != nil {
		Response_Error(w, http.StatusBadRequest, publicKey.Error.Error())
		return
	}
	if request.Acceptance.NodeID == s.node.ID {
		Response_Error(w, http.StatusBadRequest, "cannot pair a node with itself")
		return
	}
	if err := TrustStore_CompleteIssuedPairing(s.store.Database,
		r.Context(),
		request.Invite,
		request.Acceptance,
		publicKey.Value,
	); err != nil {
		Response_Error(w, http.StatusConflict, err.Error())
		return
	}
	Response_JSON(w, http.StatusOK, map[string]any{
		"status":  "paired",
		"node_id": request.Acceptance.NodeID,
	})
}

func (s *Server) baselineTrustListPeers(w http.ResponseWriter, r *http.Request) {
	if !HttpAuth_RequireLocalOperator(w, r, s.cfg.AdminToken) {
		return
	}
	listedPeers := TrustStore_ListTrustedPeers(s.store.Database, r.Context())
	peers, err := listedPeers.Value, listedPeers.Error
	if err != nil {
		Response_Error(w, http.StatusInternalServerError, "peer list failed")
		return
	}
	Response_JSON(w, http.StatusOK, map[string]any{"peers": peers})
}

func (s *Server) baselineTrustCreateSpace(w http.ResponseWriter, r *http.Request) {
	if !HttpAuth_RequireLocalOperator(w, r, s.cfg.AdminToken) {
		return
	}
	bodyResult := HttpBody_ReadJSON(w, r, s.cfg.MaxBodyBytes)
	body, err := bodyResult.Value, bodyResult.Error
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	var req struct {
		DisplayName string `json:"display_name"`
	}
	if err := json.Unmarshal(body, &req); err != nil || strings.TrimSpace(req.DisplayName) == "" {
		Response_Error(w, http.StatusBadRequest, "invalid trust space")
		return
	}
	displayName := strings.TrimSpace(req.DisplayName)
	createdSpace := TrustStore_CreateTrustSpace(s.store.Database, r.Context(), displayName)
	spaceID, err := createdSpace.Value, createdSpace.Error
	if err != nil {
		Response_Error(w, http.StatusInternalServerError, "trust space creation failed")
		return
	}
	Response_JSON(w, http.StatusCreated, map[string]any{
		"space_id":     spaceID,
		"display_name": displayName,
	})
}

func (s *Server) baselineTrustRegisterName(w http.ResponseWriter, r *http.Request) {
	if !HttpAuth_RequireLocalOperator(w, r, s.cfg.AdminToken) {
		return
	}
	bodyResult := HttpBody_ReadJSON(w, r, s.cfg.MaxBodyBytes)
	body, err := bodyResult.Value, bodyResult.Error
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	var claim NameClaim
	if err := json.Unmarshal(body, &claim); err != nil {
		Response_Error(w, http.StatusBadRequest, "invalid name claim")
		return
	}
	claim.SpaceID = strings.TrimSpace(claim.SpaceID)
	claim.Name = NodeIdentity_NormalizeName(claim.Name)
	claim.NodeID = strings.TrimSpace(claim.NodeID)
	if !Identity_ValidUserID(claim.SpaceID) || !NodeIdentity_ValidName(claim.Name) ||
		!Identity_ValidUserID(claim.NodeID) {
		Response_Error(w, http.StatusBadRequest, "invalid space, name, or node ID")
		return
	}
	if claim.ExpiresAt == 0 {
		claim.ExpiresAt = time.Now().Add(defaultNameLifetime).Unix()
	}
	remaining := time.Until(time.Unix(claim.ExpiresAt, 0))
	if remaining <= 0 || remaining > maximumNameLifetime {
		Response_Error(w, http.StatusBadRequest, "invalid name expiry")
		return
	}
	if err := TrustStore_ValidateServices(claim.Services); err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	signedClaim := TrustStore_SignAndStoreNameClaim(s.store.Database, r.Context(), claim)
	claim, err = signedClaim.Value, signedClaim.Error
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	Response_JSON(w, http.StatusOK, claim)
}

func (s *Server) baselineTrustResolveName(w http.ResponseWriter, r *http.Request) {
	spaceID := strings.TrimSpace(r.URL.Query().Get("space_id"))
	name := NodeIdentity_NormalizeName(r.URL.Query().Get("name"))
	if !Identity_ValidUserID(spaceID) || !NodeIdentity_ValidName(name) {
		Response_Error(w, http.StatusBadRequest, "invalid space or name")
		return
	}
	resolvedClaim := TrustStore_ResolveNameClaim(s.store.Database, r.Context(), spaceID, name)
	claim, found, err := resolvedClaim.Value, resolvedClaim.Found, resolvedClaim.Error
	if err != nil {
		Response_Error(w, http.StatusInternalServerError, "name resolution failed")
		return
	}
	if !found {
		Response_Error(w, http.StatusNotFound, "name not found")
		return
	}
	Response_JSON(w, http.StatusOK, map[string]any{
		"uri":         "daochi://" + spaceID + "/" + name,
		"claim":       claim,
		"ttl_seconds": claim.ExpiresAt - time.Now().Unix(),
	})
}

func baselineTrustInboundPolicy(policy NodeSyncPolicy) bool {
	if len(policy.Data) == 0 {
		return false
	}
	hasRecords := MeshPolicy_IncludesData(&policy, "encrypted_records") &&
		(len(policy.Apps) > 0 || len(policy.Collections) > 0)
	hasNames := MeshPolicy_IncludesData(&policy, "names") && len(policy.Spaces) > 0
	hasAppRegistry := MeshPolicy_IncludesData(&policy, "app_registry") && len(policy.Apps) > 0
	return hasRecords || hasNames || hasAppRegistry
}
