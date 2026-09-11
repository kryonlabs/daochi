package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultInviteLifetime = 10 * time.Minute
	maximumInviteLifetime = 24 * time.Hour
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

func (s *Server) requireLocalOperator(w http.ResponseWriter, r *http.Request) bool {
	if s.cfg.AdminToken != "" {
		return s.requireAdmin(w, r)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		writeError(w, http.StatusForbidden,
			"administration requires loopback access or DAOCHI_ADMIN_TOKEN")
		return false
	}
	return true
}

func (s *Server) handleCreatePairingInvite(w http.ResponseWriter, r *http.Request) {
	if !s.requireLocalOperator(w, r) {
		return
	}
	body, err := readJSONBody(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var req createInviteRequest
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid pairing invite request")
			return
		}
	}

	lifetime := defaultInviteLifetime
	if req.ExpiresIn > 0 {
		lifetime = time.Duration(req.ExpiresIn) * time.Second
	}
	if lifetime > maximumInviteLifetime {
		writeError(w, http.StatusBadRequest, "pairing invite expiry exceeds 24 hours")
		return
	}
	req.Policy.Direction = normalizeNodeSyncDirection(req.Policy.Direction)
	if !validPairingPolicy(req.Policy) {
		writeError(w, http.StatusBadRequest, "explicit pairing policy required")
		return
	}
	addresses := req.Addresses
	if len(addresses) == 0 && strings.TrimSpace(s.cfg.BaseURL) != "" {
		addresses = []string{strings.TrimRight(s.cfg.BaseURL, "/")}
	}
	if err := validateHTTPAddresses(addresses); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	invite := PairingInvite{
		Version:     1,
		InviteID:    randomHex(16),
		NodeID:      s.node.ID,
		PublicKey:   hex.EncodeToString(s.node.PublicKey),
		DisplayName: defaultString(strings.TrimSpace(req.DisplayName), s.cfg.NodeDisplayName),
		Addresses:   addresses,
		SpaceID:     strings.TrimSpace(req.SpaceID),
		ExpiresAt:   time.Now().Add(lifetime).Unix(),
		Nonce:       randomHex(16),
		Policy:      req.Policy,
	}
	s.node.signInvite(&invite)
	if err := s.store.RecordIssuedPairingInvite(r.Context(), invite); err != nil {
		writeError(w, http.StatusInternalServerError, "pairing invite creation failed")
		return
	}
	writeJSON(w, http.StatusOK, invite)
}

func validPairingPolicy(policy NodeSyncPolicy) bool {
	switch strings.ToLower(strings.TrimSpace(policy.Direction)) {
	case "pull", "push", "bidirectional":
		return validInboundMeshPolicy(policy)
	default:
		return false
	}
}

func validateHTTPAddresses(addresses []string) error {
	if len(addresses) == 0 {
		return errors.New("at least one reachable address is required")
	}
	for _, address := range addresses {
		parsed, err := url.Parse(address)
		if err != nil || parsed.Host == "" ||
			(parsed.Scheme != "http" && parsed.Scheme != "https") {
			return errors.New("invalid pairing address")
		}
	}
	return nil
}

func (s *Server) handleAcceptPairingInvite(w http.ResponseWriter, r *http.Request) {
	if !s.requireLocalOperator(w, r) {
		return
	}
	body, err := readJSONBody(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var invite PairingInvite
	if err := json.Unmarshal(body, &invite); err != nil {
		writeError(w, http.StatusBadRequest, "invalid pairing invite")
		return
	}
	publicKey, err := validatePairingInvite(invite, time.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if invite.NodeID == s.node.ID {
		writeError(w, http.StatusBadRequest, "cannot pair a node with itself")
		return
	}
	acceptance, err := s.newPairingAcceptance(invite)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := completeRemotePairing(r.Context(), invite, acceptance); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if err := s.store.TrustPeer(r.Context(), invite, publicKey); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "paired",
		"node_id": invite.NodeID,
	})
}

func (s *Server) newPairingAcceptance(invite PairingInvite) (PairingAcceptance, error) {
	addresses := []string{strings.TrimRight(strings.TrimSpace(s.cfg.BaseURL), "/")}
	if err := validateHTTPAddresses(addresses); err != nil {
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
		Nonce:       randomHex(16),
	}
	s.node.signAcceptance(invite, &acceptance)
	return acceptance, nil
}

func completeRemotePairing(
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

func (s *Server) handleCompletePairing(w http.ResponseWriter, r *http.Request) {
	body, err := readJSONBody(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var request completePairingRequest
	if err := json.Unmarshal(body, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid pairing completion")
		return
	}
	if _, err := validatePairingInvite(request.Invite, time.Now()); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if request.Invite.NodeID != s.node.ID {
		writeError(w, http.StatusBadRequest, "pairing invite belongs to another node")
		return
	}
	publicKey, err := validatePairingAcceptance(request.Invite, request.Acceptance, time.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if request.Acceptance.NodeID == s.node.ID {
		writeError(w, http.StatusBadRequest, "cannot pair a node with itself")
		return
	}
	if err := s.store.CompleteIssuedPairing(
		r.Context(),
		request.Invite,
		request.Acceptance,
		publicKey,
	); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "paired",
		"node_id": request.Acceptance.NodeID,
	})
}

func (s *Server) handleListTrustedPeers(w http.ResponseWriter, r *http.Request) {
	if !s.requireLocalOperator(w, r) {
		return
	}
	peers, err := s.store.ListTrustedPeers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "peer list failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"peers": peers})
}

func (s *Server) handleCreateTrustSpace(w http.ResponseWriter, r *http.Request) {
	if !s.requireLocalOperator(w, r) {
		return
	}
	body, err := readJSONBody(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var req struct {
		DisplayName string `json:"display_name"`
	}
	if err := json.Unmarshal(body, &req); err != nil || strings.TrimSpace(req.DisplayName) == "" {
		writeError(w, http.StatusBadRequest, "invalid trust space")
		return
	}
	displayName := strings.TrimSpace(req.DisplayName)
	spaceID, err := s.store.CreateTrustSpace(r.Context(), displayName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "trust space creation failed")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"space_id":     spaceID,
		"display_name": displayName,
	})
}

func (s *Server) handleRegisterNameClaim(w http.ResponseWriter, r *http.Request) {
	if !s.requireLocalOperator(w, r) {
		return
	}
	body, err := readJSONBody(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var claim NameClaim
	if err := json.Unmarshal(body, &claim); err != nil {
		writeError(w, http.StatusBadRequest, "invalid name claim")
		return
	}
	claim.SpaceID = strings.TrimSpace(claim.SpaceID)
	claim.Name = normalizeName(claim.Name)
	claim.NodeID = strings.TrimSpace(claim.NodeID)
	if !validUserID(claim.SpaceID) || !namePattern.MatchString(claim.Name) ||
		!validUserID(claim.NodeID) {
		writeError(w, http.StatusBadRequest, "invalid space, name, or node ID")
		return
	}
	if claim.ExpiresAt == 0 {
		claim.ExpiresAt = time.Now().Add(defaultNameLifetime).Unix()
	}
	remaining := time.Until(time.Unix(claim.ExpiresAt, 0))
	if remaining <= 0 || remaining > maximumNameLifetime {
		writeError(w, http.StatusBadRequest, "invalid name expiry")
		return
	}
	if err := validateServices(claim.Services); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	claim, err = s.store.SignAndStoreNameClaim(r.Context(), claim)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, claim)
}

func validateServices(services []ServiceRecord) error {
	for _, service := range services {
		if !namePattern.MatchString(normalizeName(service.Service)) {
			return errors.New("invalid service name")
		}
		if err := validateHTTPAddresses(service.Endpoints); err != nil {
			return errors.New("invalid service endpoint")
		}
	}
	return nil
}

func (s *Server) handleResolveName(w http.ResponseWriter, r *http.Request) {
	spaceID := strings.TrimSpace(r.URL.Query().Get("space_id"))
	name := normalizeName(r.URL.Query().Get("name"))
	if !validUserID(spaceID) || !namePattern.MatchString(name) {
		writeError(w, http.StatusBadRequest, "invalid space or name")
		return
	}
	claim, found, err := s.store.ResolveNameClaim(r.Context(), spaceID, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "name resolution failed")
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "name not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"uri":         "daochi://" + spaceID + "/" + name,
		"claim":       claim,
		"ttl_seconds": claim.ExpiresAt - time.Now().Unix(),
	})
}
