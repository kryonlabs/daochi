package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const (
	defaultNodeSyncBatchLimit = 500
	maxNodeSyncBatchLimit     = 2000
)

type MeshEncryptedRecord struct {
	UserIDHash  string `json:"user_id_hash"`
	PublicKey   string `json:"public_key"`
	CreatedAt   string `json:"created_at,omitempty"`
	LastSeenAt  string `json:"last_seen_at,omitempty"`
	MeshVersion int64  `json:"mesh_version,omitempty"`
	Record      EncryptedRecord
}

// MeshEncryptedRecordDeletion is a tombstone for a record removed on a
// peer node. It rides in a separate payload field so older nodes that do
// not understand deletions keep working unchanged.
type MeshEncryptedRecordDeletion struct {
	UserIDHash  string `json:"user_id_hash"`
	Collection  string `json:"collection"`
	ID          string `json:"id"`
	DeletedAt   string `json:"deleted_at"`
	MeshVersion int64  `json:"mesh_version,omitempty"`
}

type NodeMeshExportRequest struct {
	Cursor string         `json:"cursor,omitempty"`
	Limit  int            `json:"limit,omitempty"`
	Policy NodeSyncPolicy `json:"policy,omitempty"`
}

type NodeMeshExportResponse struct {
	Status     string                         `json:"status"`
	Apps       []SignedAppRegistrationRequest `json:"apps,omitempty"`
	Records    []MeshEncryptedRecord          `json:"records"`
	Deletions  []MeshEncryptedRecordDeletion  `json:"deletions,omitempty"`
	Spaces     []MeshTrustSpace               `json:"spaces,omitempty"`
	Names      []NameClaim                    `json:"names,omitempty"`
	NextCursor string                         `json:"next_cursor,omitempty"`
	Truncated  bool                           `json:"truncated,omitempty"`
}

type NodeMeshImportRequest struct {
	Apps      []SignedAppRegistrationRequest `json:"apps,omitempty"`
	Records   []MeshEncryptedRecord          `json:"records"`
	Deletions []MeshEncryptedRecordDeletion  `json:"deletions,omitempty"`
	Spaces    []MeshTrustSpace               `json:"spaces,omitempty"`
	Names     []NameClaim                    `json:"names,omitempty"`
	Policy    NodeSyncPolicy                 `json:"policy,omitempty"`
}

type NodeMeshImportResponse struct {
	Status  string `json:"status"`
	Records int    `json:"records"`
	Applied int    `json:"applied"`
}

type meshCursor struct {
	Seq        int64  `json:"seq,omitempty"`
	UpdatedAt  string `json:"updated_at"`
	UserIDHash string `json:"user_id_hash"`
	Collection string `json:"collection"`
	ID         string `json:"id"`
}

func (s *Server) handleNodeMeshExport(w http.ResponseWriter, r *http.Request) {
	body, err := readJSONBody(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.authorizeNodeSync(w, r, body) {
		return
	}
	var req NodeMeshExportRequest
	if len(bytes.TrimSpace(body)) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid mesh export request")
			return
		}
	}
	if !validInboundMeshPolicy(req.Policy) {
		writeError(w, http.StatusBadRequest, "explicit mesh policy required")
		return
	}
	if !s.authorizeRequestedPolicy(w, r, req.Policy, "export") {
		return
	}
	apps, err := s.store.ExportMeshApps(r.Context(), req.Policy)
	if err != nil {
		slog.Error("mesh app registry export", "error", err)
		writeError(w, http.StatusInternalServerError, "mesh app registry export failed")
		return
	}
	limit := meshBatchLimit(req.Limit, s.cfg.NodeSyncBatchLimit)
	records, deletions, nextCursor, truncated, err := s.store.ExportMeshEncryptedRecords(r.Context(), req.Policy, req.Cursor, limit)
	if err != nil {
		slog.Error("mesh export", "error", err)
		writeError(w, http.StatusInternalServerError, "mesh export failed")
		return
	}
	spaces, names, err := s.store.ExportMeshNames(r.Context(), req.Policy)
	if err != nil {
		slog.Error("mesh name export", "error", err)
		writeError(w, http.StatusInternalServerError, "mesh name export failed")
		return
	}
	writeJSON(w, http.StatusOK, NodeMeshExportResponse{
		Status:     "ok",
		Apps:       apps,
		Records:    records,
		Deletions:  deletions,
		Spaces:     spaces,
		Names:      names,
		NextCursor: nextCursor,
		Truncated:  truncated,
	})
}

func (s *Server) handleNodeMeshImport(w http.ResponseWriter, r *http.Request) {
	body, err := readJSONBody(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.authorizeNodeSync(w, r, body) {
		return
	}
	var req NodeMeshImportRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid mesh import request")
		return
	}
	if !validInboundMeshPolicy(req.Policy) {
		writeError(w, http.StatusBadRequest, "explicit mesh policy required")
		return
	}
	if !s.authorizeRequestedPolicy(w, r, req.Policy, "import") {
		return
	}
	appCount, err := s.ImportMeshApps(r.Context(), req.Policy, req.Apps)
	if err != nil {
		slog.Error("mesh app registry import", "error", err)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	applied, err := s.store.ImportMeshEncryptedBatch(r.Context(), req.Policy, req.Records, req.Deletions)
	if err != nil {
		slog.Error("mesh import", "error", err)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	nameCount, err := s.store.ImportMeshNames(r.Context(), req.Policy, req.Spaces, req.Names)
	if err != nil {
		slog.Error("mesh name import", "error", err)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, NodeMeshImportResponse{
		Status:  "ok",
		Records: len(req.Apps) + len(req.Records) + len(req.Deletions) + len(req.Names),
		Applied: appCount + applied + nameCount,
	})
}

func (s *Server) authorizeNodeSync(w http.ResponseWriter, r *http.Request, body []byte) bool {
	if nodeID := strings.TrimSpace(r.Header.Get("X-Daochi-Node-ID")); nodeID != "" {
		if err := s.verifyNodeRequest(r.Context(), r, body); err != nil {
			writeError(w, http.StatusUnauthorized, err.Error())
			return false
		}
		return true
	}
	token := strings.TrimSpace(s.cfg.NodeSyncToken)
	if token == "" {
		writeError(w, http.StatusServiceUnavailable, "node sync disabled")
		return false
	}
	got := strings.TrimSpace(requestHeaderAlias(r, "X-Daochi-Node-Token", "X-Ksync-Node-Token"))
	if got == "" {
		got = bearerToken(r.Header.Get("Authorization"))
	}
	if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
		writeError(w, http.StatusUnauthorized, "invalid node token")
		return false
	}
	return true
}

func (s *Server) authorizeRequestedPolicy(
	w http.ResponseWriter,
	r *http.Request,
	requested NodeSyncPolicy,
	operation string,
) bool {
	nodeID := strings.TrimSpace(r.Header.Get("X-Daochi-Node-ID"))
	if nodeID == "" {
		return true
	}
	approved, found, err := s.store.TrustedPeerPolicy(r.Context(), nodeID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "peer policy lookup failed")
		return false
	}
	if !found || !policyAllowsOperation(approved, requested, operation) {
		writeError(w, http.StatusForbidden, "requested mesh policy exceeds paired scope")
		return false
	}
	return true
}

func policyAllowsOperation(approved, requested NodeSyncPolicy, operation string) bool {
	direction := strings.ToLower(strings.TrimSpace(approved.Direction))
	if operation == "export" && direction != "push" && direction != "bidirectional" {
		return false
	}
	if operation == "import" && direction != "pull" && direction != "bidirectional" {
		return false
	}
	return stringSetContains(approved.Apps, requested.Apps) &&
		stringSetContains(approved.Collections, requested.Collections) &&
		stringSetContains(approved.Spaces, requested.Spaces) &&
		stringSetContains(approved.Data, requested.Data)
}

func stringSetContains(approved, requested []string) bool {
	if len(requested) == 0 {
		return true
	}
	allowed := make(map[string]bool, len(approved))
	for _, value := range approved {
		allowed[strings.ToLower(strings.TrimSpace(value))] = true
	}
	for _, value := range requested {
		if !allowed[strings.ToLower(strings.TrimSpace(value))] {
			return false
		}
	}
	return true
}

func bearerToken(header string) string {
	if before, after, ok := strings.Cut(strings.TrimSpace(header), " "); ok && strings.EqualFold(before, "Bearer") {
		return strings.TrimSpace(after)
	}
	return ""
}

func meshBatchLimit(requested, configured int) int {
	limit := configured
	if limit <= 0 {
		limit = defaultNodeSyncBatchLimit
	}
	if requested > 0 && requested < limit {
		limit = requested
	}
	if limit > maxNodeSyncBatchLimit {
		return maxNodeSyncBatchLimit
	}
	return limit
}

func (s *Server) runNodeSync(ctx context.Context) {
	if s.cfg.NodeSyncInterval <= 0 {
		return
	}
	ticker := time.NewTicker(s.cfg.NodeSyncInterval)
	defer ticker.Stop()
	s.pullConfiguredNodePeers(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.pullConfiguredNodePeers(ctx)
		}
	}
}

func (s *Server) pullConfiguredNodePeers(ctx context.Context) {
	peers := append([]NodePeer(nil), s.cfg.KnownNodes...)
	trusted, err := s.store.ListTrustedPeers(ctx)
	if err != nil {
		slog.Warn("load paired mesh peers", "error", err)
	}
	for _, item := range trusted {
		if len(item.Addresses) > 0 {
			policy := item.Policy
			peers = append(peers, NodePeer{
				Name:   item.DisplayName,
				URL:    item.Addresses[0],
				NodeID: item.NodeID,
				Sync:   &policy,
			})
		}
	}
	for _, peer := range peers {
		if !nodePolicyAllowsPull(peer.Sync) {
			continue
		}
		if err := s.pullNodePeer(ctx, peer); err != nil {
			slog.Warn("mesh peer pull failed", "peer", peer.Name, "url", peer.URL, "error", err)
		}
	}
}

func (s *Server) pullNodePeer(ctx context.Context, peer NodePeer) error {
	baseURL := strings.TrimRight(strings.TrimSpace(peer.URL), "/")
	if baseURL == "" {
		return nil
	}
	policy := effectiveNodeSyncPolicy(peer.Sync)
	peerKey := meshPeerCursorKey(baseURL, policy)
	cursor, err := s.store.LoadNodeSyncCursor(ctx, peerKey)
	if err != nil {
		return err
	}
	for {
		req := NodeMeshExportRequest{
			Cursor: cursor,
			Limit:  meshBatchLimit(0, s.cfg.NodeSyncBatchLimit),
			Policy: policy,
		}
		var exported NodeMeshExportResponse
		if err := s.postNodeMeshJSON(ctx, peer.NodeID, baseURL+"/api/v1/node/mesh/export", req, &exported); err != nil {
			return err
		}
		if len(exported.Apps) == 0 && len(exported.Records) == 0 && len(exported.Deletions) == 0 &&
			len(exported.Names) == 0 {
			return nil
		}
		appCount, err := s.ImportMeshApps(ctx, policy, exported.Apps)
		if err != nil {
			return err
		}
		applied, err := s.store.ImportMeshEncryptedBatch(ctx, policy, exported.Records, exported.Deletions)
		if err != nil {
			return err
		}
		nameCount, err := s.store.ImportMeshNames(ctx, policy, exported.Spaces, exported.Names)
		if err != nil {
			return err
		}
		slog.Info("mesh peer pull applied changes", "peer", peer.Name, "url", baseURL,
			"apps", len(exported.Apps),
			"records", len(exported.Records), "deletions", len(exported.Deletions),
			"names", len(exported.Names), "applied", appCount+applied+nameCount)
		lastCursor := exported.NextCursor
		if lastCursor == "" {
			lastSeq := int64(0)
			for _, record := range exported.Records {
				if record.MeshVersion > lastSeq {
					lastSeq = record.MeshVersion
				}
			}
			for _, deletion := range exported.Deletions {
				if deletion.MeshVersion > lastSeq {
					lastSeq = deletion.MeshVersion
				}
			}
			lastCursor, err = encodeMeshCursor(meshCursor{Seq: lastSeq})
			if err != nil {
				return err
			}
		}
		if err := s.store.SaveNodeSyncCursor(ctx, peerKey, lastCursor); err != nil {
			return err
		}
		if !exported.Truncated || exported.NextCursor == "" {
			return nil
		}
		cursor = exported.NextCursor
	}
}

func (s *Server) postNodeMeshJSON(ctx context.Context, peerNodeID, target string, req any, resp any) error {
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if peerNodeID != "" {
		s.signNodeRequest(httpReq, body)
	} else {
		httpReq.Header.Set("Authorization", "Bearer "+s.cfg.NodeSyncToken)
	}
	client := &http.Client{Timeout: 20 * time.Second}
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return err
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(httpResp.Body, 2048))
		return fmt.Errorf("node mesh request failed: %s %s", httpResp.Status, strings.TrimSpace(string(data)))
	}
	if err := json.NewDecoder(httpResp.Body).Decode(resp); err != nil {
		return err
	}
	return nil
}

func nodePolicyAllowsPull(policy *NodeSyncPolicy) bool {
	if policy == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(policy.Direction)) {
	case "pull", "bidirectional":
		return nodePolicyIncludesData(policy, "encrypted_records") ||
			nodePolicyIncludesData(policy, "names") ||
			nodePolicyIncludesData(policy, "app_registry")
	default:
		return false
	}
}

func effectiveNodeSyncPolicy(policy *NodeSyncPolicy) NodeSyncPolicy {
	if policy == nil {
		return NodeSyncPolicy{}
	}
	return *policy
}

func meshPeerCursorKey(baseURL string, policy NodeSyncPolicy) string {
	body, _ := json.Marshal(policy)
	sum := sha256.Sum256([]byte(strings.TrimRight(baseURL, "/") + "\x00" + string(body)))
	return hex.EncodeToString(sum[:])
}

func nodePolicyIncludesData(policy *NodeSyncPolicy, dataType string) bool {
	if policy == nil || len(policy.Data) == 0 {
		return true
	}
	for _, item := range policy.Data {
		if strings.EqualFold(strings.TrimSpace(item), dataType) {
			return true
		}
	}
	return false
}

func validInboundMeshPolicy(policy NodeSyncPolicy) bool {
	if len(policy.Data) == 0 {
		return false
	}
	hasRecords := nodePolicyIncludesData(&policy, "encrypted_records") &&
		(len(policy.Apps) > 0 || len(policy.Collections) > 0)
	hasNames := nodePolicyIncludesData(&policy, "names") && len(policy.Spaces) > 0
	hasAppRegistry := nodePolicyIncludesData(&policy, "app_registry") && len(policy.Apps) > 0
	return hasRecords || hasNames || hasAppRegistry
}

func encodeMeshCursor(cursor meshCursor) (string, error) {
	data, err := json.Marshal(cursor)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func decodeMeshCursor(raw string) (meshCursor, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return meshCursor{}, nil
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return meshCursor{}, errors.New("invalid mesh cursor")
	}
	var cursor meshCursor
	if err := json.Unmarshal(data, &cursor); err != nil {
		return meshCursor{}, errors.New("invalid mesh cursor")
	}
	return cursor, nil
}
