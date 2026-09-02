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
	UserIDHash string `json:"user_id_hash"`
	PublicKey  string `json:"public_key"`
	CreatedAt  string `json:"created_at,omitempty"`
	LastSeenAt string `json:"last_seen_at,omitempty"`
	Record     EncryptedRecord
}

type NodeMeshExportRequest struct {
	Cursor string         `json:"cursor,omitempty"`
	Limit  int            `json:"limit,omitempty"`
	Policy NodeSyncPolicy `json:"policy,omitempty"`
}

type NodeMeshExportResponse struct {
	Status     string                `json:"status"`
	Records    []MeshEncryptedRecord `json:"records"`
	NextCursor string                `json:"next_cursor,omitempty"`
	Truncated  bool                  `json:"truncated,omitempty"`
}

type NodeMeshImportRequest struct {
	Records []MeshEncryptedRecord `json:"records"`
	Policy  NodeSyncPolicy        `json:"policy,omitempty"`
}

type NodeMeshImportResponse struct {
	Status  string `json:"status"`
	Records int    `json:"records"`
	Applied int    `json:"applied"`
}

type meshCursor struct {
	UpdatedAt  string `json:"updated_at"`
	UserIDHash string `json:"user_id_hash"`
	Collection string `json:"collection"`
	ID         string `json:"id"`
}

func (s *Server) handleNodeMeshExport(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeNodeSync(w, r) {
		return
	}
	body, err := readJSONBody(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var req NodeMeshExportRequest
	if len(bytes.TrimSpace(body)) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid mesh export request")
			return
		}
	}
	limit := meshBatchLimit(req.Limit, s.cfg.NodeSyncBatchLimit)
	records, nextCursor, truncated, err := s.store.ExportMeshEncryptedRecords(r.Context(), req.Policy, req.Cursor, limit)
	if err != nil {
		slog.Error("mesh export", "error", err)
		writeError(w, http.StatusInternalServerError, "mesh export failed")
		return
	}
	writeJSON(w, http.StatusOK, NodeMeshExportResponse{
		Status:     "ok",
		Records:    records,
		NextCursor: nextCursor,
		Truncated:  truncated,
	})
}

func (s *Server) handleNodeMeshImport(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeNodeSync(w, r) {
		return
	}
	body, err := readJSONBody(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var req NodeMeshImportRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid mesh import request")
		return
	}
	applied, err := s.store.ImportMeshEncryptedRecords(r.Context(), req.Policy, req.Records)
	if err != nil {
		slog.Error("mesh import", "error", err)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, NodeMeshImportResponse{
		Status:  "ok",
		Records: len(req.Records),
		Applied: applied,
	})
}

func (s *Server) authorizeNodeSync(w http.ResponseWriter, r *http.Request) bool {
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
	if strings.TrimSpace(s.cfg.NodeSyncToken) == "" || s.cfg.NodeSyncInterval <= 0 {
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
	for _, peer := range s.cfg.KnownNodes {
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
		if err := s.postNodeMeshJSON(ctx, baseURL+"/api/v1/node/mesh/export", req, &exported); err != nil {
			return err
		}
		if len(exported.Records) == 0 {
			return nil
		}
		applied, err := s.store.ImportMeshEncryptedRecords(ctx, policy, exported.Records)
		if err != nil {
			return err
		}
		slog.Info("mesh peer pull applied records", "peer", peer.Name, "url", baseURL, "records", len(exported.Records), "applied", applied)
		lastCursor, err := meshCursorForRecord(exported.Records[len(exported.Records)-1])
		if err != nil {
			return err
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

func (s *Server) postNodeMeshJSON(ctx context.Context, target string, req any, resp any) error {
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+s.cfg.NodeSyncToken)
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
		return nodePolicyIncludesData(policy, "encrypted_records")
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

func meshCursorForRecord(record MeshEncryptedRecord) (string, error) {
	return encodeMeshCursor(meshCursor{
		UpdatedAt:  record.Record.UpdatedAt,
		UserIDHash: record.UserIDHash,
		Collection: record.Record.Collection,
		ID:         record.Record.ID,
	})
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
