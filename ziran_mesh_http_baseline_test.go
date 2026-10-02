// Original mesh orchestration from 9c61336, retained as an independent port oracle.
package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

func (s *Server) baselineMeshHandleNodeMeshExport(w http.ResponseWriter, r *http.Request) {
	bodyResult := HttpBody_ReadJSON(w, r, s.Cfg.MaxBodyBytes)
	body, err := bodyResult.Value, bodyResult.Error
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.baselineMeshAuthorizeNodeSync(w, r, body) {
		return
	}
	var req NodeMeshExportRequest
	if len(bytes.TrimSpace(body)) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			Response_Error(w, http.StatusBadRequest, "invalid mesh export request")
			return
		}
	}
	if !MeshPolicy_ValidInbound(req.Policy) {
		Response_Error(w, http.StatusBadRequest, "explicit mesh policy required")
		return
	}
	if !s.baselineMeshAuthorizeRequestedPolicy(w, r, req.Policy, "export") {
		return
	}
	exportedApps := MeshApps_Export(s.Store.Database, r.Context(), req.Policy)
	apps, err := exportedApps.Value, exportedApps.Error
	if err != nil {
		slog.Error("mesh app registry export", "error", err)
		Response_Error(w, http.StatusInternalServerError, "mesh app registry export failed")
		return
	}
	limit := MeshCursor_BatchLimit(req.Limit, s.Cfg.NodeSyncBatchLimit)
	exportedRecords := MeshStore_ExportEncryptedRecords(s.Store.Database, r.Context(), req.Policy, req.Cursor, limit)
	records, deletions, nextCursor, truncated, err := exportedRecords.Records, exportedRecords.Deletions, exportedRecords.NextCursor, exportedRecords.Truncated, exportedRecords.Error
	if err != nil {
		slog.Error("mesh export", "error", err)
		Response_Error(w, http.StatusInternalServerError, "mesh export failed")
		return
	}
	exportedNames := TrustStore_ExportMeshNames(s.Store.Database, r.Context(), req.Policy)
	spaces, names, err := exportedNames.Spaces, exportedNames.Names, exportedNames.Error
	if err != nil {
		slog.Error("mesh name export", "error", err)
		Response_Error(w, http.StatusInternalServerError, "mesh name export failed")
		return
	}
	Response_JSON(w, http.StatusOK, NodeMeshExportResponse{
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

func (s *Server) baselineMeshHandleNodeMeshImport(w http.ResponseWriter, r *http.Request) {
	bodyResult := HttpBody_ReadJSON(w, r, s.Cfg.MaxBodyBytes)
	body, err := bodyResult.Value, bodyResult.Error
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.baselineMeshAuthorizeNodeSync(w, r, body) {
		return
	}
	var req NodeMeshImportRequest
	if err := json.Unmarshal(body, &req); err != nil {
		Response_Error(w, http.StatusBadRequest, "invalid mesh import request")
		return
	}
	if !MeshPolicy_ValidInbound(req.Policy) {
		Response_Error(w, http.StatusBadRequest, "explicit mesh policy required")
		return
	}
	if !s.baselineMeshAuthorizeRequestedPolicy(w, r, req.Policy, "import") {
		return
	}
	importedApps := MeshApps_Import(s.Store.Database, r.Context(), s.Cfg.NodeRegistryPublicKey, req.Policy, req.Apps, baselineAuthenticationError)
	appCount, err := importedApps.Value, importedApps.Error
	if err != nil {
		slog.Error("mesh app registry import", "error", err)
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	importedRecords := MeshStore_ImportEncryptedBatch(s.Store.Database, r.Context(), req.Policy, req.Records, req.Deletions)
	applied, err := importedRecords.Value, importedRecords.Error
	if err != nil {
		slog.Error("mesh import", "error", err)
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	importedNames := TrustStore_ImportMeshNames(s.Store.Database, r.Context(), req.Policy, req.Spaces, req.Names)
	nameCount, err := importedNames.Value, importedNames.Error
	if err != nil {
		slog.Error("mesh name import", "error", err)
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	Response_JSON(w, http.StatusOK, NodeMeshImportResponse{
		Status:  "ok",
		Records: len(req.Apps) + len(req.Records) + len(req.Deletions) + len(req.Names),
		Applied: appCount + applied + nameCount,
	})
}

func (s *Server) baselineMeshAuthorizeNodeSync(w http.ResponseWriter, r *http.Request, body []byte) bool {
	if nodeID := strings.TrimSpace(r.Header.Get("X-Daochi-Node-ID")); nodeID != "" {
		if err := NodeAuth_Verify(s.Store.Database, r.Context(), r, body); err != nil {
			Response_Error(w, http.StatusUnauthorized, err.Error())
			return false
		}
		return true
	}
	token := strings.TrimSpace(s.Cfg.NodeSyncToken)
	if token == "" {
		Response_Error(w, http.StatusServiceUnavailable, "node sync disabled")
		return false
	}
	got := strings.TrimSpace(HttpAuth_HeaderAlias(r, []string{"X-Daochi-Node-Token", "X-Ksync-Node-Token"}))
	if got == "" {
		got = baselineMeshBearerToken(r.Header.Get("Authorization"))
	}
	if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
		Response_Error(w, http.StatusUnauthorized, "invalid node token")
		return false
	}
	return true
}

func (s *Server) baselineMeshAuthorizeRequestedPolicy(
	w http.ResponseWriter,
	r *http.Request,
	requested NodeSyncPolicy,
	operation string,
) bool {
	nodeID := strings.TrimSpace(r.Header.Get("X-Daochi-Node-ID"))
	if nodeID == "" {
		return true
	}
	trustedPolicy := TrustStore_TrustedPeerPolicy(s.Store.Database, r.Context(), nodeID)
	approved, found, err := trustedPolicy.Value, trustedPolicy.Found, trustedPolicy.Error
	if err != nil {
		Response_Error(w, http.StatusInternalServerError, "peer policy lookup failed")
		return false
	}
	if !found || !MeshPolicy_AllowsOperation(approved, requested, operation) {
		Response_Error(w, http.StatusForbidden, "requested mesh policy exceeds paired scope")
		return false
	}
	return true
}

func baselineMeshBearerToken(header string) string {
	if before, after, ok := strings.Cut(strings.TrimSpace(header), " "); ok && strings.EqualFold(before, "Bearer") {
		return strings.TrimSpace(after)
	}
	return ""
}

func (s *Server) baselineMeshRunNodeSync(ctx context.Context) {
	if s.Cfg.NodeSyncInterval <= 0 {
		return
	}
	ticker := time.NewTicker(s.Cfg.NodeSyncInterval)
	defer ticker.Stop()
	s.baselineMeshPullConfiguredNodePeers(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.baselineMeshPullConfiguredNodePeers(ctx)
		}
	}
}

func (s *Server) baselineMeshPullConfiguredNodePeers(ctx context.Context) {
	peers := append([]NodePeer(nil), s.Cfg.KnownNodes...)
	listedPeers := TrustStore_ListTrustedPeers(s.Store.Database, ctx)
	trusted, err := listedPeers.Value, listedPeers.Error
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
		if !MeshPolicy_AllowsPull(peer.Sync) {
			continue
		}
		if err := s.baselineMeshPullNodePeer(ctx, peer); err != nil {
			slog.Warn("mesh peer pull failed", "peer", peer.Name, "url", peer.URL, "error", err)
		}
	}
}

func (s *Server) baselineMeshPullNodePeer(ctx context.Context, peer NodePeer) error {
	baseURL := strings.TrimRight(strings.TrimSpace(peer.URL), "/")
	if baseURL == "" {
		return nil
	}
	policy := baselineMeshEffectiveNodeSyncPolicy(peer.Sync)
	peerKey := MeshCursor_PeerKey(baseURL, policy)
	loadedCursor := MeshStore_LoadCursor(s.Store.Database, ctx, peerKey)
	cursor, err := loadedCursor.Value, loadedCursor.Error
	if err != nil {
		return err
	}
	for {
		req := NodeMeshExportRequest{
			Cursor: cursor,
			Limit:  MeshCursor_BatchLimit(0, s.Cfg.NodeSyncBatchLimit),
			Policy: policy,
		}
		var exported NodeMeshExportResponse
		if err := s.baselineMeshPostNodeMeshJSON(ctx, peer.NodeID, baseURL+"/api/v1/node/mesh/export", req, &exported); err != nil {
			return err
		}
		if len(exported.Apps) == 0 && len(exported.Records) == 0 && len(exported.Deletions) == 0 &&
			len(exported.Names) == 0 {
			return nil
		}
		importedApps := MeshApps_Import(s.Store.Database, ctx, s.Cfg.NodeRegistryPublicKey, policy, exported.Apps, baselineAuthenticationError)
		appCount, err := importedApps.Value, importedApps.Error
		if err != nil {
			return err
		}
		importedRecords := MeshStore_ImportEncryptedBatch(s.Store.Database, ctx, policy, exported.Records, exported.Deletions)
		applied, err := importedRecords.Value, importedRecords.Error
		if err != nil {
			return err
		}
		importedNames := TrustStore_ImportMeshNames(s.Store.Database, ctx, policy, exported.Spaces, exported.Names)
		nameCount, err := importedNames.Value, importedNames.Error
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
			encodedCursor := MeshCursor_Encode(MeshCursor{Seq: lastSeq})
			lastCursor, err = encodedCursor.Value, encodedCursor.Error
			if err != nil {
				return err
			}
		}
		if err := MeshStore_SaveCursor(s.Store.Database, ctx, peerKey, lastCursor); err != nil {
			return err
		}
		if !exported.Truncated || exported.NextCursor == "" {
			return nil
		}
		cursor = exported.NextCursor
	}
}

func (s *Server) baselineMeshPostNodeMeshJSON(ctx context.Context, peerNodeID, target string, req any, resp any) error {
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
		NodeAuth_Sign(s.Node.ID, s.Node.PrivateKey, httpReq, body)
	} else {
		httpReq.Header.Set("Authorization", "Bearer "+s.Cfg.NodeSyncToken)
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

func baselineMeshEffectiveNodeSyncPolicy(policy *NodeSyncPolicy) NodeSyncPolicy {
	if policy == nil {
		return NodeSyncPolicy{}
	}
	return *policy
}
