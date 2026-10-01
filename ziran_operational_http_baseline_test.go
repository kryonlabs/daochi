package main

// Original operational HTTP handlers at 6cd0e7e.
import (
	"context"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const baselineOpsRecentWindowDays = 30
const baselineOpsConnectionLimitPerUser = 8

var baselineOpsCapabilities = []string{
	"aliases",
	"friends",
	"v3-typed-sync",
	"v4-encrypted-records",
	"v4-dual-write-transition",
	"v5-encrypted-primary",
	"v5-private-hierarchy",
	"v5-dual-read",
	"v5-legacy-encrypted-collections",
	"protocol-v1-v5-valid-through-2027-09-01",
	"protocol-previous-version-grace-days-365",
	"v6-signed-transactions",
	"v6-signed-app-manifests",
	"profile-stats",
	"pub-relay",
	"node-mesh-encrypted-records",
	"node-identity-v1",
	"node-pairing-v1",
	"trust-space-names-v1",
	"monero-account-addresses",
	"monero-gifts",
}

func (s *Server) baselineOpsHandleHealth(w http.ResponseWriter, r *http.Request) {
	Response_JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) baselineOpsHandleReady(w http.ResponseWriter, r *http.Request) {
	checks := map[string]string{
		"database":     "ok",
		"token_secret": "ok",
		"verifier":     "ok",
		"token_issuer": TokenPolicy_IssuerStatus(s.cfg),
	}
	status := http.StatusOK
	if s.cfg.TokenSecretEphemeral || len(s.cfg.TokenSecret) < 32 {
		checks["token_secret"] = "ephemeral"
		status = http.StatusServiceUnavailable
	}
	if s.verifier == nil {
		checks["verifier"] = "missing"
		status = http.StatusServiceUnavailable
	}
	if s.cfg.TokenDirectPurchasesEnabled {
		checks["token_direct_purchases"] = "ok"
		if TokenPolicy_IssuerStatus(s.cfg) != "ok" {
			checks["token_direct_purchases"] = "issuer_private_key_missing"
			status = http.StatusServiceUnavailable
		} else if !TokenPolicy_HasMoneroProduct(s.cfg.TokenProducts) && !MoneroWallet_ValidRate(s.cfg) {
			checks["token_direct_purchases"] = "monero_rate_or_product_missing"
			status = http.StatusServiceUnavailable
		} else if strings.TrimSpace(s.cfg.MoneroWalletRPCURL) == "" {
			checks["token_direct_purchases"] = "monero_wallet_rpc_missing"
			status = http.StatusServiceUnavailable
		}
	}
	if err := s.store.Health(r.Context()); err != nil {
		checks["database"] = err.Error()
		status = http.StatusServiceUnavailable
	}
	Response_JSON(w, status, map[string]any{
		"status": baselineOpsStatusText(status == http.StatusOK),
		"checks": checks,
	})
}

func (s *Server) baselineOpsHandleNodeInfo(w http.ResponseWriter, r *http.Request) {
	knownNodes := s.cfg.KnownNodes
	if knownNodes == nil {
		knownNodes = []NodePeer{}
	}
	usage, err := s.baselineOpsNodeUsage(r.Context())
	if err != nil {
		slog.Error("load node usage", "error", err)
		Response_Error(w, http.StatusInternalServerError, "node usage failed")
		return
	}
	storage, err := s.store.NodeStorageUsage(r.Context())
	if err != nil {
		slog.Error("load node storage usage", "error", err)
		Response_Error(w, http.StatusInternalServerError, "node storage usage failed")
		return
	}
	Response_JSON(w, http.StatusOK, map[string]any{
		"status":          "ok",
		"node_id":         s.node.ID,
		"node_public_key": hex.EncodeToString(s.node.PublicKey),
		"node_name":       s.cfg.NodeDisplayName,
		"base_url":        strings.TrimSpace(s.cfg.BaseURL),
		"capabilities":    baselineOpsCapabilities,
		"known_nodes":     knownNodes,
		"usage":           usage,
		"storage":         storage,
		"protocol": map[string]int{
			"min_supported": MinSupportedProtocol,
			"latest":        LatestProtocol,
		},
	})
}

func (s *Server) baselineOpsHandleMetrics(w http.ResponseWriter, r *http.Request) {
	// Metrics expose user counts, traffic, and topology; when an admin
	// token is configured, require it. Deployments without one keep the
	// historical public endpoint (health checks use /healthz and /readyz).
	if s.cfg.AdminToken != "" && !HttpAuth_RequireAdmin(w, r, s.cfg.AdminToken) {
		return
	}
	usage, err := s.baselineOpsNodeUsage(r.Context())
	if err != nil {
		slog.Error("load metrics usage", "error", err)
		usage = NodeUsage{RecentActivityWindowDays: baselineOpsRecentWindowDays}
		stats := SyncHub_Stats(s.syncHub)
		usage.ConnectedUsers = stats.Users
		usage.ConnectedWebSocketClients = stats.Connections
		usage.WebSocketConnectionLimitPerUser = baselineOpsConnectionLimitPerUser
	}
	storage, err := s.store.NodeStorageUsage(r.Context())
	if err != nil {
		slog.Error("load metrics storage usage", "error", err)
	}
	Metrics_Prometheus(s.metrics, w, usage, storage, BuildVersion)
}

func (s *Server) baselineOpsNodeUsage(ctx context.Context) (NodeUsage, error) {
	usage, err := s.store.NodeUsage(ctx, time.Now())
	if err != nil {
		return NodeUsage{}, err
	}
	stats := SyncHub_Stats(s.syncHub)
	usage.ConnectedUsers = stats.Users
	usage.ConnectedWebSocketClients = stats.Connections
	usage.RecentActivityWindowDays = baselineOpsRecentWindowDays
	usage.WebSocketConnectionLimitPerUser = baselineOpsConnectionLimitPerUser
	return usage, nil
}

func (s *Server) baselineOpsHandleSyncDiagnostics(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	report, err := s.store.SyncDiagnosticReport(r.Context(), userID)
	if err != nil {
		slog.Error("sync diagnostics", "user", LogSafety_LogText(userID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "diagnostics failed")
		return
	}
	Response_JSON(w, http.StatusOK, report)
}

func baselineOpsStatusText(ok bool) string {
	if ok {
		return "ok"
	}
	return "not_ready"
}
