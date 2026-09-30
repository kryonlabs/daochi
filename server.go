package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	daochiSignatureContext          = "daochi-sync-v1"
	legacySyncSignatureContext      = "ksync-sync-v1"
	legacyInbeSignatureContext      = "inbe-sync-v1"
	minSupportedProtocol            = 1
	latestProtocol                  = 6
	compatibilityDeadline           = "2027-09-01"
	previousVersionGraceDays        = 365
	nodeUsageRecentWindowDays       = 30
	webSocketConnectionLimitPerUser = 8
)

var errSignedTxReplay = errors.New("signed transaction replay")
var errAppScopeNotOwned = errors.New("app does not own collection scope")

var serverCapabilities = []string{
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

type Server struct {
	cfg        Config
	store      *Store
	challenges *ChallengeStore
	verifier   Verifier
	syncHub    *syncHub
	limiter    *RateLimiter
	metrics    *ServerMetrics
	node       NodeIdentity
	// Per-account Monero address allocation locks; key is account ID.
	moneroAddressLocks sync.Map
	// Invoice IDs already reported as carrying uncredited funds, so the
	// expired-invoice sweep logs and counts each one once per process.
	moneroStuckNotified sync.Map
}

func NewServer(cfg Config, store *Store, verifier Verifier) *Server {
	node := NodeIdentity_New(cfg.NodeIdentityPrivateKey)
	if node.Error != nil {
		panic(node.Error)
	}
	return &Server{
		cfg:        cfg,
		store:      store,
		challenges: Challenge_New(cfg.ChallengeTTL),
		verifier:   verifier,
		syncHub:    newSyncHub(),
		limiter:    RateLimit_New(),
		metrics:    &ServerMetrics{},
		node:       node.Value,
	}
}

func (s *Server) appRegistry() Registry {
	return Registry{
		Database:      s.store.db,
		Configuration: &s.cfg,
		Counters:      s.metrics,
		Verify:        s.verifier.Verify,
		ReplayError:   errSignedTxReplay,
		MissingUser:   ErrSyncUserNotFound,
		ScopeNotOwned: errAppScopeNotOwned,
	}
}

func (s *Server) devices() Devices {
	return Devices{
		Database:      s.store.db,
		Configuration: &s.cfg,
		Counters:      s.metrics,
		Verify:        s.verifier.Verify,
		ReplayError:   errSignedTxReplay,
	}
}

func (s *Server) trust() Trust {
	return Trust{
		Database:      s.store.db,
		Configuration: &s.cfg,
		Identity:      s.node,
	}
}

func (s *Server) authenticateToken(r *http.Request) (string, error) {
	result := HttpAuth_AuthenticateToken(s.store.db, r, s.cfg.TokenSecret)
	return result.Value, authenticationError(result.Authentication)
}

func (s *Server) bearerUser(w http.ResponseWriter, r *http.Request) (string, bool) {
	result := HttpAuth_BearerUser(s.store.db, r, s.cfg.TokenSecret)
	if result.Authentication.Error != nil || result.Authentication.Status != 0 {
		HttpAuth_Respond(w, s.metrics, result.Authentication)
		return "", false
	}
	return result.Value, true
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.handleDocs)
	mux.HandleFunc("GET /openapi.json", s.handleOpenAPI)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	mux.HandleFunc("GET /api/v1/node", s.handleNodeInfo)
	mux.HandleFunc("POST /api/v1/node/pairing/invites", func(w http.ResponseWriter, r *http.Request) {
		TrustHttp_CreateInvite(s.trust(), w, r)
	})
	mux.HandleFunc("POST /api/v1/node/pairing/accept", func(w http.ResponseWriter, r *http.Request) {
		TrustHttp_AcceptInvite(s.trust(), w, r)
	})
	mux.HandleFunc("POST /api/v1/node/pairing/complete", func(w http.ResponseWriter, r *http.Request) {
		TrustHttp_CompletePairing(s.trust(), w, r)
	})
	mux.HandleFunc("GET /api/v1/node/peers", func(w http.ResponseWriter, r *http.Request) {
		TrustHttp_ListPeers(s.trust(), w, r)
	})
	mux.HandleFunc("POST /api/v1/namespaces", func(w http.ResponseWriter, r *http.Request) {
		TrustHttp_CreateSpace(s.trust(), w, r)
	})
	mux.HandleFunc("POST /api/v1/namespaces/claims", func(w http.ResponseWriter, r *http.Request) {
		TrustHttp_RegisterName(s.trust(), w, r)
	})
	mux.HandleFunc("GET /api/v1/namespaces/resolve", func(w http.ResponseWriter, r *http.Request) {
		TrustHttp_ResolveName(s.trust(), w, r)
	})
	mux.HandleFunc("POST /api/v1/node/mesh/export", s.handleNodeMeshExport)
	mux.HandleFunc("POST /api/v1/node/mesh/import", s.handleNodeMeshImport)
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	mux.HandleFunc("GET /api/v1/apps", func(w http.ResponseWriter, r *http.Request) {
		AppHttp_List(s.appRegistry(), w, r)
	})
	mux.HandleFunc("POST /api/v1/apps", func(w http.ResponseWriter, r *http.Request) {
		AppHttp_List(s.appRegistry(), w, r)
	})
	mux.HandleFunc("POST /api/v1/apps/register-signed", func(w http.ResponseWriter, r *http.Request) {
		AppHttp_RegisterSigned(s.appRegistry(), w, r)
	})
	mux.HandleFunc("GET /api/v1/apps/", func(w http.ResponseWriter, r *http.Request) {
		AppHttp_Route(s.appRegistry(), w, r)
	})
	mux.HandleFunc("PUT /api/v1/apps/", func(w http.ResponseWriter, r *http.Request) {
		AppHttp_Route(s.appRegistry(), w, r)
	})
	mux.HandleFunc("GET /api/v1/tokens/assets", s.handleTokenAssets)
	mux.HandleFunc("GET /api/v1/tokens/products", s.handleTokenProducts)
	mux.HandleFunc("GET /api/v1/tokens/issuer", s.handleTokenIssuer)
	mux.HandleFunc("GET /api/v1/tokens/balance", s.handleTokenBalance)
	mux.HandleFunc("GET /api/v1/tokens/ledger", s.handleTokenLedger)
	mux.HandleFunc("POST /api/v1/tokens/spend", s.handleTokenSpend)
	mux.HandleFunc("POST /api/v1/tokens/purchases/google/verify", s.handleGooglePurchaseVerify)
	mux.HandleFunc("POST /api/v1/tokens/purchases/monero/invoices", s.handleMoneroInvoices)
	mux.HandleFunc("GET /api/v1/tokens/purchases/monero/invoices/", s.handleMoneroInvoiceRoute)
	mux.HandleFunc("GET /api/v1/tokens/purchases/monero/address", s.handleMoneroAddress)
	mux.HandleFunc("GET /api/v1/tokens/purchases/monero/address/", s.handleMoneroAddress)
	mux.HandleFunc("GET /api/v1/tokens/purchases/monero/deposits", s.handleMoneroDeposits)
	mux.HandleFunc("GET /api/v1/tokens/checkpoints/latest", s.handleTokenCheckpointLatest)
	mux.HandleFunc("GET /api/v1/tokens/receipts/", s.handleTokenReceipt)
	mux.HandleFunc("POST /api/v1/admin/tokens/manual-credit", s.handleAdminManualCredit)
	mux.HandleFunc("POST /api/v1/admin/tokens/checkpoint", s.handleAdminTokenCheckpoint)
	mux.HandleFunc("GET /api/v1/sync/diagnostics", s.handleSyncDiagnostics)
	mux.HandleFunc("GET /api/v1/sync/challenge", s.handleChallenge)
	mux.HandleFunc("GET /api/v1/sync/ws", s.handleSyncWebSocket)
	mux.HandleFunc("POST /api/v1/sync/login", s.handleLogin)
	mux.HandleFunc("POST /api/v1/sync", s.handleSync)
	mux.HandleFunc("POST /api/v1/account/alias", s.handleAlias)
	mux.HandleFunc("POST /api/v1/account/profile-icon", s.handleProfileIcon)
	mux.HandleFunc("GET /api/v1/account/export", s.handleAccountExport)
	mux.HandleFunc("GET /api/v1/account/devices", func(w http.ResponseWriter, r *http.Request) {
		DeviceHttp_Route(s.devices(), w, r)
	})
	mux.HandleFunc("POST /api/v1/account/devices", func(w http.ResponseWriter, r *http.Request) {
		DeviceHttp_Route(s.devices(), w, r)
	})
	mux.HandleFunc("DELETE /api/v1/account/devices", func(w http.ResponseWriter, r *http.Request) {
		DeviceHttp_Route(s.devices(), w, r)
	})
	mux.HandleFunc("GET /api/v1/account/app-grants", func(w http.ResponseWriter, r *http.Request) {
		AppHttp_Grants(s.appRegistry(), w, r)
	})
	mux.HandleFunc("POST /api/v1/account/app-grants", func(w http.ResponseWriter, r *http.Request) {
		AppHttp_Grants(s.appRegistry(), w, r)
	})
	mux.HandleFunc("POST /api/v1/account/app-grants/signed", func(w http.ResponseWriter, r *http.Request) {
		AppHttp_GrantSigned(s.appRegistry(), w, r)
	})
	mux.HandleFunc("DELETE /api/v1/account/app-grants/", func(w http.ResponseWriter, r *http.Request) {
		AppHttp_GrantRoute(s.appRegistry(), w, r)
	})
	mux.HandleFunc("GET /api/v1/account/app-records", func(w http.ResponseWriter, r *http.Request) {
		AppHttp_Records(s.appRegistry(), w, r)
	})
	mux.HandleFunc("DELETE /api/v1/account", s.handleDeleteAccount)
	mux.HandleFunc("POST /api/v1/account/delete", s.handleDeleteAccount)
	mux.HandleFunc("POST /api/v1/account/delete-with-key", s.handleDeleteAccountWithKey)
	mux.HandleFunc("GET /api/v1/friends", s.handleFriends)
	mux.HandleFunc("DELETE /api/v1/friends/", s.handleFriendRoute)
	mux.HandleFunc("GET /api/v1/friends/requests", s.handleFriendRequests)
	mux.HandleFunc("POST /api/v1/friends/requests", s.handleFriendRequestCreate)
	mux.HandleFunc("POST /api/v1/friends/requests/", s.handleFriendRequestRoute)
	mux.HandleFunc("PUT /api/v1/profile/stats", s.handleProfileStatsPut)
	mux.HandleFunc("GET /api/v1/friends/stats", s.handleFriendStats)
	return s.withCommonHeaders(mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	Response_JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	checks := map[string]string{
		"database":     "ok",
		"token_secret": "ok",
		"verifier":     "ok",
		"token_issuer": s.tokenIssuerStatus(),
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
		if s.tokenIssuerStatus() != "ok" {
			checks["token_direct_purchases"] = "issuer_private_key_missing"
			status = http.StatusServiceUnavailable
		} else if !hasMoneroTokenProduct(s.cfg.TokenProducts) && !validMoneroRate(s.cfg) {
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
		"status": statusText(status == http.StatusOK),
		"checks": checks,
	})
}

func (s *Server) handleNodeInfo(w http.ResponseWriter, r *http.Request) {
	knownNodes := s.cfg.KnownNodes
	if knownNodes == nil {
		knownNodes = []NodePeer{}
	}
	usage, err := s.nodeUsage(r.Context())
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
		"capabilities":    serverCapabilities,
		"known_nodes":     knownNodes,
		"usage":           usage,
		"storage":         storage,
		"protocol": map[string]int{
			"min_supported": minSupportedProtocol,
			"latest":        latestProtocol,
		},
	})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	// Metrics expose user counts, traffic, and topology; when an admin
	// token is configured, require it. Deployments without one keep the
	// historical public endpoint (health checks use /healthz and /readyz).
	if s.cfg.AdminToken != "" && !HttpAuth_RequireAdmin(w, r, s.cfg.AdminToken) {
		return
	}
	usage, err := s.nodeUsage(r.Context())
	if err != nil {
		slog.Error("load metrics usage", "error", err)
		usage = NodeUsage{RecentActivityWindowDays: nodeUsageRecentWindowDays}
		stats := s.syncHub.stats()
		usage.ConnectedUsers = stats.Users
		usage.ConnectedWebSocketClients = stats.Connections
		usage.WebSocketConnectionLimitPerUser = webSocketConnectionLimitPerUser
	}
	storage, err := s.store.NodeStorageUsage(r.Context())
	if err != nil {
		slog.Error("load metrics storage usage", "error", err)
	}
	Metrics_Prometheus(s.metrics, w, usage, storage, BuildVersion)
}

func (s *Server) nodeUsage(ctx context.Context) (NodeUsage, error) {
	usage, err := s.store.NodeUsage(ctx, time.Now())
	if err != nil {
		return NodeUsage{}, err
	}
	stats := s.syncHub.stats()
	usage.ConnectedUsers = stats.Users
	usage.ConnectedWebSocketClients = stats.Connections
	usage.RecentActivityWindowDays = nodeUsageRecentWindowDays
	usage.WebSocketConnectionLimitPerUser = webSocketConnectionLimitPerUser
	return usage, nil
}

func (s *Server) handleSyncDiagnostics(w http.ResponseWriter, r *http.Request) {
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

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	userID := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("user_id")))
	if !Identity_ValidUserID(userID) {
		Response_Error(w, http.StatusBadRequest, "invalid user_id")
		return
	}
	if !s.allowRequest(r, "challenge:ip:"+ClientAddress_FromRequest(r), 60, time.Minute) ||
		!s.allowRequest(r, "challenge:user:"+userID, 20, time.Minute) {
		Response_Error(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}
	issued := Challenge_Issue(s.challenges, userID)
	nonce, err := issued.Nonce, issued.Error
	if err != nil {
		slog.Error("issue challenge", "error", err)
		Response_Error(w, http.StatusInternalServerError, "challenge failed")
		return
	}
	Response_JSON(w, http.StatusOK, ChallengeResponse{
		UserIDHash: userID,
		Nonce:      hex.EncodeToString(nonce),
		ExpiresIn:  int64(s.cfg.ChallengeTTL.Seconds()),
	})
}

func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	s.metrics.SyncRequests.Add(1)
	syncOK := false
	var signedTx *SignedTxEnvelope
	defer func() {
		if !syncOK {
			s.metrics.SyncFailures.Add(1)
			if signedTx != nil {
				SignedTx_Forget(s.store.db, r.Context(), *signedTx)
			}
		}
	}()
	bodyResult := HttpBody_ReadJSON(w, r, s.cfg.MaxBodyBytes)
	body, err := bodyResult.Value, bodyResult.Error
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if isEncryptedSyncEnvelope(body) {
		if s.handleEncryptedSyncEnvelope(w, r, body) {
			syncOK = true
		}
		return
	}
	req, err := parseSyncRequestBody(body)
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := applyHeaderUser(r, &req.UserIDHash); err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if !Identity_ValidClientID(req.ClientID) {
		Response_Error(w, http.StatusBadRequest, "invalid client_id")
		return
	}
	tokenUser, err := s.authenticateToken(r)
	if err != nil {
		s.writeAuthError(w, err)
		return
	}
	if tokenUser != req.UserIDHash {
		Response_Error(w, http.StatusUnauthorized, "token user mismatch")
		return
	}
	publicKey, err := syncRequestPublicKey(req)
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.validateSyncRequest(r.Context(), req); err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.ProtocolVersion >= 6 {
		header := SignedTx_ReadHeader(r)
		tx, err := header.Value, authenticationError(header.Authentication)
		if err != nil {
			s.writeAuthError(w, err)
			return
		}
		if err := authenticationError(SignedTx_Verify(s.store.db, r.Context(), r, body, tx, req.UserIDHash, req.AppID, s.verifier.Verify, errSignedTxReplay)); err != nil {
			s.writeAuthError(w, err)
			return
		}
		signedTx = &tx
	}
	normalizeMeditationDurations(req.MeditationLogs)

	baseHash, err := s.store.StateHash(r.Context(), req.UserIDHash)
	if err != nil {
		slog.Error("hash sync state", "user", LogSafety_LogText(req.UserIDHash), "error", err)
		Response_Error(w, http.StatusInternalServerError, "state hash failed")
		return
	}

	result := SyncResult{}
	acceptedOps := []string{}
	remoteOps := []SyncOp{}
	fullSnapshotRequired := false
	changesComplete := true
	sinceVersion := req.SinceServerVersion
	recordedClientClock := req.ClientClock
	snapshotReason := ""
	compactedThrough := int64(0)
	if req.LastServerStateHash != "" &&
		!strings.EqualFold(req.LastServerStateHash, baseHash) &&
		!req.FullSyncRequested {
		fullSnapshotRequired = true
		changesComplete = false
		sinceVersion = 0
		snapshotReason = "state_hash_mismatch"
	} else if req.ProtocolVersion >= 2 && !req.FullSyncRequested {
		compacted, through, err := s.store.SyncOpsCompacted(r.Context(), req.UserIDHash, req.ClientClock)
		if err != nil {
			slog.Error("check sync op compaction", "user", LogSafety_LogText(req.UserIDHash), "error", err)
			Response_Error(w, http.StatusInternalServerError, "compaction check failed")
			return
		}
		compactedThrough = through
		if compacted {
			fullSnapshotRequired = true
			changesComplete = false
			sinceVersion = 0
			snapshotReason = "sync_ops_compacted"
		} else {
			result, acceptedOps, err = s.store.ApplySyncDetailed(r.Context(), req, publicKey)
			if err != nil {
				slog.Error("apply sync", "user", LogSafety_LogText(req.UserIDHash), "error", err)
				Response_Error(w, http.StatusInternalServerError, "sync failed")
				return
			}
		}
	} else {
		result, acceptedOps, err = s.store.ApplySyncDetailed(r.Context(), req, publicKey)
		if err != nil {
			slog.Error("apply sync", "user", LogSafety_LogText(req.UserIDHash), "error", err)
			Response_Error(w, http.StatusInternalServerError, "sync failed")
			return
		}
	}
	if fullSnapshotRequired && syncRequestHasLocalChanges(req) {
		result, acceptedOps, err = s.store.ApplySyncDetailed(r.Context(), req, publicKey)
		if err != nil {
			slog.Error("apply stale sync uploads", "user", LogSafety_LogText(req.UserIDHash), "error", err)
			Response_Error(w, http.StatusInternalServerError, "sync failed")
			return
		}
	}
	if fullSnapshotRequired {
		Metrics_RecordFullSnapshot(s.metrics, snapshotReason)
	}

	changes, serverVersion, err := s.store.ChangesSince(r.Context(), req.UserIDHash, sinceVersion)
	if err != nil {
		slog.Error("load sync changes", "user", LogSafety_LogText(req.UserIDHash), "error", err)
		Response_Error(w, http.StatusInternalServerError, "changes failed")
		return
	}
	changes.SocialCache, err = s.store.AuthoritativeSocial(r.Context(), req.UserIDHash)
	if err != nil {
		slog.Error("load authoritative social state", "user", LogSafety_LogText(req.UserIDHash), "error", err)
		Response_Error(w, http.StatusInternalServerError, "social state failed")
		return
	}
	if req.ProtocolVersion >= 2 {
		if fullSnapshotRequired {
			remoteOps = []SyncOp{}
			recordedClientClock = serverVersion
		} else {
			remoteOps, err = s.store.OpsSince(r.Context(), req.UserIDHash, req.ClientClock)
			if err != nil {
				slog.Error("load sync ops", "user", LogSafety_LogText(req.UserIDHash), "error", err)
				Response_Error(w, http.StatusInternalServerError, "ops failed")
				return
			}
		}
	}
	serverHash, err := s.store.StateHash(r.Context(), req.UserIDHash)
	if err != nil {
		slog.Error("hash sync response", "user", LogSafety_LogText(req.UserIDHash), "error", err)
		Response_Error(w, http.StatusInternalServerError, "state hash failed")
		return
	}
	if err := s.store.RecordClientSync(r.Context(), req.UserIDHash, req.ClientID, req.SinceServerVersion, serverVersion, req.ProtocolVersion, recordedClientClock); err != nil {
		slog.Error("record sync client", "user", LogSafety_LogText(req.UserIDHash), "client", LogSafety_LogText(req.ClientID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "client state failed")
		return
	}
	if req.ProtocolVersion >= 2 {
		if err := s.store.CompactSyncOps(r.Context(), req.UserIDHash); err != nil {
			slog.Error("compact sync ops", "user", LogSafety_LogText(req.UserIDHash), "error", err)
			Response_Error(w, http.StatusInternalServerError, "compaction failed")
			return
		}
	}
	if syncResultApplied(result) {
		s.syncHub.publish(req.UserIDHash, serverVersion)
	}
	accountAlias, err := s.store.AccountAlias(r.Context(), req.UserIDHash)
	if err != nil {
		slog.Error("load account alias", "user", LogSafety_LogText(req.UserIDHash), "error", err)
		Response_Error(w, http.StatusInternalServerError, "alias failed")
		return
	}
	profileIcon, err := s.store.AccountProfileIcon(r.Context(), req.UserIDHash)
	if err != nil {
		slog.Error("load profile icon", "user", LogSafety_LogText(req.UserIDHash), "error", err)
		Response_Error(w, http.StatusInternalServerError, "profile icon failed")
		return
	}
	response := SyncResponse{
		ProtocolVersion:      req.ProtocolVersion,
		Status:               "ok",
		ServerCapabilities:   serverCapabilities,
		TransitionMode:       syncTransitionMode(req),
		Applied:              result,
		AccountAlias:         accountAlias,
		ProfileIcon:          profileIcon,
		ServerVersion:        serverVersion,
		ServerClock:          serverVersion,
		ServerStateHash:      serverHash,
		BaseStateHash:        baseHash,
		ChangesComplete:      changesComplete,
		FullSnapshotRequired: fullSnapshotRequired,
		AcceptedOps:          acceptedOps,
		Ops:                  remoteOps,
		Changes:              changes,
		MinSupportedProtocol: minSupportedProtocol,
		LatestProtocol:       req.ProtocolVersion,
		ServerLatestProtocol: latestProtocol,
		Diagnostics: &SyncDiagnostics{
			SnapshotReason:              snapshotReason,
			RequestedSinceServerVersion: req.SinceServerVersion,
			EffectiveSinceServerVersion: sinceVersion,
			ClientClock:                 req.ClientClock,
			CompactedThroughVersion:     compactedThrough,
			HasLocalChanges:             syncRequestHasLocalChanges(req),
			AcceptedOps:                 len(acceptedOps),
			RemoteOps:                   len(remoteOps),
			AppliedInput:                result,
			ReturnedChanges:             syncChangesResult(changes),
		},
	}
	if req.ProtocolVersion >= 3 {
		if err := s.store.AutoMigrateAccountForProtocol(r.Context(), req.UserIDHash, req.ProtocolVersion); err != nil {
			slog.Error("auto migrate account", "user", LogSafety_LogText(req.UserIDHash), "error", err)
			Response_Error(w, http.StatusInternalServerError, "migration failed")
			return
		}
		serverVersion, err = s.store.currentUserVersion(r.Context(), req.UserIDHash)
		if err != nil {
			slog.Error("load migrated server version", "user", LogSafety_LogText(req.UserIDHash), "error", err)
			Response_Error(w, http.StatusInternalServerError, "version failed")
			return
		}
		serverHash, err = s.store.StateHash(r.Context(), req.UserIDHash)
		if err != nil {
			slog.Error("hash migrated sync response", "user", LogSafety_LogText(req.UserIDHash), "error", err)
			Response_Error(w, http.StatusInternalServerError, "state hash failed")
			return
		}
		response.ServerVersion = serverVersion
		response.ServerClock = serverVersion
		response.ServerStateHash = serverHash
		response.Data, err = s.store.CleanData(r.Context(), req.UserIDHash)
		if err != nil {
			slog.Error("load clean data", "user", LogSafety_LogText(req.UserIDHash), "error", err)
			Response_Error(w, http.StatusInternalServerError, "clean data failed")
			return
		}
		if !includeLegacyPrivateData(req) {
			response.Data.Habits = []Habit{}
			response.Data.HabitDays = []CleanHabitDay{}
			response.Data.Sessions = []Session{}
			response.Data.MeditationLogs = []MeditationLog{}
		}
		response.Changes.Habits = response.Data.Habits
		response.Changes.HabitDays = make([]HabitDay, 0, len(response.Data.HabitDays))
		for _, day := range response.Data.HabitDays {
			response.Changes.HabitDays = append(response.Changes.HabitDays, HabitDay{
				HabitID:   day.HabitID,
				LocalDate: day.LocalDate,
				Completed: day.Completed,
				Count:     day.Count,
				UpdatedAt: day.UpdatedAt,
			})
		}
		response.Changes.Sessions = response.Data.Sessions
		response.Changes.MeditationLogs = response.Data.MeditationLogs
		response.Changes.SocialCache = response.Data.Social
		response.Changes.EncryptedRecords = response.Data.EncryptedRecords
		response.Logs, err = s.store.SyncLogs(r.Context(), req.UserIDHash, req.ClientClock)
		if err != nil {
			slog.Error("load sync logs", "user", LogSafety_LogText(req.UserIDHash), "error", err)
			Response_Error(w, http.StatusInternalServerError, "logs failed")
			return
		}
		response.Deletes, err = s.store.DeleteLogs(r.Context(), req.UserIDHash, req.ClientClock)
		if err != nil {
			slog.Error("load delete logs", "user", LogSafety_LogText(req.UserIDHash), "error", err)
			Response_Error(w, http.StatusInternalServerError, "delete logs failed")
			return
		}
		response.LegacyClients, err = s.store.LegacyClients(
			r.Context(), req.UserIDHash, latestProtocol)
		if err != nil {
			slog.Error("load legacy clients", "user", LogSafety_LogText(req.UserIDHash), "error", err)
			Response_Error(w, http.StatusInternalServerError, "legacy clients failed")
			return
		}
		if len(response.LegacyClients) > 0 {
			s.metrics.LegacyClientHints.Add(uint64(len(response.LegacyClients)))
		}
	}
	response.LegacyWriteRequired, response.LegacyProjectionEpoch, err =
		s.store.LegacyWritePolicy(r.Context(), req.UserIDHash)
	if err != nil {
		slog.Error("load legacy write policy", "user", LogSafety_LogText(req.UserIDHash), "error", err)
		Response_Error(w, http.StatusInternalServerError, "legacy write policy failed")
		return
	}
	if response.Diagnostics != nil {
		response.Diagnostics.ReturnedChanges = syncChangesResult(response.Changes)
	}
	if result.EncryptedRecords > 0 {
		s.metrics.SyncEncryptedRecords.Add(uint64(result.EncryptedRecords))
	}
	if err := s.store.RecordSyncAudit(r.Context(), SyncAuditEntry{
		UserIDHash:           req.UserIDHash,
		ClientID:             req.ClientID,
		AppID:                req.AppID,
		ProtocolVersion:      req.ProtocolVersion,
		SinceServerVersion:   req.SinceServerVersion,
		ClientClock:          req.ClientClock,
		ServerVersion:        response.ServerVersion,
		Applied:              result,
		RemoteOps:            len(remoteOps),
		FullSnapshotRequired: fullSnapshotRequired,
		SnapshotReason:       snapshotReason,
	}); err != nil {
		slog.Error("record sync audit", "user", LogSafety_LogText(req.UserIDHash), "client", LogSafety_LogText(req.ClientID), "error", err)
	}
	syncOK = true
	Response_JSON(w, http.StatusOK, response)
}

func (s *Server) handleEncryptedSyncEnvelope(w http.ResponseWriter, r *http.Request, body []byte) bool {
	userHeader := HttpAuth_UserHeader(r)
	userID, headerName := userHeader.Value, userHeader.Name
	if userID == "" {
		Response_Error(w, http.StatusBadRequest, "missing X-Daochi-User")
		return false
	}
	if !Identity_ValidUserID(userID) {
		Response_Error(w, http.StatusBadRequest, "invalid "+headerName)
		return false
	}
	tokenUser, err := s.authenticateToken(r)
	if err != nil {
		s.writeAuthError(w, err)
		return false
	}
	if tokenUser != userID {
		s.writeAuthError(w, authError{status: http.StatusUnauthorized, message: "token user mismatch"})
		return false
	}
	clientID := HttpAuth_HeaderAlias(r, []string{"X-Daochi-Client", "X-Ksync-Client"})
	if clientID != "" && !Identity_ValidClientID(clientID) {
		Response_Error(w, http.StatusBadRequest, "invalid X-Daochi-Client")
		return false
	}
	sinceVersion := int64(0)
	if text := HttpAuth_HeaderAlias(r, []string{"X-Daochi-Since-Version", "X-Ksync-Since-Version"}); text != "" {
		parsed, err := strconv.ParseInt(text, 10, 64)
		if err != nil || parsed < 0 {
			Response_Error(w, http.StatusBadRequest, "invalid X-Daochi-Since-Version")
			return false
		}
		sinceVersion = parsed
	}
	limit, err := encryptedPayloadLimit(r, s.cfg.EncryptedPayloadMaxReturn)
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return false
	}
	if s.cfg.EncryptedPayloadMaxAccountBytes > 0 {
		currentBytes, err := s.store.EncryptedPayloadBytes(r.Context(), userID)
		if err != nil {
			slog.Error("load encrypted payload usage", "user", LogSafety_LogText(userID), "error", err)
			Response_Error(w, http.StatusInternalServerError, "encrypted sync failed")
			return false
		}
		if int64(len(body)) > s.cfg.EncryptedPayloadMaxAccountBytes ||
			currentBytes+int64(len(body)) > s.cfg.EncryptedPayloadMaxAccountBytes {
			Response_Error(w, http.StatusRequestEntityTooLarge, "encrypted payload quota exceeded")
			return false
		}
	}
	accountAlias, err := s.store.AccountAlias(r.Context(), userID)
	if err != nil {
		slog.Error("load encrypted sync account alias", "user", LogSafety_LogText(userID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "alias failed")
		return false
	}
	profileIcon, err := s.store.AccountProfileIcon(r.Context(), userID)
	if err != nil {
		slog.Error("load encrypted sync profile icon", "user", LogSafety_LogText(userID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "profile icon failed")
		return false
	}
	social, err := s.store.AuthoritativeSocial(r.Context(), userID)
	if err != nil {
		slog.Error("load encrypted sync social state", "user", LogSafety_LogText(userID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "social state failed")
		return false
	}
	serverVersion, err := s.store.StoreEncryptedPayload(r.Context(), userID, clientID, body)
	if err != nil {
		if errors.Is(err, ErrSyncUserNotFound) {
			Response_Error(w, http.StatusNotFound, "sync account not found")
			return false
		}
		slog.Error("store encrypted payload", "user", LogSafety_LogText(userID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "encrypted sync failed")
		return false
	}
	if result, err := s.store.PruneEncryptedPayloads(r.Context(), userID, s.cfg.EncryptedPayloadRetention, 0); err != nil {
		slog.Error("prune encrypted payloads", "user", LogSafety_LogText(userID), "error", err)
	} else if result.Deleted > 0 {
		slog.Info("pruned encrypted payloads", "user", LogSafety_LogText(userID), "deleted", result.Deleted)
	}
	payloads, truncated, err := s.store.EncryptedPayloadsSince(r.Context(), userID, sinceVersion, limit)
	if err != nil {
		slog.Error("load encrypted payloads", "user", LogSafety_LogText(userID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "encrypted sync failed")
		return false
	}
	if err := s.store.RecordClientSync(r.Context(), userID, clientID, sinceVersion, serverVersion, latestProtocol, serverVersion); err != nil {
		slog.Error("record encrypted sync client", "user", LogSafety_LogText(userID), "client", LogSafety_LogText(clientID), "error", err)
	}
	if err := s.store.RecordSyncAudit(r.Context(), SyncAuditEntry{
		UserIDHash:            userID,
		ClientID:              clientID,
		ProtocolVersion:       latestProtocol,
		SinceServerVersion:    sinceVersion,
		ClientClock:           sinceVersion,
		ServerVersion:         serverVersion,
		EncryptedPayload:      true,
		EncryptedPayloadBytes: int64(len(body)),
	}); err != nil {
		slog.Error("record encrypted sync audit", "user", LogSafety_LogText(userID), "client", LogSafety_LogText(clientID), "error", err)
	}
	s.metrics.SyncEncryptedPayloads.Add(1)
	s.syncHub.publish(userID, serverVersion)
	response := SyncResponse{
		ProtocolVersion:      latestProtocol,
		Status:               "ok",
		ServerCapabilities:   serverCapabilities,
		TransitionMode:       "encrypted_payload",
		AccountAlias:         accountAlias,
		ProfileIcon:          profileIcon,
		ServerVersion:        serverVersion,
		ServerClock:          serverVersion,
		ChangesComplete:      true,
		Changes:              emptySyncChanges(),
		EncryptedPayloads:    payloads,
		MinSupportedProtocol: minSupportedProtocol,
		ServerLatestProtocol: latestProtocol,
	}
	response.Changes.SocialCache = social
	if truncated {
		response.EncryptedPayloadsTruncated = true
		response.EncryptedPayloadsNextSinceVersion = payloads[len(payloads)-1].ServerVersion
	}
	Response_JSON(w, http.StatusOK, response)
	return true
}

func encryptedPayloadLimit(r *http.Request, configuredMax int) (int, error) {
	limit := configuredMax
	if text := HttpAuth_HeaderAlias(r, []string{"X-Daochi-Limit", "X-Ksync-Limit"}); text != "" {
		parsed, err := strconv.Atoi(text)
		if err != nil || parsed <= 0 {
			return 0, errors.New("invalid X-Daochi-Limit")
		}
		limit = parsed
	}
	if configuredMax > 0 && (limit == 0 || limit > configuredMax) {
		limit = configuredMax
	}
	return limit, nil
}

func syncTransitionMode(req SyncRequest) string {
	if req.ProtocolVersion >= 5 {
		return "encrypted_primary"
	}
	if req.ProtocolVersion >= 4 {
		return "dual_write"
	}
	return ""
}

func includeLegacyPrivateData(req SyncRequest) bool {
	return req.ProtocolVersion < 5 || req.IncludeLegacyData
}

func syncRequestHasLocalChanges(req SyncRequest) bool {
	return req.FullSyncRequested ||
		len(req.MeditationLogs) > 0 ||
		len(req.Habits) > 0 ||
		len(req.HabitDays) > 0 ||
		len(req.Sessions) > 0 ||
		len(req.EncryptedRecords) > 0 ||
		len(req.Ops) > 0
}

func (s *Server) handleAlias(w http.ResponseWriter, r *http.Request) {
	_, req, err := readAliasRequest(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := applyHeaderUser(r, &req.UserIDHash); err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	tokenUser, err := s.authenticateToken(r)
	if err != nil {
		s.writeAuthError(w, err)
		return
	}
	if tokenUser != req.UserIDHash {
		Response_Error(w, http.StatusUnauthorized, "token user mismatch")
		return
	}
	alias := normalizeAlias(req.Alias)
	if !Identity_ValidAccountAlias(alias) {
		Response_Error(w, http.StatusBadRequest, "invalid alias")
		return
	}
	if err := s.store.SetAccountAlias(r.Context(), req.UserIDHash, alias); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			Response_Error(w, http.StatusConflict, "alias unavailable")
			return
		}
		if errors.Is(err, ErrSyncUserNotFound) {
			Response_Error(w, http.StatusNotFound, "sync account not found")
			return
		}
		slog.Error("set account alias", "user", LogSafety_LogText(req.UserIDHash), "error", err)
		Response_Error(w, http.StatusInternalServerError, "alias failed")
		return
	}
	Response_JSON(w, http.StatusOK, AliasResponse{Status: "ok", Alias: alias})
}

func (s *Server) handleProfileIcon(w http.ResponseWriter, r *http.Request) {
	_, req, err := readProfileIconRequest(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := applyHeaderUser(r, &req.UserIDHash); err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	tokenUser, err := s.authenticateToken(r)
	if err != nil {
		s.writeAuthError(w, err)
		return
	}
	if tokenUser != req.UserIDHash {
		Response_Error(w, http.StatusUnauthorized, "token user mismatch")
		return
	}
	if !validProfileIcon(req.ProfileIcon) {
		Response_Error(w, http.StatusBadRequest, "invalid profile_icon")
		return
	}
	if err := s.store.SetAccountProfileIcon(r.Context(), req.UserIDHash, req.ProfileIcon); err != nil {
		if errors.Is(err, ErrSyncUserNotFound) {
			Response_Error(w, http.StatusNotFound, "sync account not found")
			return
		}
		slog.Error("set profile icon", "user", LogSafety_LogText(req.UserIDHash), "error", err)
		Response_Error(w, http.StatusInternalServerError, "profile icon failed")
		return
	}
	Response_JSON(w, http.StatusOK, ProfileIconResponse{Status: "ok", ProfileIcon: req.ProfileIcon})
}

func (s *Server) handleAccountExport(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	response, err := s.store.ExportAccount(r.Context(), userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			Response_Error(w, http.StatusNotFound, "sync account not found")
			return
		}
		slog.Error("export account", "user", LogSafety_LogText(userID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "export failed")
		return
	}
	Response_JSON(w, http.StatusOK, response)
}

func (s *Server) handleFriends(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	friends, err := s.store.ListFriends(r.Context(), userID)
	if err != nil {
		slog.Error("list friends", "user", LogSafety_LogText(userID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "friends failed")
		return
	}
	response := FriendsResponse{Friends: friends}
	s.cacheSocialSnapshot(r.Context(), userID, "friends.list", response)
	Response_JSON(w, http.StatusOK, response)
}

func (s *Server) handleFriendRoute(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	friendID := strings.TrimPrefix(r.URL.Path, "/api/v1/friends/")
	friendID = strings.ToLower(strings.Trim(friendID, "/"))
	if !Identity_ValidUserID(friendID) {
		Response_Error(w, http.StatusNotFound, "friend not found")
		return
	}
	if err := s.store.RemoveFriend(r.Context(), userID, friendID); err != nil {
		slog.Error("remove friend", "user", LogSafety_LogText(userID), "friend", LogSafety_LogText(friendID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "friend remove failed")
		return
	}
	s.syncHub.publish(userID, 0)
	s.syncHub.publish(friendID, 0)
	Response_JSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

func (s *Server) handleFriendRequests(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	incoming, outgoing, err := s.store.ListFriendRequests(r.Context(), userID)
	if err != nil {
		slog.Error("list friend requests", "user", LogSafety_LogText(userID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "friend requests failed")
		return
	}
	response := FriendRequestsResponse{Incoming: incoming, Outgoing: outgoing}
	s.cacheSocialSnapshot(r.Context(), userID, "friends.requests", response)
	Response_JSON(w, http.StatusOK, response)
}

func (s *Server) handleFriendRequestCreate(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	req, err := readFriendRequestCreateRequest(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	target, found, err := s.store.ResolveAccountRef(r.Context(), req.Target)
	if err != nil {
		slog.Error("resolve friend target", "user", LogSafety_LogText(userID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "friend request failed")
		return
	}
	if !found {
		Response_Error(w, http.StatusNotFound, "friend target not found")
		return
	}
	resource := ResourceId_New()
	id, err := resource.Value, resource.Error
	if err != nil {
		slog.Error("generate friend request id", "error", err)
		Response_Error(w, http.StatusInternalServerError, "friend request failed")
		return
	}
	item, err := s.store.CreateFriendRequest(r.Context(), id, userID, target)
	if err != nil {
		if strings.Contains(err.Error(), "self") || strings.Contains(err.Error(), "already friends") {
			Response_Error(w, http.StatusConflict, err.Error())
			return
		}
		slog.Error("create friend request", "user", LogSafety_LogText(userID), "target", LogSafety_LogText(target), "error", err)
		Response_Error(w, http.StatusInternalServerError, "friend request failed")
		return
	}
	s.syncHub.publish(userID, 0)
	s.syncHub.publish(target, 0)
	Response_JSON(w, http.StatusCreated, FriendRequestResponse{Status: "ok", Request: item})
}

func (s *Server) handleFriendRequestRoute(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	requestID, action, ok := parseFriendRequestPath(r.URL.Path)
	if !ok {
		Response_Error(w, http.StatusNotFound, "friend request not found")
		return
	}
	var item FriendRequest
	var err error
	switch action {
	case "accept":
		item, err = s.store.AcceptFriendRequest(r.Context(), userID, requestID)
	case "decline":
		item, err = s.store.DeclineFriendRequest(r.Context(), userID, requestID)
	default:
		Response_Error(w, http.StatusNotFound, "friend request not found")
		return
	}
	if errors.Is(err, sql.ErrNoRows) {
		Response_Error(w, http.StatusNotFound, "friend request not found")
		return
	}
	if errors.Is(err, ErrSyncUserNotFound) {
		Response_Error(w, http.StatusForbidden, "friend request not owned by user")
		return
	}
	if err != nil {
		if strings.Contains(err.Error(), "not pending") {
			Response_Error(w, http.StatusConflict, err.Error())
			return
		}
		slog.Error("friend request action", "user", LogSafety_LogText(userID), "request", LogSafety_LogText(requestID), "action", LogSafety_LogText(action), "error", err)
		Response_Error(w, http.StatusInternalServerError, "friend request failed")
		return
	}
	s.syncHub.publish(item.RequesterUserID, 0)
	s.syncHub.publish(item.TargetUserID, 0)
	Response_JSON(w, http.StatusOK, FriendRequestResponse{Status: item.Status, Request: item})
}

func (s *Server) handleProfileStatsPut(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	req, err := readProfileStatsRequest(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	applied, err := s.store.UpsertProfileStats(r.Context(), userID, req.App, req.Metrics)
	if err != nil {
		slog.Error("upsert profile stats", "user", LogSafety_LogText(userID), "app", LogSafety_LogText(req.App), "error", err)
		Response_Error(w, http.StatusInternalServerError, "profile stats failed")
		return
	}
	if applied > 0 {
		s.syncHub.publish(userID, 0)
		if friends, err := s.store.ListFriends(r.Context(), userID); err == nil {
			for _, friend := range friends {
				s.syncHub.publish(friend.UserIDHash, 0)
			}
		} else {
			slog.Error("notify profile stats friends", "user", LogSafety_LogText(userID), "error", err)
		}
	}
	Response_JSON(w, http.StatusOK, ProfileStatsResponse{Status: "ok", Applied: applied})
}

func (s *Server) handleFriendStats(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	app := strings.TrimSpace(r.URL.Query().Get("app"))
	practice := strings.TrimSpace(r.URL.Query().Get("practice"))
	metric := strings.TrimSpace(r.URL.Query().Get("metric"))
	if !Identity_ValidNamespace(app) || !Identity_ValidNamespace(practice) || !Identity_ValidNamespace(metric) ||
		!validLeaderboardMetric(practice, metric) {
		Response_Error(w, http.StatusBadRequest, "invalid stats query")
		return
	}
	rows, err := s.store.FriendStats(r.Context(), userID, app, practice, metric)
	if err != nil {
		slog.Error("friend stats", "user", LogSafety_LogText(userID), "app", LogSafety_LogText(app), "practice", LogSafety_LogText(practice), "metric", LogSafety_LogText(metric), "error", err)
		Response_Error(w, http.StatusInternalServerError, "friend stats failed")
		return
	}
	response := FriendStatsResponse{Rows: rows}
	s.cacheSocialSnapshot(r.Context(), userID,
		"leaderboard."+app+"."+practice+"."+metric, response)
	Response_JSON(w, http.StatusOK, response)
}

func syncRequestPublicKey(req SyncRequest) ([]byte, error) {
	if strings.TrimSpace(req.PublicKey) == "" {
		return nil, nil
	}
	publicKeyField := Codec_DecodeBinaryField(req.PublicKey)
	publicKey := []byte(publicKeyField.Value)
	if publicKeyField.Error != "" {
		return nil, errors.New("invalid public_key")
	}
	if len(publicKey) != mlDSA44PublicKeySize {
		return nil, errors.New("wrong public_key size")
	}
	if err := EncryptedRecord_ValidateAccountKey(req.UserIDHash, publicKey); err != nil {
		return nil, errors.New("public_key does not match user_id_hash")
	}
	return publicKey, nil
}

func (s *Server) validateSyncRequest(ctx context.Context, req SyncRequest) error {
	if req.AppID != "" {
		if !Identity_ValidNamespace(req.AppID) {
			return errors.New("invalid app_id")
		}
		appResult := AppStore_ByID(s.store.db, ctx, req.AppID)
		app, exists, err := appResult.Value, appResult.Found, appResult.Error
		if err != nil {
			return err
		}
		if !exists {
			return errors.New("unknown app_id")
		}
		if app.Status != "active" {
			return errors.New("app_id inactive")
		}
		if req.ProtocolVersion >= 6 && app.ManifestExpiresAt > 0 &&
			time.Now().Unix() > app.ManifestExpiresAt {
			return errors.New("app manifest expired")
		}
		if req.ProtocolVersion < 6 {
			legacyResult := AppStore_AllowsLegacyProtocol(s.store.db, ctx, req.AppID, req.ProtocolVersion)
			allowed, err := legacyResult.Value, legacyResult.Error
			if err != nil {
				return err
			}
			if !allowed {
				return errors.New("legacy protocol not allowed for app_id")
			}
		}
	}
	if req.ProtocolVersion >= 6 && req.AppID == "" {
		return errors.New("app_id required")
	}
	for _, item := range req.EncryptedRecords {
		if !EncryptedRecord_ValidForProtocol(item, req.ProtocolVersion) {
			return errors.New("invalid encrypted record")
		}
		if req.AppID != "" {
			ownership := AppStore_OwnsCollection(s.store.db, ctx, req.AppID, item.Collection)
			owns, err := ownership.Value, ownership.Error
			if err != nil {
				return err
			}
			if !owns {
				if req.ProtocolVersion >= 6 {
					return errors.New("encrypted record collection is not registered for app_id")
				}
				slog.Warn("sync request used unregistered app collection", "app_id", LogSafety_LogText(req.AppID), "collection", LogSafety_LogText(item.Collection), "mode", "compat")
			}
		}
	}
	return nil
}

func syncResultApplied(result SyncResult) bool {
	return result.MeditationLogs > 0 ||
		result.Habits > 0 ||
		result.HabitDays > 0 ||
		result.Sessions > 0 ||
		result.SocialCache > 0 ||
		result.EncryptedRecords > 0
}

func syncChangesResult(changes SyncChanges) SyncResult {
	return SyncResult{
		MeditationLogs:   len(changes.MeditationLogs),
		Habits:           len(changes.Habits),
		HabitDays:        len(changes.HabitDays),
		Sessions:         len(changes.Sessions),
		SocialCache:      len(changes.SocialCache),
		EncryptedRecords: len(changes.EncryptedRecords),
	}
}

func (s *Server) cacheSocialSnapshot(ctx context.Context, userID, kind string, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		slog.Error("marshal social cache", "user", LogSafety_LogText(userID), "kind", LogSafety_LogText(kind), "error", err)
		return
	}
	applied, err := s.store.SetSocialCacheJSON(ctx, userID, kind, payload)
	if err != nil {
		slog.Error("write social cache", "user", LogSafety_LogText(userID), "kind", LogSafety_LogText(kind), "error", err)
		return
	}
	if applied > 0 {
		s.syncHub.publish(userID, 0)
	}
}

func normalizeAlias(alias string) string {
	alias = strings.ToLower(strings.TrimSpace(alias))
	alias = strings.TrimPrefix(alias, "@")
	return alias
}

func validProfileIcon(profileIcon int) bool {
	return profileIcon >= ProfileIconNone && profileIcon <= ProfileIconTree5
}

func validLeaderboardMetric(practice, metric string) bool {
	switch practice {
	case "whm":
		return metric == "streak" || metric == "avg_hold"
	case "meditation":
		return metric == "streak" || metric == "avg_time"
	case "sun_salutation":
		return metric == "streak"
	default:
		return false
	}
}

func statusText(ok bool) string {
	if ok {
		return "ok"
	}
	return "not_ready"
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	body, req, err := readLoginRequest(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := applyHeaderUser(r, &req.UserIDHash); err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if !Identity_ValidClientID(req.ClientID) {
		Response_Error(w, http.StatusBadRequest, "invalid client_id")
		return
	}
	if !s.allowRequest(r, "login:ip:"+ClientAddress_FromRequest(r), 40, time.Minute) ||
		!s.allowRequest(r, "login:user:"+req.UserIDHash, 20, time.Minute) {
		Response_Error(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}
	signature, context := requestSignatureHeader(r)
	publicKey, err := s.authenticateSignature(r.Context(), req.UserIDHash, req.PublicKey, signature, context, r.Method, r.URL.Path, body)
	if err != nil {
		s.writeAuthError(w, err)
		return
	}
	if err := s.store.RegisterUser(r.Context(), req.UserIDHash, publicKey); err != nil {
		slog.Error("register sync user", "user", LogSafety_LogText(req.UserIDHash), "error", err)
		Response_Error(w, http.StatusInternalServerError, "login failed")
		return
	}
	if err := s.store.RecordClientLogin(r.Context(), req.UserIDHash, req.ClientID); err != nil {
		slog.Error("record login client", "user", LogSafety_LogText(req.UserIDHash), "client", LogSafety_LogText(req.ClientID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "login failed")
		return
	}
	token := Token_IssueAuthToken(s.cfg.TokenSecret, req.UserIDHash, time.Now().Add(s.cfg.TokenTTL).Unix())
	if token.Error != "" {
		slog.Error("issue auth token", "user", LogSafety_LogText(req.UserIDHash), "error", token.Error)
		Response_Error(w, http.StatusInternalServerError, "login failed")
		return
	}
	accountAlias, err := s.store.AccountAlias(r.Context(), req.UserIDHash)
	if err != nil {
		slog.Error("load account alias", "user", LogSafety_LogText(req.UserIDHash), "error", err)
		Response_Error(w, http.StatusInternalServerError, "alias failed")
		return
	}
	profileIcon, err := s.store.AccountProfileIcon(r.Context(), req.UserIDHash)
	if err != nil {
		slog.Error("load profile icon", "user", LogSafety_LogText(req.UserIDHash), "error", err)
		Response_Error(w, http.StatusInternalServerError, "profile icon failed")
		return
	}
	Response_JSON(w, http.StatusOK, LoginResponse{
		Status:       "ok",
		AuthToken:    token.Value,
		ExpiresIn:    int64(s.cfg.TokenTTL.Seconds()),
		ServerTime:   time.Now().Unix(),
		AccountAlias: accountAlias,
		ProfileIcon:  profileIcon,
	})
}

func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	body, req, err := readDeleteRequest(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := applyHeaderUser(r, &req.UserIDHash); err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	signature, context := requestSignatureHeader(r)
	_, err = s.authenticateSignature(r.Context(), req.UserIDHash, "", signature, context, r.Method, r.URL.Path, body)
	if err != nil {
		s.writeAuthError(w, err)
		return
	}
	if err := s.store.DeleteAccount(r.Context(), req.UserIDHash); err != nil {
		slog.Error("delete account", "user", LogSafety_LogText(req.UserIDHash), "error", err)
		Response_Error(w, http.StatusInternalServerError, "delete failed")
		return
	}
	Response_JSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleDeleteAccountWithKey(w http.ResponseWriter, r *http.Request) {
	req, err := readDeleteWithKeyRequest(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.allowRequest(r, "delete-key:ip:"+ClientAddress_FromRequest(r), 8, time.Hour) ||
		!s.allowRequest(r, "delete-key:user:"+req.UserIDHash, 4, time.Hour) {
		Response_Error(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}
	account := AccountKeys_PublicKey(s.store.db, r.Context(), req.UserIDHash)
	publicKey, found, err := account.Value, account.Found, account.Error
	if err != nil {
		slog.Error("load account key", "user", LogSafety_LogText(req.UserIDHash), "error", err)
		Response_Error(w, http.StatusInternalServerError, "delete failed")
		return
	}
	if !found {
		Response_Error(w, http.StatusNotFound, "sync account not found")
		return
	}
	exportedKey, err := parseExportedSyncKey(req.ExportedKey)
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if exportedKey.PublicID != "" && exportedKey.PublicID != req.UserIDHash {
		Response_Error(w, http.StatusBadRequest, "exported key public_id does not match user_id_hash")
		return
	}
	message := []byte("inbe-delete-account-v1\n" + req.UserIDHash + "\n")
	signature, err := signWithPrivateKey(message, exportedKey.PrivateKey)
	if err != nil || !s.verifier.Verify(publicKey, []byte(message), signature) {
		Response_Error(w, http.StatusUnauthorized, "exported key does not match sync account")
		return
	}
	if err := s.store.DeleteAccount(r.Context(), req.UserIDHash); err != nil {
		slog.Error("delete account with key", "user", LogSafety_LogText(req.UserIDHash), "error", err)
		Response_Error(w, http.StatusInternalServerError, "delete failed")
		return
	}
	Response_JSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) authenticateSignature(ctx context.Context, userID, publicKeyText, signatureText, signatureContext, method, path string, signedPayload []byte) ([]byte, error) {
	userID = strings.ToLower(strings.TrimSpace(userID))
	if !Identity_ValidUserID(userID) {
		return nil, authError{status: http.StatusBadRequest, message: "invalid user_id_hash"}
	}
	consumed := Challenge_Consume(s.challenges, userID)
	nonce, ok := consumed.Nonce, consumed.Found
	if !ok {
		return nil, authError{status: http.StatusBadRequest, message: "missing or expired challenge"}
	}
	account := AccountKeys_PublicKey(s.store.db, ctx, userID)
	publicKey, found, err := account.Value, account.Found, account.Error
	if err != nil {
		return nil, err
	}
	if !found {
		if publicKeyText == "" {
			return nil, authError{status: http.StatusBadRequest, message: "public_key required for first sync"}
		}
		publicKeyField := Codec_DecodeBinaryField(publicKeyText)
		publicKey = []byte(publicKeyField.Value)
		if publicKeyField.Error != "" {
			return nil, authError{status: http.StatusBadRequest, message: "invalid public_key"}
		}
		if len(publicKey) != mlDSA44PublicKeySize {
			return nil, authError{status: http.StatusBadRequest, message: "wrong public_key size"}
		}
		if err := EncryptedRecord_ValidateAccountKey(userID, publicKey); err != nil {
			return nil, authError{status: http.StatusBadRequest, message: "public_key does not match user_id_hash"}
		}
	} else if publicKeyText != "" {
		suppliedField := Codec_DecodeBinaryField(publicKeyText)
		supplied := []byte(suppliedField.Value)
		if suppliedField.Error != "" || subtle.ConstantTimeCompare(supplied, publicKey) != 1 {
			return nil, authError{status: http.StatusBadRequest, message: "public_key does not match registered user"}
		}
	}
	signatureField := Codec_DecodeBinaryField(signatureText)
	signature := []byte(signatureField.Value)
	if signatureField.Error != "" {
		return nil, authError{status: http.StatusBadRequest, message: "invalid signature"}
	}
	if len(signature) != mlDSA44SignatureSize {
		return nil, authError{status: http.StatusBadRequest, message: "wrong signature size"}
	}
	message := Signing_CanonicalMessageWithContext(signatureContext, nonce, method, path, signedPayload)
	if !s.verifier.Verify(publicKey, []byte(message), signature) {
		return nil, authError{status: http.StatusUnauthorized, message: "signature rejected"}
	}
	return publicKey, nil
}

func applyHeaderUser(r *http.Request, bodyUser *string) error {
	userHeader := HttpAuth_UserHeader(r)
	headerUser, headerName := userHeader.Value, userHeader.Name
	if headerUser == "" {
		return errors.New("missing X-Daochi-User")
	}
	if *bodyUser == "" {
		*bodyUser = headerUser
		return nil
	}
	*bodyUser = strings.ToLower(strings.TrimSpace(*bodyUser))
	if *bodyUser != headerUser {
		return errors.New(headerName + " does not match user_id_hash")
	}
	return nil
}

func requestSignatureHeader(r *http.Request) (string, string) {
	if value := strings.TrimSpace(r.Header.Get("X-Daochi-Signature")); value != "" {
		return value, daochiSignatureContext
	}
	if value := strings.TrimSpace(r.Header.Get("X-Ksync-Signature")); value != "" {
		return value, legacySyncSignatureContext
	}
	if value := strings.TrimSpace(r.Header.Get("X-Inbe-Signature")); value != "" {
		return value, legacyInbeSignatureContext
	}
	return "", legacySyncSignatureContext
}

func readSyncRequest(w http.ResponseWriter, r *http.Request, maxBody int64) ([]byte, SyncRequest, error) {
	bodyResult := HttpBody_ReadJSON(w, r, maxBody)
	body, err := bodyResult.Value, bodyResult.Error
	if err != nil {
		return nil, SyncRequest{}, err
	}
	req, err := parseSyncRequestBody(body)
	return body, req, err
}

func parseSyncRequestBody(body []byte) (SyncRequest, error) {
	var req SyncRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return req, errors.New("invalid json")
	}
	req.UserIDHash = strings.ToLower(strings.TrimSpace(req.UserIDHash))
	req.AppID = strings.TrimSpace(req.AppID)
	req.PublicKey = strings.TrimSpace(req.PublicKey)
	req.ClientID = strings.TrimSpace(req.ClientID)
	for i := range req.EncryptedRecords {
		req.EncryptedRecords[i].Collection = strings.TrimSpace(req.EncryptedRecords[i].Collection)
		req.EncryptedRecords[i].ID = strings.TrimSpace(req.EncryptedRecords[i].ID)
		req.EncryptedRecords[i].KeyID = strings.TrimSpace(req.EncryptedRecords[i].KeyID)
		req.EncryptedRecords[i].Nonce = strings.TrimSpace(req.EncryptedRecords[i].Nonce)
		req.EncryptedRecords[i].UpdatedAt = strings.TrimSpace(req.EncryptedRecords[i].UpdatedAt)
		req.EncryptedRecords[i].ContentHash = strings.ToLower(strings.TrimSpace(req.EncryptedRecords[i].ContentHash))
		req.EncryptedRecords[i].ParentID = strings.TrimSpace(req.EncryptedRecords[i].ParentID)
	}
	return req, nil
}

func isEncryptedSyncEnvelope(body []byte) bool {
	var envelope struct {
		V          int    `json:"v"`
		Nonce      string `json:"nonce"`
		Ciphertext string `json:"ciphertext"`
	}
	if !json.Valid(body) || json.Unmarshal(body, &envelope) != nil {
		return false
	}
	return (envelope.V == 1 || envelope.V == 2) &&
		strings.TrimSpace(envelope.Nonce) != "" &&
		strings.TrimSpace(envelope.Ciphertext) != ""
}

func emptySyncChanges() SyncChanges {
	return SyncChanges{
		Habits:           []Habit{},
		HabitDays:        []HabitDay{},
		Sessions:         []Session{},
		MeditationLogs:   []MeditationLog{},
		SocialCache:      []SocialSnapshot{},
		EncryptedRecords: []EncryptedRecord{},
	}
}

func readLoginRequest(w http.ResponseWriter, r *http.Request, maxBody int64) ([]byte, LoginRequest, error) {
	var req LoginRequest
	bodyResult := HttpBody_ReadJSON(w, r, maxBody)
	body, err := bodyResult.Value, bodyResult.Error
	if err != nil {
		return nil, req, err
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, req, errors.New("invalid json")
	}
	req.UserIDHash = strings.ToLower(strings.TrimSpace(req.UserIDHash))
	req.PublicKey = strings.TrimSpace(req.PublicKey)
	req.ClientID = strings.TrimSpace(req.ClientID)
	return body, req, nil
}

func readDeleteRequest(w http.ResponseWriter, r *http.Request, maxBody int64) ([]byte, DeleteRequest, error) {
	var req DeleteRequest
	bodyResult := HttpBody_ReadJSON(w, r, maxBody)
	body, err := bodyResult.Value, bodyResult.Error
	if err != nil {
		return nil, req, err
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, req, errors.New("invalid json")
	}
	req.UserIDHash = strings.ToLower(strings.TrimSpace(req.UserIDHash))
	return body, req, nil
}

func readAliasRequest(w http.ResponseWriter, r *http.Request, maxBody int64) ([]byte, AliasRequest, error) {
	var req AliasRequest
	bodyResult := HttpBody_ReadJSON(w, r, maxBody)
	body, err := bodyResult.Value, bodyResult.Error
	if err != nil {
		return nil, req, err
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, req, errors.New("invalid json")
	}
	req.UserIDHash = strings.ToLower(strings.TrimSpace(req.UserIDHash))
	req.Alias = normalizeAlias(req.Alias)
	return body, req, nil
}

func readProfileIconRequest(w http.ResponseWriter, r *http.Request, maxBody int64) ([]byte, ProfileIconRequest, error) {
	var req ProfileIconRequest
	bodyResult := HttpBody_ReadJSON(w, r, maxBody)
	body, err := bodyResult.Value, bodyResult.Error
	if err != nil {
		return nil, req, err
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, req, errors.New("invalid json")
	}
	req.UserIDHash = strings.ToLower(strings.TrimSpace(req.UserIDHash))
	return body, req, nil
}

func readFriendRequestCreateRequest(w http.ResponseWriter, r *http.Request, maxBody int64) (FriendRequestCreateRequest, error) {
	var req FriendRequestCreateRequest
	bodyResult := HttpBody_ReadJSON(w, r, maxBody)
	body, err := bodyResult.Value, bodyResult.Error
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return req, errors.New("invalid json")
	}
	req.Target = strings.TrimSpace(req.Target)
	if req.Target == "" {
		return req, errors.New("target required")
	}
	return req, nil
}

func readProfileStatsRequest(w http.ResponseWriter, r *http.Request, maxBody int64) (ProfileStatsRequest, error) {
	var req ProfileStatsRequest
	bodyResult := HttpBody_ReadJSON(w, r, maxBody)
	body, err := bodyResult.Value, bodyResult.Error
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return req, errors.New("invalid json")
	}
	req.App = strings.TrimSpace(req.App)
	if !Identity_ValidNamespace(req.App) {
		return req, errors.New("invalid app")
	}
	if len(req.Metrics) > 100 {
		return req, errors.New("too many metrics")
	}
	for i := range req.Metrics {
		req.Metrics[i].Practice = strings.TrimSpace(req.Metrics[i].Practice)
		req.Metrics[i].Metric = strings.TrimSpace(req.Metrics[i].Metric)
		req.Metrics[i].Label = strings.TrimSpace(req.Metrics[i].Label)
		if !Identity_ValidNamespace(req.Metrics[i].Practice) || !Identity_ValidNamespace(req.Metrics[i].Metric) {
			return req, errors.New("invalid metric")
		}
	}
	return req, nil
}

func readDeleteWithKeyRequest(w http.ResponseWriter, r *http.Request, maxBody int64) (DeleteWithKeyRequest, error) {
	var req DeleteWithKeyRequest
	bodyResult := HttpBody_ReadJSON(w, r, maxBody)
	body, err := bodyResult.Value, bodyResult.Error
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return req, errors.New("invalid json")
	}
	req.UserIDHash = strings.ToLower(strings.TrimSpace(req.UserIDHash))
	req.ExportedKey = strings.TrimSpace(req.ExportedKey)
	if !Identity_ValidUserID(req.UserIDHash) {
		return req, errors.New("invalid user_id_hash")
	}
	if req.ExportedKey == "" {
		return req, errors.New("exported_key required")
	}
	return req, nil
}

func normalizeMeditationDurations(logs []MeditationLog) {
	for i := range logs {
		if logs[i].DurationSeconds == 0 && logs[i].Duration != 0 {
			logs[i].DurationSeconds = logs[i].Duration
		}
	}
}

func parseFriendRequestPath(path string) (requestID string, action string, ok bool) {
	const prefix = "/api/v1/friends/requests/"
	rest := strings.TrimPrefix(path, prefix)
	if rest == path || rest == "" {
		return "", "", false
	}
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 2 && Identity_ValidResourceID(parts[0]) && (parts[1] == "accept" || parts[1] == "decline") {
		return parts[0], parts[1], true
	}
	return "", "", false
}

type exportedSyncKey struct {
	PublicID   string
	PrivateKey []byte
}

const (
	accountKeyHeader       = "ksync-account-key-v1"
	legacyAccountKeyHeader = "lyra-account-key-v1"
	legacyUkuKeyHeader     = "account-key-v1"
	legacyInbeKeyHeader    = "inbe-sync-key-v1"
)

func parseExportedSyncKey(text string) (exportedSyncKey, error) {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	if len(lines) == 0 {
		return exportedSyncKey{}, errors.New("invalid account key file")
	}
	header := strings.TrimSpace(lines[0])
	if header != accountKeyHeader && header != legacyAccountKeyHeader &&
		header != legacyUkuKeyHeader && header != legacyInbeKeyHeader {
		return exportedSyncKey{}, errors.New("invalid account key file")
	}
	algorithmOK := false
	publicID := ""
	privateKeyText := ""
	for _, line := range lines[1:] {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "algorithm":
			algorithmOK = strings.TrimSpace(value) == "ML-DSA-44"
		case "public_id":
			publicID = strings.ToLower(strings.TrimSpace(value))
		case "private_key":
			privateKeyText = strings.TrimSpace(value)
		}
	}
	if !algorithmOK {
		return exportedSyncKey{}, errors.New("account key algorithm must be ML-DSA-44")
	}
	if publicID != "" && !Identity_ValidUserID(publicID) {
		return exportedSyncKey{}, errors.New("invalid public_id")
	}
	privateKeyField := Codec_DecodeBinaryField(privateKeyText)
	privateKey := []byte(privateKeyField.Value)
	if privateKeyField.Error != "" {
		return exportedSyncKey{}, errors.New("invalid private_key")
	}
	if len(privateKey) != mlDSA44PrivateKeySize {
		return exportedSyncKey{}, errors.New("wrong private_key size")
	}
	return exportedSyncKey{PublicID: publicID, PrivateKey: privateKey}, nil
}

type authError struct {
	status  int
	message string
}

func (e authError) Error() string {
	return e.message
}

func (s *Server) writeAuthError(w http.ResponseWriter, err error) {
	var ae authError
	if errors.As(err, &ae) {
		Metrics_RecordAuthFailure(s.metrics, ae.status, ae.message)
		Response_Error(w, ae.status, ae.message)
		return
	}
	slog.Error("auth", "error", err)
	Metrics_RecordAuthFailure(s.metrics, http.StatusInternalServerError, "authentication failed")
	Response_Error(w, http.StatusInternalServerError, "authentication failed")
}

type metricsResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *metricsResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *metricsResponseWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(data)
}

func (w *metricsResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("hijack unsupported")
	}
	if w.status == 0 {
		w.status = http.StatusSwitchingProtocols
	}
	return hijacker.Hijack()
}

func (s *Server) withCommonHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		mw := &metricsResponseWriter{ResponseWriter: w}
		defer func() {
			status := mw.status
			if status == 0 {
				status = http.StatusOK
			}
			Metrics_RecordHTTP(s.metrics, r.Method, r.URL.Path, status, time.Since(start))
		}()
		w = mw
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		if origin := allowedCORSOrigin(r.Header.Get("Origin")); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Daochi-User, X-Daochi-Signature, X-Daochi-Client, X-Daochi-Since-Version, X-Daochi-Limit, X-Daochi-Admin, X-Ksync-User, X-Ksync-Signature, X-Ksync-Client, X-Ksync-Since-Version, X-Ksync-Limit, X-Ksync-Admin, X-Inbe-User, X-Inbe-Signature")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) allowRequest(r *http.Request, key string, limit int, window time.Duration) bool {
	if s.limiter == nil {
		return true
	}
	allowed := RateLimit_Allow(s.limiter, key, limit, window)
	if !allowed {
		s.metrics.RateLimitedRequests.Add(1)
	}
	return allowed
}

func allowedCORSOrigin(origin string) string {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Path != "" ||
		u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return ""
	}
	if origin == "https://daochi.pages.dev" ||
		origin == "https://daochi.kryonlabs.com" ||
		origin == "https://daochi.net" ||
		origin == "https://www.daochi.net" ||
		origin == "https://inbe.waozi.xyz" ||
		origin == "https://uku.waozi.xyz" {
		return origin
	}
	if u.Scheme == "chrome-extension" && validChromeExtensionID(u.Host) {
		return origin
	}
	if u.Scheme != "http" {
		return ""
	}
	switch u.Hostname() {
	case "localhost", "127.0.0.1", "0.0.0.0", "::1":
		return origin
	default:
		return ""
	}
}

func validChromeExtensionID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, r := range id {
		if r < 'a' || r > 'p' {
			return false
		}
	}
	return true
}
