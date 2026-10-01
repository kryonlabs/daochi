package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

const (
	daochiSignatureContext     = "daochi-sync-v1"
	legacySyncSignatureContext = "ksync-sync-v1"
	legacyInbeSignatureContext = "inbe-sync-v1"
)

var errSignedTxReplay = errors.New("signed transaction replay")
var errAppScopeNotOwned = errors.New("app does not own collection scope")

type Server struct {
	cfg        Config
	store      *Store
	challenges *ChallengeStore
	verifier   Verifier
	syncHub    *SyncHub
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
		syncHub:    SyncHub_New(),
		limiter:    RateLimit_New(),
		metrics:    &ServerMetrics{},
		node:       node.Value,
	}
}

func (s *Server) access() AccountAccess {
	return AccountAccess{
		Database:      s.store.db,
		Configuration: &s.cfg,
		Challenges:    s.challenges,
		Limiter:       s.limiter,
		Counters:      s.metrics,
		Verify: func(publicKey, message, signature []byte) bool {
			return s.verifier.Verify(publicKey, message, signature)
		},
		Sign: signAccountProof,
	}
}

func (s *Server) operations() Operations {
	return Operations{
		Database:          s.store.db,
		Path:              s.store.path,
		Configuration:     &s.cfg,
		Identity:          &s.node,
		Notifications:     s.syncHub,
		Counters:          s.metrics,
		VerifierAvailable: s.verifier != nil,
	}
}

func (s *Server) tokens() Tokens {
	return Tokens{
		Database:          s.store.db,
		Configuration:     &s.cfg,
		Counters:          s.metrics,
		Limiter:           s.limiter,
		Verify:            s.verifier.Verify,
		ReplayError:       errSignedTxReplay,
		IssuerUnavailable: errTokenIssuerReadOnly,
	}
}

func (s *Server) monero() Monero {
	return Monero{
		Database:          s.store.db,
		Configuration:     &s.cfg,
		Counters:          s.metrics,
		Limiter:           s.limiter,
		AddressLocks:      &s.moneroAddressLocks,
		StuckNotified:     &s.moneroStuckNotified,
		Verify:            s.verifier.Verify,
		ReplayError:       errSignedTxReplay,
		Unavailable:       errPaymentUnavailable,
		IssuerUnavailable: errTokenIssuerReadOnly,
		MissingUser:       ErrSyncUserNotFound,
	}
}

func (s *Server) accounts() Accounts {
	return Accounts{
		Database:      s.store.db,
		Configuration: &s.cfg,
		Counters:      s.metrics,
		MissingUser:   ErrSyncUserNotFound,
	}
}

func (s *Server) social() Social {
	return Social{Accounts: s.accounts(), Notifications: s.syncHub}
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

func (s *Server) mesh() Mesh {
	return Mesh{
		Database:      s.store.db,
		Configuration: &s.cfg,
		Identity:      &s.node,
		ConvertError:  authenticationError,
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
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		Docs_Handle(w, r, s.cfg.DBPath, func(ctx context.Context, databasePath string) PublicStatsResult {
			value, err := s.store.PublicStats(ctx, databasePath)
			return PublicStatsResult{Value: value, Error: err}
		})
	})
	mux.HandleFunc("GET /openapi.json", Docs_OpenAPI)
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
	mux.HandleFunc("POST /api/v1/node/mesh/export", func(w http.ResponseWriter, r *http.Request) {
		Mesh_Export(s.mesh(), w, r)
	})
	mux.HandleFunc("POST /api/v1/node/mesh/import", func(w http.ResponseWriter, r *http.Request) {
		Mesh_Import(s.mesh(), w, r)
	})
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
	mux.HandleFunc("GET /api/v1/tokens/assets", func(w http.ResponseWriter, r *http.Request) {
		TokenHttp_Assets(s.tokens(), w, r)
	})
	mux.HandleFunc("GET /api/v1/tokens/products", func(w http.ResponseWriter, r *http.Request) {
		TokenHttp_Products(s.tokens(), w, r)
	})
	mux.HandleFunc("GET /api/v1/tokens/issuer", func(w http.ResponseWriter, r *http.Request) {
		TokenHttp_Issuer(s.tokens(), w, r)
	})
	mux.HandleFunc("GET /api/v1/tokens/balance", func(w http.ResponseWriter, r *http.Request) {
		TokenHttp_Balance(s.tokens(), w, r)
	})
	mux.HandleFunc("GET /api/v1/tokens/ledger", func(w http.ResponseWriter, r *http.Request) {
		TokenHttp_Ledger(s.tokens(), w, r)
	})
	mux.HandleFunc("POST /api/v1/tokens/spend", func(w http.ResponseWriter, r *http.Request) {
		TokenHttp_Spend(s.tokens(), w, r)
	})
	mux.HandleFunc("POST /api/v1/tokens/purchases/google/verify", func(w http.ResponseWriter, r *http.Request) {
		GooglePlayHttp_Verify(s.tokens(), w, r)
	})
	mux.HandleFunc("POST /api/v1/tokens/purchases/monero/invoices", func(w http.ResponseWriter, r *http.Request) {
		MoneroInvoices_Create(s.monero(), w, r)
	})
	mux.HandleFunc("GET /api/v1/tokens/purchases/monero/invoices/", func(w http.ResponseWriter, r *http.Request) {
		MoneroInvoices_Read(s.monero(), w, r)
	})
	mux.HandleFunc("GET /api/v1/tokens/purchases/monero/address", func(w http.ResponseWriter, r *http.Request) { MoneroDeposits_Address(s.monero(), w, r) })
	mux.HandleFunc("GET /api/v1/tokens/purchases/monero/address/", func(w http.ResponseWriter, r *http.Request) { MoneroDeposits_Address(s.monero(), w, r) })
	mux.HandleFunc("GET /api/v1/tokens/purchases/monero/deposits", func(w http.ResponseWriter, r *http.Request) { MoneroDeposits_Deposits(s.monero(), w, r) })
	mux.HandleFunc("GET /api/v1/tokens/checkpoints/latest", func(w http.ResponseWriter, r *http.Request) {
		TokenHttp_LatestCheckpoint(s.tokens(), w, r)
	})
	mux.HandleFunc("GET /api/v1/tokens/receipts/", func(w http.ResponseWriter, r *http.Request) {
		TokenHttp_Receipt(s.tokens(), w, r)
	})
	mux.HandleFunc("POST /api/v1/admin/tokens/manual-credit", func(w http.ResponseWriter, r *http.Request) {
		TokenHttp_ManualCredit(s.tokens(), w, r)
	})
	mux.HandleFunc("POST /api/v1/admin/tokens/checkpoint", func(w http.ResponseWriter, r *http.Request) {
		TokenHttp_CreateCheckpoint(s.tokens(), w, r)
	})
	mux.HandleFunc("GET /api/v1/sync/diagnostics", s.handleSyncDiagnostics)
	mux.HandleFunc("GET /api/v1/sync/challenge", s.handleChallenge)
	mux.HandleFunc("GET /api/v1/sync/ws", s.handleSyncWebSocket)
	mux.HandleFunc("POST /api/v1/sync/login", s.handleLogin)
	mux.HandleFunc("POST /api/v1/sync", s.handleSync)
	mux.HandleFunc("POST /api/v1/account/alias", func(w http.ResponseWriter, r *http.Request) {
		AccountHttp_Alias(s.accounts(), w, r)
	})
	mux.HandleFunc("POST /api/v1/account/profile-icon", func(w http.ResponseWriter, r *http.Request) {
		AccountHttp_ProfileIcon(s.accounts(), w, r)
	})
	mux.HandleFunc("GET /api/v1/account/export", func(w http.ResponseWriter, r *http.Request) {
		AccountHttp_Export(s.accounts(), w, r)
	})
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
	mux.HandleFunc("GET /api/v1/friends", func(w http.ResponseWriter, r *http.Request) {
		SocialHttp_Friends(s.social(), w, r)
	})
	mux.HandleFunc("DELETE /api/v1/friends/", func(w http.ResponseWriter, r *http.Request) {
		SocialHttp_RemoveFriend(s.social(), w, r)
	})
	mux.HandleFunc("GET /api/v1/friends/requests", func(w http.ResponseWriter, r *http.Request) {
		SocialHttp_Requests(s.social(), w, r)
	})
	mux.HandleFunc("POST /api/v1/friends/requests", func(w http.ResponseWriter, r *http.Request) {
		SocialHttp_CreateRequest(s.social(), w, r)
	})
	mux.HandleFunc("POST /api/v1/friends/requests/", func(w http.ResponseWriter, r *http.Request) {
		SocialHttp_RequestAction(s.social(), w, r)
	})
	mux.HandleFunc("PUT /api/v1/profile/stats", func(w http.ResponseWriter, r *http.Request) {
		SocialHttp_PutStats(s.social(), w, r)
	})
	mux.HandleFunc("GET /api/v1/friends/stats", func(w http.ResponseWriter, r *http.Request) {
		SocialHttp_FriendStats(s.social(), w, r)
	})
	return s.withCommonHeaders(mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	OperationalHttp_Health(w, r)
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	OperationalHttp_Ready(s.operations(), w, r)
}

func (s *Server) handleNodeInfo(w http.ResponseWriter, r *http.Request) {
	OperationalHttp_Node(s.operations(), w, r)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	OperationalHttp_Metrics(s.operations(), w, r)
}

func (s *Server) nodeUsage(ctx context.Context) (NodeUsage, error) {
	result := OperationalHttp_Usage(s.operations(), ctx)
	return result.Value, result.Error
}

func (s *Server) handleSyncDiagnostics(w http.ResponseWriter, r *http.Request) {
	OperationalHttp_Diagnostics(s.operations(), w, r)
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	AccountAccess_Challenge(s.access(), w, r)
}

func (s *Server) synchronization() Synchronization {
	return Synchronization{
		Database:      s.store.db,
		Configuration: &s.cfg,
		Counters:      s.metrics,
		Notifications: s.syncHub,
		Verify: func(publicKey, message, signature []byte) bool {
			return s.verifier.Verify(publicKey, message, signature)
		},
		ReplayError: errSignedTxReplay,
		MissingUser: ErrSyncUserNotFound,
	}
}

func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	SyncHttp_Handle(s.synchronization(), w, r)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	AccountAccess_Login(s.access(), w, r)
}

func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	AccountAccess_Delete(s.access(), w, r)
}

func (s *Server) handleDeleteAccountWithKey(w http.ResponseWriter, r *http.Request) {
	AccountAccess_DeleteWithKey(s.access(), w, r)
}

func (s *Server) authenticateSignature(ctx context.Context, userID, publicKeyText, signatureText, signatureContext, method, path string, signedPayload []byte) ([]byte, error) {
	result := AccountSignature_Authenticate(s.store.db, s.challenges, s.access().Verify, ctx, userID, publicKeyText, signatureText, signatureContext, method, path, signedPayload)
	return result.Value, authenticationError(result.Authentication)
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

func (s *Server) withCommonHeaders(next http.Handler) http.Handler {
	return Middleware_New(&s.metrics, next)
}

func (s *Server) allowRequest(r *http.Request, key string, limit int, window time.Duration) bool {
	return RequestRate_Allow(s.limiter, s.metrics, key, limit, window)
}

func (s *Server) syncSocket() SyncSocket {
	return SyncSocket{
		Database:      s.store.db,
		Configuration: &s.cfg,
		Counters:      s.metrics,
		Limiter:       s.limiter,
		Hub:           s.syncHub,
	}
}

func (s *Server) handleSyncWebSocket(w http.ResponseWriter, r *http.Request) {
	SyncWs_Handle(s.syncSocket(), w, r)
}
