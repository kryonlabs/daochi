package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var userIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var clientIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{8,128}$`)
var accountAliasPattern = regexp.MustCompile(`^[a-z0-9_]{4,32}$`)
var ukuIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{4,128}$`)
var lyraNamespacePattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)

type Server struct {
	cfg        Config
	store      *Store
	challenges *ChallengeStore
	verifier   Verifier
	syncHub    *syncHub
}

func NewServer(cfg Config, store *Store, verifier Verifier) *Server {
	return &Server{
		cfg:        cfg,
		store:      store,
		challenges: NewChallengeStore(cfg.ChallengeTTL),
		verifier:   verifier,
		syncHub:    newSyncHub(),
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.handleDocs)
	mux.HandleFunc("GET /openapi.json", s.handleOpenAPI)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /api/v1/sync/challenge", s.handleChallenge)
	mux.HandleFunc("GET /api/v1/sync/ws", s.handleSyncWebSocket)
	mux.HandleFunc("POST /api/v1/sync/login", s.handleLogin)
	mux.HandleFunc("POST /api/v1/sync", s.handleSync)
	mux.HandleFunc("POST /api/v1/account/alias", s.handleAlias)
	mux.HandleFunc("DELETE /api/v1/account", s.handleDeleteAccount)
	mux.HandleFunc("POST /api/v1/account/delete-with-key", s.handleDeleteAccountWithKey)
	mux.HandleFunc("GET /api/v1/friends", s.handleFriends)
	mux.HandleFunc("DELETE /api/v1/friends/", s.handleFriendRoute)
	mux.HandleFunc("GET /api/v1/friends/requests", s.handleFriendRequests)
	mux.HandleFunc("POST /api/v1/friends/requests", s.handleFriendRequestCreate)
	mux.HandleFunc("POST /api/v1/friends/requests/", s.handleFriendRequestRoute)
	mux.HandleFunc("PUT /api/v1/profile/stats", s.handleProfileStatsPut)
	mux.HandleFunc("GET /api/v1/friends/stats", s.handleFriendStats)
	mux.HandleFunc("GET /api/v1/uku/processes", s.handleUkuProcessList)
	mux.HandleFunc("POST /api/v1/uku/processes", s.handleUkuProcessCreate)
	mux.HandleFunc("GET /api/v1/uku/processes/", s.handleUkuProcessRoute)
	mux.HandleFunc("PATCH /api/v1/uku/processes/", s.handleUkuProcessRoute)
	mux.HandleFunc("POST /api/v1/uku/processes/", s.handleUkuProcessRoute)
	return s.withCommonHeaders(mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	userID := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("user_id")))
	if !validUserID(userID) {
		writeError(w, http.StatusBadRequest, "invalid user_id")
		return
	}
	nonce, err := s.challenges.Issue(userID)
	if err != nil {
		slog.Error("issue challenge", "error", err)
		writeError(w, http.StatusInternalServerError, "challenge failed")
		return
	}
	writeJSON(w, http.StatusOK, ChallengeResponse{
		UserIDHash: userID,
		Nonce:      hex.EncodeToString(nonce),
		ExpiresIn:  int64(s.cfg.ChallengeTTL.Seconds()),
	})
}

func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	_, req, err := readSyncRequest(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := applyHeaderUser(r, &req.UserIDHash); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !validClientID(req.ClientID) {
		writeError(w, http.StatusBadRequest, "invalid client_id")
		return
	}
	tokenUser, err := s.authenticateToken(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	if tokenUser != req.UserIDHash {
		writeError(w, http.StatusUnauthorized, "token user mismatch")
		return
	}
	publicKey, err := syncRequestPublicKey(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	normalizeMeditationDurations(req.MeditationLogs)

	baseHash, err := s.store.StateHash(r.Context(), req.UserIDHash)
	if err != nil {
		slog.Error("hash sync state", "user", req.UserIDHash, "error", err)
		writeError(w, http.StatusInternalServerError, "state hash failed")
		return
	}

	result := SyncResult{}
	acceptedOps := []string{}
	remoteOps := []SyncOp{}
	fullSnapshotRequired := false
	changesComplete := true
	sinceVersion := req.SinceServerVersion
	recordedClientClock := req.ClientClock
	if req.LastServerStateHash != "" &&
		!strings.EqualFold(req.LastServerStateHash, baseHash) &&
		!req.FullSyncRequested {
		fullSnapshotRequired = true
		changesComplete = false
		sinceVersion = 0
	} else if req.ProtocolVersion >= 2 && !req.FullSyncRequested {
		compacted, _, err := s.store.SyncOpsCompacted(r.Context(), req.UserIDHash, req.ClientClock)
		if err != nil {
			slog.Error("check sync op compaction", "user", req.UserIDHash, "error", err)
			writeError(w, http.StatusInternalServerError, "compaction check failed")
			return
		}
		if compacted {
			fullSnapshotRequired = true
			changesComplete = false
			sinceVersion = 0
		} else {
			result, acceptedOps, err = s.store.ApplySyncDetailed(r.Context(), req, publicKey)
			if err != nil {
				slog.Error("apply sync", "user", req.UserIDHash, "error", err)
				writeError(w, http.StatusInternalServerError, "sync failed")
				return
			}
		}
	} else {
		result, acceptedOps, err = s.store.ApplySyncDetailed(r.Context(), req, publicKey)
		if err != nil {
			slog.Error("apply sync", "user", req.UserIDHash, "error", err)
			writeError(w, http.StatusInternalServerError, "sync failed")
			return
		}
	}

	changes, serverVersion, err := s.store.ChangesSince(r.Context(), req.UserIDHash, sinceVersion)
	if err != nil {
		slog.Error("load sync changes", "user", req.UserIDHash, "error", err)
		writeError(w, http.StatusInternalServerError, "changes failed")
		return
	}
	if req.ProtocolVersion >= 2 {
		if fullSnapshotRequired {
			remoteOps = []SyncOp{}
			recordedClientClock = serverVersion
		} else {
			remoteOps, err = s.store.OpsSince(r.Context(), req.UserIDHash, req.ClientClock)
			if err != nil {
				slog.Error("load sync ops", "user", req.UserIDHash, "error", err)
				writeError(w, http.StatusInternalServerError, "ops failed")
				return
			}
		}
	}
	serverHash, err := s.store.StateHash(r.Context(), req.UserIDHash)
	if err != nil {
		slog.Error("hash sync response", "user", req.UserIDHash, "error", err)
		writeError(w, http.StatusInternalServerError, "state hash failed")
		return
	}
	if err := s.store.RecordClientSync(r.Context(), req.UserIDHash, req.ClientID, req.SinceServerVersion, serverVersion, req.ProtocolVersion, recordedClientClock); err != nil {
		slog.Error("record sync client", "user", req.UserIDHash, "client", req.ClientID, "error", err)
		writeError(w, http.StatusInternalServerError, "client state failed")
		return
	}
	if req.ProtocolVersion >= 2 {
		if err := s.store.CompactSyncOps(r.Context(), req.UserIDHash); err != nil {
			slog.Error("compact sync ops", "user", req.UserIDHash, "error", err)
			writeError(w, http.StatusInternalServerError, "compaction failed")
			return
		}
	}
	if syncResultApplied(result) {
		s.syncHub.publish(req.UserIDHash, serverVersion)
	}
	accountAlias, err := s.store.AccountAlias(r.Context(), req.UserIDHash)
	if err != nil {
		slog.Error("load account alias", "user", req.UserIDHash, "error", err)
		writeError(w, http.StatusInternalServerError, "alias failed")
		return
	}
	writeJSON(w, http.StatusOK, SyncResponse{
		ProtocolVersion:      req.ProtocolVersion,
		Status:               "ok",
		Applied:              result,
		AccountAlias:         accountAlias,
		ServerVersion:        serverVersion,
		ServerClock:          serverVersion,
		ServerStateHash:      serverHash,
		BaseStateHash:        baseHash,
		ChangesComplete:      changesComplete,
		FullSnapshotRequired: fullSnapshotRequired,
		AcceptedOps:          acceptedOps,
		Ops:                  remoteOps,
		Changes:              changes,
	})
}

func (s *Server) handleAlias(w http.ResponseWriter, r *http.Request) {
	_, req, err := readAliasRequest(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := applyHeaderUser(r, &req.UserIDHash); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	tokenUser, err := s.authenticateToken(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	if tokenUser != req.UserIDHash {
		writeError(w, http.StatusUnauthorized, "token user mismatch")
		return
	}
	alias := normalizeAlias(req.Alias)
	if !validAccountAlias(alias) {
		writeError(w, http.StatusBadRequest, "invalid alias")
		return
	}
	if err := s.store.SetAccountAlias(r.Context(), req.UserIDHash, alias); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			writeError(w, http.StatusConflict, "alias unavailable")
			return
		}
		if errors.Is(err, ErrSyncUserNotFound) {
			writeError(w, http.StatusNotFound, "sync account not found")
			return
		}
		slog.Error("set account alias", "user", req.UserIDHash, "error", err)
		writeError(w, http.StatusInternalServerError, "alias failed")
		return
	}
	writeJSON(w, http.StatusOK, AliasResponse{Status: "ok", Alias: alias})
}

func (s *Server) bearerUser(w http.ResponseWriter, r *http.Request) (string, bool) {
	userID, err := s.authenticateToken(r)
	if err != nil {
		writeAuthError(w, err)
		return "", false
	}
	headerUser := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Inbe-User")))
	if headerUser != "" && headerUser != userID {
		writeAuthError(w, authError{status: http.StatusUnauthorized, message: "token user mismatch"})
		return "", false
	}
	return userID, true
}

func (s *Server) handleFriends(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	friends, err := s.store.ListFriends(r.Context(), userID)
	if err != nil {
		slog.Error("list friends", "user", userID, "error", err)
		writeError(w, http.StatusInternalServerError, "friends failed")
		return
	}
	response := FriendsResponse{Friends: friends}
	s.cacheSocialSnapshot(r.Context(), userID, "friends.list", response)
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleFriendRoute(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	friendID := strings.TrimPrefix(r.URL.Path, "/api/v1/friends/")
	friendID = strings.ToLower(strings.Trim(friendID, "/"))
	if !validUserID(friendID) {
		writeError(w, http.StatusNotFound, "friend not found")
		return
	}
	if err := s.store.RemoveFriend(r.Context(), userID, friendID); err != nil {
		slog.Error("remove friend", "user", userID, "friend", friendID, "error", err)
		writeError(w, http.StatusInternalServerError, "friend remove failed")
		return
	}
	s.syncHub.publish(userID, 0)
	s.syncHub.publish(friendID, 0)
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

func (s *Server) handleFriendRequests(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	incoming, outgoing, err := s.store.ListFriendRequests(r.Context(), userID)
	if err != nil {
		slog.Error("list friend requests", "user", userID, "error", err)
		writeError(w, http.StatusInternalServerError, "friend requests failed")
		return
	}
	response := FriendRequestsResponse{Incoming: incoming, Outgoing: outgoing}
	s.cacheSocialSnapshot(r.Context(), userID, "friends.requests", response)
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleFriendRequestCreate(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	req, err := readFriendRequestCreateRequest(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	target, found, err := s.store.ResolveAccountRef(r.Context(), req.Target)
	if err != nil {
		slog.Error("resolve friend target", "user", userID, "error", err)
		writeError(w, http.StatusInternalServerError, "friend request failed")
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "friend target not found")
		return
	}
	id, err := randomUkuID()
	if err != nil {
		slog.Error("generate friend request id", "error", err)
		writeError(w, http.StatusInternalServerError, "friend request failed")
		return
	}
	item, err := s.store.CreateFriendRequest(r.Context(), id, userID, target)
	if err != nil {
		if strings.Contains(err.Error(), "self") || strings.Contains(err.Error(), "already friends") {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		slog.Error("create friend request", "user", userID, "target", target, "error", err)
		writeError(w, http.StatusInternalServerError, "friend request failed")
		return
	}
	s.syncHub.publish(userID, 0)
	s.syncHub.publish(target, 0)
	writeJSON(w, http.StatusCreated, FriendRequestResponse{Status: "ok", Request: item})
}

func (s *Server) handleFriendRequestRoute(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	requestID, action, ok := parseFriendRequestPath(r.URL.Path)
	if !ok {
		writeError(w, http.StatusNotFound, "friend request not found")
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
		writeError(w, http.StatusNotFound, "friend request not found")
		return
	}
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "friend request not found")
		return
	}
	if errors.Is(err, ErrSyncUserNotFound) {
		writeError(w, http.StatusForbidden, "friend request not owned by user")
		return
	}
	if err != nil {
		if strings.Contains(err.Error(), "not pending") {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		slog.Error("friend request action", "user", userID, "request", requestID, "action", action, "error", err)
		writeError(w, http.StatusInternalServerError, "friend request failed")
		return
	}
	s.syncHub.publish(item.RequesterUserID, 0)
	s.syncHub.publish(item.TargetUserID, 0)
	writeJSON(w, http.StatusOK, FriendRequestResponse{Status: item.Status, Request: item})
}

func (s *Server) handleProfileStatsPut(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	req, err := readProfileStatsRequest(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	applied, err := s.store.UpsertProfileStats(r.Context(), userID, req.App, req.Metrics)
	if err != nil {
		slog.Error("upsert profile stats", "user", userID, "app", req.App, "error", err)
		writeError(w, http.StatusInternalServerError, "profile stats failed")
		return
	}
	if applied > 0 {
		s.syncHub.publish(userID, 0)
		if friends, err := s.store.ListFriends(r.Context(), userID); err == nil {
			for _, friend := range friends {
				s.syncHub.publish(friend.UserIDHash, 0)
			}
		} else {
			slog.Error("notify profile stats friends", "user", userID, "error", err)
		}
	}
	writeJSON(w, http.StatusOK, ProfileStatsResponse{Status: "ok", Applied: applied})
}

func (s *Server) handleFriendStats(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	app := strings.TrimSpace(r.URL.Query().Get("app"))
	practice := strings.TrimSpace(r.URL.Query().Get("practice"))
	metric := strings.TrimSpace(r.URL.Query().Get("metric"))
	if !validLyraNamespace(app) || !validLyraNamespace(practice) || !validLyraNamespace(metric) {
		writeError(w, http.StatusBadRequest, "invalid stats query")
		return
	}
	rows, err := s.store.FriendStats(r.Context(), userID, app, practice, metric)
	if err != nil {
		slog.Error("friend stats", "user", userID, "app", app, "practice", practice, "metric", metric, "error", err)
		writeError(w, http.StatusInternalServerError, "friend stats failed")
		return
	}
	response := FriendStatsResponse{Rows: rows}
	s.cacheSocialSnapshot(r.Context(), userID,
		"leaderboard."+app+"."+practice+"."+metric, response)
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleUkuProcessList(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListUkuPublicProcesses(r.Context(), 50)
	if err != nil {
		slog.Error("list uku processes", "error", err)
		writeError(w, http.StatusInternalServerError, "process list failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"processes": items})
}

func (s *Server) handleUkuProcessCreate(w http.ResponseWriter, r *http.Request) {
	req, err := readUkuCreateProcessRequest(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.applyBearerUser(r, &req.UserIDHash); err != nil {
		writeAuthError(w, err)
		return
	}
	if req.ID == "" {
		req.ID, err = randomUkuID()
		if err != nil {
			slog.Error("generate uku process id", "error", err)
			writeError(w, http.StatusInternalServerError, "process create failed")
			return
		}
	}
	process, err := s.store.CreateUkuProcess(r.Context(), req)
	if err != nil {
		slog.Error("create uku process", "user", req.UserIDHash, "error", err)
		writeError(w, http.StatusInternalServerError, "process create failed")
		return
	}
	writeJSON(w, http.StatusCreated, process)
}

func (s *Server) handleUkuProcessRoute(w http.ResponseWriter, r *http.Request) {
	processID, action, ok := parseUkuProcessPath(r.URL.Path)
	if !ok || !validUkuID(processID) {
		writeError(w, http.StatusNotFound, "process not found")
		return
	}
	if r.Method == http.MethodGet && action == "" {
		process, found, err := s.store.UkuProcess(r.Context(), processID)
		if err != nil {
			slog.Error("load uku process", "process", processID, "error", err)
			writeError(w, http.StatusInternalServerError, "process load failed")
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, "process not found")
			return
		}
		writeJSON(w, http.StatusOK, process)
		return
	}
	if r.Method == http.MethodPatch && action == "" {
		req, err := readUkuUpdateProcessRequest(w, r, s.cfg.MaxBodyBytes)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.applyBearerUser(r, &req.UserIDHash); err != nil {
			writeAuthError(w, err)
			return
		}
		process, err := s.store.UpdateUkuProcess(r.Context(), processID, req)
		if err != nil {
			writeUkuMutationError(w, err, "process update failed")
			return
		}
		writeJSON(w, http.StatusOK, process)
		return
	}
	if r.Method == http.MethodPost && action == "proposals" {
		req, err := readUkuProposalRequest(w, r, s.cfg.MaxBodyBytes)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.applyBearerUser(r, &req.UserIDHash); err != nil {
			writeAuthError(w, err)
			return
		}
		if req.ID == "" {
			req.ID, err = randomUkuID()
			if err != nil {
				slog.Error("generate uku proposal id", "error", err)
				writeError(w, http.StatusInternalServerError, "proposal failed")
				return
			}
		}
		process, err := s.store.UpsertUkuProposal(r.Context(), processID, req)
		if err != nil {
			writeUkuMutationError(w, err, "proposal failed")
			return
		}
		writeJSON(w, http.StatusOK, process)
		return
	}
	if r.Method == http.MethodPost && action == "votes" {
		req, err := readUkuVoteRequest(w, r, s.cfg.MaxBodyBytes)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.applyBearerUser(r, &req.UserIDHash); err != nil {
			writeAuthError(w, err)
			return
		}
		process, err := s.store.UpsertUkuVote(r.Context(), processID, req)
		if err != nil {
			writeUkuMutationError(w, err, "vote failed")
			return
		}
		writeJSON(w, http.StatusOK, process)
		return
	}
	writeError(w, http.StatusNotFound, "process not found")
}

func (s *Server) applyBearerUser(r *http.Request, bodyUser *string) error {
	if err := applyHeaderUser(r, bodyUser); err != nil {
		return authError{status: http.StatusBadRequest, message: err.Error()}
	}
	tokenUser, err := s.authenticateToken(r)
	if err != nil {
		return err
	}
	if tokenUser != *bodyUser {
		return authError{status: http.StatusUnauthorized, message: "token user mismatch"}
	}
	return nil
}

func writeUkuMutationError(w http.ResponseWriter, err error, fallback string) {
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "process not found")
		return
	}
	if errors.Is(err, ErrSyncUserNotFound) {
		writeError(w, http.StatusForbidden, "not process owner")
		return
	}
	writeError(w, http.StatusInternalServerError, fallback)
}

func syncRequestPublicKey(req SyncRequest) ([]byte, error) {
	if strings.TrimSpace(req.PublicKey) == "" {
		return nil, nil
	}
	publicKey, err := decodeBinaryField(req.PublicKey)
	if err != nil {
		return nil, errors.New("invalid public_key")
	}
	if len(publicKey) != mlDSA44PublicKeySize {
		return nil, errors.New("wrong public_key size")
	}
	if err := validateUserIDForPublicKey(req.UserIDHash, publicKey); err != nil {
		return nil, errors.New("public_key does not match user_id_hash")
	}
	return publicKey, nil
}

func syncResultApplied(result SyncResult) bool {
	return result.MeditationLogs > 0 ||
		result.Habits > 0 ||
		result.HabitDays > 0 ||
		result.Sessions > 0 ||
		result.SocialCache > 0
}

func (s *Server) cacheSocialSnapshot(ctx context.Context, userID, kind string, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		slog.Error("marshal social cache", "user", userID, "kind", kind, "error", err)
		return
	}
	applied, err := s.store.SetSocialCacheJSON(ctx, userID, kind, payload)
	if err != nil {
		slog.Error("write social cache", "user", userID, "kind", kind, "error", err)
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

func validAccountAlias(alias string) bool {
	return accountAliasPattern.MatchString(alias)
}

func validLyraNamespace(value string) bool {
	return lyraNamespacePattern.MatchString(value)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	body, req, err := readLoginRequest(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := applyHeaderUser(r, &req.UserIDHash); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !validClientID(req.ClientID) {
		writeError(w, http.StatusBadRequest, "invalid client_id")
		return
	}
	publicKey, err := s.authenticateSignature(r.Context(), req.UserIDHash, req.PublicKey, r.Header.Get("X-Inbe-Signature"), r.Method, r.URL.Path, body)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	if err := s.store.RegisterUser(r.Context(), req.UserIDHash, publicKey); err != nil {
		slog.Error("register sync user", "user", req.UserIDHash, "error", err)
		writeError(w, http.StatusInternalServerError, "login failed")
		return
	}
	if err := s.store.RecordClientLogin(r.Context(), req.UserIDHash, req.ClientID); err != nil {
		slog.Error("record login client", "user", req.UserIDHash, "client", req.ClientID, "error", err)
		writeError(w, http.StatusInternalServerError, "login failed")
		return
	}
	token, err := issueAuthToken(s.cfg.TokenSecret, req.UserIDHash, s.cfg.TokenTTL)
	if err != nil {
		slog.Error("issue auth token", "user", req.UserIDHash, "error", err)
		writeError(w, http.StatusInternalServerError, "login failed")
		return
	}
	accountAlias, err := s.store.AccountAlias(r.Context(), req.UserIDHash)
	if err != nil {
		slog.Error("load account alias", "user", req.UserIDHash, "error", err)
		writeError(w, http.StatusInternalServerError, "alias failed")
		return
	}
	writeJSON(w, http.StatusOK, LoginResponse{
		Status:       "ok",
		AuthToken:    token,
		ExpiresIn:    int64(s.cfg.TokenTTL.Seconds()),
		AccountAlias: accountAlias,
	})
}

func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	body, req, err := readDeleteRequest(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := applyHeaderUser(r, &req.UserIDHash); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_, err = s.authenticateSignature(r.Context(), req.UserIDHash, "", r.Header.Get("X-Inbe-Signature"), r.Method, r.URL.Path, body)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	if err := s.store.DeleteAccount(r.Context(), req.UserIDHash); err != nil {
		slog.Error("delete account", "user", req.UserIDHash, "error", err)
		writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleDeleteAccountWithKey(w http.ResponseWriter, r *http.Request) {
	req, err := readDeleteWithKeyRequest(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	publicKey, found, err := s.store.PublicKey(r.Context(), req.UserIDHash)
	if err != nil {
		slog.Error("load account key", "user", req.UserIDHash, "error", err)
		writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "sync account not found")
		return
	}
	exportedKey, err := parseExportedSyncKey(req.ExportedKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if exportedKey.PublicID != "" && exportedKey.PublicID != req.UserIDHash {
		writeError(w, http.StatusBadRequest, "exported key public_id does not match user_id_hash")
		return
	}
	message := []byte("inbe-delete-account-v1\n" + req.UserIDHash + "\n")
	signature, err := signWithPrivateKey(message, exportedKey.PrivateKey)
	if err != nil || !s.verifier.Verify(publicKey, message, signature) {
		writeError(w, http.StatusUnauthorized, "exported key does not match sync account")
		return
	}
	if err := s.store.DeleteAccount(r.Context(), req.UserIDHash); err != nil {
		slog.Error("delete account with key", "user", req.UserIDHash, "error", err)
		writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) authenticateSignature(ctx context.Context, userID, publicKeyText, signatureText, method, path string, signedPayload []byte) ([]byte, error) {
	userID = strings.ToLower(strings.TrimSpace(userID))
	if !validUserID(userID) {
		return nil, authError{status: http.StatusBadRequest, message: "invalid user_id_hash"}
	}
	nonce, ok := s.challenges.Consume(userID)
	if !ok {
		return nil, authError{status: http.StatusBadRequest, message: "missing or expired challenge"}
	}
	publicKey, found, err := s.store.PublicKey(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !found {
		if publicKeyText == "" {
			return nil, authError{status: http.StatusBadRequest, message: "public_key required for first sync"}
		}
		publicKey, err = decodeBinaryField(publicKeyText)
		if err != nil {
			return nil, authError{status: http.StatusBadRequest, message: "invalid public_key"}
		}
		if len(publicKey) != mlDSA44PublicKeySize {
			return nil, authError{status: http.StatusBadRequest, message: "wrong public_key size"}
		}
		if err := validateUserIDForPublicKey(userID, publicKey); err != nil {
			return nil, authError{status: http.StatusBadRequest, message: "public_key does not match user_id_hash"}
		}
	} else if publicKeyText != "" {
		supplied, err := decodeBinaryField(publicKeyText)
		if err != nil || subtle.ConstantTimeCompare(supplied, publicKey) != 1 {
			return nil, authError{status: http.StatusBadRequest, message: "public_key does not match registered user"}
		}
	}
	signature, err := decodeBinaryField(signatureText)
	if err != nil {
		return nil, authError{status: http.StatusBadRequest, message: "invalid signature"}
	}
	if len(signature) != mlDSA44SignatureSize {
		return nil, authError{status: http.StatusBadRequest, message: "wrong signature size"}
	}
	message := canonicalMessage(nonce, method, path, signedPayload)
	if !s.verifier.Verify(publicKey, message, signature) {
		return nil, authError{status: http.StatusUnauthorized, message: "signature rejected"}
	}
	return publicKey, nil
}

func (s *Server) authenticateToken(r *http.Request) (string, error) {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	token, ok := strings.CutPrefix(header, "Bearer ")
	if !ok || strings.TrimSpace(token) == "" {
		return "", authError{status: http.StatusUnauthorized, message: "bearer token required"}
	}
	userID, err := verifyAuthToken(s.cfg.TokenSecret, strings.TrimSpace(token))
	if err != nil {
		return "", authError{status: http.StatusUnauthorized, message: "invalid bearer token"}
	}
	return userID, nil
}

func applyHeaderUser(r *http.Request, bodyUser *string) error {
	headerUser := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Inbe-User")))
	if headerUser == "" {
		return errors.New("missing X-Inbe-User")
	}
	if *bodyUser == "" {
		*bodyUser = headerUser
		return nil
	}
	*bodyUser = strings.ToLower(strings.TrimSpace(*bodyUser))
	if *bodyUser != headerUser {
		return errors.New("X-Inbe-User does not match user_id_hash")
	}
	return nil
}

func readSyncRequest(w http.ResponseWriter, r *http.Request, maxBody int64) ([]byte, SyncRequest, error) {
	var req SyncRequest
	body, err := readJSONBody(w, r, maxBody)
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

func readLoginRequest(w http.ResponseWriter, r *http.Request, maxBody int64) ([]byte, LoginRequest, error) {
	var req LoginRequest
	body, err := readJSONBody(w, r, maxBody)
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
	body, err := readJSONBody(w, r, maxBody)
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
	body, err := readJSONBody(w, r, maxBody)
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

func readFriendRequestCreateRequest(w http.ResponseWriter, r *http.Request, maxBody int64) (FriendRequestCreateRequest, error) {
	var req FriendRequestCreateRequest
	body, err := readJSONBody(w, r, maxBody)
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
	body, err := readJSONBody(w, r, maxBody)
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return req, errors.New("invalid json")
	}
	req.App = strings.TrimSpace(req.App)
	if !validLyraNamespace(req.App) {
		return req, errors.New("invalid app")
	}
	if len(req.Metrics) > 100 {
		return req, errors.New("too many metrics")
	}
	for i := range req.Metrics {
		req.Metrics[i].Practice = strings.TrimSpace(req.Metrics[i].Practice)
		req.Metrics[i].Metric = strings.TrimSpace(req.Metrics[i].Metric)
		req.Metrics[i].Label = strings.TrimSpace(req.Metrics[i].Label)
		if !validLyraNamespace(req.Metrics[i].Practice) || !validLyraNamespace(req.Metrics[i].Metric) {
			return req, errors.New("invalid metric")
		}
	}
	return req, nil
}

func readUkuCreateProcessRequest(w http.ResponseWriter, r *http.Request, maxBody int64) (UkuCreateProcessRequest, error) {
	var req UkuCreateProcessRequest
	body, err := readJSONBody(w, r, maxBody)
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return req, errors.New("invalid json")
	}
	req.UserIDHash = strings.ToLower(strings.TrimSpace(req.UserIDHash))
	req.ID = strings.TrimSpace(req.ID)
	req.Question = strings.TrimSpace(req.Question)
	req.Description = strings.TrimSpace(req.Description)
	req.Visibility = normalizeUkuVisibility(req.Visibility)
	if req.ID != "" && !validUkuID(req.ID) {
		return req, errors.New("invalid process id")
	}
	if req.Question == "" {
		return req, errors.New("question required")
	}
	if !validUkuVisibility(req.Visibility) {
		return req, errors.New("invalid visibility")
	}
	if req.ProposalMinutes <= 0 || req.ProposalMinutes > 525600 {
		return req, errors.New("invalid proposal_minutes")
	}
	if req.VotingMinutes <= 0 || req.VotingMinutes > 525600 {
		return req, errors.New("invalid voting_minutes")
	}
	if req.NegativeWeight < 0 || req.NegativeWeight > 1000000 {
		return req, errors.New("invalid negative_weight")
	}
	return req, nil
}

func readUkuUpdateProcessRequest(w http.ResponseWriter, r *http.Request, maxBody int64) (UkuUpdateProcessRequest, error) {
	var req UkuUpdateProcessRequest
	body, err := readJSONBody(w, r, maxBody)
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return req, errors.New("invalid json")
	}
	req.UserIDHash = strings.ToLower(strings.TrimSpace(req.UserIDHash))
	req.Question = strings.TrimSpace(req.Question)
	req.Description = strings.TrimSpace(req.Description)
	req.Visibility = normalizeUkuVisibility(req.Visibility)
	if req.Visibility != "" && !validUkuVisibility(req.Visibility) {
		return req, errors.New("invalid visibility")
	}
	return req, nil
}

func readUkuProposalRequest(w http.ResponseWriter, r *http.Request, maxBody int64) (UkuProposalRequest, error) {
	var req UkuProposalRequest
	body, err := readJSONBody(w, r, maxBody)
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return req, errors.New("invalid json")
	}
	req.UserIDHash = strings.ToLower(strings.TrimSpace(req.UserIDHash))
	req.ID = strings.TrimSpace(req.ID)
	req.Title = strings.TrimSpace(req.Title)
	req.Description = strings.TrimSpace(req.Description)
	if req.ID != "" && !validUkuID(req.ID) {
		return req, errors.New("invalid proposal id")
	}
	if req.Title == "" {
		return req, errors.New("title required")
	}
	return req, nil
}

func readUkuVoteRequest(w http.ResponseWriter, r *http.Request, maxBody int64) (UkuVoteRequest, error) {
	var req UkuVoteRequest
	body, err := readJSONBody(w, r, maxBody)
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return req, errors.New("invalid json")
	}
	req.UserIDHash = strings.ToLower(strings.TrimSpace(req.UserIDHash))
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	if len(req.Scores) == 0 {
		return req, errors.New("scores required")
	}
	for proposalID, score := range req.Scores {
		if !validUkuID(proposalID) {
			return req, errors.New("invalid proposal id")
		}
		if score < -3 || score > 3 {
			return req, errors.New("score out of range")
		}
	}
	return req, nil
}

func readDeleteWithKeyRequest(w http.ResponseWriter, r *http.Request, maxBody int64) (DeleteWithKeyRequest, error) {
	var req DeleteWithKeyRequest
	body, err := readJSONBody(w, r, maxBody)
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return req, errors.New("invalid json")
	}
	req.UserIDHash = strings.ToLower(strings.TrimSpace(req.UserIDHash))
	req.ExportedKey = strings.TrimSpace(req.ExportedKey)
	if !validUserID(req.UserIDHash) {
		return req, errors.New("invalid user_id_hash")
	}
	if req.ExportedKey == "" {
		return req, errors.New("exported_key required")
	}
	return req, nil
}

func readJSONBody(w http.ResponseWriter, r *http.Request, maxBody int64) ([]byte, error) {
	defer r.Body.Close()
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		return nil, errors.New("request body too large")
	}
	if !json.Valid(body) {
		return nil, errors.New("invalid json")
	}
	return body, nil
}

func normalizeMeditationDurations(logs []MeditationLog) {
	for i := range logs {
		if logs[i].DurationSeconds == 0 && logs[i].Duration != 0 {
			logs[i].DurationSeconds = logs[i].Duration
		}
	}
}

func validUserID(value string) bool {
	return userIDPattern.MatchString(value)
}

func validClientID(value string) bool {
	return clientIDPattern.MatchString(value)
}

func validUkuID(value string) bool {
	return ukuIDPattern.MatchString(value)
}

func normalizeUkuVisibility(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "public"
	}
	if value == "unlisted" || value == "private" || value == "private_link" {
		return "unlisted"
	}
	return value
}

func validUkuVisibility(value string) bool {
	return value == "public" || value == "unlisted"
}

func parseUkuProcessPath(path string) (processID string, action string, ok bool) {
	const prefix = "/api/v1/uku/processes/"
	rest := strings.TrimPrefix(path, prefix)
	if rest == path || rest == "" {
		return "", "", false
	}
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 1 {
		return parts[0], "", true
	}
	if len(parts) == 2 && (parts[1] == "proposals" || parts[1] == "votes") {
		return parts[0], parts[1], true
	}
	return "", "", false
}

func parseFriendRequestPath(path string) (requestID string, action string, ok bool) {
	const prefix = "/api/v1/friends/requests/"
	rest := strings.TrimPrefix(path, prefix)
	if rest == path || rest == "" {
		return "", "", false
	}
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 2 && validUkuID(parts[0]) && (parts[1] == "accept" || parts[1] == "decline") {
		return parts[0], parts[1], true
	}
	return "", "", false
}

func randomUkuID() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes[:]), nil
}

type exportedSyncKey struct {
	PublicID   string
	PrivateKey []byte
}

const (
	accountKeyHeader    = "account-key-v1"
	legacyInbeKeyHeader = "inbe-sync-key-v1"
)

func parseExportedSyncKey(text string) (exportedSyncKey, error) {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	if len(lines) == 0 {
		return exportedSyncKey{}, errors.New("invalid account key file")
	}
	header := strings.TrimSpace(lines[0])
	if header != accountKeyHeader && header != legacyInbeKeyHeader {
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
	if publicID != "" && !validUserID(publicID) {
		return exportedSyncKey{}, errors.New("invalid public_id")
	}
	privateKey, err := decodeBinaryField(privateKeyText)
	if err != nil {
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

func writeAuthError(w http.ResponseWriter, err error) {
	var ae authError
	if errors.As(err, &ae) {
		writeError(w, ae.status, ae.message)
		return
	}
	slog.Error("auth", "error", err)
	writeError(w, http.StatusInternalServerError, "authentication failed")
}

func (s *Server) withCommonHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		if origin := allowedCORSOrigin(r.Header.Get("Origin")); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Inbe-User, X-Inbe-Signature")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func allowedCORSOrigin(origin string) string {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Path != "" ||
		u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return ""
	}
	if origin == "https://inbe.waozi.xyz" {
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

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
