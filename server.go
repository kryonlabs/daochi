package main

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
)

var userIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Server struct {
	cfg        Config
	store      *Store
	challenges *ChallengeStore
	verifier   Verifier
}

func NewServer(cfg Config, store *Store, verifier Verifier) *Server {
	return &Server{
		cfg:        cfg,
		store:      store,
		challenges: NewChallengeStore(cfg.ChallengeTTL),
		verifier:   verifier,
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.handleDocs)
	mux.HandleFunc("GET /openapi.json", s.handleOpenAPI)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /api/v1/sync/challenge", s.handleChallenge)
	mux.HandleFunc("POST /api/v1/sync", s.handleSync)
	mux.HandleFunc("DELETE /api/v1/account", s.handleDeleteAccount)
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
	body, req, err := readSyncRequest(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := applyHeaderUser(r, &req.UserIDHash); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	publicKey, err := s.authenticate(r.Context(), req.UserIDHash, req.PublicKey, r.Header.Get("X-Inbe-Signature"), r.Method, r.URL.Path, body)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	normalizeMeditationDurations(req.MeditationLogs)
	result, err := s.store.ApplySync(r.Context(), req, publicKey)
	if err != nil {
		slog.Error("apply sync", "user", req.UserIDHash, "error", err)
		writeError(w, http.StatusInternalServerError, "sync failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "applied": result})
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
	_, err = s.authenticate(r.Context(), req.UserIDHash, "", r.Header.Get("X-Inbe-Signature"), r.Method, r.URL.Path, body)
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

func (s *Server) authenticate(ctx context.Context, userID, publicKeyText, signatureText, method, path string, signedPayload []byte) ([]byte, error) {
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
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
