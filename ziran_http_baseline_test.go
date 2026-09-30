package main

// Original HTTP handlers and helpers retained as a migration oracle.
import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const (
	appStatusActive          = "active"
	appStatusSuspended       = "suspended"
	appGrantRead             = "read"
	appCompatibilityDeadline = "2027-09-01"
)

func (s *Server) baselineHandleAppList(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.baselineHandleAppRegister(w, r)
		return
	}
	appsResult := AppStore_List(s.store.db, r.Context())
	apps, err := appsResult.Value, appsResult.Error
	if err != nil {
		slog.Error("list apps", "error", err)
		baselineWriteError(w, http.StatusInternalServerError, "apps failed")
		return
	}
	baselineWriteJSON(w, http.StatusOK, AppRegistryResponse{Apps: apps})
}

func (s *Server) baselineHandleAppRoute(w http.ResponseWriter, r *http.Request) {
	appID := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/apps/"), "/")
	if strings.HasSuffix(appID, "/collections") {
		appID = strings.TrimSuffix(appID, "/collections")
		appID = strings.Trim(appID, "/")
		collectionsResult := AppStore_Collections(s.store.db, r.Context(), appID)
		collections, err := collectionsResult.Value, collectionsResult.Error
		if err != nil {
			slog.Error("app collections", "app", LogSafety_LogText(appID), "error", err)
			baselineWriteError(w, http.StatusInternalServerError, "apps failed")
			return
		}
		if len(collections) == 0 {
			existence := AppStore_Exists(s.store.db, r.Context(), appID)
			if exists, err := existence.Value, existence.Error; err != nil || !exists {
				if err != nil {
					slog.Error("app exists", "app", LogSafety_LogText(appID), "error", err)
					baselineWriteError(w, http.StatusInternalServerError, "apps failed")
					return
				}
				baselineWriteError(w, http.StatusNotFound, "app not found")
				return
			}
		}
		baselineWriteJSON(w, http.StatusOK, map[string]any{"collections": collections})
		return
	}
	if r.Method == http.MethodPut {
		s.baselineHandleAppRegister(w, r)
		return
	}
	if !Identity_ValidNamespace(appID) {
		baselineWriteError(w, http.StatusNotFound, "app not found")
		return
	}
	appResult := AppStore_ByID(s.store.db, r.Context(), appID)
	app, found, err := appResult.Value, appResult.Found, appResult.Error
	if err != nil {
		slog.Error("load app", "app", LogSafety_LogText(appID), "error", err)
		baselineWriteError(w, http.StatusInternalServerError, "apps failed")
		return
	}
	if !found {
		baselineWriteError(w, http.StatusNotFound, "app not found")
		return
	}
	baselineWriteJSON(w, http.StatusOK, app)
}

func (s *Server) baselineHandleAppRegister(w http.ResponseWriter, r *http.Request) {
	if !s.baselineAuthenticateAdmin(w, r) {
		return
	}
	req, err := baselineReadAppRegistrationRequest(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		baselineWriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	pathID := ""
	if strings.HasPrefix(r.URL.Path, "/api/v1/apps/") {
		pathID = strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/apps/"), "/")
	}
	if pathID != "" && pathID != req.AppID {
		baselineWriteError(w, http.StatusBadRequest, "app_id path mismatch")
		return
	}
	if err := AppStore_Upsert(s.store.db, r.Context(), req); err != nil {
		slog.Error("register app", "app", LogSafety_LogText(req.AppID), "error", err)
		baselineWriteError(w, http.StatusInternalServerError, "app registration failed")
		return
	}
	appResult := AppStore_ByID(s.store.db, r.Context(), req.AppID)
	app, _, err := appResult.Value, appResult.Found, appResult.Error
	if err != nil {
		slog.Error("load registered app", "app", LogSafety_LogText(req.AppID), "error", err)
		baselineWriteError(w, http.StatusInternalServerError, "app registration failed")
		return
	}
	baselineWriteJSON(w, http.StatusOK, app)
}

func (s *Server) baselineHandleAppGrants(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.baselineBearerUser(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		req, err := baselineReadAppGrantRequest(w, r, s.cfg.MaxBodyBytes)
		if err != nil {
			baselineWriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		createdGrant := AppGrants_Create(s.store.db, r.Context(), userID, req, ErrSyncUserNotFound)
		grant, err := createdGrant.Value, createdGrant.Error
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				baselineWriteError(w, http.StatusNotFound, "app not found")
				return
			}
			if strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "registered") {
				baselineWriteError(w, http.StatusBadRequest, err.Error())
				return
			}
			slog.Error("create app grant", "user", LogSafety_LogText(userID), "error", err)
			baselineWriteError(w, http.StatusInternalServerError, "app grant failed")
			return
		}
		baselineWriteJSON(w, http.StatusCreated, grant)
		return
	}
	listedGrants := AppGrants_List(s.store.db, r.Context(), userID)
	grants, err := listedGrants.Value, listedGrants.Error
	if err != nil {
		slog.Error("list app grants", "user", LogSafety_LogText(userID), "error", err)
		baselineWriteError(w, http.StatusInternalServerError, "app grants failed")
		return
	}
	baselineWriteJSON(w, http.StatusOK, AppGrantsResponse{Grants: grants})
}

func (s *Server) baselineHandleSignedAppGrant(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.baselineBearerUser(w, r)
	if !ok {
		return
	}
	req, body, err := baselineReadSignedAppGrantRequest(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		baselineWriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	serialized := JsonGo_Marshal(req.Grant)
	grantBody, err := serialized.Value, serialized.Error
	if err != nil {
		baselineWriteError(w, http.StatusBadRequest, "invalid app grant")
		return
	}
	if req.Tx.BodySHA256 != "" && req.Tx.BodySHA256 != Signing_SHA256Hex(grantBody) {
		baselineWriteError(w, http.StatusBadRequest, "signed transaction body hash must cover grant payload")
		return
	}
	if req.Tx.BodySHA256 == "" {
		req.Tx.BodySHA256 = Signing_SHA256Hex(grantBody)
	}
	_ = body
	if err := authenticationError(SignedTx_Verify(s.store.db, r.Context(), r, grantBody, req.Tx, userID, req.Grant.TargetAppID, s.verifier.Verify, errSignedTxReplay)); err != nil {
		s.baselineWriteAuthError(w, err)
		return
	}
	created := false
	defer func() {
		if !created {
			SignedTx_Forget(s.store.db, r.Context(), req.Tx)
		}
	}()
	createdGrant := AppGrants_Create(s.store.db, r.Context(), userID, req.Grant, ErrSyncUserNotFound)
	grant, err := createdGrant.Value, createdGrant.Error
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			baselineWriteError(w, http.StatusNotFound, "app not found")
			return
		}
		if strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "registered") {
			baselineWriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		slog.Error("create signed app grant", "user", LogSafety_LogText(userID), "error", err)
		baselineWriteError(w, http.StatusInternalServerError, "app grant failed")
		return
	}
	created = true
	baselineWriteJSON(w, http.StatusCreated, grant)
}

func (s *Server) baselineHandleAppGrantRoute(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.baselineBearerUser(w, r)
	if !ok {
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/account/app-grants/"), "/")
	if id == "" {
		baselineWriteError(w, http.StatusNotFound, "app grant not found")
		return
	}
	if err := AppGrants_Revoke(s.store.db, r.Context(), userID, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			baselineWriteError(w, http.StatusNotFound, "app grant not found")
			return
		}
		slog.Error("revoke app grant", "user", LogSafety_LogText(userID), "grant", LogSafety_LogText(id), "error", err)
		baselineWriteError(w, http.StatusInternalServerError, "app grant failed")
		return
	}
	baselineWriteJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) baselineHandleAppRecords(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.baselineBearerUser(w, r)
	if !ok {
		return
	}
	sourceAppID := strings.TrimSpace(r.URL.Query().Get("source_app_id"))
	targetAppID := strings.TrimSpace(r.URL.Query().Get("target_app_id"))
	collectionPrefix := strings.TrimSpace(r.URL.Query().Get("collection_prefix"))
	if !Identity_ValidNamespace(sourceAppID) || !Identity_ValidNamespace(targetAppID) || !Scope_ValidCollectionPrefix(collectionPrefix) {
		baselineWriteError(w, http.StatusBadRequest, "invalid app records query")
		return
	}
	header := SignedTx_ReadHeader(r)
	tx, err := header.Value, authenticationError(header.Authentication)
	if err != nil {
		s.baselineWriteAuthError(w, err)
		return
	}
	if err := authenticationError(SignedTx_Verify(s.store.db, r.Context(), r, nil, tx, userID, targetAppID, s.verifier.Verify, errSignedTxReplay)); err != nil {
		s.baselineWriteAuthError(w, err)
		return
	}
	readCompleted := false
	defer func() {
		if !readCompleted {
			SignedTx_Forget(s.store.db, r.Context(), tx)
		}
	}()
	authorized := AppGrants_AuthorizedRecords(s.store.db, r.Context(), userID, sourceAppID, targetAppID, collectionPrefix, errAppScopeNotOwned, ErrSyncUserNotFound)
	records, err := authorized.Value, authorized.Error
	if err != nil {
		if errors.Is(err, ErrSyncUserNotFound) {
			baselineWriteError(w, http.StatusForbidden, "app grant required")
			return
		}
		if errors.Is(err, errAppScopeNotOwned) {
			baselineWriteError(w, http.StatusBadRequest, "source app does not own collection scope")
			return
		}
		if errors.Is(err, sql.ErrNoRows) {
			baselineWriteError(w, http.StatusNotFound, "app not found")
			return
		}
		slog.Error("read app records", "user", LogSafety_LogText(userID), "source_app", LogSafety_LogText(sourceAppID), "target_app", LogSafety_LogText(targetAppID), "error", err)
		baselineWriteError(w, http.StatusInternalServerError, "app records failed")
		return
	}
	readCompleted = true
	baselineWriteJSON(w, http.StatusOK, AppRecordsResponse{Records: records})
}

func (s *Server) baselineAuthenticateAdmin(w http.ResponseWriter, r *http.Request) bool {
	if s.cfg.AdminToken == "" {
		baselineWriteError(w, http.StatusForbidden, "admin registration disabled")
		return false
	}
	if baselineRequestHeaderAlias(r, "X-Daochi-Admin", "X-Ksync-Admin") != s.cfg.AdminToken {
		baselineWriteError(w, http.StatusUnauthorized, "admin token required")
		return false
	}
	return true
}

func baselineReadAppRegistrationRequest(w http.ResponseWriter, r *http.Request, maxBody int64) (AppRegistration, error) {
	body, err := baselineReadJSONBody(w, r, maxBody)
	if err != nil {
		return AppRegistration{}, err
	}
	decoded := AppRegistration_Decode(body)
	return decoded.Value, decoded.Error
}

func baselineReadAppGrantRequest(w http.ResponseWriter, r *http.Request, maxBody int64) (AppGrantRequest, error) {
	body, err := baselineReadJSONBody(w, r, maxBody)
	if err != nil {
		return AppGrantRequest{}, err
	}
	decoded := AppRegistration_DecodeGrant(body)
	return decoded.Value, decoded.Error
}

func baselineReadSignedAppGrantRequest(w http.ResponseWriter, r *http.Request, maxBody int64) (SignedAppGrantRequest, []byte, error) {
	body, err := baselineReadJSONBody(w, r, maxBody)
	if err != nil {
		return SignedAppGrantRequest{}, nil, err
	}
	decoded := AppRegistration_DecodeSignedGrant(body)
	return decoded.Value, decoded.Body, decoded.Error
}

func (s *Server) baselineHandleSignedAppRegister(w http.ResponseWriter, r *http.Request) {
	req, err := baselineReadSignedAppRegistrationRequest(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		baselineWriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	verified := AppRegistration_Verify(req, s.cfg.NodeRegistryPublicKey)
	manifestBytes, manifestHash, err := verified.Value, verified.Hash, authenticationError(verified.Authentication)
	if err != nil {
		s.baselineWriteAuthError(w, err)
		return
	}
	if err := AppStore_UpsertSignedManifest(s.store.db, r.Context(), req.Manifest, manifestBytes, manifestHash, req.ManifestSignature, req.ApprovalSignature); err != nil {
		slog.Error("register signed app manifest", "app", LogSafety_LogText(req.Manifest.AppID), "error", err)
		baselineWriteError(w, http.StatusInternalServerError, "app registration failed")
		return
	}
	appResult := AppStore_ByID(s.store.db, r.Context(), req.Manifest.AppID)
	app, _, err := appResult.Value, appResult.Found, appResult.Error
	if err != nil {
		slog.Error("load signed app manifest", "app", LogSafety_LogText(req.Manifest.AppID), "error", err)
		baselineWriteError(w, http.StatusInternalServerError, "app registration failed")
		return
	}
	baselineWriteJSON(w, http.StatusOK, app)
}

func baselineReadSignedAppRegistrationRequest(w http.ResponseWriter, r *http.Request, maxBody int64) (SignedAppRegistrationRequest, error) {
	body, err := baselineReadJSONBody(w, r, maxBody)
	if err != nil {
		return SignedAppRegistrationRequest{}, err
	}
	decoded := AppRegistration_DecodeSigned(body)
	return decoded.Value, decoded.Error
}

func (s *Server) baselineBearerUser(w http.ResponseWriter, r *http.Request) (string, bool) {
	userID, err := s.baselineAuthenticateToken(r)
	if err != nil {
		s.baselineWriteAuthError(w, err)
		return "", false
	}
	headerUser, _ := baselineRequestUserHeader(r)
	if headerUser != "" && headerUser != userID {
		s.baselineWriteAuthError(w, authError{status: http.StatusUnauthorized, message: "token user mismatch"})
		return "", false
	}
	return userID, true
}

func (s *Server) baselineAuthenticateToken(r *http.Request) (string, error) {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	token, ok := strings.CutPrefix(header, "Bearer ")
	if !ok || strings.TrimSpace(token) == "" {
		return "", authError{status: http.StatusUnauthorized, message: "bearer token required"}
	}
	verified := Token_VerifyAuthToken(s.cfg.TokenSecret, strings.TrimSpace(token), time.Now().Unix())
	if verified.Error != "" {
		return "", authError{status: http.StatusUnauthorized, message: "invalid bearer token"}
	}
	userID := verified.Value
	account := AccountKeys_PublicKey(s.store.db, r.Context(), userID)
	found, err := account.Found, account.Error
	if err != nil {
		return "", err
	}
	if !found {
		// Released Inbe clients can bootstrap a missing account through sync by
		// presenting the matching public key in the signed payload.
		if r.URL.Path == "/api/v1/sync" {
			deleted, err := s.store.baselineAccountTombstoned(r.Context(), userID)
			if err != nil {
				return "", err
			}
			if !deleted {
				return userID, nil
			}
		}
		return "", authError{status: http.StatusUnauthorized, message: "sync account not found"}
	}
	return userID, nil
}

func baselineRequestUserHeader(r *http.Request) (string, string) {
	if value := strings.ToLower(baselineRequestHeaderAlias(r, "X-Daochi-User")); value != "" {
		return value, "X-Daochi-User"
	}
	if value := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Ksync-User"))); value != "" {
		return value, "X-Ksync-User"
	}
	if value := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Inbe-User"))); value != "" {
		return value, "X-Inbe-User"
	}
	return "", ""
}

func baselineRequestHeaderAlias(r *http.Request, names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(r.Header.Get(name)); value != "" {
			return value
		}
	}
	return ""
}

func baselineReadJSONBody(w http.ResponseWriter, r *http.Request, maxBody int64) ([]byte, error) {
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

func baselineWriteJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func baselineWriteError(w http.ResponseWriter, status int, message string) {
	baselineWriteJSON(w, status, map[string]string{"error": message})
}

func (s *Server) baselineWriteAuthError(w http.ResponseWriter, err error) {
	var ae authError
	if errors.As(err, &ae) {
		Metrics_RecordAuthFailure(s.metrics, ae.status, ae.message)
		baselineWriteError(w, ae.status, ae.message)
		return
	}
	slog.Error("auth", "error", err)
	Metrics_RecordAuthFailure(s.metrics, http.StatusInternalServerError, "authentication failed")
	baselineWriteError(w, http.StatusInternalServerError, "authentication failed")
}

func (s *Store) baselineAccountTombstoned(ctx context.Context, userID string) (bool, error) {
	var exists int
	err := s.db.QueryRowContext(ctx, `
SELECT EXISTS(SELECT 1 FROM server_account_tombstones WHERE user_id_hash=?1)`, userID).Scan(&exists)
	return exists != 0, err
}
