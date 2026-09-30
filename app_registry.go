package main

import (
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"strings"
)

const (
	appStatusActive          = "active"
	appStatusSuspended       = "suspended"
	appGrantRead             = "read"
	appCompatibilityDeadline = "2027-09-01"
)

var errAppScopeNotOwned = errors.New("app does not own collection scope")

func (s *Server) handleAppList(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.handleAppRegister(w, r)
		return
	}
	appsResult := AppStore_List(s.store.db, r.Context())
	apps, err := appsResult.Value, appsResult.Error
	if err != nil {
		slog.Error("list apps", "error", err)
		writeError(w, http.StatusInternalServerError, "apps failed")
		return
	}
	writeJSON(w, http.StatusOK, AppRegistryResponse{Apps: apps})
}

func (s *Server) handleAppRoute(w http.ResponseWriter, r *http.Request) {
	appID := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/apps/"), "/")
	if strings.HasSuffix(appID, "/collections") {
		appID = strings.TrimSuffix(appID, "/collections")
		appID = strings.Trim(appID, "/")
		collectionsResult := AppStore_Collections(s.store.db, r.Context(), appID)
		collections, err := collectionsResult.Value, collectionsResult.Error
		if err != nil {
			slog.Error("app collections", "app", LogSafety_LogText(appID), "error", err)
			writeError(w, http.StatusInternalServerError, "apps failed")
			return
		}
		if len(collections) == 0 {
			existence := AppStore_Exists(s.store.db, r.Context(), appID)
			if exists, err := existence.Value, existence.Error; err != nil || !exists {
				if err != nil {
					slog.Error("app exists", "app", LogSafety_LogText(appID), "error", err)
					writeError(w, http.StatusInternalServerError, "apps failed")
					return
				}
				writeError(w, http.StatusNotFound, "app not found")
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"collections": collections})
		return
	}
	if r.Method == http.MethodPut {
		s.handleAppRegister(w, r)
		return
	}
	if !Identity_ValidNamespace(appID) {
		writeError(w, http.StatusNotFound, "app not found")
		return
	}
	appResult := AppStore_ByID(s.store.db, r.Context(), appID)
	app, found, err := appResult.Value, appResult.Found, appResult.Error
	if err != nil {
		slog.Error("load app", "app", LogSafety_LogText(appID), "error", err)
		writeError(w, http.StatusInternalServerError, "apps failed")
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "app not found")
		return
	}
	writeJSON(w, http.StatusOK, app)
}

func (s *Server) handleAppRegister(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateAdmin(w, r) {
		return
	}
	req, err := readAppRegistrationRequest(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	pathID := ""
	if strings.HasPrefix(r.URL.Path, "/api/v1/apps/") {
		pathID = strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/apps/"), "/")
	}
	if pathID != "" && pathID != req.AppID {
		writeError(w, http.StatusBadRequest, "app_id path mismatch")
		return
	}
	if err := AppStore_Upsert(s.store.db, r.Context(), req); err != nil {
		slog.Error("register app", "app", LogSafety_LogText(req.AppID), "error", err)
		writeError(w, http.StatusInternalServerError, "app registration failed")
		return
	}
	appResult := AppStore_ByID(s.store.db, r.Context(), req.AppID)
	app, _, err := appResult.Value, appResult.Found, appResult.Error
	if err != nil {
		slog.Error("load registered app", "app", LogSafety_LogText(req.AppID), "error", err)
		writeError(w, http.StatusInternalServerError, "app registration failed")
		return
	}
	writeJSON(w, http.StatusOK, app)
}

func (s *Server) handleAppGrants(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		req, err := readAppGrantRequest(w, r, s.cfg.MaxBodyBytes)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		createdGrant := AppGrants_Create(s.store.db, r.Context(), userID, req, ErrSyncUserNotFound)
		grant, err := createdGrant.Value, createdGrant.Error
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				writeError(w, http.StatusNotFound, "app not found")
				return
			}
			if strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "registered") {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			slog.Error("create app grant", "user", LogSafety_LogText(userID), "error", err)
			writeError(w, http.StatusInternalServerError, "app grant failed")
			return
		}
		writeJSON(w, http.StatusCreated, grant)
		return
	}
	listedGrants := AppGrants_List(s.store.db, r.Context(), userID)
	grants, err := listedGrants.Value, listedGrants.Error
	if err != nil {
		slog.Error("list app grants", "user", LogSafety_LogText(userID), "error", err)
		writeError(w, http.StatusInternalServerError, "app grants failed")
		return
	}
	writeJSON(w, http.StatusOK, AppGrantsResponse{Grants: grants})
}

func (s *Server) handleSignedAppGrant(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	req, body, err := readSignedAppGrantRequest(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	serialized := JsonGo_Marshal(req.Grant)
	grantBody, err := serialized.Value, serialized.Error
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid app grant")
		return
	}
	if req.Tx.BodySHA256 != "" && req.Tx.BodySHA256 != Signing_SHA256Hex(grantBody) {
		writeError(w, http.StatusBadRequest, "signed transaction body hash must cover grant payload")
		return
	}
	if req.Tx.BodySHA256 == "" {
		req.Tx.BodySHA256 = Signing_SHA256Hex(grantBody)
	}
	_ = body
	if err := authenticationError(SignedTx_Verify(s.store.db, r.Context(), r, grantBody, req.Tx, userID, req.Grant.TargetAppID, s.verifier.Verify, errSignedTxReplay)); err != nil {
		s.writeAuthError(w, err)
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
			writeError(w, http.StatusNotFound, "app not found")
			return
		}
		if strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "registered") {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		slog.Error("create signed app grant", "user", LogSafety_LogText(userID), "error", err)
		writeError(w, http.StatusInternalServerError, "app grant failed")
		return
	}
	created = true
	writeJSON(w, http.StatusCreated, grant)
}

func (s *Server) handleAppGrantRoute(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/account/app-grants/"), "/")
	if id == "" {
		writeError(w, http.StatusNotFound, "app grant not found")
		return
	}
	if err := AppGrants_Revoke(s.store.db, r.Context(), userID, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "app grant not found")
			return
		}
		slog.Error("revoke app grant", "user", LogSafety_LogText(userID), "grant", LogSafety_LogText(id), "error", err)
		writeError(w, http.StatusInternalServerError, "app grant failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) handleAppRecords(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	sourceAppID := strings.TrimSpace(r.URL.Query().Get("source_app_id"))
	targetAppID := strings.TrimSpace(r.URL.Query().Get("target_app_id"))
	collectionPrefix := strings.TrimSpace(r.URL.Query().Get("collection_prefix"))
	if !Identity_ValidNamespace(sourceAppID) || !Identity_ValidNamespace(targetAppID) || !Scope_ValidCollectionPrefix(collectionPrefix) {
		writeError(w, http.StatusBadRequest, "invalid app records query")
		return
	}
	header := SignedTx_ReadHeader(r)
	tx, err := header.Value, authenticationError(header.Authentication)
	if err != nil {
		s.writeAuthError(w, err)
		return
	}
	if err := authenticationError(SignedTx_Verify(s.store.db, r.Context(), r, nil, tx, userID, targetAppID, s.verifier.Verify, errSignedTxReplay)); err != nil {
		s.writeAuthError(w, err)
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
			writeError(w, http.StatusForbidden, "app grant required")
			return
		}
		if errors.Is(err, errAppScopeNotOwned) {
			writeError(w, http.StatusBadRequest, "source app does not own collection scope")
			return
		}
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "app not found")
			return
		}
		slog.Error("read app records", "user", LogSafety_LogText(userID), "source_app", LogSafety_LogText(sourceAppID), "target_app", LogSafety_LogText(targetAppID), "error", err)
		writeError(w, http.StatusInternalServerError, "app records failed")
		return
	}
	readCompleted = true
	writeJSON(w, http.StatusOK, AppRecordsResponse{Records: records})
}

func (s *Server) authenticateAdmin(w http.ResponseWriter, r *http.Request) bool {
	if s.cfg.AdminToken == "" {
		writeError(w, http.StatusForbidden, "admin registration disabled")
		return false
	}
	if requestHeaderAlias(r, "X-Daochi-Admin", "X-Ksync-Admin") != s.cfg.AdminToken {
		writeError(w, http.StatusUnauthorized, "admin token required")
		return false
	}
	return true
}

func readAppRegistrationRequest(w http.ResponseWriter, r *http.Request, maxBody int64) (AppRegistration, error) {
	body, err := readJSONBody(w, r, maxBody)
	if err != nil {
		return AppRegistration{}, err
	}
	decoded := AppRegistration_Decode(body)
	return decoded.Value, decoded.Error
}

func readAppGrantRequest(w http.ResponseWriter, r *http.Request, maxBody int64) (AppGrantRequest, error) {
	body, err := readJSONBody(w, r, maxBody)
	if err != nil {
		return AppGrantRequest{}, err
	}
	decoded := AppRegistration_DecodeGrant(body)
	return decoded.Value, decoded.Error
}

func readSignedAppGrantRequest(w http.ResponseWriter, r *http.Request, maxBody int64) (SignedAppGrantRequest, []byte, error) {
	body, err := readJSONBody(w, r, maxBody)
	if err != nil {
		return SignedAppGrantRequest{}, nil, err
	}
	decoded := AppRegistration_DecodeSignedGrant(body)
	return decoded.Value, decoded.Body, decoded.Error
}
