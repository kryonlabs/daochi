package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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

func (s *Store) CreateAppGrant(ctx context.Context, userID string, req AppGrantRequest) (AppGrant, error) {
	id, err := randomResourceID()
	if err != nil {
		return AppGrant{}, err
	}
	if req.Permission == "" {
		req.Permission = appGrantRead
	}
	existence := AppStore_Exists(s.db, ctx, req.SourceAppID)
	if exists, err := existence.Value, existence.Error; err != nil || !exists {
		if err != nil {
			return AppGrant{}, err
		}
		return AppGrant{}, sql.ErrNoRows
	}
	existence = AppStore_Exists(s.db, ctx, req.TargetAppID)
	if exists, err := existence.Value, existence.Error; err != nil || !exists {
		if err != nil {
			return AppGrant{}, err
		}
		return AppGrant{}, sql.ErrNoRows
	}
	visibility, ok, err := s.appCollectionVisibility(ctx, req.SourceAppID, req.CollectionPrefix)
	if err != nil {
		return AppGrant{}, err
	}
	if !ok {
		return AppGrant{}, fmt.Errorf("collection is not registered for source app")
	}
	if visibility == "private" {
		return AppGrant{}, fmt.Errorf("private collections cannot be granted across apps")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AppGrant{}, err
	}
	defer tx.Rollback()
	if err := touchUser(ctx, tx, userID); err != nil {
		return AppGrant{}, err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO server_app_grants(id,user_id_hash,source_app_id,target_app_id,collection_prefix,permission,status)
VALUES(?1,?2,?3,?4,?5,?6,'active')`,
		id, userID, req.SourceAppID, req.TargetAppID, req.CollectionPrefix, req.Permission); err != nil {
		return AppGrant{}, err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO server_app_grant_audit(grant_id,user_id_hash,action,payload_json)
VALUES(?1,?2,'create',?3)`, id, userID, auditJSON(req)); err != nil {
		return AppGrant{}, err
	}
	if err := tx.Commit(); err != nil {
		return AppGrant{}, err
	}
	return s.AppGrantByID(ctx, userID, id)
}

func (s *Store) AppGrantByID(ctx context.Context, userID, id string) (AppGrant, error) {
	var grant AppGrant
	err := s.db.QueryRowContext(ctx, `
SELECT id,user_id_hash,source_app_id,target_app_id,collection_prefix,permission,status,created_at,updated_at,revoked_at
FROM server_app_grants
WHERE user_id_hash=?1 AND id=?2`, userID, id).Scan(&grant.ID, &grant.UserIDHash,
		&grant.SourceAppID, &grant.TargetAppID, &grant.CollectionPrefix, &grant.Permission,
		&grant.Status, &grant.CreatedAt, &grant.UpdatedAt, &grant.RevokedAt)
	return grant, err
}

func (s *Store) ListAppGrants(ctx context.Context, userID string) ([]AppGrant, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id,user_id_hash,source_app_id,target_app_id,collection_prefix,permission,status,created_at,updated_at,revoked_at
FROM server_app_grants
WHERE user_id_hash=?1
ORDER BY updated_at DESC,id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []AppGrant{}
	for rows.Next() {
		var item AppGrant
		if err := rows.Scan(&item.ID, &item.UserIDHash, &item.SourceAppID, &item.TargetAppID,
			&item.CollectionPrefix, &item.Permission, &item.Status, &item.CreatedAt,
			&item.UpdatedAt, &item.RevokedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) RevokeAppGrant(ctx context.Context, userID, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `
UPDATE server_app_grants
SET status='revoked', revoked_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP
WHERE user_id_hash=?1 AND id=?2 AND status='active'`, userID, id)
	if err != nil {
		return err
	}
	if rowsAffected(res) == 0 {
		return sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO server_app_grant_audit(grant_id,user_id_hash,action)
VALUES(?1,?2,'revoke')`, id, userID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) AuthorizedAppRecords(ctx context.Context, userID, sourceAppID, targetAppID, collectionPrefix string) ([]EncryptedRecord, error) {
	sourceAppID = strings.TrimSpace(sourceAppID)
	targetAppID = strings.TrimSpace(targetAppID)
	collectionPrefix = strings.TrimSpace(collectionPrefix)
	if sourceAppID == "" || targetAppID == "" || collectionPrefix == "" {
		return nil, fmt.Errorf("source_app_id, target_app_id, and collection_prefix are required")
	}
	if _, ok, err := s.appCollectionVisibility(ctx, sourceAppID, collectionPrefix); err != nil {
		return nil, err
	} else if !ok {
		return nil, errAppScopeNotOwned
	}
	existence := AppStore_Exists(s.db, ctx, targetAppID)
	if exists, err := existence.Value, existence.Error; err != nil {
		return nil, err
	} else if !exists {
		return nil, sql.ErrNoRows
	}
	if sourceAppID != targetAppID {
		var exists int
		err := s.db.QueryRowContext(ctx, `
SELECT EXISTS(
	SELECT 1 FROM server_app_grants
	WHERE user_id_hash=?1 AND source_app_id=?2 AND target_app_id=?3
	  AND collection_prefix=?4 AND permission='read' AND status='active'
)`, userID, sourceAppID, targetAppID, collectionPrefix).Scan(&exists)
		if err != nil {
			return nil, err
		}
		if exists == 0 {
			return nil, ErrSyncUserNotFound
		}
	}
	return s.snapshotEncryptedRecordsByCollectionPrefix(ctx, userID, collectionPrefix)
}

func (s *Store) appCollectionVisibility(ctx context.Context, appID, collectionPrefix string) (string, bool, error) {
	var visibility string
	err := s.db.QueryRowContext(ctx, `
SELECT visibility
FROM server_app_collections
WHERE app_id=?1 AND collection_prefix=?2`, appID, collectionPrefix).Scan(&visibility)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return visibility, true, nil
}

func (s *Store) snapshotEncryptedRecordsByCollectionPrefix(ctx context.Context, userID, collectionPrefix string) ([]EncryptedRecord, error) {
	query := `
SELECT collection,id,key_id,nonce,ciphertext,updated_at,deleted_at,content_hash,schema_version,parent_id
FROM server_encrypted_records
WHERE user_id_hash=?1 AND collection=?2
ORDER BY collection,id`
	args := []any{userID, collectionPrefix}
	if strings.HasSuffix(collectionPrefix, ".*") {
		query = `
SELECT collection,id,key_id,nonce,ciphertext,updated_at,deleted_at,content_hash,schema_version,parent_id
FROM server_encrypted_records
WHERE user_id_hash=?1 AND collection LIKE ?2 ESCAPE '\'
ORDER BY collection,id`
		args[1] = Scope_LikePatternForCollectionPrefix(collectionPrefix)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []EncryptedRecord{}
	for rows.Next() {
		var item EncryptedRecord
		if err := rows.Scan(&item.Collection, &item.ID, &item.KeyID, &item.Nonce,
			&item.Ciphertext, &item.UpdatedAt, &item.DeletedAt, &item.ContentHash,
			&item.SchemaVersion, &item.ParentID); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

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
		grant, err := s.store.CreateAppGrant(r.Context(), userID, req)
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
	grants, err := s.store.ListAppGrants(r.Context(), userID)
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
	grant, err := s.store.CreateAppGrant(r.Context(), userID, req.Grant)
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
	if err := s.store.RevokeAppGrant(r.Context(), userID, id); err != nil {
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
	records, err := s.store.AuthorizedAppRecords(r.Context(), userID, sourceAppID, targetAppID, collectionPrefix)
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

func auditJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(data)
}
