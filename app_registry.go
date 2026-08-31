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
	appStatusActive    = "active"
	appStatusSuspended = "suspended"
	appGrantRead       = "read"
)

func (s *Store) SeedBuiltinApps(ctx context.Context) error {
	inbe := AppRegistration{
		AppID:       "inbe",
		DisplayName: "Inner Breeze",
		Description: "Breathing, meditation, and habit data.",
		Status:      appStatusActive,
		Collections: []AppCollection{
			{CollectionPrefix: "inbe.habits", Visibility: "private", SchemaVersion: 4, Description: "Released v4 encrypted habit records."},
			{CollectionPrefix: "inbe.habit_days", Visibility: "private", SchemaVersion: 4, Description: "Released v4 encrypted habit-day records."},
			{CollectionPrefix: "inbe.sessions", Visibility: "private", SchemaVersion: 4, Description: "Released v4 encrypted session records."},
			{CollectionPrefix: "private.inbe.v1.*", Visibility: "private", SchemaVersion: 1, Description: "Future private Inbe records."},
			{CollectionPrefix: "shared.inbe.v1.*", Visibility: "shared", SchemaVersion: 1, Description: "User-grantable Inbe records."},
			{CollectionPrefix: "friends.inbe.v1.*", Visibility: "friends", SchemaVersion: 1, Description: "Friend-visible Inbe records."},
			{CollectionPrefix: "public.inbe.v1.*", Visibility: "public", SchemaVersion: 1, Description: "Public Inbe records."},
		},
		Capabilities: []string{"sync", "encrypted-records", "profile-stats", "friends", "leaderboard"},
	}
	uku := AppRegistration{
		AppID:       "uku",
		DisplayName: "Uku",
		Description: "Public and shared decision data.",
		Status:      appStatusActive,
		Collections: []AppCollection{
			{CollectionPrefix: "private.uku.v1.*", Visibility: "private", SchemaVersion: 1},
			{CollectionPrefix: "shared.uku.v1.*", Visibility: "shared", SchemaVersion: 1},
			{CollectionPrefix: "public.uku.v1.*", Visibility: "public", SchemaVersion: 1},
		},
		Capabilities: []string{"processes", "proposals", "voting"},
	}
	if err := s.UpsertApp(ctx, inbe); err != nil {
		return err
	}
	return s.UpsertApp(ctx, uku)
}

func (s *Store) UpsertApp(ctx context.Context, app AppRegistration) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := upsertAppTx(ctx, tx, app); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ListApps(ctx context.Context) ([]AppRegistration, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT app_id,display_name,description,homepage_url,source_url,public_key,status,created_at,updated_at
FROM server_apps
ORDER BY app_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	apps := []AppRegistration{}
	for rows.Next() {
		var app AppRegistration
		if err := rows.Scan(&app.AppID, &app.DisplayName, &app.Description, &app.HomepageURL,
			&app.SourceURL, &app.PublicKey, &app.Status, &app.CreatedAt, &app.UpdatedAt); err != nil {
			return nil, err
		}
		apps = append(apps, app)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range apps {
		apps[i].Collections, err = s.AppCollections(ctx, apps[i].AppID)
		if err != nil {
			return nil, err
		}
		apps[i].Capabilities, err = s.AppCapabilities(ctx, apps[i].AppID)
		if err != nil {
			return nil, err
		}
		if err := s.HydrateAppManifestFields(ctx, &apps[i]); err != nil {
			return nil, err
		}
	}
	return apps, nil
}

func (s *Store) AppByID(ctx context.Context, appID string) (AppRegistration, bool, error) {
	var app AppRegistration
	err := s.db.QueryRowContext(ctx, `
SELECT app_id,display_name,description,homepage_url,source_url,public_key,status,created_at,updated_at
FROM server_apps
WHERE app_id=?1`, appID).Scan(&app.AppID, &app.DisplayName, &app.Description,
		&app.HomepageURL, &app.SourceURL, &app.PublicKey, &app.Status, &app.CreatedAt, &app.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return AppRegistration{}, false, nil
	}
	if err != nil {
		return AppRegistration{}, false, err
	}
	var err2 error
	app.Collections, err2 = s.AppCollections(ctx, appID)
	if err2 != nil {
		return AppRegistration{}, false, err2
	}
	app.Capabilities, err2 = s.AppCapabilities(ctx, appID)
	if err2 != nil {
		return AppRegistration{}, false, err2
	}
	if err := s.HydrateAppManifestFields(ctx, &app); err != nil {
		return AppRegistration{}, false, err
	}
	return app, true, nil
}

func (s *Store) AppExists(ctx context.Context, appID string) (bool, error) {
	var exists int
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM server_apps WHERE app_id=?1 AND status='active')`, appID).Scan(&exists)
	return exists != 0, err
}

func (s *Store) AppCollections(ctx context.Context, appID string) ([]AppCollection, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT app_id,collection_prefix,visibility,schema_version,description,created_at
FROM server_app_collections
WHERE app_id=?1
ORDER BY collection_prefix`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []AppCollection{}
	for rows.Next() {
		var item AppCollection
		if err := rows.Scan(&item.AppID, &item.CollectionPrefix, &item.Visibility,
			&item.SchemaVersion, &item.Description, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) AppCapabilities(ctx context.Context, appID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT capability
FROM server_app_capabilities
WHERE app_id=?1
ORDER BY capability`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []string{}
	for rows.Next() {
		var item string
		if err := rows.Scan(&item); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) AppOwnsCollection(ctx context.Context, appID, collection string) (bool, error) {
	collections, err := s.AppCollections(ctx, appID)
	if err != nil {
		return false, err
	}
	for _, item := range collections {
		if collectionMatchesPrefix(collection, item.CollectionPrefix) {
			return true, nil
		}
	}
	return false, nil
}

func (s *Store) CreateAppGrant(ctx context.Context, userID string, req AppGrantRequest) (AppGrant, error) {
	id, err := randomUkuID()
	if err != nil {
		return AppGrant{}, err
	}
	if req.Permission == "" {
		req.Permission = appGrantRead
	}
	if exists, err := s.AppExists(ctx, req.SourceAppID); err != nil || !exists {
		if err != nil {
			return AppGrant{}, err
		}
		return AppGrant{}, sql.ErrNoRows
	}
	if exists, err := s.AppExists(ctx, req.TargetAppID); err != nil || !exists {
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
		args[1] = likePatternForCollectionPrefix(collectionPrefix)
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
	apps, err := s.store.ListApps(r.Context())
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
		collections, err := s.store.AppCollections(r.Context(), appID)
		if err != nil {
			slog.Error("app collections", "app", logText(appID), "error", err)
			writeError(w, http.StatusInternalServerError, "apps failed")
			return
		}
		if len(collections) == 0 {
			if exists, err := s.store.AppExists(r.Context(), appID); err != nil || !exists {
				if err != nil {
					slog.Error("app exists", "app", logText(appID), "error", err)
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
	if !validKsyncNamespace(appID) {
		writeError(w, http.StatusNotFound, "app not found")
		return
	}
	app, found, err := s.store.AppByID(r.Context(), appID)
	if err != nil {
		slog.Error("load app", "app", logText(appID), "error", err)
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
	if err := s.store.UpsertApp(r.Context(), req); err != nil {
		slog.Error("register app", "app", logText(req.AppID), "error", err)
		writeError(w, http.StatusInternalServerError, "app registration failed")
		return
	}
	app, _, err := s.store.AppByID(r.Context(), req.AppID)
	if err != nil {
		slog.Error("load registered app", "app", logText(req.AppID), "error", err)
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
			slog.Error("create app grant", "user", logText(userID), "error", err)
			writeError(w, http.StatusInternalServerError, "app grant failed")
			return
		}
		writeJSON(w, http.StatusCreated, grant)
		return
	}
	grants, err := s.store.ListAppGrants(r.Context(), userID)
	if err != nil {
		slog.Error("list app grants", "user", logText(userID), "error", err)
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
	grantBody, err := canonicalJSON(req.Grant)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid app grant")
		return
	}
	if req.Tx.BodySHA256 != "" && req.Tx.BodySHA256 != sha256Hex(grantBody) {
		writeError(w, http.StatusBadRequest, "signed transaction body hash must cover grant payload")
		return
	}
	if req.Tx.BodySHA256 == "" {
		req.Tx.BodySHA256 = sha256Hex(grantBody)
	}
	_ = body
	if err := s.verifySignedTx(r.Context(), r, grantBody, req.Tx, userID, req.Grant.TargetAppID); err != nil {
		s.writeAuthError(w, err)
		return
	}
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
		slog.Error("create signed app grant", "user", logText(userID), "error", err)
		writeError(w, http.StatusInternalServerError, "app grant failed")
		return
	}
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
		slog.Error("revoke app grant", "user", logText(userID), "grant", logText(id), "error", err)
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
	if !validKsyncNamespace(sourceAppID) || !validKsyncNamespace(targetAppID) || !validCollectionPrefix(collectionPrefix) {
		writeError(w, http.StatusBadRequest, "invalid app records query")
		return
	}
	records, err := s.store.AuthorizedAppRecords(r.Context(), userID, sourceAppID, targetAppID, collectionPrefix)
	if err != nil {
		if errors.Is(err, ErrSyncUserNotFound) {
			writeError(w, http.StatusForbidden, "app grant required")
			return
		}
		slog.Error("read app records", "user", logText(userID), "source_app", logText(sourceAppID), "target_app", logText(targetAppID), "error", err)
		writeError(w, http.StatusInternalServerError, "app records failed")
		return
	}
	writeJSON(w, http.StatusOK, AppRecordsResponse{Records: records})
}

func (s *Server) authenticateAdmin(w http.ResponseWriter, r *http.Request) bool {
	if s.cfg.AdminToken == "" {
		writeError(w, http.StatusForbidden, "admin registration disabled")
		return false
	}
	if strings.TrimSpace(r.Header.Get("X-Ksync-Admin")) != s.cfg.AdminToken {
		writeError(w, http.StatusUnauthorized, "admin token required")
		return false
	}
	return true
}

func readAppRegistrationRequest(w http.ResponseWriter, r *http.Request, maxBody int64) (AppRegistration, error) {
	var req AppRegistration
	body, err := readJSONBody(w, r, maxBody)
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return req, errors.New("invalid json")
	}
	req.AppID = strings.TrimSpace(req.AppID)
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	req.Description = strings.TrimSpace(req.Description)
	req.HomepageURL = strings.TrimSpace(req.HomepageURL)
	req.SourceURL = strings.TrimSpace(req.SourceURL)
	req.PublicKey = strings.TrimSpace(req.PublicKey)
	req.Status = strings.TrimSpace(req.Status)
	if req.Status == "" {
		req.Status = appStatusActive
	}
	if !validKsyncNamespace(req.AppID) {
		return req, errors.New("invalid app_id")
	}
	if req.DisplayName == "" || len(req.DisplayName) > 80 {
		return req, errors.New("invalid display_name")
	}
	if req.Status != appStatusActive && req.Status != appStatusSuspended {
		return req, errors.New("invalid status")
	}
	if len(req.Collections) > 64 || len(req.Capabilities) > 64 {
		return req, errors.New("too many app fields")
	}
	for i := range req.Collections {
		req.Collections[i].AppID = req.AppID
		req.Collections[i].CollectionPrefix = strings.TrimSpace(req.Collections[i].CollectionPrefix)
		req.Collections[i].Visibility = strings.TrimSpace(req.Collections[i].Visibility)
		req.Collections[i].Description = strings.TrimSpace(req.Collections[i].Description)
		if req.Collections[i].SchemaVersion < 0 {
			return req, errors.New("invalid schema_version")
		}
		if !validCollectionPrefix(req.Collections[i].CollectionPrefix) ||
			!validAppVisibility(req.Collections[i].Visibility) {
			return req, errors.New("invalid app collection")
		}
	}
	for i := range req.Capabilities {
		req.Capabilities[i] = strings.TrimSpace(req.Capabilities[i])
		if !validKsyncNamespace(req.Capabilities[i]) {
			return req, errors.New("invalid capability")
		}
	}
	return req, nil
}

func readAppGrantRequest(w http.ResponseWriter, r *http.Request, maxBody int64) (AppGrantRequest, error) {
	var req AppGrantRequest
	body, err := readJSONBody(w, r, maxBody)
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return req, errors.New("invalid json")
	}
	req.SourceAppID = strings.TrimSpace(req.SourceAppID)
	req.TargetAppID = strings.TrimSpace(req.TargetAppID)
	req.CollectionPrefix = strings.TrimSpace(req.CollectionPrefix)
	req.Permission = strings.TrimSpace(req.Permission)
	if req.Permission == "" {
		req.Permission = appGrantRead
	}
	if !validKsyncNamespace(req.SourceAppID) || !validKsyncNamespace(req.TargetAppID) ||
		!validCollectionPrefix(req.CollectionPrefix) || req.Permission != appGrantRead {
		return req, errors.New("invalid app grant")
	}
	return req, nil
}

func readSignedAppGrantRequest(w http.ResponseWriter, r *http.Request, maxBody int64) (SignedAppGrantRequest, []byte, error) {
	var req SignedAppGrantRequest
	body, err := readJSONBody(w, r, maxBody)
	if err != nil {
		return req, nil, err
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return req, nil, errors.New("invalid json")
	}
	normalizeSignedTx(&req.Tx)
	req.Grant.SourceAppID = strings.TrimSpace(req.Grant.SourceAppID)
	req.Grant.TargetAppID = strings.TrimSpace(req.Grant.TargetAppID)
	req.Grant.CollectionPrefix = strings.TrimSpace(req.Grant.CollectionPrefix)
	req.Grant.Permission = strings.TrimSpace(req.Grant.Permission)
	if req.Grant.Permission == "" {
		req.Grant.Permission = appGrantRead
	}
	if !validKsyncNamespace(req.Grant.SourceAppID) || !validKsyncNamespace(req.Grant.TargetAppID) ||
		!validCollectionPrefix(req.Grant.CollectionPrefix) || req.Grant.Permission != appGrantRead {
		return req, nil, errors.New("invalid app grant")
	}
	return req, body, nil
}

func validAppVisibility(value string) bool {
	switch value {
	case "private", "shared", "friends", "public":
		return true
	default:
		return false
	}
}

func validCollectionPrefix(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if validLegacyEncryptedCollection(value) {
		return true
	}
	if strings.HasSuffix(value, ".*") {
		return validCollectionPrefixWildcardBase(strings.TrimSuffix(value, ".*"))
	}
	return validEncryptedHierarchyCollection(value)
}

func validCollectionPrefixWildcardBase(value string) bool {
	parts := strings.Split(strings.TrimSpace(value), ".")
	if len(parts) == 2 && parts[0] == "account" {
		return ksyncVersionSegmentPattern.MatchString(parts[1])
	}
	if len(parts) == 3 && (parts[0] == "private" || parts[0] == "shared" ||
		parts[0] == "friends" || parts[0] == "public") {
		return ksyncNamespaceSegmentPattern.MatchString(parts[1]) &&
			ksyncVersionSegmentPattern.MatchString(parts[2])
	}
	return false
}

func collectionMatchesPrefix(collection, prefix string) bool {
	if collection == prefix {
		return true
	}
	if strings.HasSuffix(prefix, ".*") {
		return strings.HasPrefix(collection, strings.TrimSuffix(prefix, "*"))
	}
	return false
}

func likePatternForCollectionPrefix(prefix string) string {
	base := strings.TrimSuffix(prefix, ".*")
	base = strings.ReplaceAll(base, `\`, `\\`)
	base = strings.ReplaceAll(base, `%`, `\%`)
	base = strings.ReplaceAll(base, `_`, `\_`)
	return base + ".%"
}

func auditJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(data)
}
