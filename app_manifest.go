package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

var errSignedTxReplay = errors.New("signed transaction replay")

func (s *Store) UpsertSignedAppManifest(ctx context.Context, manifest AppManifest, manifestBytes []byte, manifestHash, manifestSignature, approvalSignature string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	status := manifest.Status
	if status == "" {
		status = appStatusActive
	}
	app := AppRegistration{
		AppID:              manifest.AppID,
		DisplayName:        manifest.DisplayName,
		Description:        manifest.Description,
		HomepageURL:        manifest.HomepageURL,
		SourceURL:          manifest.SourceURL,
		Status:             status,
		AppSchemaVersion:   manifest.AppSchemaVersion,
		MinClientVersion:   manifest.MinClientVersion,
		CurrentVersion:     manifest.CurrentVersion,
		CompatibilityUntil: manifest.CompatibilityUntil,
		Collections:        manifest.Collections,
		Capabilities:       manifest.Capabilities,
		Features:           manifest.Features,
		LegacyProtocols:    manifest.LegacyProtocols,
	}
	if len(manifest.Keys) > 0 {
		app.PublicKey = manifest.Keys[0].PublicKey
	}
	if err := upsertAppTx(ctx, tx, app); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO server_app_manifests(app_id,manifest_version,manifest_json,manifest_hash,manifest_signature,approval_signature,expires_at,status)
VALUES(?1,?2,?3,?4,?5,?6,?7,?8)
ON CONFLICT(app_id) DO UPDATE SET
	manifest_version=excluded.manifest_version,
	manifest_json=excluded.manifest_json,
	manifest_hash=excluded.manifest_hash,
	manifest_signature=excluded.manifest_signature,
	approval_signature=excluded.approval_signature,
	expires_at=excluded.expires_at,
	status=excluded.status,
	updated_at=CURRENT_TIMESTAMP`,
		manifest.AppID, manifest.ManifestVersion, string(manifestBytes), manifestHash,
		manifestSignature, approvalSignature, manifest.ExpiresAt, status); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM server_app_keys WHERE app_id=?1`, manifest.AppID); err != nil {
		return err
	}
	for _, key := range manifest.Keys {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO server_app_keys(app_id,key_id,algorithm,public_key,purpose,status,expires_at)
VALUES(?1,?2,?3,?4,?5,?6,?7)`,
			manifest.AppID, key.KeyID, key.Algorithm, key.PublicKey,
			defaultString(key.Purpose, "signing"), defaultString(key.Status, appStatusActive),
			key.ExpiresAt); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM token_app_permissions WHERE app_id=?1`, manifest.AppID); err != nil {
		return err
	}
	for _, policy := range manifest.TokenPolicies {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO token_app_permissions(app_id,asset_id,permission,status)
VALUES(?1,?2,?3,?4)`,
			manifest.AppID, policy.AssetID, policy.Permission, defaultString(policy.Status, appStatusActive)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func upsertAppTx(ctx context.Context, tx *sql.Tx, app AppRegistration) error {
	status := strings.TrimSpace(app.Status)
	featuresJSON, err := json.Marshal(app.Features)
	if err != nil {
		return err
	}
	legacyProtocolsJSON, err := json.Marshal(app.LegacyProtocols)
	if err != nil {
		return err
	}
	if status == "" {
		status = appStatusActive
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO server_apps(app_id,display_name,description,homepage_url,source_url,public_key,status,app_schema_version,min_supported_client_version,current_client_version,compatibility_until,features_json,legacy_protocols_json)
VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
ON CONFLICT(app_id) DO UPDATE SET
	display_name=excluded.display_name,
	description=excluded.description,
	homepage_url=excluded.homepage_url,
	source_url=excluded.source_url,
	public_key=excluded.public_key,
	status=excluded.status,
	app_schema_version=excluded.app_schema_version,
	min_supported_client_version=excluded.min_supported_client_version,
	current_client_version=excluded.current_client_version,
	compatibility_until=excluded.compatibility_until,
	features_json=excluded.features_json,
	legacy_protocols_json=excluded.legacy_protocols_json,
	updated_at=CURRENT_TIMESTAMP`,
		app.AppID, app.DisplayName, app.Description, app.HomepageURL, app.SourceURL, app.PublicKey, status,
		app.AppSchemaVersion, app.MinClientVersion, app.CurrentVersion, app.CompatibilityUntil,
		string(featuresJSON), string(legacyProtocolsJSON)); err != nil {
		return err
	}
	if len(app.Collections) > 0 {
		if _, err := tx.ExecContext(ctx, `DELETE FROM server_app_collections WHERE app_id=?1`, app.AppID); err != nil {
			return err
		}
		for _, collection := range app.Collections {
			if _, err := tx.ExecContext(ctx, `
INSERT INTO server_app_collections(app_id,collection_prefix,visibility,schema_version,description)
VALUES(?1,?2,?3,?4,?5)`,
				app.AppID, collection.CollectionPrefix, collection.Visibility,
				collection.SchemaVersion, collection.Description); err != nil {
				return err
			}
		}
	}
	if len(app.Capabilities) > 0 {
		if _, err := tx.ExecContext(ctx, `DELETE FROM server_app_capabilities WHERE app_id=?1`, app.AppID); err != nil {
			return err
		}
		for _, capability := range app.Capabilities {
			if _, err := tx.ExecContext(ctx, `
INSERT OR IGNORE INTO server_app_capabilities(app_id,capability)
VALUES(?1,?2)`, app.AppID, capability); err != nil {
				return err
			}
		}
	}
	if len(app.TokenPolicies) > 0 {
		if _, err := tx.ExecContext(ctx, `DELETE FROM token_app_permissions WHERE app_id=?1`, app.AppID); err != nil {
			return err
		}
		for _, policy := range app.TokenPolicies {
			if _, err := tx.ExecContext(ctx, `
INSERT INTO token_app_permissions(app_id,asset_id,permission,status)
VALUES(?1,?2,?3,?4)`,
				app.AppID, policy.AssetID, policy.Permission,
				defaultString(policy.Status, appStatusActive)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) ActiveAppKey(ctx context.Context, appID, keyID string) (AppKey, bool, error) {
	var key AppKey
	err := s.db.QueryRowContext(ctx, `
SELECT key_id,algorithm,public_key,purpose,status,expires_at,created_at
FROM server_app_keys
WHERE app_id=?1 AND key_id=?2 AND status='active'`, appID, keyID).Scan(
		&key.KeyID, &key.Algorithm, &key.PublicKey, &key.Purpose, &key.Status, &key.ExpiresAt, &key.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return AppKey{}, false, nil
	}
	if err != nil {
		return AppKey{}, false, err
	}
	if key.ExpiresAt > 0 && time.Now().Unix() > key.ExpiresAt {
		return AppKey{}, false, nil
	}
	return key, true, nil
}

func (s *Store) HydrateAppManifestFields(ctx context.Context, app *AppRegistration) error {
	var manifestJSON string
	err := s.db.QueryRowContext(ctx, `
SELECT manifest_version,manifest_json,manifest_hash,manifest_signature,approval_signature,expires_at
FROM server_app_manifests
WHERE app_id=?1 AND status='active'`, app.AppID).Scan(
		&app.ManifestVersion, &manifestJSON, &app.ManifestHash, &app.ManifestSignature,
		&app.ApprovalSignature, &app.ManifestExpiresAt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if manifestJSON != "" {
		var manifest AppManifest
		if err := json.Unmarshal([]byte(manifestJSON), &manifest); err != nil {
			return err
		}
		app.AppSchemaVersion = manifest.AppSchemaVersion
		app.MinClientVersion = manifest.MinClientVersion
		app.CurrentVersion = manifest.CurrentVersion
		app.CompatibilityUntil = manifest.CompatibilityUntil
		app.Features = manifest.Features
		app.LegacyProtocols = manifest.LegacyProtocols
	}
	keys, err := s.AppKeys(ctx, app.AppID)
	if err != nil {
		return err
	}
	app.Keys = keys
	policies, err := s.TokenPolicies(ctx, app.AppID)
	if err != nil {
		return err
	}
	app.TokenPolicies = policies
	return nil
}

func (s *Store) AppKeys(ctx context.Context, appID string) ([]AppKey, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT key_id,algorithm,public_key,purpose,status,expires_at,created_at
FROM server_app_keys
WHERE app_id=?1
ORDER BY key_id`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AppKey
	for rows.Next() {
		var key AppKey
		if err := rows.Scan(&key.KeyID, &key.Algorithm, &key.PublicKey, &key.Purpose,
			&key.Status, &key.ExpiresAt, &key.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, key)
	}
	return out, rows.Err()
}

func (s *Store) TokenPolicies(ctx context.Context, appID string) ([]TokenPolicy, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT asset_id,permission,status
FROM token_app_permissions
WHERE app_id=?1
ORDER BY asset_id,permission`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TokenPolicy
	for rows.Next() {
		var policy TokenPolicy
		if err := rows.Scan(&policy.AssetID, &policy.Permission, &policy.Status); err != nil {
			return nil, err
		}
		out = append(out, policy)
	}
	return out, rows.Err()
}

func (s *Store) RecordSignedTx(ctx context.Context, tx SignedTxEnvelope) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM server_signed_transactions WHERE expires_at<?1`, time.Now().Unix()); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO server_signed_transactions(account_id,tx_id,app_id,nonce,expires_at)
VALUES(?1,?2,?3,?4,?5)`, tx.AccountID, tx.TxID, tx.AppID, tx.Nonce, tx.ExpiresAt)
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return errSignedTxReplay
	}
	return err
}

func (s *Store) AppTokenPermission(ctx context.Context, appID, assetID, permission string) (TokenPolicy, bool, error) {
	var policy TokenPolicy
	err := s.db.QueryRowContext(ctx, `
SELECT asset_id,permission,status
FROM token_app_permissions
WHERE app_id=?1 AND asset_id=?2 AND permission=?3 AND status='active'`, appID, assetID, permission).Scan(
		&policy.AssetID, &policy.Permission, &policy.Status)
	if errors.Is(err, sql.ErrNoRows) {
		return TokenPolicy{}, false, nil
	}
	return policy, err == nil, err
}

func (s *Store) HasTokenPolicy(ctx context.Context, appID string) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM token_app_permissions WHERE app_id=?1`, appID).Scan(&count)
	return count > 0, err
}

func (s *Server) handleSignedAppRegister(w http.ResponseWriter, r *http.Request) {
	req, err := readSignedAppRegistrationRequest(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	manifestBytes, manifestHash, err := validateSignedAppRegistration(req, s.cfg.NodeRegistryPublicKey)
	if err != nil {
		s.writeAuthError(w, err)
		return
	}
	if err := s.store.UpsertSignedAppManifest(r.Context(), req.Manifest, manifestBytes, manifestHash, req.ManifestSignature, req.ApprovalSignature); err != nil {
		slog.Error("register signed app manifest", "app", logText(req.Manifest.AppID), "error", err)
		writeError(w, http.StatusInternalServerError, "app registration failed")
		return
	}
	app, _, err := s.store.AppByID(r.Context(), req.Manifest.AppID)
	if err != nil {
		slog.Error("load signed app manifest", "app", logText(req.Manifest.AppID), "error", err)
		writeError(w, http.StatusInternalServerError, "app registration failed")
		return
	}
	writeJSON(w, http.StatusOK, app)
}

func readSignedAppRegistrationRequest(w http.ResponseWriter, r *http.Request, maxBody int64) (SignedAppRegistrationRequest, error) {
	var req SignedAppRegistrationRequest
	body, err := readJSONBody(w, r, maxBody)
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return req, errors.New("invalid json")
	}
	normalizeAppManifest(&req.Manifest)
	req.ManifestSignature = strings.TrimSpace(req.ManifestSignature)
	req.ApprovalSignature = strings.TrimSpace(req.ApprovalSignature)
	if err := validateAppManifest(req.Manifest); err != nil {
		return req, err
	}
	return req, nil
}

func validateSignedAppRegistration(req SignedAppRegistrationRequest, nodePublicKey ed25519.PublicKey) ([]byte, string, error) {
	if len(nodePublicKey) != ed25519.PublicKeySize {
		return nil, "", authError{status: http.StatusForbidden, message: "node registry approval unavailable"}
	}
	manifestBytes, err := canonicalJSON(req.Manifest)
	if err != nil {
		return nil, "", err
	}
	manifestHash := sha256Hex(manifestBytes)
	manifestSig, err := decodeBinaryField(req.ManifestSignature)
	if err != nil || len(manifestSig) != ed25519.SignatureSize {
		return nil, "", authError{status: http.StatusBadRequest, message: "invalid manifest signature"}
	}
	manifestMsg := append([]byte(daochiAppManifestContext+"\n"), manifestBytes...)
	if !manifestSignedByActiveKey(req.Manifest, manifestMsg, manifestSig) {
		return nil, "", authError{status: http.StatusUnauthorized, message: "manifest signature rejected"}
	}
	approvalSig, err := decodeBinaryField(req.ApprovalSignature)
	if err != nil || len(approvalSig) != ed25519.SignatureSize {
		return nil, "", authError{status: http.StatusBadRequest, message: "invalid approval signature"}
	}
	if !ed25519.Verify(nodePublicKey, appApprovalMessage(req.Manifest.AppID, manifestHash), approvalSig) {
		return nil, "", authError{status: http.StatusUnauthorized, message: "node approval rejected"}
	}
	return manifestBytes, manifestHash, nil
}

func manifestSignedByActiveKey(manifest AppManifest, message, signature []byte) bool {
	now := time.Now().Unix()
	for _, key := range manifest.Keys {
		if defaultString(key.Status, appStatusActive) != appStatusActive {
			continue
		}
		if key.ExpiresAt > 0 && now > key.ExpiresAt {
			continue
		}
		if !strings.EqualFold(key.Algorithm, "Ed25519") {
			continue
		}
		publicKey, err := decodeBinaryField(key.PublicKey)
		if err != nil || len(publicKey) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(publicKey, message, signature) {
			return true
		}
	}
	return false
}

func appApprovalMessage(appID, manifestHash string) []byte {
	return []byte(daochiAppApprovalContext + "\n" + appID + "\n" + manifestHash + "\n")
}

func normalizeAppManifest(manifest *AppManifest) {
	manifest.AppID = strings.TrimSpace(manifest.AppID)
	manifest.DisplayName = strings.TrimSpace(manifest.DisplayName)
	manifest.Description = strings.TrimSpace(manifest.Description)
	manifest.HomepageURL = strings.TrimSpace(manifest.HomepageURL)
	manifest.SourceURL = strings.TrimSpace(manifest.SourceURL)
	manifest.Status = strings.TrimSpace(manifest.Status)
	if manifest.Status == "" {
		manifest.Status = appStatusActive
	}
	for i := range manifest.Keys {
		manifest.Keys[i].KeyID = strings.TrimSpace(manifest.Keys[i].KeyID)
		manifest.Keys[i].Algorithm = strings.TrimSpace(manifest.Keys[i].Algorithm)
		manifest.Keys[i].PublicKey = strings.TrimSpace(manifest.Keys[i].PublicKey)
		manifest.Keys[i].Purpose = strings.TrimSpace(manifest.Keys[i].Purpose)
		manifest.Keys[i].Status = strings.TrimSpace(manifest.Keys[i].Status)
	}
	for i := range manifest.Collections {
		manifest.Collections[i].AppID = manifest.AppID
		manifest.Collections[i].CollectionPrefix = strings.TrimSpace(manifest.Collections[i].CollectionPrefix)
		manifest.Collections[i].Visibility = strings.TrimSpace(manifest.Collections[i].Visibility)
		manifest.Collections[i].Description = strings.TrimSpace(manifest.Collections[i].Description)
	}
	for i := range manifest.Capabilities {
		manifest.Capabilities[i] = strings.TrimSpace(manifest.Capabilities[i])
	}
	for i := range manifest.Features {
		manifest.Features[i].ID = strings.TrimSpace(manifest.Features[i].ID)
		manifest.Features[i].Description = strings.TrimSpace(manifest.Features[i].Description)
		for j := range manifest.Features[i].Collections {
			manifest.Features[i].Collections[j] = strings.TrimSpace(manifest.Features[i].Collections[j])
		}
	}
	for i := range manifest.LegacyProtocols {
		manifest.LegacyProtocols[i].Name = strings.TrimSpace(manifest.LegacyProtocols[i].Name)
		manifest.LegacyProtocols[i].Status = strings.TrimSpace(manifest.LegacyProtocols[i].Status)
		manifest.LegacyProtocols[i].ValidUntil = strings.TrimSpace(manifest.LegacyProtocols[i].ValidUntil)
	}
	manifest.MinClientVersion = strings.TrimSpace(manifest.MinClientVersion)
	manifest.CurrentVersion = strings.TrimSpace(manifest.CurrentVersion)
	manifest.CompatibilityUntil = strings.TrimSpace(manifest.CompatibilityUntil)
	for i := range manifest.TokenPolicies {
		manifest.TokenPolicies[i].AssetID = strings.TrimSpace(manifest.TokenPolicies[i].AssetID)
		manifest.TokenPolicies[i].Permission = strings.TrimSpace(manifest.TokenPolicies[i].Permission)
		manifest.TokenPolicies[i].Status = strings.TrimSpace(manifest.TokenPolicies[i].Status)
		if manifest.TokenPolicies[i].Status == "" {
			manifest.TokenPolicies[i].Status = appStatusActive
		}
	}
}

func validateAppManifest(manifest AppManifest) error {
	if manifest.ManifestVersion != 1 {
		return errors.New("unsupported manifest_version")
	}
	if !validNamespace(manifest.AppID) {
		return errors.New("invalid app_id")
	}
	if manifest.DisplayName == "" || len(manifest.DisplayName) > 80 {
		return errors.New("invalid display_name")
	}
	if manifest.Status != appStatusActive && manifest.Status != appStatusSuspended {
		return errors.New("invalid status")
	}
	if len(manifest.Keys) == 0 || len(manifest.Keys) > 16 {
		return errors.New("invalid app keys")
	}
	if manifest.AppSchemaVersion < 0 || manifest.AppSchemaVersion > 65535 {
		return errors.New("invalid app_schema_version")
	}
	if manifest.CompatibilityUntil != "" && !validDateString(manifest.CompatibilityUntil) {
		return errors.New("invalid compatibility_until")
	}
	if len(manifest.Collections) > 64 || len(manifest.Capabilities) > 64 ||
		len(manifest.Features) > 128 || len(manifest.LegacyProtocols) > 64 ||
		len(manifest.TokenPolicies) > 64 {
		return errors.New("too many manifest fields")
	}
	for _, key := range manifest.Keys {
		if !validClientID(key.KeyID) || !strings.EqualFold(key.Algorithm, "Ed25519") {
			return errors.New("invalid app key")
		}
		publicKey, err := decodeBinaryField(key.PublicKey)
		if err != nil || len(publicKey) != ed25519.PublicKeySize {
			return errors.New("invalid app public key")
		}
		if key.Status != "" && key.Status != appStatusActive && key.Status != appStatusSuspended {
			return errors.New("invalid app key status")
		}
	}
	for _, collection := range manifest.Collections {
		if !validCollectionPrefix(collection.CollectionPrefix) || !validAppVisibility(collection.Visibility) {
			return errors.New("invalid app collection")
		}
	}
	for _, capability := range manifest.Capabilities {
		if !validNamespace(capability) {
			return errors.New("invalid capability")
		}
	}
	for _, feature := range manifest.Features {
		if !validNamespace(feature.ID) || len(feature.Collections) > 16 {
			return errors.New("invalid app feature")
		}
		for _, collection := range feature.Collections {
			if !validCollectionPrefix(collection) {
				return errors.New("invalid app feature collection")
			}
		}
	}
	for _, legacy := range manifest.LegacyProtocols {
		if !validNamespace(legacy.Name) || legacy.Version < 0 ||
			!validLegacyProtocolStatus(legacy.Status) || !validDateString(legacy.ValidUntil) {
			return errors.New("invalid legacy protocol")
		}
	}
	for _, policy := range manifest.TokenPolicies {
		if !validTokenPolicyPermission(policy.Permission) || strings.TrimSpace(policy.AssetID) == "" {
			return errors.New("invalid token policy")
		}
		if policy.Status != "" && policy.Status != appStatusActive && policy.Status != appStatusSuspended {
			return errors.New("invalid token policy status")
		}
	}
	if manifest.ExpiresAt > 0 && time.Now().Unix() > manifest.ExpiresAt {
		return errors.New("manifest expired")
	}
	return nil
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func manifestDigest(manifest AppManifest) (string, error) {
	data, err := canonicalJSON(manifest)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func formatAppManifestForTest(manifest AppManifest) ([]byte, string, error) {
	normalizeAppManifest(&manifest)
	if err := validateAppManifest(manifest); err != nil {
		return nil, "", err
	}
	data, err := canonicalJSON(manifest)
	if err != nil {
		return nil, "", err
	}
	return data, sha256Hex(data), nil
}

func (p TokenPolicy) String() string {
	return fmt.Sprintf("%s:%s", p.AssetID, p.Permission)
}
