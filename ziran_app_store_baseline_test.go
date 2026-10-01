package main

// Storage oracle extracted before replacing the maintained Go implementation.
import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

func (s *Store) baselineUpsertSignedAppManifest(ctx context.Context, manifest AppManifest, manifestBytes []byte, manifestHash, manifestSignature, approvalSignature string) error {
	tx, err := s.Database.BeginTx(ctx, nil)
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
		TokenPolicies:      manifest.TokenPolicies,
	}
	if len(manifest.Keys) > 0 {
		app.PublicKey = manifest.Keys[0].PublicKey
	}
	if err := baselineUpsertAppTx(ctx, tx, app); err != nil {
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
			Manifest_DefaultString(key.Purpose, "signing"), Manifest_DefaultString(key.Status, appStatusActive),
			key.ExpiresAt); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM token_app_permissions WHERE app_id=?1`, manifest.AppID); err != nil {
		return err
	}
	for _, policy := range manifest.TokenPolicies {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO token_app_permissions(app_id,asset_id,permission,status,legacy_unsigned_until)
VALUES(?1,?2,?3,?4,?5)`,
			manifest.AppID, policy.AssetID, policy.Permission, Manifest_DefaultString(policy.Status, appStatusActive),
			policy.LegacyUnsignedUntil); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func baselineUpsertAppTx(ctx context.Context, tx *sql.Tx, app AppRegistration) error {
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
	if _, err := tx.ExecContext(ctx, `DELETE FROM token_app_permissions WHERE app_id=?1`, app.AppID); err != nil {
		return err
	}
	for _, policy := range app.TokenPolicies {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO token_app_permissions(app_id,asset_id,permission,status,legacy_unsigned_until)
VALUES(?1,?2,?3,?4,?5)`,
			app.AppID, policy.AssetID, policy.Permission,
			Manifest_DefaultString(policy.Status, appStatusActive), policy.LegacyUnsignedUntil); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) baselineActiveAppKey(ctx context.Context, appID, keyID string) (AppKey, bool, error) {
	var key AppKey
	err := s.Database.QueryRowContext(ctx, `
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

func (s *Store) baselineHydrateAppManifestFields(ctx context.Context, app *AppRegistration) error {
	var manifestJSON string
	err := s.Database.QueryRowContext(ctx, `
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
	keys, err := s.baselineAppKeys(ctx, app.AppID)
	if err != nil {
		return err
	}
	app.Keys = keys
	policies, err := s.baselineTokenPolicies(ctx, app.AppID)
	if err != nil {
		return err
	}
	app.TokenPolicies = policies
	return nil
}

func (s *Store) baselineAppKeys(ctx context.Context, appID string) ([]AppKey, error) {
	rows, err := s.Database.QueryContext(ctx, `
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

func (s *Store) baselineTokenPolicies(ctx context.Context, appID string) ([]TokenPolicy, error) {
	rows, err := s.Database.QueryContext(ctx, `
SELECT asset_id,permission,status,legacy_unsigned_until
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
		if err := rows.Scan(&policy.AssetID, &policy.Permission, &policy.Status, &policy.LegacyUnsignedUntil); err != nil {
			return nil, err
		}
		out = append(out, policy)
	}
	return out, rows.Err()
}

func (s *Store) baselineAppTokenPermission(ctx context.Context, appID, assetID, permission string) (TokenPolicy, bool, error) {
	var policy TokenPolicy
	err := s.Database.QueryRowContext(ctx, `
SELECT asset_id,permission,status,legacy_unsigned_until
FROM token_app_permissions
WHERE app_id=?1 AND asset_id=?2 AND permission=?3 AND status='active'`, appID, assetID, permission).Scan(
		&policy.AssetID, &policy.Permission, &policy.Status, &policy.LegacyUnsignedUntil)
	if errors.Is(err, sql.ErrNoRows) {
		return TokenPolicy{}, false, nil
	}
	return policy, err == nil, err
}

func (s *Store) baselineHasTokenPolicy(ctx context.Context, appID string) (bool, error) {
	var count int
	err := s.Database.QueryRowContext(ctx, `SELECT COUNT(*) FROM token_app_permissions WHERE app_id=?1`, appID).Scan(&count)
	return count > 0, err
}

func (s *Store) baselineSeedBuiltinApps(ctx context.Context) error {
	inbe := AppRegistration{
		AppID:              "inbe",
		DisplayName:        "Inner Breeze",
		Description:        "Breathing, meditation, and habit data.",
		HomepageURL:        "https://inbe.waozi.xyz/",
		SourceURL:          "https://github.com/waozixyz/inbe",
		Status:             appStatusActive,
		AppSchemaVersion:   1,
		MinClientVersion:   "0.0.0",
		CurrentVersion:     "next",
		CompatibilityUntil: appCompatibilityDeadline,
		Collections: []AppCollection{
			{CollectionPrefix: "inbe.habits", Visibility: "private", SchemaVersion: 4, Description: "Released v4 encrypted habit records."},
			{CollectionPrefix: "inbe.habit_days", Visibility: "private", SchemaVersion: 4, Description: "Released v4 encrypted habit-day records."},
			{CollectionPrefix: "inbe.sessions", Visibility: "private", SchemaVersion: 4, Description: "Released v4 encrypted session records."},
			{CollectionPrefix: "private.inbe.v1.*", Visibility: "private", SchemaVersion: 1, Description: "Future private Inbe records."},
			{CollectionPrefix: "private.inbe.v1.elist-lists", Visibility: "private", SchemaVersion: 1, Description: "Encrypted Inbe EList list records."},
			{CollectionPrefix: "private.inbe.v1.elist-items", Visibility: "private", SchemaVersion: 1, Description: "Encrypted Inbe EList item records."},
			{CollectionPrefix: "shared.inbe.v1.*", Visibility: "shared", SchemaVersion: 1, Description: "User-grantable Inbe records."},
			{CollectionPrefix: "friends.inbe.v1.*", Visibility: "friends", SchemaVersion: 1, Description: "Friend-visible Inbe records."},
			{CollectionPrefix: "public.inbe.v1.*", Visibility: "public", SchemaVersion: 1, Description: "Public Inbe records."},
		},
		Capabilities: []string{"sync", "encrypted-records", "profile-stats", "leaderboard"},
		Features: []AppFeature{
			{ID: "sync.private_records", Collections: []string{"private.inbe.v1.*", "inbe.habits", "inbe.habit_days", "inbe.sessions"}, RequiresSignedTx: true},
			{ID: "sync.elist", Collections: []string{"private.inbe.v1.elist-lists", "private.inbe.v1.elist-items"}, RequiresSignedTx: true},
			{ID: "sync.shared_records", Collections: []string{"shared.inbe.v1.*"}, RequiresSignedTx: true},
			{ID: "profile.stats", RequiresSignedTx: false},
		},
		LegacyProtocols: []LegacyProtocol{
			{Name: "inbe-typed-sync", Version: 5, Status: "compatibility", ValidUntil: appCompatibilityDeadline},
			{Name: "ksync-headers", Version: 5, Status: "compatibility", ValidUntil: appCompatibilityDeadline},
		},
		TokenPolicies: []TokenPolicy{
			{AssetID: AssetID, Permission: "spend", Status: appStatusActive, LegacyUnsignedUntil: 1819756800},
			{AssetID: AssetID, Permission: "purchase", Status: appStatusActive, LegacyUnsignedUntil: 1819756800},
		},
	}
	var signedManifest int
	if err := s.Database.QueryRowContext(ctx, `
SELECT EXISTS(SELECT 1 FROM server_app_manifests WHERE app_id='inbe' AND status='active')`).Scan(&signedManifest); err != nil {
		return err
	}
	if signedManifest != 0 {
		return nil
	}
	return s.baselineUpsertApp(ctx, inbe)
}

func (s *Store) baselineUpsertApp(ctx context.Context, app AppRegistration) error {
	tx, err := s.Database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := baselineUpsertAppTx(ctx, tx, app); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) baselineListApps(ctx context.Context) ([]AppRegistration, error) {
	rows, err := s.Database.QueryContext(ctx, `
SELECT app_id,display_name,description,homepage_url,source_url,public_key,status,
       app_schema_version,min_supported_client_version,current_client_version,
       compatibility_until,features_json,legacy_protocols_json,created_at,updated_at
FROM server_apps
ORDER BY app_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	apps := []AppRegistration{}
	for rows.Next() {
		var app AppRegistration
		var featuresJSON string
		var legacyProtocolsJSON string
		if err := rows.Scan(&app.AppID, &app.DisplayName, &app.Description, &app.HomepageURL,
			&app.SourceURL, &app.PublicKey, &app.Status, &app.AppSchemaVersion,
			&app.MinClientVersion, &app.CurrentVersion, &app.CompatibilityUntil,
			&featuresJSON, &legacyProtocolsJSON, &app.CreatedAt, &app.UpdatedAt); err != nil {
			return nil, err
		}
		if err := baselineDecodeAppMetadata(featuresJSON, legacyProtocolsJSON, &app); err != nil {
			return nil, err
		}
		apps = append(apps, app)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range apps {
		apps[i].Collections, err = s.baselineAppCollections(ctx, apps[i].AppID)
		if err != nil {
			return nil, err
		}
		apps[i].Capabilities, err = s.baselineAppCapabilities(ctx, apps[i].AppID)
		if err != nil {
			return nil, err
		}
		if err := s.baselineHydrateAppManifestFields(ctx, &apps[i]); err != nil {
			return nil, err
		}
	}
	return apps, nil
}

func (s *Store) baselineAppByID(ctx context.Context, appID string) (AppRegistration, bool, error) {
	var app AppRegistration
	row := s.Database.QueryRowContext(ctx, `
SELECT app_id,display_name,description,homepage_url,source_url,public_key,status,
       app_schema_version,min_supported_client_version,current_client_version,
       compatibility_until,features_json,legacy_protocols_json,created_at,updated_at
FROM server_apps
WHERE app_id=?1`, appID)
	var featuresJSON string
	var legacyProtocolsJSON string
	err := row.Scan(&app.AppID, &app.DisplayName, &app.Description,
		&app.HomepageURL, &app.SourceURL, &app.PublicKey, &app.Status,
		&app.AppSchemaVersion, &app.MinClientVersion, &app.CurrentVersion,
		&app.CompatibilityUntil, &featuresJSON, &legacyProtocolsJSON,
		&app.CreatedAt, &app.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return AppRegistration{}, false, nil
	}
	if err != nil {
		return AppRegistration{}, false, err
	}
	if err := baselineDecodeAppMetadata(featuresJSON, legacyProtocolsJSON, &app); err != nil {
		return AppRegistration{}, false, err
	}
	var err2 error
	app.Collections, err2 = s.baselineAppCollections(ctx, appID)
	if err2 != nil {
		return AppRegistration{}, false, err2
	}
	app.Capabilities, err2 = s.baselineAppCapabilities(ctx, appID)
	if err2 != nil {
		return AppRegistration{}, false, err2
	}
	if err := s.baselineHydrateAppManifestFields(ctx, &app); err != nil {
		return AppRegistration{}, false, err
	}
	return app, true, nil
}

func baselineDecodeAppMetadata(featuresJSON, legacyProtocolsJSON string, app *AppRegistration) error {
	if strings.TrimSpace(featuresJSON) != "" {
		if err := json.Unmarshal([]byte(featuresJSON), &app.Features); err != nil {
			return err
		}
	}
	if strings.TrimSpace(legacyProtocolsJSON) != "" {
		if err := json.Unmarshal([]byte(legacyProtocolsJSON), &app.LegacyProtocols); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) baselineAppExists(ctx context.Context, appID string) (bool, error) {
	var exists int
	err := s.Database.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM server_apps WHERE app_id=?1 AND status='active')`, appID).Scan(&exists)
	return exists != 0, err
}

func (s *Store) baselineAppAllowsLegacyProtocol(ctx context.Context, appID string, protocolVersion int) (bool, error) {
	app, found, err := s.baselineAppByID(ctx, appID)
	if err != nil || !found {
		return false, err
	}
	today := time.Now().UTC().Format("2006-01-02")
	for _, legacy := range app.LegacyProtocols {
		if legacy.Status != "compatibility" && legacy.Status != "active" {
			continue
		}
		if legacy.Version > 0 && protocolVersion > legacy.Version {
			continue
		}
		if legacy.ValidUntil >= today {
			return true, nil
		}
	}
	if app.CompatibilityUntil != "" && app.CompatibilityUntil >= today {
		return true, nil
	}
	return false, nil
}

func (s *Store) baselineAppCollections(ctx context.Context, appID string) ([]AppCollection, error) {
	rows, err := s.Database.QueryContext(ctx, `
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

func (s *Store) baselineAppCapabilities(ctx context.Context, appID string) ([]string, error) {
	rows, err := s.Database.QueryContext(ctx, `
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

func (s *Store) baselineAppOwnsCollection(ctx context.Context, appID, collection string) (bool, error) {
	collections, err := s.baselineAppCollections(ctx, appID)
	if err != nil {
		return false, err
	}
	for _, item := range collections {
		if Scope_CollectionMatchesPrefix(collection, item.CollectionPrefix) {
			return true, nil
		}
	}
	return false, nil
}
