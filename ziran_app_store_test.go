package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

func appStoreFixture(t *testing.T) *Store {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS server_apps (
	app_id TEXT PRIMARY KEY,
	display_name TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	homepage_url TEXT NOT NULL DEFAULT '',
	source_url TEXT NOT NULL DEFAULT '',
	public_key TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT 'active',
	app_schema_version INTEGER NOT NULL DEFAULT 0,
	min_supported_client_version TEXT NOT NULL DEFAULT '',
	current_client_version TEXT NOT NULL DEFAULT '',
	compatibility_until TEXT NOT NULL DEFAULT '',
	features_json TEXT NOT NULL DEFAULT '[]',
	legacy_protocols_json TEXT NOT NULL DEFAULT '[]',
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS server_app_collections (
	app_id TEXT NOT NULL REFERENCES server_apps(app_id) ON DELETE CASCADE,
	collection_prefix TEXT NOT NULL,
	visibility TEXT NOT NULL DEFAULT 'private',
	schema_version INTEGER NOT NULL DEFAULT 0,
	description TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY(app_id, collection_prefix)
);

CREATE TABLE IF NOT EXISTS server_app_capabilities (
	app_id TEXT NOT NULL REFERENCES server_apps(app_id) ON DELETE CASCADE,
	capability TEXT NOT NULL,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY(app_id, capability)
);

CREATE TABLE IF NOT EXISTS server_app_manifests (
	app_id TEXT PRIMARY KEY REFERENCES server_apps(app_id) ON DELETE CASCADE,
	manifest_version INTEGER NOT NULL,
	manifest_json TEXT NOT NULL,
	manifest_hash TEXT NOT NULL UNIQUE,
	manifest_signature TEXT NOT NULL,
	approval_signature TEXT NOT NULL,
	expires_at INTEGER NOT NULL DEFAULT 0,
	status TEXT NOT NULL DEFAULT 'active',
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS server_app_keys (
	app_id TEXT NOT NULL REFERENCES server_apps(app_id) ON DELETE CASCADE,
	key_id TEXT NOT NULL,
	algorithm TEXT NOT NULL,
	public_key TEXT NOT NULL,
	purpose TEXT NOT NULL DEFAULT 'signing',
	status TEXT NOT NULL DEFAULT 'active',
	expires_at INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY(app_id, key_id)
);

CREATE TABLE token_assets(asset_id TEXT PRIMARY KEY);
INSERT INTO token_assets VALUES('waozi:token');
CREATE TABLE IF NOT EXISTS token_app_permissions (
	app_id TEXT NOT NULL REFERENCES server_apps(app_id) ON DELETE CASCADE,
	asset_id TEXT NOT NULL REFERENCES token_assets(asset_id) ON DELETE CASCADE,
	permission TEXT NOT NULL,
	status TEXT NOT NULL DEFAULT 'active',
	legacy_unsigned_until INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY(app_id, asset_id, permission)
);

`); err != nil {
		t.Fatal(err)
	}
	return &Store{Database: db}
}

func withoutAppClocks(app AppRegistration) AppRegistration {
	app.CreatedAt = ""
	app.UpdatedAt = ""
	for index := range app.Collections {
		app.Collections[index].CreatedAt = ""
	}
	for index := range app.Keys {
		app.Keys[index].CreatedAt = ""
	}
	return app
}

func appStoreSnapshot(t *testing.T, store *Store) map[string][][]string {
	t.Helper()
	result := make(map[string][][]string)
	queries := map[string]string{
		"apps":         "SELECT app_id,display_name,description,homepage_url,source_url,public_key,status,app_schema_version,min_supported_client_version,current_client_version,compatibility_until,features_json,legacy_protocols_json FROM server_apps ORDER BY app_id",
		"collections":  "SELECT app_id,collection_prefix,visibility,schema_version,description FROM server_app_collections ORDER BY app_id,collection_prefix",
		"capabilities": "SELECT app_id,capability FROM server_app_capabilities ORDER BY app_id,capability",
		"manifests":    "SELECT app_id,manifest_version,manifest_json,manifest_hash,manifest_signature,approval_signature,expires_at,status FROM server_app_manifests ORDER BY app_id",
		"keys":         "SELECT app_id,key_id,algorithm,public_key,purpose,status,expires_at FROM server_app_keys ORDER BY app_id,key_id",
		"policies":     "SELECT app_id,asset_id,permission,status,legacy_unsigned_until FROM token_app_permissions ORDER BY app_id,asset_id,permission",
	}
	for name, query := range queries {
		rows, err := store.Database.Query(query)
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			values := make([]string, len(columns))
			pointers := make([]any, len(columns))
			for index := range values {
				pointers[index] = &values[index]
			}
			if err := rows.Scan(pointers...); err != nil {
				t.Fatal(err)
			}
			result[name] = append(result[name], values)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return result
}

func compareAppStores(t *testing.T, actual, expected *Store, ids ...string) {
	t.Helper()
	if got, want := appStoreSnapshot(t, actual), appStoreSnapshot(t, expected); !reflect.DeepEqual(got, want) {
		t.Fatalf("registry state = %#v, baseline = %#v", got, want)
	}
	listed := AppStore_List(actual.Database, t.Context())
	want, err := expected.baselineListApps(t.Context())
	for index := range listed.Value {
		listed.Value[index] = withoutAppClocks(listed.Value[index])
	}
	for index := range want {
		want[index] = withoutAppClocks(want[index])
	}
	if !sameIdentityError(listed.Error, err) || !reflect.DeepEqual(listed.Value, want) {
		t.Fatalf("app list = %#v, baseline = %#v, %v", listed, want, err)
	}
	for _, id := range ids {
		loaded := AppStore_ByID(actual.Database, t.Context(), id)
		app, found, err := expected.baselineAppByID(t.Context(), id)
		if !sameIdentityError(loaded.Error, err) || loaded.Found != found || !reflect.DeepEqual(withoutAppClocks(loaded.Value), withoutAppClocks(app)) {
			t.Fatalf("app %q = %#v, baseline = %#v, %v, %v", id, loaded, app, found, err)
		}
		gotExists := AppStore_Exists(actual.Database, t.Context(), id)
		exists, err := expected.baselineAppExists(t.Context(), id)
		if !sameIdentityError(gotExists.Error, err) || gotExists.Value != exists {
			t.Fatalf("existence %q = %#v, baseline = %v, %v", id, gotExists, exists, err)
		}
		for _, version := range []int{-1, 0, 5, 6, 100} {
			got := AppStore_AllowsLegacyProtocol(actual.Database, t.Context(), id, version)
			allowed, err := expected.baselineAppAllowsLegacyProtocol(t.Context(), id, version)
			if !sameIdentityError(got.Error, err) || got.Value != allowed {
				t.Fatalf("legacy %q version %d = %#v, baseline = %v, %v", id, version, got, allowed, err)
			}
		}
		for _, collection := range []string{"", "inbe.habits", "shared.demo.v1.item", "shared.demo.v1", "other.item"} {
			got := AppStore_OwnsCollection(actual.Database, t.Context(), id, collection)
			owns, err := expected.baselineAppOwnsCollection(t.Context(), id, collection)
			if !sameIdentityError(got.Error, err) || got.Value != owns {
				t.Fatalf("ownership %q, %q = %#v, baseline = %v, %v", id, collection, got, owns, err)
			}
		}
	}
}

func appManifestFixture() AppManifest {
	return AppManifest{
		AppID: "demo", DisplayName: "Demo", ManifestVersion: 2,
		Status: "active", AppSchemaVersion: 7, CurrentVersion: "2.0",
		CompatibilityUntil: "2099-12-31", ExpiresAt: 9223372036854775807,
		Collections:     []AppCollection{{CollectionPrefix: "shared.demo.v1.*", Visibility: "shared", SchemaVersion: 7}},
		Capabilities:    []string{"sync", "sync", "export"},
		Features:        []AppFeature{{ID: "records", Collections: []string{"shared.demo.v1.*"}, RequiresSignedTx: true}},
		LegacyProtocols: []LegacyProtocol{{Name: "legacy", Version: 5, Status: "compatibility", ValidUntil: "2099-12-31"}},
		Keys: []AppKey{
			{KeyID: "z", Algorithm: "ed25519", PublicKey: "key-z"},
			{KeyID: "a", Algorithm: "ed25519", PublicKey: "key-a", Status: "active", ExpiresAt: 1},
			{KeyID: "s", Algorithm: "ed25519", PublicKey: "key-s", Status: "suspended"},
		},
		TokenPolicies: []TokenPolicy{
			{AssetID: AssetID, Permission: "spend", LegacyUnsignedUntil: 9223372036854775807},
			{AssetID: AssetID, Permission: "purchase", Status: "suspended"},
		},
	}
}

func writeAppManifestPair(t *testing.T, actual, expected *Store, manifest AppManifest, hash string) {
	t.Helper()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	got := AppStore_UpsertSignedManifest(actual.Database, t.Context(), manifest, data, hash, "manifest-sig", "approval-sig")
	want := expected.baselineUpsertSignedAppManifest(t.Context(), manifest, data, hash, "manifest-sig", "approval-sig")
	if !sameIdentityError(got, want) || got != nil {
		t.Fatalf("signed manifest write = %v, baseline = %v", got, want)
	}
}

func TestZiranAppRegistryLifecycleAgainstBaseline(t *testing.T) {
	actual, expected := appStoreFixture(t), appStoreFixture(t)
	compareAppStores(t, actual, expected, "missing")
	for _, app := range []AppRegistration{
		{AppID: "z", DisplayName: "Z", Status: "\u2003active\t"},
		{AppID: "a", DisplayName: "A", Features: []AppFeature{}, LegacyProtocols: []LegacyProtocol{}},
		{AppID: "s", DisplayName: "S", Status: "suspended"},
	} {
		got := AppStore_Upsert(actual.Database, t.Context(), app)
		want := expected.baselineUpsertApp(t.Context(), app)
		if !sameIdentityError(got, want) || got != nil {
			t.Fatalf("app write = %v, baseline = %v", got, want)
		}
	}
	manifest := appManifestFixture()
	writeAppManifestPair(t, actual, expected, manifest, "hash-1")
	compareAppStores(t, actual, expected, "demo", "z", "a", "s", "missing")
	for _, keyID := range []string{"a", "s", "z", "missing"} {
		got := AppStore_ActiveKey(actual.Database, t.Context(), "demo", keyID)
		key, found, err := expected.baselineActiveAppKey(t.Context(), "demo", keyID)
		got.Value.CreatedAt, key.CreatedAt = "", ""
		if !sameIdentityError(got.Error, err) || got.Found != found || !reflect.DeepEqual(got.Value, key) {
			t.Fatalf("active key %q = %#v, baseline = %#v, %v, %v", keyID, got, key, found, err)
		}
	}
	for _, id := range []string{"demo", "missing"} {
		got := AppStore_HasPolicy(actual.Database, t.Context(), id)
		found, err := expected.baselineHasTokenPolicy(t.Context(), id)
		if got.Value != found || !sameIdentityError(got.Error, err) {
			t.Fatalf("policy existence = %#v, baseline = %v, %v", got, found, err)
		}
		for _, permission := range []string{"spend", "purchase", "missing"} {
			got := AppStore_Permission(actual.Database, t.Context(), id, AssetID, permission)
			policy, found, err := expected.baselineAppTokenPermission(t.Context(), id, AssetID, permission)
			if got.Found != found || got.Value != policy || !sameIdentityError(got.Error, err) {
				t.Fatalf("permission = %#v, baseline = %#v, %v, %v", got, policy, found, err)
			}
		}
	}
	manifest.Keys = []AppKey{{KeyID: "replacement", Algorithm: "ed25519", PublicKey: "new"}}
	manifest.Collections = nil
	manifest.Capabilities = nil
	manifest.Features = []AppFeature{}
	manifest.LegacyProtocols = nil
	manifest.TokenPolicies = nil
	writeAppManifestPair(t, actual, expected, manifest, "hash-2")
	compareAppStores(t, actual, expected, "demo")
	manifest.Status = "suspended"
	manifest.AppSchemaVersion = 0
	writeAppManifestPair(t, actual, expected, manifest, "hash-3")
	compareAppStores(t, actual, expected, "demo")
}

func TestZiranAppSeedingAgainstBaseline(t *testing.T) {
	actual, expected := appStoreFixture(t), appStoreFixture(t)
	for round := 0; round < 2; round++ {
		got := AppStore_SeedBuiltin(actual.Database, t.Context())
		want := expected.baselineSeedBuiltinApps(t.Context())
		if !sameIdentityError(got, want) || got != nil {
			t.Fatalf("seed = %v, baseline = %v", got, want)
		}
		compareAppStores(t, actual, expected, "inbe", "missing")
	}
	manifest := appManifestFixture()
	manifest.AppID = "inbe"
	manifest.DisplayName = "Signed Inbe"
	writeAppManifestPair(t, actual, expected, manifest, "signed-inbe")
	got := AppStore_SeedBuiltin(actual.Database, t.Context())
	want := expected.baselineSeedBuiltinApps(t.Context())
	if !sameIdentityError(got, want) || got != nil {
		t.Fatalf("signed seed = %v, baseline = %v", got, want)
	}
	compareAppStores(t, actual, expected, "inbe")
}

func TestZiranAppWritesRollbackAgainstBaseline(t *testing.T) {
	for _, mode := range []string{"collection", "manifest", "key", "policy", "commit", "duplicate key", "duplicate policy"} {
		t.Run(mode, func(t *testing.T) {
			actual, expected := appStoreFixture(t), appStoreFixture(t)
			manifest := appManifestFixture()
			writeAppManifestPair(t, actual, expected, manifest, "before")
			before := appStoreSnapshot(t, actual)
			query := ""
			switch mode {
			case "commit":
				query = `CREATE TABLE parent(id INTEGER PRIMARY KEY);
CREATE TABLE pending(id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED);
CREATE TRIGGER reject_app AFTER INSERT ON server_app_keys BEGIN INSERT INTO pending VALUES(99); END`
			case "duplicate key":
				manifest.Keys = append(manifest.Keys, manifest.Keys[0])
			case "duplicate policy":
				manifest.TokenPolicies = append(manifest.TokenPolicies, manifest.TokenPolicies[0])
			default:
				tables := map[string]string{"collection": "server_app_collections", "manifest": "server_app_manifests", "key": "server_app_keys", "policy": "token_app_permissions"}
				query = "CREATE TRIGGER reject_app BEFORE INSERT ON " + tables[mode] + " BEGIN SELECT RAISE(ABORT,'write rejected'); END"
			}
			for _, store := range []*Store{actual, expected} {
				if _, err := store.Database.Exec(query); err != nil {
					t.Fatal(err)
				}
			}
			manifest.DisplayName = "Changed"
			manifest.ManifestVersion++
			data, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			got := AppStore_UpsertSignedManifest(actual.Database, t.Context(), manifest, data, "after", "new-sig", "new-approval")
			want := expected.baselineUpsertSignedAppManifest(t.Context(), manifest, data, "after", "new-sig", "new-approval")
			if got == nil || !sameIdentityError(got, want) || !reflect.DeepEqual(appStoreSnapshot(t, actual), before) {
				t.Fatalf("failed %s write = %v, baseline = %v; partial changes escaped rollback", mode, got, want)
			}
			compareAppStores(t, actual, expected, "demo")
			if query != "" {
				if _, err := actual.Database.Exec("DROP TRIGGER reject_app"); err != nil {
					t.Fatal(err)
				}
			}
			if err := AppStore_Upsert(actual.Database, t.Context(), AppRegistration{AppID: "usable", DisplayName: "Usable"}); err != nil {
				t.Fatal("rollback left the connection unusable", err)
			}
		})
	}
}

func TestZiranAppQueriesAndNativeErrorsAgainstBaseline(t *testing.T) {
	for _, mode := range []string{"features", "legacy", "manifest", "key scan", "policy scan", "cancelled", "closed"} {
		t.Run(mode, func(t *testing.T) {
			actual, expected := appStoreFixture(t), appStoreFixture(t)
			writeAppManifestPair(t, actual, expected, appManifestFixture(), "manifest")
			queries := map[string]string{
				"features":    "UPDATE server_apps SET features_json='{' WHERE app_id='demo'",
				"legacy":      "UPDATE server_apps SET legacy_protocols_json='[1]' WHERE app_id='demo'",
				"manifest":    "UPDATE server_app_manifests SET manifest_json='{' WHERE app_id='demo'",
				"key scan":    "UPDATE server_app_keys SET expires_at='broken' WHERE key_id='z'",
				"policy scan": "UPDATE token_app_permissions SET legacy_unsigned_until='broken' WHERE permission='spend'",
			}
			for _, store := range []*Store{actual, expected} {
				if query := queries[mode]; query != "" {
					if _, err := store.Database.Exec(query); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "closed" {
					if err := store.Database.Close(); err != nil {
						t.Fatal(err)
					}
				}
			}
			ctx := t.Context()
			if mode == "cancelled" {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			got := AppStore_ByID(actual.Database, ctx, "demo")
			want, found, err := expected.baselineAppByID(ctx, "demo")
			if !sameIdentityError(got.Error, err) || got.Found != found || !reflect.DeepEqual(got.Value, want) {
				t.Fatalf("app error = %#v, baseline = %#v, %v, %v", got, want, found, err)
			}
			listed := AppStore_List(actual.Database, ctx)
			apps, err := expected.baselineListApps(ctx)
			if !sameIdentityError(listed.Error, err) || !reflect.DeepEqual(listed.Value, apps) {
				t.Fatalf("list error = %#v, baseline = %#v, %v", listed, apps, err)
			}
			key := AppStore_ActiveKey(actual.Database, ctx, "demo", "z")
			wantKey, found, err := expected.baselineActiveAppKey(ctx, "demo", "z")
			key.Value.CreatedAt, wantKey.CreatedAt = "", ""
			if !sameIdentityError(key.Error, err) || key.Found != found || key.Value != wantKey {
				t.Fatalf("key error = %#v, baseline = %#v, %v, %v", key, wantKey, found, err)
			}
			policy := AppStore_Permission(actual.Database, ctx, "demo", AssetID, "spend")
			wantPolicy, found, err := expected.baselineAppTokenPermission(ctx, "demo", AssetID, "spend")
			if !sameIdentityError(policy.Error, err) || policy.Found != found || policy.Value != wantPolicy {
				t.Fatalf("policy error = %#v, baseline = %#v, %v, %v", policy, wantPolicy, found, err)
			}
			if mode == "cancelled" {
				if !errors.Is(got.Error, context.Canceled) {
					t.Fatal("native cancellation identity lost", got.Error)
				}
				if err := AppStore_Upsert(actual.Database, ctx, AppRegistration{}); !errors.Is(err, context.Canceled) {
					t.Fatal("transaction cancellation identity lost", err)
				}
			}
		})
	}
}

func TestZiranAppLegacyDateBoundariesAgainstBaseline(t *testing.T) {
	actual, expected := appStoreFixture(t), appStoreFixture(t)
	today := time.Now().UTC().Format("2006-01-02")
	for _, date := range []string{"", "0000-01-01", today, "9999-12-31", "not-a-date"} {
		app := AppRegistration{AppID: "boundary", DisplayName: "Boundary", LegacyProtocols: []LegacyProtocol{{Name: "legacy", Version: 5, Status: "compatibility", ValidUntil: date}}}
		if err := AppStore_Upsert(actual.Database, t.Context(), app); err != nil {
			t.Fatal(err)
		}
		if err := expected.baselineUpsertApp(t.Context(), app); err != nil {
			t.Fatal(err)
		}
		compareAppStores(t, actual, expected, "boundary")
	}
}
