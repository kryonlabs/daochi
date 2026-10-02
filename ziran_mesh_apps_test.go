package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"reflect"
	"testing"
	"time"
)

func meshAppRegistration(t *testing.T, appID string, version int) (SignedAppRegistrationRequest, ed25519.PublicKey) {
	t.Helper()
	request, key, nodePrivate := signedRegistrationFixture(t)
	request.Manifest.AppID = appID
	request.Manifest.ManifestVersion = version
	Manifest_Normalize(&request.Manifest)
	appPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	signRegistrationFixture(t, &request, appPrivate, nodePrivate)
	return request, key
}

func compareMeshAppImport(t *testing.T, actual, expected *Store, ctx context.Context, key ed25519.PublicKey, policy NodeSyncPolicy, registrations []SignedAppRegistrationRequest) MeshAppsImportResult {
	t.Helper()
	got := MeshApps_Import(actual.Database, ctx, key, policy, registrations, AuthenticationError_Convert)
	baseline := &Server{store: expected, cfg: Config{NodeRegistryPublicKey: key}}
	want, err := baseline.baselineImportMeshApps(ctx, policy, registrations)
	if got.Value != want || !sameIdentityError(got.Error, err) {
		t.Fatalf("mesh app import = %#v, %v; baseline = %d, %v", got, got.Error, want, err)
	}
	if !equalAuthenticationError(got.Error, err) {
		t.Fatal("mesh app verification changed the wrapped authentication error", got.Error, err)
	}
	if got, want := appStoreSnapshot(t, actual), appStoreSnapshot(t, expected); !reflect.DeepEqual(got, want) {
		t.Fatal("mesh app import changed registry state", got, want)
	}
	return got
}

func compareMeshAppExport(t *testing.T, actual, expected *Store, ctx context.Context, policy NodeSyncPolicy) MeshAppsExportResult {
	t.Helper()
	got := MeshApps_Export(actual.Database, ctx, policy)
	want, err := expected.baselineExportMeshApps(ctx, policy)
	if !sameIdentityError(got.Error, err) || !reflect.DeepEqual(got.Value, want) || cap(got.Value) != cap(want) {
		t.Fatalf("mesh app export = %#v, %v; baseline = %#v, %v", got, got.Error, want, err)
	}
	return got
}

func TestZiranMeshAppsVersionsAndSignaturesAgainstBaseline(t *testing.T) {
	actual, expected := appStoreFixture(t), appStoreFixture(t)
	policy := NodeSyncPolicy{Apps: []string{" DEMO\u2003", "demo", "second"}, Data: []string{"app_registry"}}
	first, key := meshAppRegistration(t, "demo", 1)
	second, _ := meshAppRegistration(t, "second", 1)
	for _, batch := range [][]SignedAppRegistrationRequest{{first, second}, {first}, {second}, nil} {
		if got := compareMeshAppImport(t, actual, expected, t.Context(), key, policy, batch); got.Error != nil {
			t.Fatal(got.Error)
		}
		compareMeshAppExport(t, actual, expected, t.Context(), policy)
	}
	// Version one is the currently accepted wire format. Exercise ordering
	// against independently seeded stored metadata rather than inventing a
	// future wire version that the released validator rejects.
	for _, store := range []*Store{actual, expected} {
		if _, err := store.Database.Exec("UPDATE server_app_manifests SET manifest_version=0 WHERE app_id='demo'"); err != nil {
			t.Fatal(err)
		}
	}
	if got := compareMeshAppImport(t, actual, expected, t.Context(), key, policy, []SignedAppRegistrationRequest{first}); got.Value != 1 || got.Error != nil {
		t.Fatal("higher manifest version was not applied", got)
	}
	for _, store := range []*Store{actual, expected} {
		if _, err := store.Database.Exec("UPDATE server_app_manifests SET manifest_version=2 WHERE app_id='demo'"); err != nil {
			t.Fatal(err)
		}
	}
	if got := compareMeshAppImport(t, actual, expected, t.Context(), key, policy, []SignedAppRegistrationRequest{first}); got.Value != 0 || got.Error != nil {
		t.Fatal("older manifest overwrote current version", got)
	}
	for _, store := range []*Store{actual, expected} {
		if _, err := store.Database.Exec("UPDATE server_app_manifests SET manifest_version=1 WHERE app_id='demo'"); err != nil {
			t.Fatal(err)
		}
	}
	conflict, _ := meshAppRegistration(t, "demo", 1)
	conflict.Manifest.DisplayName = "Changed demo"
	signRegistrationFixture(t, &conflict,
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize)),
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x43}, ed25519.SeedSize)))
	if got := compareMeshAppImport(t, actual, expected, t.Context(), key, policy, []SignedAppRegistrationRequest{conflict}); got.Error == nil {
		t.Fatal("same-version manifest fork was accepted")
	}
	first.ManifestSignature = "not a signature"
	if got := compareMeshAppImport(t, actual, expected, t.Context(), key, policy, []SignedAppRegistrationRequest{first}); got.Error == nil {
		t.Fatal("obsolete manifest bypassed signature verification")
	}
	for _, requested := range []NodeSyncPolicy{
		{}, {Apps: []string{}}, {Apps: []string{"demo"}}, {Apps: []string{"second", "demo", "demo"}},
		{Apps: []string{"missing"}}, {Apps: []string{"demo"}, Data: []string{"names"}},
	} {
		compareMeshAppExport(t, actual, expected, t.Context(), requested)
	}
}

func TestZiranMeshAppsValidationAndPartialBatchAgainstBaseline(t *testing.T) {
	for _, mode := range []string{"scope", "invalid version", "expired", "expired key", "signature", "approval", "missing registry key", "write", "commit"} {
		t.Run(mode, func(t *testing.T) {
			actual, expected := appStoreFixture(t), appStoreFixture(t)
			first, key := meshAppRegistration(t, "first", 1)
			second, _ := meshAppRegistration(t, "second", 1)
			policy := NodeSyncPolicy{Apps: []string{"first", "second"}, Data: []string{"app_registry"}}
			query := ""
			switch mode {
			case "scope":
				policy.Apps = []string{"first"}
			case "invalid version":
				second.Manifest.ManifestVersion = 0
			case "expired":
				second.Manifest.ExpiresAt = time.Now().Add(-time.Hour).Unix()
			case "expired key":
				second.Manifest.Keys[0].ExpiresAt = time.Now().Add(-time.Hour).Unix()
			case "signature":
				second.ManifestSignature = "invalid"
			case "approval":
				second.ApprovalSignature = "invalid"
			case "missing registry key":
				key = nil
			case "write":
				query = "CREATE TRIGGER reject_mesh_app BEFORE INSERT ON server_app_keys WHEN NEW.app_id='second' BEGIN SELECT RAISE(ABORT,'key rejected'); END"
			case "commit":
				query = `CREATE TABLE parent(id INTEGER PRIMARY KEY);
CREATE TABLE pending(id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED);
CREATE TRIGGER reject_mesh_app AFTER INSERT ON server_app_manifests WHEN NEW.app_id='second' BEGIN INSERT INTO pending VALUES(99); END`
			}
			if query != "" {
				for _, store := range []*Store{actual, expected} {
					if _, err := store.Database.Exec(query); err != nil {
						t.Fatal(err)
					}
				}
			}
			got := compareMeshAppImport(t, actual, expected, t.Context(), key, policy, []SignedAppRegistrationRequest{first, second})
			if got.Error == nil || got.Value != 0 {
				t.Fatal("failed batch changed its reported count", got)
			}
			firstVersion := MeshApps_LoadVersion(actual.Database, t.Context(), "first")
			secondVersion := MeshApps_LoadVersion(actual.Database, t.Context(), "second")
			if firstVersion.Error != nil || secondVersion.Error != nil || secondVersion.Found {
				t.Fatal("failed app transaction left partial state", firstVersion, secondVersion)
			}
			if firstVersion.Found != (mode != "missing registry key") {
				t.Fatal("completed earlier app was not preserved on a later failure", firstVersion)
			}
			if query != "" {
				for _, store := range []*Store{actual, expected} {
					if _, err := store.Database.Exec("DROP TRIGGER reject_mesh_app"); err != nil {
						t.Fatal(err)
					}
				}
				if got := compareMeshAppImport(t, actual, expected, t.Context(), key, policy, []SignedAppRegistrationRequest{second}); got.Error != nil || got.Value != 1 {
					t.Fatal("failed app transaction left the connection unusable", got)
				}
			}
		})
	}
}

func TestZiranMeshAppQueryErrorsAndFilteringAgainstBaseline(t *testing.T) {
	for _, mode := range []string{"cancelled", "JSON", "scan", "version scan", "missing table", "closed"} {
		t.Run(mode, func(t *testing.T) {
			actual, expected := appStoreFixture(t), appStoreFixture(t)
			request, key := meshAppRegistration(t, "demo", 1)
			policy := NodeSyncPolicy{Apps: []string{"demo"}, Data: []string{"app_registry"}}
			compareMeshAppImport(t, actual, expected, t.Context(), key, policy, []SignedAppRegistrationRequest{request})
			ctx := t.Context()
			query := ""
			switch mode {
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			case "JSON":
				query = "UPDATE server_app_manifests SET manifest_json='{invalid'"
			case "scan":
				query = "ALTER TABLE server_app_manifests RENAME TO manifests; CREATE VIEW server_app_manifests AS SELECT app_id,NULL AS manifest_json,manifest_signature,approval_signature,manifest_version,manifest_hash FROM manifests"
			case "version scan":
				query = "UPDATE server_app_manifests SET manifest_version='invalid'"
			case "missing table":
				query = "DROP TABLE server_app_manifests"
			case "closed":
				for _, store := range []*Store{actual, expected} {
					_ = store.Database.Close()
				}
			}
			if query != "" {
				for _, store := range []*Store{actual, expected} {
					if _, err := store.Database.Exec(query); err != nil {
						t.Fatal(err)
					}
				}
			}
			compareMeshAppExport(t, actual, expected, ctx, policy)
			got := MeshApps_LoadVersion(actual.Database, ctx, "demo")
			want, found, err := expected.baselineLoadManifestVersion(ctx, "demo")
			if got.Value != ManifestVersion(want) || got.Found != found || !sameIdentityError(got.Error, err) {
				t.Fatal("stored version query changed", got, want, found, err)
			}
			if mode == "JSON" {
				if got := compareMeshAppExport(t, actual, expected, ctx, NodeSyncPolicy{Apps: []string{"other"}}); got.Error != nil {
					t.Fatal("unrequested manifest was decoded", got)
				}
			}
			if mode == "cancelled" && got.Error != context.Canceled {
				t.Fatal("version cancellation identity changed", got)
			}
			if mode == "cancelled" {
				if imported := compareMeshAppImport(t, actual, expected, ctx, key, policy, []SignedAppRegistrationRequest{request}); imported.Error != context.Canceled {
					t.Fatal("import cancellation identity changed", imported)
				}
			}
			// The no-data path does not access the database, even after closure.
			compareMeshAppExport(t, actual, expected, ctx, NodeSyncPolicy{Apps: []string{"demo"}, Data: []string{"names"}})
			compareMeshAppExport(t, actual, expected, ctx, NodeSyncPolicy{})
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got := MeshApps_Import(nil, ctx, nil, NodeSyncPolicy{Data: []string{"names"}}, nil, nil); got.Error != nil || got.Value != 0 {
		t.Fatal("disabled registry replication accessed its dependencies", got)
	}
}
