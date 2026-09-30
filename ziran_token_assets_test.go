package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestZiranTokenAssetSeedPreservesReleasedFields(t *testing.T) {
	_, store, _ := testServer(t)
	if _, err := store.db.Exec(`
UPDATE token_assets SET issuer_id='old', display_name='old', decimals=9,
status='inactive', created_at='2000-01-01', updated_at='2000-01-01'
WHERE asset_id='waozi:token';
INSERT INTO token_assets(issuer_id,asset_id,display_name,decimals,status)
VALUES('other','other:token','Other',3,'inactive')`); err != nil {
		t.Fatal(err)
	}
	for pass := 0; pass < 2; pass++ {
		if err := TokenAssets_Seed(store.db, context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	var issuer, asset, display, status, created, updated string
	var decimals int
	err := store.db.QueryRow(`
SELECT issuer_id,asset_id,display_name,decimals,status,created_at,updated_at
FROM token_assets WHERE asset_id='waozi:token'`).Scan(
		&issuer, &asset, &display, &decimals, &status, &created, &updated)
	if err != nil {
		t.Fatal(err)
	}
	if issuer != "waozi" || asset != "waozi:token" || display != "Chi" ||
		decimals != 6 || status != "active" || created != "2000-01-01" ||
		updated == "2000-01-01" {
		t.Fatalf("seeded asset fields: %q/%q/%q/%d/%q/%q/%q",
			issuer, asset, display, decimals, status, created, updated)
	}
	err = store.db.QueryRow(`
SELECT issuer_id,display_name,decimals,status FROM token_assets
WHERE asset_id='other:token'`).Scan(&issuer, &display, &decimals, &status)
	if err != nil {
		t.Fatal(err)
	}
	if issuer != "other" || display != "Other" || decimals != 3 || status != "inactive" {
		t.Fatalf("seed changed another asset: %q/%q/%d/%q", issuer, display, decimals, status)
	}
	var count int
	if err := store.db.QueryRow("SELECT count(*) FROM token_assets").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("repeat seed changed asset count: %d", count)
	}
}

func TestZiranTokenAssetSeedReturnsNativeErrors(t *testing.T) {
	_, store, _ := testServer(t)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := TokenAssets_Seed(store.db, canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation identity: %v", err)
	}
	if err := store.db.Close(); err != nil {
		t.Fatal(err)
	}
	_, expected := store.db.ExecContext(context.Background(), "SELECT 1")
	if actual := TokenAssets_Seed(store.db, context.Background()); actual != expected {
		t.Fatalf("closed database error: %v, want native error %v", actual, expected)
	}
	database, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := TokenAssets_Seed(database, context.Background()); err == nil ||
		!strings.Contains(err.Error(), "no such table: token_assets") {
		t.Fatalf("missing schema error: %v", err)
	}
}

func TestZiranBuildVersionReachesMetrics(t *testing.T) {
	expected := os.Getenv("DAOCHI_TEST_BUILD_VERSION")
	if expected == "" {
		expected = "dev"
	}
	if BuildVersion != expected {
		t.Fatalf("build stamp = %q, want %q", BuildVersion, expected)
	}
	server, _, _ := testServer(t)
	response := httptest.NewRecorder()
	server.Routes().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	want := fmt.Sprintf("daochi_build_info{version=%q} 1\n", expected)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), want) {
		t.Fatalf("metrics did not expose build stamp %q: status=%d body=%s",
			expected, response.Code, response.Body.String())
	}
}
