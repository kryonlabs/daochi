package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPortableReleaseRoutes(t *testing.T) {
	server, store, _ := testServer(t)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	manifest := AppManifest{ManifestVersion: 1, AppID: "portable", DisplayName: "Portable",
		Status: "active", Keys: []AppKey{{KeyID: "release", Algorithm: "ed25519",
			PublicKey: hex.EncodeToString(public), Status: "active"}}}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err = AppStore_UpsertSignedManifest(store.Database, context.Background(), manifest,
		encoded, "fixture", "fixture", "fixture"); err != nil {
		t.Fatal(err)
	}
	root := server.Cfg.DBPath + ".packages/portable"
	if err = os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	data := []byte("ZIB\x00signed portable test")
	digest := sha256.Sum256(data)
	release := Release{AppID: "portable", Sequence: 1, Version: "1.0.0",
		Runtime: "kryon-desktop-v1", SHA256: hex.EncodeToString(digest[:]),
		Size: int64(len(data)), KeyID: "release"}
	sign := func(value Release) Release {
		value.Signature = hex.EncodeToString(ed25519.Sign(private, []byte(BundleHttp_SigningMessage(value))))
		return value
	}
	release = sign(release)
	save := func(name string, value Release) {
		t.Helper()
		payload, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(root, name), payload, 0600); err != nil {
			t.Fatal(err)
		}
	}
	save("latest.json", release)
	save(release.SHA256+".zib.json", release)
	bundle := filepath.Join(root, release.SHA256+".zib")
	if err = os.WriteFile(bundle, data, 0600); err != nil {
		t.Fatal(err)
	}
	routes := server.Routes()
	get := func(path string, expected int) *httptest.ResponseRecorder {
		t.Helper()
		reply := httptest.NewRecorder()
		request := httptest.NewRequest("GET", "/api/v1/packages/"+path, nil)
		routes.ServeHTTP(reply, request)
		if reply.Code != expected {
			t.Fatalf("%s: %d %s", path, reply.Code, reply.Body.String())
		}
		return reply
	}
	metadata := get("portable/latest", 200)
	if metadata.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("latest was cached")
	}
	loaded := get("portable/"+release.SHA256+".zib", 200)
	if !bytes.Equal(loaded.Body.Bytes(), data) {
		t.Fatal("download bytes changed")
	}
	if loaded.Header().Get("ETag") != "\""+release.SHA256+"\"" {
		t.Fatal("missing hash ETag")
	}
	newer := release
	newer.Sequence = 2
	newer.Version = "1.0.1"
	newer.SHA256 = hex.EncodeToString(bytes.Repeat([]byte{0x77}, 32))
	save("latest.json", sign(newer))
	get("portable/"+release.SHA256+".zib", 200)
	save("latest.json", release)
	get("unknown/latest", 404)
	get("portable/not-a-hash.zib", 404)
	altered := release
	altered.Signature = hex.EncodeToString(make([]byte, ed25519.SignatureSize))
	save("latest.json", altered)
	get("portable/latest", 503)
	altered = release
	altered.AppID = "another"
	save("latest.json", sign(altered))
	get("portable/latest", 503)
	save("latest.json", release)
	if err = os.WriteFile(bundle, []byte("altered"), 0600); err != nil {
		t.Fatal(err)
	}
	get("portable/"+release.SHA256+".zib", 503)
	if _, err = store.Database.Exec("UPDATE server_app_keys SET expires_at=? WHERE app_id='portable'", time.Now().Unix()-1); err != nil {
		t.Fatal(err)
	}
	get("portable/latest", 503)
	if _, err = store.Database.Exec("UPDATE server_apps SET status='suspended' WHERE app_id='portable'"); err != nil {
		t.Fatal(err)
	}
	get("portable/latest", 404)
}
