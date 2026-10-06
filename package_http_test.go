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
)

func TestIndependentPackageReleases(t *testing.T) {
	server, database, _ := testServer(t)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x63}, ed25519.SeedSize))
	public := hex.EncodeToString(private.Public().(ed25519.PublicKey))
	for _, id := range []string{"inbe", "diary"} {
		manifest := AppManifest{ManifestVersion: 1, AppID: id, DisplayName: id,
			Status: "active", Keys: []AppKey{{KeyID: "release", Algorithm: "ed25519",
				PublicKey: public, Status: "active"}}}
		encoded, _ := json.Marshal(manifest)
		if err := AppStore_UpsertSignedManifest(database.Database, context.Background(),
			manifest, encoded, id+"-fixture", "fixture", "fixture"); err != nil {
			t.Fatal(err)
		}
	}
	module := []byte("ZIB\x00module fixture")
	standalone := []byte("ZIB\x00standalone fixture")
	artifact := func(variant string, data []byte) Artifact {
		hash := sha256.Sum256(data)
		return Artifact{Variant: variant, SHA256: hex.EncodeToString(hash[:]), Size: int64(len(data))}
	}
	makeRelease := func(id string, sequence int64, version string) ReleaseV2 {
		value := ReleaseV2{AppID: id, Sequence: sequence, Version: version,
			Runtime: "kryon-app-v1", HostAPI: 1, ModuleAPI: 1, DataSchema: 1, KeyID: "release",
			Artifacts:    []Artifact{artifact("module", module), artifact("standalone", standalone)},
			Dependencies: []Dependency{}}
		value.Signature = hex.EncodeToString(ed25519.Sign(private,
			[]byte(PackageRelease_SigningMessage(value))))
		return value
	}
	stage := func(value ReleaseV2) {
		t.Helper()
		root := server.Cfg.DBPath + ".packages/" + value.AppID
		if err := os.MkdirAll(root, 0700); err != nil {
			t.Fatal(err)
		}
		encoded, _ := json.Marshal(value)
		for name, data := range map[string][]byte{
			"latest-v2.json":                                   encoded,
			value.Artifacts[0].SHA256 + ".zib":                 module,
			value.Artifacts[1].SHA256 + ".zib":                 standalone,
			value.Artifacts[0].SHA256 + ".zib.release-v2.json": encoded,
			value.Artifacts[1].SHA256 + ".zib.release-v2.json": encoded,
		} {
			if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	rootRelease := makeRelease("inbe", 3, "2.1.0")
	diary := makeRelease("diary", 1, "1.0.0")
	stage(rootRelease)
	stage(diary)
	routes := server.Routes()
	get := func(path string, status int) *httptest.ResponseRecorder {
		t.Helper()
		response := httptest.NewRecorder()
		routes.ServeHTTP(response, httptest.NewRequest("GET", "/api/v2/packages/"+path, nil))
		if response.Code != status {
			t.Fatalf("%s: got %d: %s", path, response.Code, response.Body.String())
		}
		return response
	}
	for index, data := range [][]byte{module, standalone} {
		response := get("diary/"+diary.Artifacts[index].SHA256+".zib", 200)
		if !bytes.Equal(response.Body.Bytes(), data) {
			t.Fatal("incorrect delivery variant")
		}
	}
	newDiary := makeRelease("diary", 2, "1.0.1")
	stage(newDiary)
	var unchanged ReleaseV2
	if err := json.Unmarshal(get("inbe/latest", 200).Body.Bytes(), &unchanged); err != nil {
		t.Fatal(err)
	}
	if unchanged.Sequence != rootRelease.Sequence || unchanged.Version != rootRelease.Version {
		t.Fatal("updating Diary changed the harness version")
	}
	if get("diary/latest", 200).Header().Get("Cache-Control") != "no-store" {
		t.Fatal("latest must not be cached")
	}
	invalid := newDiary
	invalid.HostAPI = 2 // Compatibility metadata is signed too.
	stage(invalid)
	get("diary/latest", 503)
	stage(newDiary)
	get("unknown/latest", 404)
	get("diary/not-a-hash.zib", 404)
	get("diary/"+hex.EncodeToString(bytes.Repeat([]byte{0x41}, 32))+".zib", 404)
	if err := os.WriteFile(server.Cfg.DBPath+".packages/diary/"+
		newDiary.Artifacts[0].SHA256+".zib", []byte("damaged"), 0600); err != nil {
		t.Fatal(err)
	}
	get("diary/"+newDiary.Artifacts[0].SHA256+".zib", 503)
}

func TestPackageReleaseDescriptorValidation(t *testing.T) {
	hash := hex.EncodeToString(bytes.Repeat([]byte{1}, 32))
	valid := ReleaseV2{AppID: "diary", Sequence: 1, Version: "1.0.0",
		Runtime: "kryon-app-v1", HostAPI: 1, ModuleAPI: 1, KeyID: "release",
		Artifacts: []Artifact{{Variant: "module", SHA256: hash, Size: 8}}}
	if !PackageRelease_Valid(valid, "diary") {
		t.Fatal("valid thin module was rejected")
	}
	for _, version := range []string{"01.0.0", "1.0", "1.0.0\nother", "1.0.0-beta"} {
		value := valid
		value.Version = version
		if PackageRelease_Valid(value, "diary") {
			t.Fatalf("accepted invalid version %q", version)
		}
	}
	invalid := valid
	invalid.Dependencies = []Dependency{{AppID: "diary", Version: "1.0.0", SHA256: hash, Size: 8}}
	if PackageRelease_Valid(invalid, "diary") {
		t.Fatal("accepted self dependency")
	}
	invalid.Dependencies = []Dependency{
		{AppID: "shared", Version: "1.0.0", SHA256: hash, Size: 8},
		{AppID: "shared", Version: "1.0.0", SHA256: hash, Size: 8},
	}
	if PackageRelease_Valid(invalid, "diary") {
		t.Fatal("accepted duplicate dependencies")
	}
}
