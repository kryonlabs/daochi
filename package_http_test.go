package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	// History exposes only bounded, compatible publisher-signed releases.
	historyPath := server.Cfg.DBPath + ".packages/diary/history-v2.json"
	writeHistory := func(values ...ReleaseV2) {
		t.Helper()
		encoded, _ := json.Marshal(map[string]interface{}{"versions": values})
		if err := os.WriteFile(historyPath, encoded, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeHistory(newDiary, diary)
	var history struct {
		Versions []ReleaseV2 `json:"versions"`
	}
	historyResponse := get("diary/history?host_api=1&module_api=1", 200)
	if err := json.Unmarshal(historyResponse.Body.Bytes(), &history); err != nil {
		t.Fatal(err)
	}
	if len(history.Versions) != 2 || history.Versions[0].Sequence != 2 ||
		history.Versions[1].Sequence != 1 || historyResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("history did not preserve the signed newest-first choices")
	}
	for _, value := range history.Versions {
		if !ed25519.Verify(private.Public().(ed25519.PublicKey),
			[]byte(PackageRelease_SigningMessage(value)), func() []byte {
				signature, err := hex.DecodeString(value.Signature)
				if err != nil {
					t.Fatal(err)
				}
				return signature
			}()) {
			t.Fatal("history changed a signed descriptor")
		}
	}
	forged := diary
	forged.Version = "9.9.9"
	writeHistory(newDiary, forged)
	if err := json.Unmarshal(get("diary/history", 200).Body.Bytes(), &history); err != nil {
		t.Fatal(err)
	}
	if len(history.Versions) != 1 {
		t.Fatal("forged history entry was offered")
	}
	writeHistory(newDiary, newDiary)
	get("diary/history", 503)
	writeHistory(newDiary, diary, diary, diary)
	get("diary/history", 503)
	writeHistory(newDiary, rootRelease)
	get("diary/history", 503)
	writeHistory(newDiary, diary)
	get("diary/history?host_api=wrong", 400)
	get("diary/history/grant", 404)
	get("inbe/history", 200) // Older nodes/stores may only have latest metadata.
	// A beta release keeps its channel when served, so apps can hide it.
	betaDiary := makeRelease("diary", 2, "1.0.1")
	betaDiary.Channel = "beta"
	stage(betaDiary)
	var served ReleaseV2
	if err := json.Unmarshal(get("diary/latest", 200).Body.Bytes(), &served); err != nil {
		t.Fatal(err)
	}
	if served.Channel != "beta" {
		t.Fatal("the beta channel was dropped")
	}
	if strings.Contains(get("inbe/latest", 200).Body.String(), "channel") {
		t.Fatal("a release without a channel gained one")
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

func TestPackageReleaseForOlderHosts(t *testing.T) {
	server, database, _ := testServer(t)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x64}, ed25519.SeedSize))
	manifest := AppManifest{ManifestVersion: 1, AppID: "diary", DisplayName: "diary",
		Status: "active", Keys: []AppKey{{KeyID: "release", Algorithm: "ed25519",
			PublicKey: hex.EncodeToString(private.Public().(ed25519.PublicKey)), Status: "active"}}}
	encoded, _ := json.Marshal(manifest)
	if err := AppStore_UpsertSignedManifest(database.Database, context.Background(),
		manifest, encoded, "diary-fixture", "fixture", "fixture"); err != nil {
		t.Fatal(err)
	}
	root := server.Cfg.DBPath + ".packages/diary"
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	// Releases are archived by sequence the way Inbe's importer leaves them.
	publish := func(sequence int64, version string, hostAPI int64, moduleAPI int64) ReleaseV2 {
		t.Helper()
		data := []byte("ZIB\x00diary " + version)
		hash := sha256.Sum256(data)
		value := ReleaseV2{AppID: "diary", Sequence: sequence, Version: version,
			Runtime: "kryon-app-v1", HostAPI: hostAPI, ModuleAPI: moduleAPI, KeyID: "release",
			Artifacts: []Artifact{{Variant: "module", SHA256: hex.EncodeToString(hash[:]),
				Size: int64(len(data))}}, Dependencies: []Dependency{}}
		value.Signature = hex.EncodeToString(ed25519.Sign(private,
			[]byte(PackageRelease_SigningMessage(value))))
		metadata, _ := json.Marshal(value)
		for name, content := range map[string][]byte{
			"latest-v2.json":                                   metadata,
			fmt.Sprintf("release-%d.json", sequence):           metadata,
			value.Artifacts[0].SHA256 + ".zib":                 data,
			value.Artifacts[0].SHA256 + ".zib.release-v2.json": metadata,
		} {
			if err := os.WriteFile(filepath.Join(root, name), content, 0600); err != nil {
				t.Fatal(err)
			}
		}
		return value
	}
	routes := server.Routes()
	latest := func(query string, status int) ReleaseV2 {
		t.Helper()
		response := httptest.NewRecorder()
		routes.ServeHTTP(response, httptest.NewRequest("GET", "/api/v2/packages/diary/latest"+query, nil))
		if response.Code != status {
			t.Fatalf("%s: got %d: %s", query, response.Code, response.Body.String())
		}
		var value ReleaseV2
		if status == 200 {
			if err := json.Unmarshal(response.Body.Bytes(), &value); err != nil {
				t.Fatal(err)
			}
		}
		return value
	}
	publish(1, "1.0.0", 4, 2)
	forFive := publish(2, "1.0.1", 5, 2)
	if err := os.WriteFile(filepath.Join(root, "release-3.json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	newest := publish(4, "1.1.0", 6, 2)
	if value := latest("", 200); value.Sequence != newest.Sequence {
		t.Fatalf("a client naming no interface got sequence %d", value.Sequence)
	}
	if value := latest("?host_api=7&module_api=2", 200); value.Sequence != newest.Sequence {
		t.Fatalf("a newer host did not get the newest release: %d", value.Sequence)
	}
	// A damaged archive is skipped, not served.
	if value := latest("?host_api=5&module_api=2", 200); value.Sequence != forFive.Sequence ||
		value.Signature != forFive.Signature {
		t.Fatalf("host 5 got sequence %d", value.Sequence)
	}
	if value := latest("?host_api=4", 200); value.Sequence != 1 {
		t.Fatalf("host 4 got sequence %d", value.Sequence)
	}
	latest("?host_api=3", 404)
	latest("?host_api=6&module_api=3", 404)
	for _, query := range []string{"?host_api=0", "?host_api=x", "?module_api=-1", "?host_api=65536"} {
		latest(query, 400)
	}
	// An archived release whose signature no longer verifies is never served.
	forged := forFive
	forged.Version = "1.0.9"
	metadata, _ := json.Marshal(forged)
	if err := os.WriteFile(filepath.Join(root, "release-2.json"), metadata, 0600); err != nil {
		t.Fatal(err)
	}
	if value := latest("?host_api=5", 200); value.Sequence != 1 {
		t.Fatalf("a forged archive was served: %d", value.Sequence)
	}
	// A staged release reaches buckets below its share; the others keep the
	// newest earlier release, and apps that send no bucket come last.
	rollout := func(text string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, "rollout.json"), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	until := time.Now().Add(time.Hour).Unix()
	rollout(fmt.Sprintf(`{"sequence":4,"percent":20,"until":%d}`, until))
	for query, sequence := range map[string]int64{
		"?bucket=0": 4, "?bucket=19": 4, "?bucket=20": 1, "?bucket=99": 1, "": 1,
		"?host_api=6&bucket=5": 4, "?host_api=6&bucket=50": 1,
	} {
		if value := latest(query, 200); value.Sequence != sequence {
			t.Fatalf("rollout %s: got sequence %d, want %d", query, value.Sequence, sequence)
		}
	}
	for _, query := range []string{"?bucket=100", "?bucket=-1", "?bucket=x"} {
		latest(query, 400)
	}
	for _, text := range []string{fmt.Sprintf(`{"sequence":3,"percent":20,"until":%d}`, until),
		fmt.Sprintf(`{"sequence":4,"percent":100,"until":%d}`, until),
		fmt.Sprintf(`{"sequence":4,"percent":20,"until":%d}`, time.Now().Add(-time.Second).Unix()),
		`{"sequence":4,"percent":20}`, "{", ""} {
		rollout(text)
		if value := latest("?bucket=80", 200); value.Sequence != newest.Sequence {
			t.Fatalf("rollout %q held back a released version: %d", text, value.Sequence)
		}
	}
	// Retaining three releases must still serve older hosts when sequence
	// numbers have gaps larger than the legacy bounded archive walk.
	far := publish(1024, "2.0.0", 8, 2)
	history, _ := json.Marshal(struct {
		Versions []ReleaseV2 `json:"versions"`
	}{[]ReleaseV2{far, forFive}})
	if err := os.WriteFile(filepath.Join(root, "history-v2.json"), history, 0600); err != nil {
		t.Fatal(err)
	}
	if value := latest("?host_api=5", 200); value.Sequence != forFive.Sequence {
		t.Fatalf("retained compatible release lost across sequence gap: %d", value.Sequence)
	}
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
	beta := valid
	beta.Channel = "beta"
	if !PackageRelease_Valid(beta, "diary") {
		t.Fatal("rejected a beta release")
	}
	beta.Channel = "nightly"
	if PackageRelease_Valid(beta, "diary") {
		t.Fatal("accepted an unknown channel")
	}
}

func TestPortableExecutablesAndLegacyBundles(t *testing.T) {
	server, database, _ := testServer(t)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x65}, ed25519.SeedSize))
	manifest := AppManifest{ManifestVersion: 1, AppID: "lists", DisplayName: "lists",
		Status: "active", Keys: []AppKey{{KeyID: "release", Algorithm: "ed25519",
			PublicKey: hex.EncodeToString(private.Public().(ed25519.PublicKey)), Status: "active"}}}
	encoded, _ := json.Marshal(manifest)
	if err := AppStore_UpsertSignedManifest(database.Database, context.Background(),
		manifest, encoded, "lists-fixture", "fixture", "fixture"); err != nil {
		t.Fatal(err)
	}
	root := server.Cfg.DBPath + ".packages/lists"
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	// ZX hosts ask with format=zx and read `.zx` releases. Hosts released
	// before the ZX format ask without it and keep reading `.zib` releases.
	publish := func(sequence int64, data []byte, suffix string) ReleaseV2 {
		t.Helper()
		hash := sha256.Sum256(data)
		value := ReleaseV2{AppID: "lists", Sequence: sequence, Version: fmt.Sprintf("1.%d.0", sequence),
			Runtime: "kryon-app-v1", HostAPI: 1, ModuleAPI: 2, KeyID: "release",
			Artifacts: []Artifact{{Variant: "module", SHA256: hex.EncodeToString(hash[:]),
				Size: int64(len(data))}}, Dependencies: []Dependency{}}
		value.Signature = hex.EncodeToString(ed25519.Sign(private,
			[]byte(PackageRelease_SigningMessage(value))))
		metadata, _ := json.Marshal(value)
		for name, content := range map[string][]byte{
			"latest-v2.json":                                        metadata,
			fmt.Sprintf("release-%d.json", sequence):                metadata,
			value.Artifacts[0].SHA256 + suffix:                      data,
			value.Artifacts[0].SHA256 + suffix + ".release-v2.json": metadata,
		} {
			if err := os.WriteFile(filepath.Join(root, name), content, 0600); err != nil {
				t.Fatal(err)
			}
		}
		return value
	}
	legacyBytes := []byte("ZIB\x00lists legacy")
	portableBytes := []byte("ZX\x00\x00lists portable")
	legacy := publish(1, legacyBytes, ".zib")
	portable := publish(2, portableBytes, ".zx")
	routes := server.Routes()
	get := func(path string, status int) *httptest.ResponseRecorder {
		t.Helper()
		response := httptest.NewRecorder()
		routes.ServeHTTP(response, httptest.NewRequest("GET", "/api/v2/packages/lists/"+path, nil))
		if response.Code != status {
			t.Fatalf("%s: got %d: %s", path, response.Code, response.Body.String())
		}
		return response
	}
	latest := func(query string) ReleaseV2 {
		t.Helper()
		var value ReleaseV2
		if err := json.Unmarshal(get("latest"+query, 200).Body.Bytes(), &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	if latest("?module_api=2&format=zx").Sequence != portable.Sequence {
		t.Fatal("a ZX host did not get the ZX release")
	}
	if latest("?module_api=2").Sequence != legacy.Sequence {
		t.Fatal("a host from before the ZX format lost its last release")
	}
	get("latest?format=zib", 400)
	get("history?format=ZX", 400)
	encodedHistory, _ := json.Marshal(map[string][]ReleaseV2{"versions": {portable, legacy}})
	if err := os.WriteFile(filepath.Join(root, "history-v2.json"), encodedHistory, 0600); err != nil {
		t.Fatal(err)
	}
	var history struct {
		Versions []ReleaseV2 `json:"versions"`
	}
	for query, sequence := range map[string]int64{"?format=zx": portable.Sequence, "": legacy.Sequence} {
		if err := json.Unmarshal(get("history"+query, 200).Body.Bytes(), &history); err != nil {
			t.Fatal(err)
		}
		if len(history.Versions) != 1 || history.Versions[0].Sequence != sequence {
			t.Fatalf("history%s offered releases in another format", query)
		}
	}
	if latest("").Sequence != legacy.Sequence {
		t.Fatal("the retained history lost the last legacy release")
	}
	if !bytes.Equal(get(portable.Artifacts[0].SHA256+".zx", 200).Body.Bytes(), portableBytes) {
		t.Fatal("incorrect portable executable")
	}
	if !bytes.Equal(get(legacy.Artifacts[0].SHA256+".zib", 200).Body.Bytes(), legacyBytes) {
		t.Fatal("incorrect legacy bundle")
	}
	get(portable.Artifacts[0].SHA256+".zib", 404)
	get(legacy.Artifacts[0].SHA256+".zx", 404)
	get(portable.Artifacts[0].SHA256+".zx.zx", 404)
	get(portable.Artifacts[0].SHA256+".ZX", 404)
	product := filepath.Join(root, portable.Artifacts[0].SHA256+".zx.product")
	if err := os.WriteFile(product, []byte("practice-pack"), 0600); err != nil {
		t.Fatal(err)
	}
	get(portable.Artifacts[0].SHA256+".zx", 403)
}
