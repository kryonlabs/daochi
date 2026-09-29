package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestZiranManifestDatesMatchGoLayout(t *testing.T) {
	check := func(value string) {
		t.Helper()
		_, err := time.Parse("2006-01-02", value)
		if got := Manifest_ValidDate(value); got != (err == nil) {
			t.Fatalf("date %q: got %v, parse error %v", value, got, err)
		}
	}
	for _, year := range []int{0, 1, 4, 99, 100, 400, 1900, 2000, 2024, 9999} {
		for month := 0; month <= 13; month++ {
			for day := 0; day <= 32; day++ {
				check(fmt.Sprintf("%04d-%02d-%02d", year, month, day))
			}
		}
	}
	for _, value := range []string{
		"", "2024-2-01", "2024-02-1", "2024-02- 1", "2024-02-+1",
		" 2024-02-01", "2024-02-01\n", "2024-02-01T00:00:00Z",
		"-001-01-01", "10000-01-01", "２０２４-02-01", "2024/02/01",
		"2024-02-0\x00", "2024-02-０1", "2024-02-01\u2003",
	} {
		check(value)
	}
}

func TestZiranManifestNormalizationPreservesPayloads(t *testing.T) {
	input := AppManifest{
		ManifestVersion: 1,
		AppID:           "\u2003ukuvota\t",
		DisplayName:     " Ukuvota ",
		Description:     " description ",
		HomepageURL:     " https://example.org ",
		SourceURL:       " https://example.org/source ",
		Status:          "\u2003",
		Keys: []AppKey{{
			KeyID: " main-key ", Algorithm: " Ed25519 ", PublicKey: " " + strings.Repeat("00", 32) + " ",
			Purpose: " signing ", Status: " active ", CreatedAt: " untouched ",
		}},
		Collections: []AppCollection{{
			AppID: "foreign", CollectionPrefix: " private.ukuvota.v1.records.* ",
			Visibility: " private ", Description: " Records ",
		}},
		Capabilities: []string{" records.sync "},
		Features: []AppFeature{{
			ID: " archive.sync ", Description: " Sync ", Collections: []string{" private.ukuvota.v1.records.* "},
		}},
		LegacyProtocols:  []LegacyProtocol{{Name: " legacy.sync ", Status: " active ", ValidUntil: " 2024-02-29 "}},
		MinClientVersion: " 1 ", CurrentVersion: " 2 ", CompatibilityUntil: " 2024-02-29 ",
		TokenPolicies: []TokenPolicy{{AssetID: " waozi:token ", Permission: " spend ", Status: "\t"}},
	}
	want := AppManifest{
		ManifestVersion: 1, AppID: "ukuvota", DisplayName: "Ukuvota", Description: "description",
		HomepageURL: "https://example.org", SourceURL: "https://example.org/source", Status: "active",
		Keys: []AppKey{{KeyID: "main-key", Algorithm: "Ed25519", PublicKey: strings.Repeat("00", 32),
			Purpose: "signing", Status: "active", CreatedAt: " untouched "}},
		Collections: []AppCollection{{AppID: "ukuvota", CollectionPrefix: "private.ukuvota.v1.records.*",
			Visibility: "private", Description: "Records"}},
		Capabilities:     []string{"records.sync"},
		Features:         []AppFeature{{ID: "archive.sync", Description: "Sync", Collections: []string{"private.ukuvota.v1.records.*"}}},
		LegacyProtocols:  []LegacyProtocol{{Name: "legacy.sync", Status: "active", ValidUntil: "2024-02-29"}},
		MinClientVersion: "1", CurrentVersion: "2", CompatibilityUntil: "2024-02-29",
		TokenPolicies: []TokenPolicy{{AssetID: "waozi:token", Permission: "spend", Status: "active"}},
	}
	Manifest_Normalize(&input)
	if !reflect.DeepEqual(input, want) {
		t.Fatalf("normalized manifest = %#v; want %#v", input, want)
	}
	if problem := Manifest_Validate(input, 100); problem != "" {
		t.Fatal(problem)
	}
	Manifest_Normalize(&input)
	if !reflect.DeepEqual(input, want) {
		t.Fatal("normalization is not idempotent")
	}
	if Manifest_DefaultString(" \u2003\t", "fallback") != "fallback" ||
		Manifest_DefaultString(" value ", "fallback") != " value " {
		t.Fatal("default string changed nonblank content")
	}
}

func TestZiranManifestValidationBoundaries(t *testing.T) {
	const now = int64(1700000000)
	base := func() AppManifest {
		return AppManifest{
			ManifestVersion: 1, AppID: "ukuvota", DisplayName: "Ukuvota", Status: "active",
			Keys:          []AppKey{{KeyID: "main-key", Algorithm: "eD25519", PublicKey: strings.Repeat("00", 32)}},
			Collections:   []AppCollection{{CollectionPrefix: "private.ukuvota.v1.records.*", Visibility: "private"}},
			TokenPolicies: []TokenPolicy{{AssetID: "waozi:token", Permission: "spend"}},
		}
	}
	cases := []struct {
		name string
		edit func(*AppManifest)
		want string
	}{
		{"valid", func(*AppManifest) {}, ""},
		{"expiry equals now", func(m *AppManifest) { m.ExpiresAt = now }, ""},
		{"expired", func(m *AppManifest) { m.ExpiresAt = now - 1 }, "manifest expired"},
		{"negative expiry", func(m *AppManifest) { m.ExpiresAt = -1 }, ""},
		{"unsigned year boundary", func(m *AppManifest) { m.TokenPolicies[0].LegacyUnsignedUntil = now + 365*24*3600 }, ""},
		{"unsigned beyond year", func(m *AppManifest) { m.TokenPolicies[0].LegacyUnsignedUntil = now + 365*24*3600 + 1 }, "invalid legacy_unsigned_until"},
		{"unsigned negative", func(m *AppManifest) { m.TokenPolicies[0].LegacyUnsignedUntil = -1 }, "invalid legacy_unsigned_until"},
		{"version", func(m *AppManifest) { m.ManifestVersion = 2 }, "unsupported manifest_version"},
		{"namespace", func(m *AppManifest) { m.AppID = "bad/app" }, "invalid app_id"},
		{"name bytes", func(m *AppManifest) { m.DisplayName = strings.Repeat("雪", 27) }, "invalid display_name"},
		{"max name bytes", func(m *AppManifest) { m.DisplayName = strings.Repeat("a", 80) }, ""},
		{"missing keys", func(m *AppManifest) { m.Keys = nil }, "invalid app keys"},
		{"schema boundary", func(m *AppManifest) { m.AppSchemaVersion = 65535 }, ""},
		{"schema too large", func(m *AppManifest) { m.AppSchemaVersion = 65536 }, "invalid app_schema_version"},
		{"schema negative", func(m *AppManifest) { m.AppSchemaVersion = -1 }, "invalid app_schema_version"},
		{"bad date", func(m *AppManifest) { m.CompatibilityUntil = "1900-02-29" }, "invalid compatibility_until"},
		{"public key length", func(m *AppManifest) { m.Keys[0].PublicKey = "00" }, "invalid app public key"},
		{"public key encoding", func(m *AppManifest) { m.Keys[0].PublicKey = "!!" }, "invalid app public key"},
		{"key status", func(m *AppManifest) { m.Keys[0].Status = "revoked" }, "invalid app key status"},
		{"foreign scope", func(m *AppManifest) { m.Collections[0].CollectionPrefix = "private.other.v1.records.*" }, "invalid app collection"},
		{"undeclared feature", func(m *AppManifest) {
			m.Features = []AppFeature{{ID: "archive.sync", Collections: []string{"private.ukuvota.v1.other.*"}}}
		}, "invalid app feature collection"},
		{"legacy date", func(m *AppManifest) {
			m.LegacyProtocols = []LegacyProtocol{{Name: "legacy.sync", Status: "active", ValidUntil: ""}}
		}, "invalid legacy protocol"},
		{"policy permission", func(m *AppManifest) { m.TokenPolicies[0].Permission = "admin" }, "invalid token policy"},
		{"policy status", func(m *AppManifest) { m.TokenPolicies[0].Status = "disabled" }, "invalid token policy status"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			manifest := base()
			test.edit(&manifest)
			if got := Manifest_Validate(manifest, now); got != test.want {
				t.Fatalf("validation = %q; want %q", got, test.want)
			}
		})
	}
}

func TestZiranManifestSignaturesRequireEligibleKeys(t *testing.T) {
	const now = int64(1700000000)
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	key := AppKey{KeyID: "main-key", Algorithm: "Ed25519", PublicKey: hex.EncodeToString(publicKey)}
	message := []byte("daochi-app-manifest-v1\n{\"app_id\":\"ukuvota\"}")
	signature := ed25519.Sign(privateKey, message)
	cases := []struct {
		name      string
		keys      []AppKey
		message   []byte
		signature []byte
		want      bool
	}{
		{"valid", []AppKey{key}, message, signature, true},
		{"empty message", []AppKey{key}, nil, ed25519.Sign(privateKey, nil), true},
		{"no keys", nil, message, signature, false},
		{"tampered message", []AppKey{key}, []byte("tampered"), signature, false},
		{"short signature", []AppKey{key}, message, signature[:63], false},
		{"missing signature", []AppKey{key}, message, nil, false},
		{"suspended", []AppKey{{Algorithm: key.Algorithm, PublicKey: key.PublicKey, Status: "suspended"}}, message, signature, false},
		{"expired", []AppKey{{Algorithm: key.Algorithm, PublicKey: key.PublicKey, ExpiresAt: now - 1}}, message, signature, false},
		{"expiry boundary", []AppKey{{Algorithm: key.Algorithm, PublicKey: key.PublicKey, ExpiresAt: now}}, message, signature, true},
		{"wrong algorithm", []AppKey{{Algorithm: "RSA", PublicKey: key.PublicKey}}, message, signature, false},
		{"invalid key then valid", []AppKey{{Algorithm: key.Algorithm, PublicKey: "!!"}, key}, message, signature, true},
		{"all invalid keys", []AppKey{{Algorithm: key.Algorithm, PublicKey: "00"}}, message, signature, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			manifest := AppManifest{Keys: test.keys}
			if got := Manifest_SignedByActiveKey(manifest, test.message, test.signature, now); got != test.want {
				t.Fatalf("signature eligibility = %v; want %v", got, test.want)
			}
		})
	}
}
