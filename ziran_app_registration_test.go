package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"
)

func signedRegistrationFixture(t *testing.T) (SignedAppRegistrationRequest, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	appKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	nodeKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x43}, ed25519.SeedSize))
	request := SignedAppRegistrationRequest{Manifest: AppManifest{
		ManifestVersion: 1, AppID: "demo", DisplayName: "Demo <&> 日本語", Status: "active",
		Keys: []AppKey{{KeyID: "key-main1", Algorithm: "Ed25519", PublicKey: hex.EncodeToString(appKey.Public().(ed25519.PublicKey))}},
	}}
	signRegistrationFixture(t, &request, appKey, nodeKey)
	return request, nodeKey.Public().(ed25519.PublicKey), nodeKey
}

func signRegistrationFixture(t *testing.T, request *SignedAppRegistrationRequest, appKey, nodeKey ed25519.PrivateKey) {
	t.Helper()
	data, err := json.Marshal(request.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(data)
	request.ManifestSignature = hex.EncodeToString(ed25519.Sign(appKey, append([]byte(AppManifestContext+"\n"), data...)))
	request.ApprovalSignature = hex.EncodeToString(ed25519.Sign(nodeKey, []byte(Signing_AppApprovalMessage(AppApprovalContext, request.Manifest.AppID, hex.EncodeToString(hash[:])))))
}

func compareRegistrationVerification(t *testing.T, request SignedAppRegistrationRequest, nodeKey ed25519.PublicKey) {
	t.Helper()
	got := AppRegistration_Verify(request, nodeKey)
	data, hash, err := baselineValidateSignedAppRegistration(request, nodeKey)
	if !equalAuthenticationError(authenticationError(got.Authentication), err) ||
		!bytes.Equal(got.Value, data) || (got.Value == nil) != (data == nil) || got.Hash != hash {
		t.Fatalf("manifest verification = %#v, baseline = %q, %q, %v", got, data, hash, err)
	}
}

func TestZiranAppApprovalVerificationAgainstBaseline(t *testing.T) {
	for _, mode := range []string{
		"valid", "missing node key", "short node key", "long node key", "wrong node key",
		"missing manifest signature", "short manifest signature", "invalid manifest signature", "rejected manifest signature",
		"missing approval signature", "short approval signature", "invalid approval signature", "rejected approval signature",
		"expired key", "suspended key", "wrong algorithm", "malformed app key", "multiple keys", "binary metadata",
	} {
		t.Run(mode, func(t *testing.T) {
			request, nodeKey, nodePrivate := signedRegistrationFixture(t)
			appKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
			switch mode {
			case "missing node key":
				nodeKey = nil
			case "short node key":
				nodeKey = nodeKey[:31]
			case "long node key":
				nodeKey = append(nodeKey, 0)
			case "wrong node key":
				nodeKey[0] ^= 1
			case "missing manifest signature":
				request.ManifestSignature = ""
			case "short manifest signature":
				request.ManifestSignature = "00"
			case "invalid manifest signature":
				request.ManifestSignature = "!"
			case "rejected manifest signature":
				request.ManifestSignature = strings.Repeat("00", ed25519.SignatureSize)
			case "missing approval signature":
				request.ApprovalSignature = ""
			case "short approval signature":
				request.ApprovalSignature = "00"
			case "invalid approval signature":
				request.ApprovalSignature = "!"
			case "rejected approval signature":
				request.ApprovalSignature = strings.Repeat("00", ed25519.SignatureSize)
			case "expired key":
				request.Manifest.Keys[0].ExpiresAt = 1
				signRegistrationFixture(t, &request, appKey, nodePrivate)
			case "suspended key":
				request.Manifest.Keys[0].Status = "suspended"
				signRegistrationFixture(t, &request, appKey, nodePrivate)
			case "wrong algorithm":
				request.Manifest.Keys[0].Algorithm = "unknown"
				signRegistrationFixture(t, &request, appKey, nodePrivate)
			case "malformed app key":
				request.Manifest.Keys[0].PublicKey = "!"
				signRegistrationFixture(t, &request, appKey, nodePrivate)
			case "multiple keys":
				request.Manifest.Keys = append([]AppKey{{KeyID: "wrong", PublicKey: "!"}}, request.Manifest.Keys...)
				signRegistrationFixture(t, &request, appKey, nodePrivate)
			case "binary metadata":
				request.Manifest.Description = "\x00\xff\r\n\u2028<>&"
				signRegistrationFixture(t, &request, appKey, nodePrivate)
			}
			compareRegistrationVerification(t, request, nodeKey)
		})
	}
	request, nodeKey, _ := signedRegistrationFixture(t)
	if got := AppRegistration_Verify(request, nodeKey); got.Authentication.Status != 0 || got.Authentication.Error != nil || got.Value == nil || got.Hash == "" {
		t.Fatal("valid registration was rejected", got)
	}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		encoded := request
		manifest, err := hex.DecodeString(request.ManifestSignature)
		if err != nil {
			t.Fatal(err)
		}
		approval, err := hex.DecodeString(request.ApprovalSignature)
		if err != nil {
			t.Fatal(err)
		}
		encoded.ManifestSignature = encoding.EncodeToString(manifest)
		encoded.ApprovalSignature = encoding.EncodeToString(approval)
		compareRegistrationVerification(t, encoded, nodeKey)
	}
}

func TestZiranSignedRegistrationDecodeAgainstBaseline(t *testing.T) {
	request, _, _ := signedRegistrationFixture(t)
	request.Manifest.AppID = "\u2003demo\t"
	request.Manifest.DisplayName = "  Demo  "
	request.ManifestSignature = "\t signature\u2003"
	request.ApprovalSignature = "\u2003approval \t"
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	inputs := [][]byte{data, nil, []byte("null"), []byte("{}"), []byte("[]"), []byte("{"),
		[]byte(`{"manifest_signature":" partial ","manifest":{"manifest_version":"bad"}}`),
		[]byte(`{"manifest":{"manifest_version":1,"app_id":"first","app_id":"second"}}`),
		[]byte(`{"manifest":{"expires_at":9223372036854775808}}`), []byte("{} true"),
		[]byte("{\"manifest_signature\":\"\xff\"}")}
	random := rand.New(rand.NewSource(42))
	for index := 0; index < 300; index++ {
		data := make([]byte, random.Intn(128))
		_, _ = random.Read(data)
		inputs = append(inputs, data)
	}
	for _, body := range inputs {
		got := AppRegistration_DecodeSigned(body)
		want, err := baselineDecodeSignedRegistration(body)
		if !sameIdentityError(got.Error, err) || !reflect.DeepEqual(got.Value, want) {
			t.Fatalf("decode %q = %#v, baseline = %#v, %v", body, got, want, err)
		}
	}
}

func TestZiranManifestJSONAndPolicyBytes(t *testing.T) {
	request, _, _ := signedRegistrationFixture(t)
	for _, value := range []string{"", "Japanese 日本語", "\x00\xff\r\n\u2028<>&"} {
		manifest := request.Manifest
		manifest.Description = value
		got := AppRegistration_Encode(manifest)
		data, err := json.Marshal(manifest)
		hash := sha256.Sum256(data)
		if !sameIdentityError(got.Error, err) || !bytes.Equal(got.Value, data) || got.Hash != hex.EncodeToString(hash[:]) {
			t.Fatalf("manifest encoding = %#v, native = %q, %v", got, data, err)
		}
		policy := TokenPolicy{AssetID: value, Permission: value}
		if got := AppRegistration_PolicyString(policy); got != value+":"+value {
			t.Fatal("policy bytes changed", got)
		}
	}
	for _, display := range []string{"", "  Demo  ", strings.Repeat("x", 81)} {
		manifest := request.Manifest
		manifest.DisplayName = display
		got := AppRegistration_Prepare(manifest)
		Manifest_Normalize(&manifest)
		problem := Manifest_Validate(manifest, time.Now().Unix())
		if problem != "" {
			if got.Error == nil || got.Error.Error() != problem || got.Value != nil || got.Hash != "" {
				t.Fatal("prepare validation changed", got, problem)
			}
			continue
		}
		data, err := json.Marshal(manifest)
		hash := sha256.Sum256(data)
		if !sameIdentityError(got.Error, err) || !bytes.Equal(got.Value, data) || got.Hash != hex.EncodeToString(hash[:]) {
			t.Fatal("prepared manifest bytes changed", got, string(data), err)
		}
	}
}

func TestZiranAppAndGrantDecodingAgainstBaseline(t *testing.T) {
	inputs := [][]byte{nil, []byte("null"), []byte("{}"), []byte("[]"), []byte("{"), []byte("{} true"),
		[]byte(`{"app_id":" first ","app_id":" second ","display_name":" Demo "}`),
		[]byte(`{"display_name":"partial","app_schema_version":"bad"}`),
		[]byte(`{"source_app_id":"\u2003demo\t","target_app_id":"target","collection_prefix":"shared.demo.v1.*"}`),
		[]byte(`{"grant":{"source_app_id":"demo","target_app_id":"target","collection_prefix":"shared.demo.v1.*"},"tx":{"account_id":" AB ","method":" post ","nonce":" nonce "}}`),
		[]byte(`{"grant":{"source_app_id":"partial"},"tx":{"expires_at":9223372036854775808}}`)}
	for _, mode := range []string{"valid", "namespace", "display", "status", "schema", "date", "too many collections", "too many features", "collection schema", "collection ownership", "capability", "feature", "feature collection", "feature collection count", "legacy name", "legacy version", "legacy status", "legacy date", "policy asset", "policy permission", "policy status", "policy negative", "policy future"} {
		app := AppRegistration{AppID: "\u2003demo\t", DisplayName: " Demo ", Status: " ",
			Description: " Description ", PublicKey: " key ", CurrentVersion: " 1.0 ",
			Collections:     []AppCollection{{CollectionPrefix: " shared.demo.v1.* ", Visibility: " shared ", Description: " Records "}},
			Capabilities:    []string{" sync ", " export "},
			Features:        []AppFeature{{ID: " feature ", Description: " Description ", Collections: []string{" shared.demo.v1.item "}}},
			LegacyProtocols: []LegacyProtocol{{Name: " old ", Version: 5, Status: " compatibility ", ValidUntil: " 2027-09-01 "}},
			TokenPolicies:   []TokenPolicy{{AssetID: " waozi:token ", Permission: " spend ", Status: " "}},
		}
		switch mode {
		case "namespace":
			app.AppID = "!"
		case "display":
			app.DisplayName = " "
		case "status":
			app.Status = "other"
		case "schema":
			app.AppSchemaVersion = 65536
		case "date":
			app.CompatibilityUntil = "2027-02-29"
		case "too many collections":
			app.Collections = make([]AppCollection, 65)
		case "too many features":
			app.Features = make([]AppFeature, 129)
		case "collection schema":
			app.Collections[0].SchemaVersion = -1
		case "collection ownership":
			app.Collections[0].CollectionPrefix = "shared.other.v1.*"
		case "capability":
			app.Capabilities[0] = "!"
		case "feature":
			app.Features[0].ID = "!"
		case "feature collection":
			app.Features[0].Collections[0] = "private.other.v1.item"
		case "feature collection count":
			app.Features[0].Collections = make([]string, 17)
		case "legacy name":
			app.LegacyProtocols[0].Name = "!"
		case "legacy version":
			app.LegacyProtocols[0].Version = -1
		case "legacy status":
			app.LegacyProtocols[0].Status = "other"
		case "legacy date":
			app.LegacyProtocols[0].ValidUntil = ""
		case "policy asset":
			app.TokenPolicies[0].AssetID = " "
		case "policy permission":
			app.TokenPolicies[0].Permission = "other"
		case "policy status":
			app.TokenPolicies[0].Status = "other"
		case "policy negative":
			app.TokenPolicies[0].LegacyUnsignedUntil = -1
		case "policy future":
			app.TokenPolicies[0].LegacyUnsignedUntil = 9223372036854775807
		}
		body, err := json.Marshal(app)
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, body)
	}
	random := rand.New(rand.NewSource(42))
	for index := 0; index < 300; index++ {
		body := make([]byte, random.Intn(128))
		_, _ = random.Read(body)
		inputs = append(inputs, body)
	}
	for _, body := range inputs {
		app := AppRegistration_Decode(body)
		wantApp, err := baselineDecodeAppRegistration(body)
		if !sameIdentityError(app.Error, err) || !reflect.DeepEqual(app.Value, wantApp) {
			t.Fatalf("app decode %q = %#v, baseline = %#v, %v", body, app, wantApp, err)
		}
		grant := AppRegistration_DecodeGrant(body)
		wantGrant, err := baselineDecodeAppGrant(body)
		if !sameIdentityError(grant.Error, err) || !reflect.DeepEqual(grant.Value, wantGrant) {
			t.Fatalf("grant decode %q = %#v, baseline = %#v, %v", body, grant, wantGrant, err)
		}
		signed := AppRegistration_DecodeSignedGrant(body)
		wantSigned, wantBody, err := baselineDecodeSignedAppGrant(body)
		if !sameIdentityError(signed.Error, err) || !reflect.DeepEqual(signed.Value, wantSigned) ||
			!bytes.Equal(signed.Body, wantBody) || (signed.Body == nil) != (wantBody == nil) {
			t.Fatalf("signed grant decode %q = %#v, baseline = %#v, %q, %v", body, signed, wantSigned, wantBody, err)
		}
		if signed.Error == nil && len(signed.Body) > 0 && &signed.Body[0] != &body[0] {
			t.Fatal("signed grant decoder changed raw body ownership")
		}
	}
}
