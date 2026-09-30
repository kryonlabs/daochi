package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func sameIdentityError(got, want error) bool {
	if got == nil || want == nil {
		return got == nil && want == nil
	}
	return got.Error() == want.Error()
}

func TestZiranNodeIdentityRecordLayouts(t *testing.T) {
	for _, pair := range [][2]any{
		{NodeIdentity{}, baselineNodeIdentity{}},
		{PairingInvite{}, baselinePairingInvite{}},
		{PairingAcceptance{}, baselinePairingAcceptance{}},
		{ServiceRecord{}, baselineServiceRecord{}},
		{NameClaim{}, baselineNameClaim{}},
		{MeshTrustSpace{}, baselineMeshTrustSpace{}},
	} {
		actual, expected := reflect.TypeOf(pair[0]), reflect.TypeOf(pair[1])
		if actual.NumField() != expected.NumField() {
			t.Fatalf("%s field count changed", actual.Name())
		}
		for index := 0; index < actual.NumField(); index++ {
			got, want := actual.Field(index), expected.Field(index)
			if got.Name != want.Name || got.Type != want.Type || got.Tag != want.Tag {
				t.Fatalf("%s field %d = %#v, baseline = %#v", actual.Name(), index, got, want)
			}
		}
	}
}

func TestZiranNodeIdentityKeyDerivationAndCopies(t *testing.T) {
	for _, length := range []int{1, 31, 32, 63, 64, 65, 128} {
		key := bytes.Repeat([]byte{0x42}, length)
		got := NodeIdentity_New(key)
		want, err := baselineNewNodeIdentity(key)
		if !sameIdentityError(got.Error, err) || !reflect.DeepEqual(got.Value, want) {
			t.Fatalf("identity from %d bytes = %#v, baseline = %#v, %v", length, got, want, err)
		}
		if got.Error == nil {
			copyOfPrivate := append([]byte(nil), got.Value.PrivateKey...)
			copyOfPublic := append([]byte(nil), got.Value.PublicKey...)
			key[0] ^= 255
			key[32] ^= 255
			if !bytes.Equal(got.Value.PrivateKey, copyOfPrivate) || !bytes.Equal(got.Value.PublicKey, copyOfPublic) {
				t.Fatal("identity keys alias caller storage")
			}
			got.Value.PrivateKey[32] ^= 255
			if !bytes.Equal(got.Value.PublicKey, copyOfPublic) {
				t.Fatal("public key aliases private key storage")
			}
		}
	}
	for _, key := range []ed25519.PrivateKey{nil, {}} {
		got := NodeIdentity_New(key)
		digest := sha256.Sum256(got.Value.PublicKey)
		if got.Error != nil || len(got.Value.PrivateKey) != ed25519.PrivateKeySize ||
			len(got.Value.PublicKey) != ed25519.PublicKeySize ||
			got.Value.ID != hex.EncodeToString(digest[:]) {
			t.Fatalf("generated identity = %#v", got)
		}
		message := []byte("generated key")
		if !ed25519.Verify(got.Value.PublicKey, message, ed25519.Sign(got.Value.PrivateKey, message)) {
			t.Fatal("generated identity cannot sign")
		}
	}
}

func TestZiranNodeIdentityKeyFilesAgainstBaseline(t *testing.T) {
	for _, content := range []string{
		"", "!", "0", "00", strings.Repeat("42", 31), strings.Repeat("42", 32),
		strings.Repeat("FF", 64), strings.Repeat("42", 65), "\u2003" + strings.Repeat("42", 32) + "\t\n",
	} {
		path := filepath.Join(t.TempDir(), "node.key")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		got := NodeIdentity_LoadOrCreateKey("\u2003" + path + "\t")
		want, err := baselineLoadOrCreateNodeIdentityKey("\u2003" + path + "\t")
		if !sameIdentityError(got.Error, err) || !bytes.Equal(got.Value, want) || (got.Value == nil) != (want == nil) {
			t.Fatalf("key file %q = %#v, baseline = %x, %v", content, got, want, err)
		}
		var gotHex, wantHex hex.InvalidByteError
		if errors.As(got.Error, &gotHex) != errors.As(err, &wantHex) || gotHex != wantHex ||
			errors.Is(got.Error, hex.ErrLength) != errors.Is(err, hex.ErrLength) {
			t.Fatal("key decoding lost wrapped native error identity")
		}
		data, err := os.ReadFile(path)
		if err != nil || string(data) != content {
			t.Fatal("existing key file was modified")
		}
	}
	for _, path := range []string{"", "\u2003\t"} {
		got := NodeIdentity_LoadOrCreateKey(path)
		_, want := baselineLoadOrCreateNodeIdentityKey(path)
		if !sameIdentityError(got.Error, want) || got.Value != nil {
			t.Fatalf("empty key path = %#v, baseline = %v", got, want)
		}
	}
	root := t.TempDir()
	path := filepath.Join(root, "private", "nested", "node.key")
	got := NodeIdentity_LoadOrCreateKey(path)
	if got.Error != nil {
		t.Fatal(got.Error)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != hex.EncodeToString(got.Value)+"\n" {
		t.Fatalf("persisted key bytes = %q, %v", data, err)
	}
	for _, item := range []struct {
		path string
		mode os.FileMode
	}{
		{path, 0600},
		{filepath.Dir(path), 0700},
		{filepath.Join(root, "private"), 0700},
	} {
		info, err := os.Stat(item.path)
		if err != nil || info.Mode().Perm() != item.mode {
			t.Fatalf("permissions on %s = %v, %v", item.path, info, err)
		}
	}
	want, err := baselineLoadOrCreateNodeIdentityKey(path)
	if err != nil || !bytes.Equal(got.Value, want) {
		t.Fatal("persisted identity did not survive baseline reload")
	}
	if _, err := os.Stat(path + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary key file remains: %v", err)
	}
}

type identityEntropyReader struct {
	error  error
	before func()
}

func (reader identityEntropyReader) Read(data []byte) (int, error) {
	if reader.before != nil {
		reader.before()
	}
	if reader.error != nil {
		return 0, reader.error
	}
	for index := range data {
		data[index] = 0x42
	}
	return len(data), nil
}

func TestZiranNodeIdentityFailureCleanup(t *testing.T) {
	t.Run("entropy", func(t *testing.T) {
		sentinel := errors.New("entropy unavailable")
		original := rand.Reader
		rand.Reader = identityEntropyReader{error: sentinel}
		defer func() { rand.Reader = original }()
		if got := NodeIdentity_New(nil); got.Error != sentinel || !reflect.DeepEqual(got.Value, NodeIdentity{}) {
			t.Fatalf("identity entropy failure = %#v", got)
		}
		path := filepath.Join(t.TempDir(), "node.key")
		if got := NodeIdentity_LoadOrCreateKey(path); got.Error != sentinel || got.Value != nil {
			t.Fatalf("key-file entropy failure = %#v", got)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("entropy failure persisted an identity")
		}
	})
	t.Run("rename", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "node.key")
		original := rand.Reader
		rand.Reader = identityEntropyReader{before: func() {
			if err := os.MkdirAll(path, 0700); err != nil {
				t.Fatal(err)
			}
		}}
		defer func() { rand.Reader = original }()
		got := NodeIdentity_LoadOrCreateKey(path)
		var pathError *os.LinkError
		if !errors.As(got.Error, &pathError) || pathError.Op != "rename" || got.Value != nil {
			t.Fatalf("key-file rename failure = %#v", got)
		}
		if _, err := os.Stat(path + ".tmp"); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed rename left temporary secret: %v", err)
		}
	})
	t.Run("read directory", func(t *testing.T) {
		path := t.TempDir()
		got := NodeIdentity_LoadOrCreateKey(path)
		_, want := baselineLoadOrCreateNodeIdentityKey(path)
		if !sameIdentityError(got.Error, want) || got.Value != nil {
			t.Fatalf("directory key file = %#v, baseline = %v", got, want)
		}
	})
}

func TestZiranPairingMessagesAndSignaturesAgainstBaseline(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	node, err := baselineNewNodeIdentity(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, addresses := range [][]string{nil, {}, {"https://z.example", "http://a.example", "https://z.example"}, {"日本語", "\x00\xff"}} {
		original := append([]string(nil), addresses...)
		invite := PairingInvite{
			Version: -3, InviteID: "invite\nline", NodeID: node.ID, PublicKey: hex.EncodeToString(node.PublicKey),
			DisplayName: "日本語\x00\xff", Addresses: addresses, SpaceID: "space", ExpiresAt: -1 << 63, Nonce: "nonce",
			Policy: NodeSyncPolicy{Direction: "bidirectional", Apps: []string{"<app>", "日本語"}, Data: []string{}},
		}
		if got, want := NodeIdentity_InviteMessage(invite), baselinePairingInviteMessage(invite); !bytes.Equal(got, want) {
			t.Fatalf("invite message = %q, baseline = %q", got, want)
		}
		expectedInvite := invite
		node.baselineSignInvite(&expectedInvite)
		NodeIdentity_SignInvite(node, &invite)
		if !reflect.DeepEqual(invite, expectedInvite) || !reflect.DeepEqual(addresses, original) && len(addresses) > 0 {
			t.Fatal("invite signature or address storage changed")
		}
		acceptance := PairingAcceptance{
			Version: 2, InviteID: invite.InviteID, NodeID: node.ID, PublicKey: invite.PublicKey,
			DisplayName: invite.DisplayName, Addresses: addresses, AcceptedAt: 1<<63 - 1, Nonce: "acceptance",
		}
		if got, want := NodeIdentity_AcceptanceMessage(invite, acceptance), baselinePairingAcceptanceMessage(invite, acceptance); !bytes.Equal(got, want) {
			t.Fatalf("acceptance message = %q, baseline = %q", got, want)
		}
		expectedAcceptance := acceptance
		node.baselineSignAcceptance(invite, &expectedAcceptance)
		NodeIdentity_SignAcceptance(node, invite, &acceptance)
		if !reflect.DeepEqual(acceptance, expectedAcceptance) {
			t.Fatal("acceptance signature changed")
		}
	}
	for _, services := range [][]ServiceRecord{nil, {}, {{Service: "<service>", Endpoints: []string{"日本語", "\x00\xff"}, Capabilities: []string{"read", "write"}}}} {
		claim := NameClaim{Version: 1, SpaceID: "space", Name: "home", NodeID: node.ID, Sequence: -1 << 63, ExpiresAt: 1<<63 - 1, Services: services}
		if got, want := NodeIdentity_NameClaimMessage(claim), baselineNameClaimMessage(claim); !bytes.Equal(got, want) {
			t.Fatalf("name claim message = %q, baseline = %q", got, want)
		}
	}
}

func TestZiranPairingInviteValidationAgainstBaseline(t *testing.T) {
	now := time.Unix(1790709000, 987654321)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	node, err := baselineNewNodeIdentity(key)
	if err != nil {
		t.Fatal(err)
	}
	base := PairingInvite{Version: 1, InviteID: "invite", NodeID: node.ID, PublicKey: hex.EncodeToString(node.PublicKey),
		DisplayName: "Home", Addresses: []string{"https://home.example/a%2Fb"}, ExpiresAt: now.Unix() + 1, Nonce: "nonce"}
	for _, mutate := range []func(*PairingInvite){
		func(*PairingInvite) {},
		func(v *PairingInvite) { v.Version = 2 },
		func(v *PairingInvite) { v.InviteID = "" },
		func(v *PairingInvite) { v.Nonce = "" },
		func(v *PairingInvite) { v.NodeID = strings.ToUpper(v.NodeID) },
		func(v *PairingInvite) { v.ExpiresAt = now.Unix() },
		func(v *PairingInvite) { v.ExpiresAt = now.Unix() + 86400 },
		func(v *PairingInvite) { v.ExpiresAt = now.Unix() + 86401 },
		func(v *PairingInvite) { v.PublicKey = "!" },
		func(v *PairingInvite) { v.PublicKey = "00" },
		func(v *PairingInvite) { v.PublicKey = strings.Repeat("42", 32) },
		func(v *PairingInvite) { v.Addresses = nil },
		func(v *PairingInvite) { v.Addresses = []string{"ftp://home.example"} },
		func(v *PairingInvite) { v.Addresses = []string{"https://%"} },
	} {
		invite := base
		mutate(&invite)
		node.baselineSignInvite(&invite)
		for _, signature := range []string{invite.Signature, "\r\n" + invite.Signature + "\n", "!", invite.Signature + "==", "AQ"} {
			invite.Signature = signature
			got := NodeIdentity_ValidateInvite(invite, now)
			want, err := baselineValidatePairingInvite(invite, now)
			if !sameIdentityError(got.Error, err) || !bytes.Equal(got.Value, want) || (got.Value == nil) != (want == nil) {
				t.Fatalf("invite validation = %#v, baseline = %x, %v", got, want, err)
			}
		}
	}
}

func TestZiranPairingAcceptanceValidationAgainstBaseline(t *testing.T) {
	now := time.Unix(1790709000, 987654321)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	node, err := baselineNewNodeIdentity(key)
	if err != nil {
		t.Fatal(err)
	}
	invite := PairingInvite{InviteID: "invite", Signature: "signed invite\x00"}
	base := PairingAcceptance{Version: 1, InviteID: "invite", NodeID: node.ID, PublicKey: hex.EncodeToString(node.PublicKey),
		Addresses: []string{"https://home.example"}, AcceptedAt: now.Unix(), Nonce: "nonce"}
	for _, mutate := range []func(*PairingAcceptance){
		func(*PairingAcceptance) {},
		func(v *PairingAcceptance) { v.Version = 2 },
		func(v *PairingAcceptance) { v.InviteID = "other" },
		func(v *PairingAcceptance) { v.Nonce = "" },
		func(v *PairingAcceptance) { v.NodeID = "" },
		func(v *PairingAcceptance) { v.AcceptedAt = now.Unix() - 300 },
		func(v *PairingAcceptance) { v.AcceptedAt = now.Unix() - 301 },
		func(v *PairingAcceptance) { v.AcceptedAt = now.Unix() + 300 },
		func(v *PairingAcceptance) { v.AcceptedAt = now.Unix() + 301 },
		func(v *PairingAcceptance) { v.Addresses = nil },
		func(v *PairingAcceptance) { v.PublicKey = "!" },
		func(v *PairingAcceptance) { v.PublicKey = "00" },
		func(v *PairingAcceptance) { v.PublicKey = strings.Repeat("42", 32) },
	} {
		acceptance := base
		mutate(&acceptance)
		node.baselineSignAcceptance(invite, &acceptance)
		for _, signature := range []string{acceptance.Signature, "\r\n" + acceptance.Signature + "\n", "!", "AQ"} {
			acceptance.Signature = signature
			got := NodeIdentity_ValidateAcceptance(invite, acceptance, now)
			want, err := baselineValidatePairingAcceptance(invite, acceptance, now)
			if !sameIdentityError(got.Error, err) || !bytes.Equal(got.Value, want) || (got.Value == nil) != (want == nil) {
				t.Fatalf("acceptance validation = %#v, baseline = %x, %v", got, want, err)
			}
		}
	}
}

func TestZiranNodeNamesAndAddressesAgainstBaseline(t *testing.T) {
	for _, name := range []string{"", "a", "0", "-a", "a-", "a-b", "A", "é", "\xff", "a\n", strings.Repeat("a", 63), strings.Repeat("a", 64), "\u2003HOME\t"} {
		if got, want := NodeIdentity_ValidName(name), baselineNamePattern.MatchString(name); got != want {
			t.Fatalf("valid name %q = %v, baseline = %v", name, got, want)
		}
		if got, want := NodeIdentity_NormalizeName(name), baselineNormalizeName(name); got != want {
			t.Fatalf("normalize name %q = %q, baseline = %q", name, got, want)
		}
	}
	for _, addresses := range [][]string{nil, {}, {""}, {"https://home.example"}, {"HTTP://HOME"}, {"http://[::1]:80/a%2Fb"},
		{"ftp://home.example"}, {"https://"}, {"https://%"}, {"https://home.example", "bad"}, {"http://user:password@home.example/a"}} {
		if got, want := NodeIdentity_ValidateAddresses(addresses), baselineValidateHTTPAddresses(addresses); !sameIdentityError(got, want) {
			t.Fatalf("validate addresses %q = %v, baseline = %v", addresses, got, want)
		}
	}
}
