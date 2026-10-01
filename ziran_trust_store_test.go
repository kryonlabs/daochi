package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func trustStoreFixture(t *testing.T) *Store {
	t.Helper()
	database, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = database.Close() })
	store := &Store{Database: database}
	if err := store.baselineEnsureMeshTrustSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	return store
}

func trustKeyFixture() (ed25519.PrivateKey, ed25519.PublicKey, string) {
	key := ed25519.NewKeyFromSeed(bytesOf(0x42, ed25519.SeedSize))
	publicKey := key.Public().(ed25519.PublicKey)
	digest := sha256.Sum256(publicKey)
	return key, publicKey, hex.EncodeToString(digest[:])
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}

func trustSnapshot(t *testing.T, store *Store) map[string][][]any {
	t.Helper()
	queries := map[string]string{
		"peers":    "SELECT node_id,hex(public_key),display_name,addresses_json,space_id,policy_json,revoked_at FROM trusted_node_peers ORDER BY node_id",
		"consumed": "SELECT invite_id FROM consumed_pairing_invites ORDER BY invite_id",
		"issued":   "SELECT invite_id,signature,expires_at,completed_node_id FROM issued_pairing_invites ORDER BY invite_id",
		"spaces":   "SELECT space_id,display_name,hex(authority_public_key),hex(authority_private_key) FROM trust_spaces ORDER BY space_id",
		"claims":   "SELECT space_id,name,node_id,sequence,expires_at,services_json,signature FROM name_claims ORDER BY space_id,name",
	}
	result := make(map[string][][]any)
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
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for index := range pointers {
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

func compareTrustState(t *testing.T, actual, expected *Store) {
	t.Helper()
	if got, want := trustSnapshot(t, actual), trustSnapshot(t, expected); !reflect.DeepEqual(got, want) {
		t.Fatalf("trust state = %#v, baseline = %#v", got, want)
	}
	// Non-deterministic clock values must still use the released canonical form.
	for _, tableColumn := range [][2]string{
		{"trusted_node_peers", "trusted_at"}, {"consumed_pairing_invites", "consumed_at"},
		{"issued_pairing_invites", "created_at"}, {"trust_spaces", "created_at"}, {"name_claims", "updated_at"},
	} {
		rows, err := actual.Database.Query("SELECT " + tableColumn[1] + " FROM " + tableColumn[0])
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var value string
			if err := rows.Scan(&value); err != nil {
				t.Fatal(err)
			}
			instant, err := time.Parse(time.RFC3339Nano, value)
			if err != nil || value != instant.UTC().Format("2006-01-02T15:04:05.000000000Z07:00") {
				t.Fatalf("noncanonical trust timestamp %q", value)
			}
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
	}
}

func TestZiranTrustPeerTransactionsAndPoliciesAgainstBaseline(t *testing.T) {
	actual, expected := trustStoreFixture(t), trustStoreFixture(t)
	_, key, nodeID := trustKeyFixture()
	invite := PairingInvite{InviteID: "first", NodeID: nodeID, DisplayName: "日本語", SpaceID: "space",
		Policy: NodeSyncPolicy{Direction: "receive", Apps: []string{"inbe"}, Data: []string{"names"}}}
	for _, id := range []string{"first", "first", "replacement"} {
		invite.InviteID = id
		got := TrustStore_TrustPeer(actual.Database, t.Context(), invite, key)
		want := expected.baselineTrustPeer(t.Context(), invite, key)
		if !sameIdentityError(got, want) {
			t.Fatalf("trust peer = %v, baseline = %v", got, want)
		}
		compareTrustState(t, actual, expected)
		gotPolicy := TrustStore_TrustedPeerPolicy(actual.Database, t.Context(), nodeID)
		wantPolicy, found, err := expected.baselineTrustedPeerPolicy(t.Context(), nodeID)
		if !sameIdentityError(gotPolicy.Error, err) || gotPolicy.Found != found || !reflect.DeepEqual(gotPolicy.Value, wantPolicy) {
			t.Fatalf("peer policy = %#v, baseline = %#v, %v", gotPolicy, wantPolicy, err)
		}
	}
	for _, policyJSON := range []string{"null", "{}", "{", `{"direction":"pull","apps":[1]}`} {
		for _, store := range []*Store{actual, expected} {
			if _, err := store.Database.Exec("UPDATE trusted_node_peers SET policy_json=?1", policyJSON); err != nil {
				t.Fatal(err)
			}
		}
		got := TrustStore_TrustedPeerPolicy(actual.Database, t.Context(), nodeID)
		want, found, err := expected.baselineTrustedPeerPolicy(t.Context(), nodeID)
		if !sameIdentityError(got.Error, err) || got.Found != found || !reflect.DeepEqual(got.Value, want) {
			t.Fatalf("policy JSON %q = %#v, baseline = %#v, %v", policyJSON, got, want, err)
		}
	}
	for _, query := range []string{"UPDATE trusted_node_peers SET revoked_at='revoked'", "DELETE FROM trusted_node_peers"} {
		for _, store := range []*Store{actual, expected} {
			if _, err := store.Database.Exec(query); err != nil {
				t.Fatal(err)
			}
		}
		got := TrustStore_TrustedPeerPolicy(actual.Database, t.Context(), nodeID)
		want, found, err := expected.baselineTrustedPeerPolicy(t.Context(), nodeID)
		if !sameIdentityError(got.Error, err) || got.Found != found || !reflect.DeepEqual(got.Value, want) {
			t.Fatalf("absent peer policy = %#v, baseline = %#v, %v", got, want, err)
		}
	}
}

func TestZiranTrustPeersPreserveJSONAndEmptyLists(t *testing.T) {
	actual, expected := trustStoreFixture(t), trustStoreFixture(t)
	_, key, nodeID := trustKeyFixture()
	for index, addresses := range [][]string{nil, {}, {"http://home.example", "日本語\x00\xff"}} {
		invite := PairingInvite{InviteID: "invite" + strings.Repeat("x", index), NodeID: nodeID,
			DisplayName: "Home", Addresses: addresses, Policy: NodeSyncPolicy{Apps: []string{}}}
		if err := TrustStore_TrustPeer(actual.Database, t.Context(), invite, key); err != nil {
			t.Fatal(err)
		}
		if err := expected.baselineTrustPeer(t.Context(), invite, key); err != nil {
			t.Fatal(err)
		}
		got := TrustStore_ListTrustedPeers(actual.Database, t.Context())
		want, err := expected.baselineListTrustedPeers(t.Context())
		for item := range got.Value {
			got.Value[item].TrustedAt = ""
			want[item].TrustedAt = ""
		}
		if !sameIdentityError(got.Error, err) || !reflect.DeepEqual(got.Value, want) {
			t.Fatalf("peer list = %#v, baseline = %#v, %v", got, want, err)
		}
		compareTrustState(t, actual, expected)
	}
	for _, statement := range []string{
		"UPDATE trusted_node_peers SET addresses_json='{'",
		"DELETE FROM trusted_node_peers",
	} {
		for _, store := range []*Store{actual, expected} {
			if _, err := store.Database.Exec(statement); err != nil {
				t.Fatal(err)
			}
		}
		got := TrustStore_ListTrustedPeers(actual.Database, t.Context())
		want, err := expected.baselineListTrustedPeers(t.Context())
		if !sameIdentityError(got.Error, err) || !reflect.DeepEqual(got.Value, want) {
			t.Fatalf("peer list after %q = %#v, baseline = %#v, %v", statement, got, want, err)
		}
	}
}

func TestZiranPairingCompletionCasesAgainstBaseline(t *testing.T) {
	_, key, nodeID := trustKeyFixture()
	for _, mode := range []string{"valid", "missing", "signature", "expiry mismatch", "expired", "same node", "other node", "ignored update", "failed upsert"} {
		t.Run(mode, func(t *testing.T) {
			actual, expected := trustStoreFixture(t), trustStoreFixture(t)
			invite := PairingInvite{InviteID: "invite", Signature: "signed", ExpiresAt: time.Now().Add(time.Hour).Unix(),
				Policy: NodeSyncPolicy{Direction: "pull", Spaces: []string{"space"}}}
			acceptance := PairingAcceptance{NodeID: nodeID, DisplayName: "Neighbor", Addresses: []string{"http://neighbor.example"}}
			for _, store := range []*Store{actual, expected} {
				if mode != "missing" {
					if err := store.baselineRecordIssuedPairingInvite(t.Context(), invite); err != nil {
						t.Fatal(err)
					}
				}
				var query string
				switch mode {
				case "signature":
					query = "UPDATE issued_pairing_invites SET signature='different'"
				case "expiry mismatch":
					query = "UPDATE issued_pairing_invites SET expires_at=0"
				case "same node":
					query = "UPDATE issued_pairing_invites SET completed_node_id='" + nodeID + "'"
				case "other node":
					query = "UPDATE issued_pairing_invites SET completed_node_id='other'"
				case "ignored update":
					query = "CREATE TRIGGER ignore_completion BEFORE UPDATE ON issued_pairing_invites BEGIN SELECT RAISE(IGNORE); END"
				case "failed upsert":
					query = "CREATE TRIGGER reject_peer BEFORE INSERT ON trusted_node_peers BEGIN SELECT RAISE(ABORT,'peer rejected'); END"
				}
				if query != "" {
					if _, err := store.Database.Exec(query); err != nil {
						t.Fatal(err)
					}
				}
			}
			if mode == "expired" {
				invite.ExpiresAt = 0
				for _, store := range []*Store{actual, expected} {
					if _, err := store.Database.Exec("UPDATE issued_pairing_invites SET expires_at=0"); err != nil {
						t.Fatal(err)
					}
				}
			}
			got := TrustStore_CompleteIssuedPairing(actual.Database, t.Context(), invite, acceptance, key)
			want := expected.baselineCompleteIssuedPairing(t.Context(), invite, acceptance, key)
			if !sameIdentityError(got, want) {
				t.Fatalf("pairing completion = %v, baseline = %v", got, want)
			}
			compareTrustState(t, actual, expected)
			if mode == "valid" {
				if err := TrustStore_CompleteIssuedPairing(actual.Database, t.Context(), invite, acceptance, key); err != nil {
					t.Fatal("same-node retry is not idempotent", err)
				}
				policy := TrustStore_TrustedPeerPolicy(actual.Database, t.Context(), nodeID)
				if policy.Error != nil || policy.Value.Direction != "push" {
					t.Fatalf("reciprocal peer policy = %#v", policy)
				}
			}
		})
	}
}

func TestZiranTrustTransactionsRollbackAndConcurrentConsumption(t *testing.T) {
	_, key, nodeID := trustKeyFixture()
	for _, mode := range []string{"upsert failure", "commit failure"} {
		t.Run(mode, func(t *testing.T) {
			actual, expected := trustStoreFixture(t), trustStoreFixture(t)
			query := "CREATE TRIGGER reject_peer BEFORE INSERT ON trusted_node_peers BEGIN SELECT RAISE(ABORT,'peer rejected'); END"
			if mode == "commit failure" {
				query = `PRAGMA foreign_keys=ON;
CREATE TABLE parent(id INTEGER PRIMARY KEY);
CREATE TABLE pending(id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED);
CREATE TRIGGER reject_peer AFTER INSERT ON trusted_node_peers BEGIN INSERT INTO pending VALUES(99); END;`
			}
			for _, store := range []*Store{actual, expected} {
				if _, err := store.Database.Exec(query); err != nil {
					t.Fatal(err)
				}
			}
			before := trustSnapshot(t, actual)
			invite := PairingInvite{InviteID: "invite", NodeID: nodeID}
			got := TrustStore_TrustPeer(actual.Database, t.Context(), invite, key)
			want := expected.baselineTrustPeer(t.Context(), invite, key)
			if got == nil || !sameIdentityError(got, want) || !reflect.DeepEqual(trustSnapshot(t, actual), before) {
				t.Fatalf("failed trust transaction = %v, baseline = %v", got, want)
			}
			compareTrustState(t, actual, expected)
			if _, err := actual.Database.Exec("DROP TRIGGER reject_peer"); err != nil {
				t.Fatal(err)
			}
			if err := TrustStore_TrustPeer(actual.Database, t.Context(), invite, key); err != nil {
				t.Fatal("failed transaction left invite consumed or connection unusable", err)
			}
		})
	}
	store := trustStoreFixture(t)
	invite := PairingInvite{InviteID: "shared", NodeID: nodeID}
	const count = 16
	results := make(chan error, count)
	var workers sync.WaitGroup
	for index := 0; index < count; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			results <- TrustStore_TrustPeer(store.Database, context.Background(), invite, key)
		}()
	}
	workers.Wait()
	close(results)
	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
		} else if err.Error() != "pairing invite already consumed" {
			t.Fatal(err)
		}
	}
	if accepted != 1 {
		t.Fatalf("shared invite consumed %d times", accepted)
	}
}

func trustSpaceFixture(t *testing.T, store *Store) (ed25519.PrivateKey, MeshTrustSpace) {
	t.Helper()
	key, publicKey, spaceID := trustKeyFixture()
	if _, err := store.Database.Exec(`INSERT INTO trust_spaces
(space_id,display_name,authority_public_key,authority_private_key,created_at)
VALUES(?1,'Neighborhood',?2,?3,'2000-01-01T00:00:00.000000000Z')`, spaceID, []byte(publicKey), []byte(key)); err != nil {
		t.Fatal(err)
	}
	return key, MeshTrustSpace{SpaceID: spaceID, DisplayName: "Neighborhood", AuthorityPublicKey: hex.EncodeToString(publicKey)}
}

func TestZiranNameSigningAndResolutionAgainstBaseline(t *testing.T) {
	actual, expected := trustStoreFixture(t), trustStoreFixture(t)
	_, space := trustSpaceFixture(t, actual)
	trustSpaceFixture(t, expected)
	claim := NameClaim{Version: 7, SpaceID: space.SpaceID, Name: "home", NodeID: space.SpaceID, Sequence: 42,
		ExpiresAt: time.Now().Add(time.Hour).Unix(), Services: []ServiceRecord{{Service: "sync", Endpoints: []string{"https://home.example"}}}}
	for index := 0; index < 2; index++ {
		got := TrustStore_SignAndStoreNameClaim(actual.Database, t.Context(), claim)
		want, err := expected.baselineSignAndStoreNameClaim(t.Context(), claim)
		if !sameIdentityError(got.Error, err) || !reflect.DeepEqual(got.Value, want) {
			t.Fatalf("signed claim = %#v, baseline = %#v, %v", got, want, err)
		}
		compareTrustState(t, actual, expected)
		resolved := TrustStore_ResolveNameClaim(actual.Database, t.Context(), claim.SpaceID, claim.Name)
		baseline, found, err := expected.baselineResolveNameClaim(t.Context(), claim.SpaceID, claim.Name)
		if !sameIdentityError(resolved.Error, err) || resolved.Found != found || !reflect.DeepEqual(resolved.Value, baseline) {
			t.Fatalf("resolved claim = %#v, baseline = %#v, %v", resolved, baseline, err)
		}
	}
	for _, query := range []string{
		"UPDATE name_claims SET signature='!'",
		"UPDATE name_claims SET services_json='{'",
		"UPDATE name_claims SET services_json='null',expires_at=0",
		"DELETE FROM name_claims",
	} {
		for _, store := range []*Store{actual, expected} {
			if _, err := store.Database.Exec(query); err != nil {
				t.Fatal(err)
			}
		}
		got := TrustStore_ResolveNameClaim(actual.Database, t.Context(), claim.SpaceID, claim.Name)
		want, found, err := expected.baselineResolveNameClaim(t.Context(), claim.SpaceID, claim.Name)
		if !sameIdentityError(got.Error, err) || got.Found != found || !reflect.DeepEqual(got.Value, want) {
			t.Fatalf("resolution after %q = %#v, baseline = %#v, %v", query, got, want, err)
		}
	}
	for _, query := range []string{"UPDATE trust_spaces SET authority_private_key=''", "DELETE FROM trust_spaces"} {
		for _, store := range []*Store{actual, expected} {
			if _, err := store.Database.Exec(query); err != nil {
				t.Fatal(err)
			}
		}
		got := TrustStore_SignAndStoreNameClaim(actual.Database, t.Context(), claim)
		want, err := expected.baselineSignAndStoreNameClaim(t.Context(), claim)
		if !sameIdentityError(got.Error, err) || !reflect.DeepEqual(got.Value, want) {
			t.Fatalf("signing without authority = %#v, baseline = %#v, %v", got, want, err)
		}
	}
}

func signedTrustClaim(key ed25519.PrivateKey, space MeshTrustSpace, name string, sequence int64) NameClaim {
	claim := NameClaim{Version: 1, SpaceID: space.SpaceID, Name: name, NodeID: space.SpaceID,
		Sequence: sequence, ExpiresAt: time.Now().Add(time.Hour).Unix(), Services: []ServiceRecord{}}
	claim.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, baselineNameClaimMessage(claim)))
	return claim
}

func TestZiranMeshNameImportAgainstBaseline(t *testing.T) {
	key, publicKey, spaceID := trustKeyFixture()
	space := MeshTrustSpace{SpaceID: spaceID, DisplayName: "Neighborhood", AuthorityPublicKey: hex.EncodeToString(publicKey)}
	for _, mode := range []string{"valid", "disabled", "out of scope", "bad space key", "wrong space ID", "bad name", "bad signature", "bad service", "missing authority", "late failure"} {
		t.Run(mode, func(t *testing.T) {
			actual, expected := trustStoreFixture(t), trustStoreFixture(t)
			policy := NodeSyncPolicy{Spaces: []string{space.SpaceID}, Data: []string{"\u2003NAMES\t"}}
			spaces := []MeshTrustSpace{space}
			claims := []NameClaim{signedTrustClaim(key, space, "home", 1)}
			switch mode {
			case "disabled":
				policy.Data = []string{"encrypted_records"}
			case "out of scope":
				policy.Spaces = []string{"different"}
			case "bad space key":
				spaces[0].AuthorityPublicKey = "!"
			case "wrong space ID":
				spaces[0].AuthorityPublicKey = strings.Repeat("42", 32)
			case "bad name":
				claims[0].Name = "-invalid"
			case "bad signature":
				claims[0].Signature = "!"
			case "bad service":
				claims[0].Services = []ServiceRecord{{Service: "sync", Endpoints: []string{"ftp://home.example"}}}
			case "missing authority":
				spaces = nil
			case "late failure":
				invalid := signedTrustClaim(key, space, "other", 1)
				invalid.Signature = "!"
				claims = append(claims, invalid)
			}
			got := TrustStore_ImportMeshNames(actual.Database, t.Context(), policy, spaces, claims)
			want, err := expected.baselineImportMeshNames(t.Context(), policy, spaces, claims)
			if !sameIdentityError(got.Error, err) || got.Value != want {
				t.Fatalf("mesh name import = %#v, baseline = %d, %v", got, want, err)
			}
			compareTrustState(t, actual, expected)
			if got.Error != nil && len(trustSnapshot(t, actual)) != 0 {
				t.Fatal("failed mesh name import committed partial trust or claims")
			}
		})
	}
}

func TestZiranMeshNameForksAndExportAgainstBaseline(t *testing.T) {
	actual, expected := trustStoreFixture(t), trustStoreFixture(t)
	key, space := trustSpaceFixture(t, actual)
	trustSpaceFixture(t, expected)
	policy := NodeSyncPolicy{Spaces: []string{space.SpaceID, "missing", space.SpaceID}, Data: []string{"names"}}
	for _, sequence := range []int64{2, 1, 2, 3} {
		claim := signedTrustClaim(key, space, "home", sequence)
		got := TrustStore_ImportMeshNames(actual.Database, t.Context(), policy, nil, []NameClaim{claim})
		want, err := expected.baselineImportMeshNames(t.Context(), policy, nil, []NameClaim{claim})
		if !sameIdentityError(got.Error, err) || got.Value != want {
			t.Fatalf("claim sequence %d = %#v, baseline = %d, %v", sequence, got, want, err)
		}
		compareTrustState(t, actual, expected)
	}
	claim := signedTrustClaim(key, space, "home", 3)
	claim.NodeID = strings.Repeat("a", 64)
	claim.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, baselineNameClaimMessage(claim)))
	got := TrustStore_ImportMeshNames(actual.Database, t.Context(), policy, nil, []NameClaim{claim})
	want, err := expected.baselineImportMeshNames(t.Context(), policy, nil, []NameClaim{claim})
	if !sameIdentityError(got.Error, err) || got.Value != want || got.Error == nil || got.Error.Error() != "namespace history fork detected" {
		t.Fatalf("namespace fork = %#v, baseline = %d, %v", got, want, err)
	}
	compareTrustState(t, actual, expected)
	for _, item := range []NodeSyncPolicy{policy, {}, {Data: []string{"encrypted_records"}}, {Spaces: []string{"missing"}}} {
		exported := TrustStore_ExportMeshNames(actual.Database, t.Context(), item)
		spaces, names, err := expected.baselineExportMeshNames(t.Context(), item)
		if !sameIdentityError(exported.Error, err) || !reflect.DeepEqual(exported.Spaces, spaces) || !reflect.DeepEqual(exported.Names, names) {
			t.Fatalf("export policy %#v = %#v, baseline = %#v, %#v, %v", item, exported, spaces, names, err)
		}
	}
	for _, store := range []*Store{actual, expected} {
		if _, err := store.Database.Exec("UPDATE trust_spaces SET authority_public_key=x'01'"); err != nil {
			t.Fatal(err)
		}
	}
	got = TrustStore_ImportMeshNames(actual.Database, t.Context(), policy, []MeshTrustSpace{space}, nil)
	want, err = expected.baselineImportMeshNames(t.Context(), policy, []MeshTrustSpace{space}, nil)
	if !sameIdentityError(got.Error, err) || got.Value != want || got.Error == nil || got.Error.Error() != "trust-space authority fork detected" {
		t.Fatalf("authority fork = %#v, baseline = %d, %v", got, want, err)
	}
}

func TestZiranTrustSpaceCreationAndCancellation(t *testing.T) {
	actual, expected := trustStoreFixture(t), trustStoreFixture(t)
	original := rand.Reader
	rand.Reader = identityEntropyReader{}
	defer func() { rand.Reader = original }()
	got := TrustStore_CreateTrustSpace(actual.Database, t.Context(), "Neighborhood")
	want, err := expected.baselineCreateTrustSpace(t.Context(), "Neighborhood")
	if !sameIdentityError(got.Error, err) || got.Value != want {
		t.Fatalf("create trust space = %#v, baseline = %s, %v", got, want, err)
	}
	compareTrustState(t, actual, expected)
	got = TrustStore_CreateTrustSpace(actual.Database, t.Context(), "Duplicate")
	want, err = expected.baselineCreateTrustSpace(t.Context(), "Duplicate")
	if !sameIdentityError(got.Error, err) || got.Value != want || got.Value == "" || got.Error == nil {
		t.Fatalf("failed space insert must retain generated ID = %#v, baseline = %s, %v", got, want, err)
	}
	sentinel := errors.New("no entropy")
	rand.Reader = identityEntropyReader{error: sentinel}
	if got := TrustStore_CreateTrustSpace(actual.Database, t.Context(), "Unavailable"); got.Error != sentinel || got.Value != "" {
		t.Fatalf("entropy failure = %#v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, key, nodeID := trustKeyFixture()
	if err := TrustStore_TrustPeer(actual.Database, ctx, PairingInvite{NodeID: nodeID}, key); err != context.Canceled {
		t.Fatalf("canceled transaction lost error identity: %v", err)
	}
	if got := TrustStore_TrustedPeerPolicy(actual.Database, ctx, nodeID); got.Error != context.Canceled || got.Found {
		t.Fatalf("canceled policy query = %#v", got)
	}
	if got := TrustStore_ListTrustedPeers(actual.Database, ctx); got.Error != context.Canceled || got.Value != nil {
		t.Fatalf("canceled peer query = %#v", got)
	}
}

func TestZiranMeshPolicyAndTrustedPeerLayout(t *testing.T) {
	actual, expected := reflect.TypeOf(TrustedNodePeer{}), reflect.TypeOf(baselineTrustedNodePeer{})
	if actual.NumField() != expected.NumField() {
		t.Fatal("trusted peer field count changed")
	}
	for index := 0; index < actual.NumField(); index++ {
		got, want := actual.Field(index), expected.Field(index)
		if got.Name != want.Name || got.Type != want.Type || got.Tag != want.Tag {
			t.Fatalf("trusted peer field %d = %#v, baseline = %#v", index, got, want)
		}
	}
	for _, direction := range []string{"", " PULL ", "send", "receive", "both", "OFF", "unknown", "日本語"} {
		policy := NodeSyncPolicy{Direction: direction, Spaces: []string{"space"}}
		if got, want := MeshPolicy_Inverse(policy), baselineInverseNodeSyncPolicy(policy); !reflect.DeepEqual(got, want) {
			t.Fatalf("inverse policy = %#v, baseline = %#v", got, want)
		}
	}
	for _, policy := range []*NodeSyncPolicy{nil, {}, {Data: []string{}}, {Data: []string{"\u2003NAMES\t"}}, {Data: []string{"encrypted_records"}}} {
		if got, want := MeshPolicy_IncludesData(policy, "names"), baselineIncludesMeshData(policy, "names"); got != want {
			t.Fatalf("policy data inclusion = %v, baseline = %v", got, want)
		}
	}
}
