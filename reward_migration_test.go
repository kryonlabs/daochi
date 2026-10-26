package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

func legacyRecord(t *testing.T, account string, unlocked int, completed string, salt byte) (string, string, string) {
	t.Helper()
	key := bytes.Repeat([]byte{0x71}, 32)
	nonce := bytes.Repeat([]byte{salt}, 24)
	aad, err := json.Marshal(map[string]string{"account_id": account, "app_id": "entity", "collection": ProgressCollection,
		"id": ProgressRecordID, "schema": "entity.game-progress.v1"})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := json.Marshal(map[string]any{"game": "shovey.classic", "unlocked": unlocked, "completed": completed,
		"state": "old-device-only-state-is-not-migrated"})
	if err != nil {
		t.Fatal(err)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := json.Marshal(map[string]any{"aad": json.RawMessage(aad), "alg": "xchacha20poly1305",
		"key_id": "entity-v1", "profile": "daochi-record-v1", "nonce": base64.RawURLEncoding.EncodeToString(nonce),
		"ciphertext": base64.RawURLEncoding.EncodeToString(aead.Seal(nil, nonce, plain, aad))})
	if err != nil {
		t.Fatal(err)
	}
	subkey, err := chacha20.HChaCha20(key, nonce[:16])
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(envelope), hex.EncodeToString(subkey), base64.RawURLEncoding.EncodeToString(nonce)
}

func saveLegacyRecord(t *testing.T, store *Store, account, ciphertext, nonce string) {
	t.Helper()
	_, err := store.Database.Exec(`INSERT INTO server_encrypted_records(user_id_hash,collection,id,key_id,nonce,ciphertext,updated_at,server_version)
        VALUES(?,?,?,'entity-v1',?,?,'2026-10-25T00:00:00Z',1)
        ON CONFLICT(user_id_hash,collection,id) DO UPDATE SET nonce=excluded.nonce,ciphertext=excluded.ciphertext,server_version=server_version+1`,
		account, ProgressCollection, ProgressRecordID, nonce, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
}

func freezeUpgrade(t *testing.T, store *Store) {
	t.Helper()
	// A fixture's initial empty database is the old version. Simulate its
	// first upgrade after the released account records have been written.
	if _, err := store.Database.Exec(`DELETE FROM game_legacy_migration`); err != nil {
		t.Fatal(err)
	}
	if err := RewardMigration_Freeze(store.Database, context.Background()); err != nil {
		t.Fatal(err)
	}
}

func migrationBody(t *testing.T, ciphertext, key string) []byte {
	t.Helper()
	hash := sha256.Sum256([]byte(ciphertext))
	result, err := json.Marshal(map[string]string{"snapshot": hex.EncodeToString(hash[:]), "key": key})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestRewardMigrationPreservesEarnedUnlocksWithoutInventingRoutes(t *testing.T) {
	_, store, handler, _ := unlockFixture(t)
	player, other := newTestIdentity(t, handler, 0xd1), newTestIdentity(t, handler, 0xd2)
	frozen, key, nonce := legacyRecord(t, player.UserID, 74, strings.Repeat("1", 73), 0x31)
	saveLegacyRecord(t, store, player.UserID, frozen, nonce)
	freezeUpgrade(t, store)
	// A later upload cannot enlarge the pre-upgrade entitlement.
	inflated, inflatedKey, inflatedNonce := legacyRecord(t, player.UserID, 176, strings.Repeat("1", 175), 0x32)
	saveLegacyRecord(t, store, player.UserID, inflated, inflatedNonce)
	if err := RewardMigration_Freeze(store.Database, context.Background()); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/rewards/migration"
	got := tokenJSONRequest(t, handler, http.MethodGet, path, player.Token, nil)
	var snapshot struct {
		Status, Snapshot, Ciphertext string
		NonceHex                     string `json:"nonce_hex"`
	}
	if got.Code != 200 || json.Unmarshal(got.Body.Bytes(), &snapshot) != nil || snapshot.Status != "available" || snapshot.Ciphertext != frozen {
		t.Fatalf("frozen account progress missing: %d %s", got.Code, got.Body.String())
	}
	if got.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatal("migration snapshot may be cached")
	}
	request := func(token string, body []byte, status int) {
		t.Helper()
		got := tokenJSONRequest(t, handler, http.MethodPost, path, token, body)
		if got.Code != status {
			t.Fatalf("migration: %d %s", got.Code, got.Body.String())
		}
	}
	request("", migrationBody(t, frozen, key), 401)
	request(other.Token, migrationBody(t, frozen, key), 403)
	request(player.Token, migrationBody(t, frozen, strings.Repeat("00", 32)), 403)
	request(player.Token, migrationBody(t, inflated, inflatedKey), 403)
	request(player.Token, migrationBody(t, frozen, key), 200)
	request(player.Token, migrationBody(t, frozen, key), 200)
	var count, unlocked int
	if err := store.Database.QueryRow(`SELECT COUNT(*) FROM game_completions WHERE account_id=?`, player.UserID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("migration invented route histories: %d %v", count, err)
	}
	if err := store.Database.QueryRow(`SELECT unlocked FROM game_legacy_progress WHERE account_id=?`, player.UserID).Scan(&unlocked); err != nil || unlocked != 74 {
		t.Fatalf("legacy frontier changed: %d %v", unlocked, err)
	}
	if balance := TokenLedger_Balance(store.Database, context.Background(), player.UserID, AssetID); balance.Error != nil || balance.Value != 0 {
		t.Fatalf("migration credited a reward without a claim: %+v", balance)
	}
	if eligible := GameEvidence_Eligible(store.Database, context.Background(), player.UserID, "shovey.secret-chest"); eligible.Error != nil || !eligible.Eligible {
		t.Fatalf("earned chest entitlement lost: %+v", eligible)
	}
	if eligible := GameEvidence_Eligible(store.Database, context.Background(), player.UserID, "shovey.campaign-complete"); eligible.Error != nil || eligible.Eligible {
		t.Fatalf("migration granted unfinished campaign: %+v", eligible)
	}
	for attempt := 0; attempt < 2; attempt++ {
		got := tokenJSONRequest(t, handler, http.MethodPost, "/api/v1/rewards", player.Token, []byte(`{"reward":"shovey.secret-chest"}`))
		var claim rewardClaimResponse
		if got.Code != 200 || json.Unmarshal(got.Body.Bytes(), &claim) != nil || claim.Credited != (attempt == 0) || claim.Balance != 2*UnitsPerDew {
			t.Fatalf("migrated reward claim %d: %d %s", attempt, got.Code, got.Body.String())
		}
	}
	// Newly earned history fills only the remaining campaign levels.
	board := evidenceMap()
	for level := int32(74); level <= 175; level++ {
		registerEvidenceMap(t, store, board, level, "after-upgrade")
		if result := GameEvidence_Put(store.Database, context.Background(), player.UserID, evidenceAttempt(level, board, true)); result.Error != nil {
			t.Fatal(result.Error)
		}
	}
	if eligible := GameEvidence_Eligible(store.Database, context.Background(), player.UserID, "shovey.campaign-complete"); eligible.Error != nil || !eligible.Eligible {
		t.Fatalf("legacy and new progress did not combine: %+v", eligible)
	}
}

func TestRewardMigrationCannotImportPostUpgradeProgress(t *testing.T) {
	_, store, handler, _ := unlockFixture(t)
	player := newTestIdentity(t, handler, 0xd3)
	frozen, key, nonce := legacyRecord(t, player.UserID, 176, strings.Repeat("1", 175), 0x41)
	// The normal fixture has already run the upgrade with no saved progress.
	saveLegacyRecord(t, store, player.UserID, frozen, nonce)
	if err := RewardMigration_Freeze(store.Database, context.Background()); err != nil {
		t.Fatal(err)
	}
	got := tokenJSONRequest(t, handler, http.MethodPost, "/api/v1/rewards/migration", player.Token, migrationBody(t, frozen, key))
	if got.Code != 403 {
		t.Fatalf("post-upgrade progress was grandfathered: %d %s", got.Code, got.Body.String())
	}
	if eligible := GameEvidence_Eligible(store.Database, context.Background(), player.UserID, "shovey.secret-chest"); eligible.Error != nil || eligible.Eligible {
		t.Fatalf("migration bypassed new proof rules: %+v", eligible)
	}
}

func TestRewardMigrationRejectsMalformedProgress(t *testing.T) {
	for _, test := range []struct {
		name      string
		unlocked  int
		completed string
	}{
		{"invalid frontier", 4097, "1"}, {"negative frontier", -1, "1"}, {"invalid marks", 29, "yes"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, store, handler, _ := unlockFixture(t)
			player := newTestIdentity(t, handler, 0xd4)
			frozen, key, nonce := legacyRecord(t, player.UserID, test.unlocked, test.completed, 0x51)
			saveLegacyRecord(t, store, player.UserID, frozen, nonce)
			freezeUpgrade(t, store)
			got := tokenJSONRequest(t, handler, http.MethodPost, "/api/v1/rewards/migration", player.Token, migrationBody(t, frozen, key))
			if got.Code != 403 {
				t.Fatalf("malformed progress migrated: %d %s", got.Code, got.Body.String())
			}
		})
	}
}
