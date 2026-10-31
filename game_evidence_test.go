package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func evidenceMap() string {
	layers := make([]byte, 720)
	for at := 0; at < 240; at++ {
		layers[at] = 12
	}
	for _, at := range []int{13, 14, 25} {
		layers[at], layers[240+at] = 0, 0
	}
	layers[13], layers[14] = 10, 7
	return hex.EncodeToString(layers)
}

func evidenceAttempt(level int32, board string, long bool) Completion {
	c := Completion{Game: "shovey.classic", Level: level, MapHash: GameEvidence_MapHash("shovey.classic", level, board),
		Moves: 1, Actions: "2", Trace: "0d0e", EvidenceComplete: true}
	if long {
		c.Moves, c.Actions, c.Trace = 11, "31313131312", "0d190d190d190d190d190d0e"
	}
	return c
}

func registerEvidenceMap(t *testing.T, store *Store, board string, level int32, version string) string {
	t.Helper()
	hash := GameEvidence_MapHash("shovey.classic", level, board)
	err := GameEvidence_Register(store.Database, context.Background(), MapRegistration{Game: "shovey.classic",
		SourceVersion: version, Maps: []MapRevision{{Level: level, MapHash: hash, Map: board}}})
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func TestGameEvidenceRetainsExactMapVersionsAndAccountHistory(t *testing.T) {
	_, store, handler, _ := unlockFixture(t)
	player, other := newTestIdentity(t, handler, 0xb1), newTestIdentity(t, handler, 0xb2)
	ctx := context.Background()
	v1 := evidenceMap()
	hash := registerEvidenceMap(t, store, v1, 1, "v1")
	c := evidenceAttempt(1, v1, true)
	first := GameEvidence_Put(store.Database, ctx, player.UserID, c)
	if first.Error != nil || !first.Created {
		t.Fatalf("first evidence: %+v", first)
	}
	if again := GameEvidence_Put(store.Database, ctx, player.UserID, c); again.Error != nil || again.Created || again.ID != first.ID {
		t.Fatalf("identical submission was not idempotent: %+v", again)
	}
	// The map revision stays distinct even when only the decoration changes.
	v2 := v1[:960+26] + "39" + v1[960+28:]
	registerEvidenceMap(t, store, v2, 1, "v2")
	history := GameEvidence_History(store.Database, ctx, player.UserID, "shovey.classic", 1, hash, 0)
	if history.Error != nil || history.Map != v1 || len(history.Completions) != 1 || history.Completions[0].Trace != c.Trace {
		t.Fatalf("old map/evidence changed: %+v", history)
	}
	private := GameEvidence_History(store.Database, ctx, other.UserID, "shovey.classic", 1, hash, 0)
	if private.Error != nil || len(private.Completions) != 0 || private.Map != "" {
		t.Fatalf("another account could read private evidence: %+v", private)
	}
	bad := MapRegistration{Game: "shovey.classic", SourceVersion: "bad", Maps: []MapRevision{{Level: 1, MapHash: hash, Map: v2}}}
	if GameEvidence_Register(store.Database, ctx, bad) == nil {
		t.Fatal("mismatched immutable map hash accepted")
	}
}

func TestGameEvidenceEligibilityRetainsQualifyingAttemptBesideShortestAndLegacy(t *testing.T) {
	_, store, handler, _ := unlockFixture(t)
	player, other := newTestIdentity(t, handler, 0xb3), newTestIdentity(t, handler, 0xb4)
	ctx, board := context.Background(), evidenceMap()
	for level := int32(1); level <= 28; level++ {
		registerEvidenceMap(t, store, board, level, "test")
		c := evidenceAttempt(level, board, true)
		if level == 28 {
			c.EvidenceComplete = false
		}
		if result := GameEvidence_Put(store.Database, ctx, player.UserID, c); result.Error != nil {
			t.Fatal(result.Error)
		}
	}
	if value := GameEvidence_Eligible(store.Database, ctx, player.UserID, "shovey.secret-chest"); value.Error != nil || value.Eligible {
		t.Fatalf("incomplete legacy evidence granted reward: %+v", value)
	}
	for _, long := range []bool{false, true} {
		if result := GameEvidence_Put(store.Database, ctx, player.UserID, evidenceAttempt(28, board, long)); result.Error != nil {
			t.Fatal(result.Error)
		}
	}
	if value := GameEvidence_Eligible(store.Database, ctx, player.UserID, "shovey.secret-chest"); value.Error != nil || !value.Eligible {
		t.Fatalf("sub10 shortest or legacy attempt hid qualifying evidence: %+v", value)
	}
	for _, reward := range []string{"shovey.secret-chest", "shovey.campaign-complete"} {
		if value := GameEvidence_Eligible(store.Database, ctx, other.UserID, reward); value.Error != nil || value.Eligible {
			t.Fatalf("unsynced other account eligible: %+v", value)
		}
	}
	if value := GameEvidence_Eligible(store.Database, ctx, player.UserID, "shovey.campaign-complete"); value.Error != nil || value.Eligible {
		t.Fatalf("missing later levels granted final reward: %+v", value)
	}
	history := GameEvidence_History(store.Database, ctx, player.UserID, "shovey.classic", 28, GameEvidence_MapHash("shovey.classic", 28, board), 0)
	if history.Error != nil || len(history.Completions) != 3 || history.Completions[0].Moves != 1 {
		t.Fatalf("shortest, incomplete and eligible history were not all retained: %+v", history)
	}
}

func TestGameEvidenceLegacyMarksCannotMintRewards(t *testing.T) {
	_, store, handler, _ := unlockFixture(t)
	player := newTestIdentity(t, handler, 0xc7)
	if _, err := store.Database.Exec(`INSERT INTO game_legacy_progress(account_id,unlocked,completed,snapshot,migrated_at) VALUES(?1,175,?2,'test',0)`, player.UserID, strings.Repeat("1", 175)); err != nil {
		t.Fatal(err)
	}
	for _, reward := range []string{"shovey.secret-chest", "shovey.campaign-complete"} {
		result := GameEvidence_Eligible(store.Database, context.Background(), player.UserID, reward)
		if result.Error != nil || result.Eligible {
			t.Fatalf("unproven legacy marks granted %s: %+v", reward, result)
		}
	}
}

func TestGameEvidenceRejectsSolidsJumpsAndInventedCount(t *testing.T) {
	board := evidenceMap()
	for _, mutate := range []func(*Completion){
		func(c *Completion) { c.Trace = "0d000e" },
		func(c *Completion) { c.Trace = "0d250e" },
		func(c *Completion) { c.Trace = "0e" },
		func(c *Completion) { c.Moves = 1000 },
		func(c *Completion) { c.Actions = "x" },
		func(c *Completion) { c.MapHash = strings.Repeat("0", 64) },
	} {
		c := evidenceAttempt(1, board, false)
		mutate(&c)
		if GameEvidence_Validate(c, board) == nil {
			t.Fatalf("invalid evidence accepted: %+v", c)
		}
	}
}

func TestGameEvidenceAllowsExactPortalPairWithoutInterpolatingWalls(t *testing.T) {
	layers, err := hex.DecodeString(evidenceMap())
	if err != nil {
		t.Fatal(err)
	}
	layers[14] = 0
	layers[25], layers[200], layers[199] = 8, 8, 7
	layers[240+200], layers[240+199] = 0, 0
	board := hex.EncodeToString(layers)
	c := Completion{Game: "shovey.classic", Level: 1, MapHash: GameEvidence_MapHash("shovey.classic", 1, board),
		Moves: 2, Actions: "30", Trace: "0d19c8c7", EvidenceComplete: true}
	if err := GameEvidence_Validate(c, board); err != nil {
		t.Fatalf("paired portal crossing rejected: %v", err)
	}
	// A third same-colour portal cannot license an arbitrary jump.
	layers[40], layers[240+40] = 8, 0
	board = hex.EncodeToString(layers)
	c.MapHash = GameEvidence_MapHash("shovey.classic", 1, board)
	if GameEvidence_Validate(c, board) == nil {
		t.Fatal("ambiguous portal group permitted a jump")
	}
}

func TestGameEvidenceActualCapturedRoutes(t *testing.T) {
	folder := os.Getenv("SHOVEY_EVIDENCE_FIXTURES")
	if folder == "" {
		t.Skip("optional actual game capture fixture directory not supplied")
	}
	var maps MapRegistration
	data, err := os.ReadFile(folder + "/fixture-maps.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &maps); err != nil {
		t.Fatal(err)
	}
	byHash := map[string]string{}
	for _, entry := range maps.Maps {
		byHash[entry.MapHash] = entry.Map
	}
	file, err := os.Open(folder + "/evidence.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 65536), 1048576)
	count := 0
	for scanner.Scan() {
		var c Completion
		if err := json.Unmarshal(scanner.Bytes(), &c); err != nil {
			t.Fatal(err)
		}
		if err := GameEvidence_Validate(c, byHash[c.MapHash]); err != nil {
			t.Fatalf("actual level %d: %v", c.Level, err)
		}
		count++
	}
	if scanner.Err() != nil || count < 9 {
		t.Fatalf("captured fixture count %d: %v", count, scanner.Err())
	}
}
