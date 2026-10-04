package main

import (
	"bytes"
	"encoding/base64"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestZiranChallengeOverlappingIssuesStayUsable(t *testing.T) {
	store := Challenge_New(time.Minute)
	first := Challenge_Issue(store, "alice")
	if first.Error != nil || len(first.Nonce) != 32 {
		t.Fatalf("issue failed: %#v", first)
	}
	second := Challenge_Issue(store, "alice")
	if second.Error != nil || len(second.Nonce) != 32 {
		t.Fatalf("second issue failed: %#v", second)
	}
	pending := Challenge_Outstanding(store, "alice")
	if len(pending) != 2 || !bytes.Equal(pending[0].Nonce, second.Nonce) || !bytes.Equal(pending[1].Nonce, first.Nonce) {
		t.Fatalf("both challenges must stay outstanding, newest first: %#v", pending)
	}
	preview := Challenge_PeekBase64(store, "alice")
	if !preview.Found || preview.Nonce != base64.StdEncoding.EncodeToString(second.Nonce) {
		t.Fatalf("preview changed nonce or encoding: %#v", preview)
	}
	if !Challenge_Take(store, Challenge_Key("alice", first.Nonce)) {
		t.Fatal("the older challenge was replaced")
	}
	if Challenge_Take(store, Challenge_Key("alice", first.Nonce)) {
		t.Fatal("a used challenge was reusable")
	}
	pending = Challenge_Outstanding(store, "alice")
	if len(pending) != 1 || !bytes.Equal(pending[0].Nonce, second.Nonce) {
		t.Fatalf("taking one challenge removed another: %#v", pending)
	}
	if len(Challenge_Outstanding(store, "bob")) != 0 || Challenge_Take(store, Challenge_Key("bob", second.Nonce)) {
		t.Fatal("another account reached alice's challenge")
	}
	if missing := Challenge_PeekBase64(store, "unknown"); missing.Found || missing.Nonce != "" {
		t.Fatalf("missing challenge was exposed: %#v", missing)
	}
}

func TestZiranChallengeBoundsEachAccount(t *testing.T) {
	store := Challenge_New(time.Minute)
	var issued [][]byte
	for i := 0; i < MaxOutstanding+2; i++ {
		result := Challenge_Issue(store, "alice")
		if result.Error != nil {
			t.Fatal(result.Error)
		}
		issued = append(issued, result.Nonce)
		time.Sleep(time.Millisecond)
	}
	other := Challenge_Issue(store, "bob")
	if other.Error != nil {
		t.Fatal(other.Error)
	}
	if count := len(Challenge_Outstanding(store, "alice")); count != MaxOutstanding {
		t.Fatalf("outstanding challenges = %d", count)
	}
	if Challenge_Take(store, Challenge_Key("alice", issued[0])) || Challenge_Take(store, Challenge_Key("alice", issued[1])) {
		t.Fatal("the oldest challenges beyond the bound must be gone")
	}
	if !Challenge_Take(store, Challenge_Key("alice", issued[len(issued)-1])) {
		t.Fatal("the newest challenge must be kept")
	}
	if len(Challenge_Outstanding(store, "bob")) != 1 {
		t.Fatal("another account's challenges must not count")
	}
}

func TestZiranChallengeExpiryAndPruning(t *testing.T) {
	now := time.Now()
	nonce := []byte{0, 1, 2, 255}
	store := Challenge_New(time.Minute)
	store.ByUser["expired"] = Challenge{User: "u", ExpiresAt: now.Add(-time.Nanosecond)}
	store.ByUser["equal"] = Challenge{User: "u", ExpiresAt: now}
	store.ByUser["future"] = Challenge{User: "u", ExpiresAt: now.Add(time.Nanosecond)}
	Challenge_Prune(store, now)
	if len(store.ByUser) != 2 {
		t.Fatalf("wrong pruning boundary: %#v", store.ByUser)
	}
	if _, found := store.ByUser["expired"]; found {
		t.Fatal("pruning retained an expired challenge")
	}
	key := Challenge_Key("alice", nonce)
	store.ByUser[key] = Challenge{User: "alice", Nonce: nonce, ExpiresAt: now.Add(-time.Hour)}
	if preview := Challenge_PeekBase64(store, "alice"); preview.Found {
		t.Fatal("preview exposed an expired nonce")
	}
	if len(Challenge_Outstanding(store, "alice")) != 0 {
		t.Fatal("an expired challenge was outstanding")
	}
	if _, found := store.ByUser[key]; found {
		t.Fatal("reading challenges must remove expired ones")
	}
	store.ByUser[key] = Challenge{User: "alice", Nonce: nonce, ExpiresAt: now.Add(-time.Hour)}
	if Challenge_Take(store, key) {
		t.Fatal("an expired challenge was accepted")
	}
	if _, found := store.ByUser[key]; found {
		t.Fatal("taking an expired challenge must delete it")
	}
}

func TestZiranChallengeNegativeTTL(t *testing.T) {
	store := Challenge_New(-time.Hour)
	issued := Challenge_Issue(store, "alice")
	if issued.Error != nil || len(issued.Nonce) != 32 {
		t.Fatalf("issue changed its negative-TTL behavior: %#v", issued)
	}
	if Challenge_PeekBase64(store, "alice").Found || len(Challenge_Outstanding(store, "alice")) != 0 ||
		Challenge_Take(store, Challenge_Key("alice", issued.Nonce)) {
		t.Fatal("negative-TTL nonce remained valid")
	}
}

func TestZiranChallengeConcurrentSingleUse(t *testing.T) {
	store := Challenge_New(time.Minute)
	issued := Challenge_Issue(store, "alice")
	if issued.Error != nil {
		t.Fatal(issued.Error)
	}
	key := Challenge_Key("alice", issued.Nonce)
	var accepted atomic.Int64
	var workers sync.WaitGroup
	for i := 0; i < 64; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if Challenge_Take(store, key) {
				accepted.Add(1)
			}
		}()
	}
	workers.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("single-use nonce was accepted %d times", accepted.Load())
	}
}
