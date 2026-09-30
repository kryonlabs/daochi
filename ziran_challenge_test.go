package main

import (
	"bytes"
	"encoding/base64"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestZiranChallengeIssueReplaceAndConsume(t *testing.T) {
	store := Challenge_New(time.Minute)
	first := Challenge_Issue(store, "alice")
	if first.Error != nil || len(first.Nonce) != 32 {
		t.Fatalf("issue failed: %#v", first)
	}
	preview := Challenge_PeekBase64(store, "alice")
	if !preview.Found || preview.Nonce != base64.StdEncoding.EncodeToString(first.Nonce) {
		t.Fatalf("preview changed nonce or encoding: %#v", preview)
	}
	replacement := Challenge_Issue(store, "alice")
	if replacement.Error != nil || len(replacement.Nonce) != 32 {
		t.Fatalf("replacement failed: %#v", replacement)
	}
	consumed := Challenge_Consume(store, "alice")
	if !consumed.Found || !bytes.Equal(consumed.Nonce, replacement.Nonce) {
		t.Fatalf("consume did not use the latest challenge: %#v", consumed)
	}
	if next := Challenge_Consume(store, "alice"); next.Found || next.Nonce != nil {
		t.Fatalf("consumed nonce was reusable: %#v", next)
	}
	if missing := Challenge_PeekBase64(store, "unknown"); missing.Found || missing.Nonce != "" {
		t.Fatalf("missing challenge was exposed: %#v", missing)
	}
}

func TestZiranChallengeExpiryAndPruning(t *testing.T) {
	now := time.Now()
	nonce := []byte{0, 1, 2, 255}
	if equal := Challenge_Consumed(Challenge{Nonce: nonce, ExpiresAt: now}, now); !equal.Found || !bytes.Equal(equal.Nonce, nonce) {
		t.Fatal("a nonce exactly at its expiry must remain valid")
	}
	if expired := Challenge_Consumed(Challenge{Nonce: nonce, ExpiresAt: now}, now.Add(time.Nanosecond)); expired.Found || expired.Nonce != nil {
		t.Fatal("an expired nonce was accepted")
	}
	store := Challenge_New(time.Minute)
	store.ByUser["expired"] = Challenge{ExpiresAt: now.Add(-time.Nanosecond)}
	store.ByUser["equal"] = Challenge{ExpiresAt: now}
	store.ByUser["future"] = Challenge{ExpiresAt: now.Add(time.Nanosecond)}
	Challenge_Prune(store, now)
	if len(store.ByUser) != 2 {
		t.Fatalf("wrong pruning boundary: %#v", store.ByUser)
	}
	if _, found := store.ByUser["expired"]; found {
		t.Fatal("pruning retained an expired challenge")
	}
	store.ByUser["expired"] = Challenge{Nonce: nonce, ExpiresAt: now.Add(-time.Hour)}
	if preview := Challenge_PeekBase64(store, "expired"); preview.Found {
		t.Fatal("preview exposed an expired nonce")
	}
	if _, found := store.ByUser["expired"]; !found {
		t.Fatal("preview must not consume an expired challenge")
	}
	if consumed := Challenge_Consume(store, "expired"); consumed.Found || consumed.Nonce != nil {
		t.Fatal("consume exposed an expired nonce")
	}
	if _, found := store.ByUser["expired"]; found {
		t.Fatal("consume failed to delete an expired challenge")
	}
}

func TestZiranChallengeNegativeTTL(t *testing.T) {
	store := Challenge_New(-time.Hour)
	if issued := Challenge_Issue(store, "alice"); issued.Error != nil || len(issued.Nonce) != 32 {
		t.Fatalf("issue changed its negative-TTL behavior: %#v", issued)
	}
	if Challenge_PeekBase64(store, "alice").Found || Challenge_Consume(store, "alice").Found {
		t.Fatal("negative-TTL nonce remained valid")
	}
}

func TestZiranChallengeConcurrentSingleUse(t *testing.T) {
	store := Challenge_New(time.Minute)
	issued := Challenge_Issue(store, "alice")
	if issued.Error != nil {
		t.Fatal(issued.Error)
	}
	var accepted atomic.Int64
	var workers sync.WaitGroup
	for i := 0; i < 64; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			result := Challenge_Consume(store, "alice")
			if result.Found {
				accepted.Add(1)
				if !bytes.Equal(result.Nonce, issued.Nonce) {
					t.Error("accepted nonce bytes changed")
				}
			}
		}()
	}
	workers.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("single-use nonce was accepted %d times", accepted.Load())
	}
}
