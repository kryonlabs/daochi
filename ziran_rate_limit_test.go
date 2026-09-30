package main

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestZiranRateLimiterExpiryBoundary(t *testing.T) {
	now := time.Now()
	limiter := RateLimit_New()
	limiter.Windows["equal"] = RateWindow{ResetAt: now, Count: 3}
	if RateLimit_Record(limiter, "equal", 3, time.Hour, now) {
		t.Fatal("a request exactly at reset time must still count in the old window")
	}
	if item := limiter.Windows["equal"]; item.Count != 4 || item.ResetAt != now {
		t.Fatalf("equal boundary changed window: %#v", item)
	}
	if !RateLimit_Record(limiter, "equal", 3, time.Hour, now.Add(time.Nanosecond)) {
		t.Fatal("request after reset must start a fresh window")
	}
	if item := limiter.Windows["equal"]; item.Count != 1 || item.ResetAt != now.Add(time.Hour+time.Nanosecond) {
		t.Fatalf("new window lost its timestamp or count: %#v", item)
	}
}

func TestZiranRateLimiterDisabledPolicy(t *testing.T) {
	limiter := RateLimit_New()
	for _, policy := range []struct {
		key    string
		limit  int
		window time.Duration
	}{
		{"", 3, time.Hour},
		{"zero-limit", 0, time.Hour},
		{"negative-limit", -1, time.Hour},
		{"zero-window", 3, 0},
		{"negative-window", 3, -time.Nanosecond},
	} {
		if !RateLimit_Allow(limiter, policy.key, policy.limit, policy.window) {
			t.Fatalf("disabled policy blocked a request: %#v", policy)
		}
	}
	if len(limiter.Windows) != 0 || limiter.Windows == nil {
		t.Fatalf("disabled policy changed map storage: %#v", limiter.Windows)
	}
}

func TestZiranRateLimiterPruning(t *testing.T) {
	now := time.Now()
	limiter := RateLimit_New()
	for i := 0; i < 8191; i++ {
		limiter.Windows[fmt.Sprint(i)] = RateWindow{ResetAt: now.Add(-time.Nanosecond)}
	}
	if !RateLimit_Record(limiter, "equal", 3, time.Hour, now) || len(limiter.Windows) != 8192 {
		t.Fatal("pruning must wait until the map exceeds 8192 entries")
	}
	limiter.Windows["equal"] = RateWindow{ResetAt: now, Count: 1}
	if !RateLimit_Record(limiter, "new", 3, time.Hour, now) {
		t.Fatal("new bucket was rejected")
	}
	if len(limiter.Windows) != 2 || limiter.Windows["equal"].ResetAt != now {
		t.Fatalf("pruning removed a live/equal window or retained expired windows: %#v", limiter.Windows)
	}
}

func TestZiranRateLimiterConcurrentRequests(t *testing.T) {
	limiter := RateLimit_New()
	var allowed atomic.Int64
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 100; j++ {
				if RateLimit_Allow(limiter, "shared", 101, time.Hour) {
					allowed.Add(1)
				}
			}
		}()
	}
	workers.Wait()
	if allowed.Load() != 101 || limiter.Windows["shared"].Count != 3200 {
		t.Fatalf("lost or excess requests: allowed=%d, count=%d", allowed.Load(), limiter.Windows["shared"].Count)
	}
}
