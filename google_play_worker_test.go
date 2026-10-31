package main

import (
	"context"
	"testing"
	"time"
)

func TestGooglePlayStartupWorkerRunsWhenPurchasesDisabled(t *testing.T) {
	server := &Server{Cfg: Config{GoogleServiceAccountJSON: "configured"}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan string, 5)
	worker := func(name string) Worker {
		return func(actual *Server, actualContext context.Context) {
			if actual != server || actualContext != ctx {
				t.Error("worker lost server or cancellation context")
			}
			started <- name
			<-actualContext.Done()
		}
	}
	workers := Workers{Google: worker("google"), Mesh: worker("mesh"), Discovery: worker("discovery"), Retention: worker("retention"), Rates: worker("rates")}
	var group WorkerGroup
	Startup_StartWorkers(server, ctx, &group, workers)
	seen := map[string]bool{}
	for len(seen) < 5 {
		select {
		case name := <-started:
			seen[name] = true
		case <-time.After(5 * time.Second):
			t.Fatalf("missing background recovery worker: %v", seen)
		}
	}
	cancel()
	done := make(chan struct{})
	go func() { group.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("workers did not stop on cancellation")
	}
	if Startup_NativeWorkers().Google == nil {
		t.Fatal("native startup has no Google recovery callback")
	}
}
