package main

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestZiranSocialCacheWritesAgainstBaseline(t *testing.T) {
	for _, mode := range []string{"normal", "write failure", "commit failure", "missing user", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			actual, users := socialHTTPFixture(t)
			expected, _ := socialHTTPFixture(t)
			user := users[0]
			ctx := context.Background()
			query := ""
			switch mode {
			case "write failure":
				query = "CREATE TRIGGER reject_snapshot BEFORE INSERT ON server_social_snapshots BEGIN SELECT RAISE(ABORT,'snapshot rejected'); END"
			case "commit failure":
				query = "CREATE TABLE required(id INTEGER PRIMARY KEY); CREATE TABLE pending(id INTEGER REFERENCES required(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER reject_snapshot_commit AFTER INSERT ON server_social_snapshots BEGIN INSERT INTO pending VALUES(99); END"
			case "missing user":
				user = strings.Repeat("f", 64)
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if query != "" {
				for _, store := range []*Store{actual.store, expected.store} {
					if _, err := store.db.Exec(query); err != nil {
						t.Fatal(err)
					}
				}
			}
			for _, kind := range []string{"friends.list", " \u2003friends.requests ", "", strings.Repeat("a", 96), strings.Repeat("a", 97), "\xff"} {
				for _, payload := range []json.RawMessage{nil, {}, json.RawMessage("{}"), json.RawMessage("null"), json.RawMessage("[1,2]"), json.RawMessage(`{"text":"日本語"}`), json.RawMessage("{invalid"), {0xff}} {
					for attempt := 0; attempt < 2; attempt++ {
						got := SocialCache_Set(actual.store.db, ctx, user, kind, payload)
						applied, err := expected.store.baselineSnapshotSet(ctx, user, kind, payload)
						if got.Applied != applied || !sameIdentityError(got.Error, err) {
							t.Fatalf("snapshot write differs for %q, %q: %#v, %d, %v", kind, payload, got, applied, err)
						}
						if mode == "cancelled" && !errors.Is(got.Error, context.Canceled) {
							t.Fatal("snapshot write lost cancellation identity")
						}
					}
				}
			}
			for _, existing := range users {
				got := AccountExport_Export(actual.store.db, context.Background(), existing)
				want := AccountExport_Export(expected.store.db, context.Background(), existing)
				if !reflect.DeepEqual(got.Value, want.Value) || !sameIdentityError(got.Error, want.Error) {
					t.Fatal("snapshot writes or rollback changed account state")
				}
			}
			if err := actual.store.db.Ping(); err != nil {
				t.Fatal("failed snapshot write retained a transaction", err)
			}
		})
	}
}

func TestZiranSocialCacheConcurrentIdempotence(t *testing.T) {
	server, users := socialHTTPFixture(t)
	var workers sync.WaitGroup
	results := make(chan SnapshotWriteResult, 16)
	for index := 0; index < cap(results); index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			results <- SocialCache_Set(server.store.db, context.Background(), users[0], "friends.list", []byte("{}"))
		}()
	}
	workers.Wait()
	close(results)
	applied := 0
	for result := range results {
		if result.Error != nil {
			t.Fatal(result.Error)
		}
		applied += result.Applied
	}
	var version int64
	if err := server.store.db.QueryRow("SELECT server_version FROM server_sync_state WHERE user_id_hash=?", users[0]).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if applied != 1 || version != 8 {
		t.Fatalf("idempotent snapshot writes consumed versions: %d writes, version %d", applied, version)
	}
}
