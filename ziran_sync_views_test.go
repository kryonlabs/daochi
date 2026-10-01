package main

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func viewsFixture(t *testing.T) *Store {
	t.Helper()
	_, store, _ := testServer(t)
	for accountIndex, user := range lifecycleAccounts {
		if err := store.RegisterUser(t.Context(), user, []byte("key")); err != nil {
			t.Fatal(err)
		}
		lifecycleExecute(t, store, "UPDATE server_sync_state SET server_version=20 WHERE user_id_hash=?1", user)
		for index, id := range []string{"z-last", "a-first", "deleted"} {
			deleted := 0
			if id == "deleted" {
				deleted = 922
			}
			lifecycleExecute(t, store, `INSERT INTO server_habits(user_id_hash,id,name,color_r,color_g,color_b,sync_mode,sync_activity,counter_enabled,sort_order,deleted_at,updated_at,server_version) VALUES(?1,?2,?3,-1,196,165,2,3,1,?4,?5,?6,?7)`,
				user, id, fmt.Sprintf("account-%d 日本語\t\n\x00\xff", accountIndex), 2-index, deleted, lifecycleFixtureTime, index+1)
			lifecycleExecute(t, store, `INSERT INTO server_sessions(user_id_hash,id,started_at,local_date,topic,activity,source,rounds_hash,mood_before,mood_after,energy,stress,note,tags,deleted_at,updated_at,server_version) VALUES(?1,?2,?3,20261001,?4,3,'source','rounds',-1,2,3,4,?5,'[]',?6,?3,?7)`,
				user, id, lifecycleFixtureTime, fmt.Sprintf("topic-%d", accountIndex), "arbitrary\t\n\x00\xff", deleted, index+1)
			if index != 1 {
				for _, round := range []int{4, 1} {
					lifecycleExecute(t, store, `INSERT INTO server_session_rounds(user_id_hash,session_id,round_index,breaths,hold_seconds) VALUES(?1,?2,?3,?4,-2)`, user, id, round, accountIndex+5)
				}
			}
		}
		for index, day := range []struct {
			id        string
			completed int
			count     int
		}{
			{"z-last", -2, -3}, {"a-first", 0, 3}, {"deleted", 1, 0},
			{"orphan", 0, 0}, {"orphan", 3, 0}, {"a-first", 0, 0},
		} {
			lifecycleExecute(t, store, `INSERT INTO server_habit_days(user_id_hash,habit_id,local_date,completed,count,updated_at,server_version) VALUES(?1,?2,?3,?4,?5,?6,?7)`,
				user, day.id, 20261001+index, day.completed, day.count, lifecycleFixtureTime, index+1)
		}
		for index, payload := range []string{"", "arbitrary\x00\xff", `{"account":1}`} {
			lifecycleExecute(t, store, `INSERT INTO server_social_snapshots(user_id_hash,kind,json,updated_at,server_version) VALUES(?1,?2,?3,?4,?5)`,
				user, fmt.Sprintf("kind-%d", index), payload, lifecycleFixtureTime, index+1)
			lifecycleExecute(t, store, `INSERT INTO server_encrypted_records(user_id_hash,collection,id,key_id,nonce,ciphertext,updated_at,deleted_at,content_hash,schema_version,parent_id,server_version) VALUES(?1,?2,?3,'key','nonce',?4,?5,?6,'hash',-3,'parent',?7)`,
				user, []string{"z.collection", "a.collection", "a.collection"}[index], fmt.Sprintf("record-%d", 2-index), payload, lifecycleFixtureTime, index, index+1)
			lifecycleExecute(t, store, `INSERT INTO server_sync_ops(user_id_hash,op_id,client_id,seq,entity_type,entity_id,local_date,op_type,payload_json,created_at,server_version) VALUES(?1,?2,?3,?4,'habit','a-first',20261001,'upsert',?5,?6,?7)`,
				user, fmt.Sprintf("op-%d", index), []string{"b-client", "a-client", "a-client"}[index], 3-index, payload, lifecycleFixtureTime, 2)
			lifecycleExecute(t, store, `INSERT INTO server_meditation_logs(id,user_id_hash,session_id,duration_seconds,completed_at,server_version,created_at) VALUES(?1,?2,'z-last',?3,?4,?5,?4)`,
				fmt.Sprintf("meditation-%d-%d", accountIndex, 2-index), user, index-1, lifecycleFixtureTime, index+1)
		}
	}
	lifecycleExecute(t, store, `INSERT INTO server_friendships(user_id_a,user_id_b,created_at) VALUES(?1,?2,?3)`, lifecycleAccounts[0], lifecycleAccounts[1], lifecycleFixtureTime)
	return store
}

type viewsReadCase struct {
	name     string
	actual   func(*Store, context.Context, string, int64) lifecycleReadResult
	baseline func(*Store, context.Context, string, int64) lifecycleReadResult
}

func viewsReadCases() []viewsReadCase {
	return []viewsReadCase{
		{"habits", func(s *Store, ctx context.Context, user string, since int64) lifecycleReadResult {
			r := SyncViews_HabitsSince(s.Database, ctx, user, since)
			return lifecycleReadResult{r.Value, nil, r.Error}
		}, func(s *Store, ctx context.Context, user string, since int64) lifecycleReadResult {
			v, err := s.baselineViewsSnapshotHabits(ctx, user, since)
			return lifecycleReadResult{v, nil, err}
		}},
		{"days", func(s *Store, ctx context.Context, user string, since int64) lifecycleReadResult {
			r := SyncViews_HabitDaysSince(s.Database, ctx, user, since)
			return lifecycleReadResult{r.Value, nil, r.Error}
		}, func(s *Store, ctx context.Context, user string, since int64) lifecycleReadResult {
			v, err := s.baselineViewsSnapshotHabitDays(ctx, user, since)
			return lifecycleReadResult{v, nil, err}
		}},
		{"sessions", func(s *Store, ctx context.Context, user string, since int64) lifecycleReadResult {
			r := SyncViews_SessionsSince(s.Database, ctx, user, since)
			return lifecycleReadResult{r.Value, nil, r.Error}
		}, func(s *Store, ctx context.Context, user string, since int64) lifecycleReadResult {
			v, err := s.baselineViewsSnapshotSessions(ctx, user, since)
			return lifecycleReadResult{v, nil, err}
		}},
		{"rounds", func(s *Store, ctx context.Context, user string, _ int64) lifecycleReadResult {
			r := SyncViews_SessionRounds(s.Database, ctx, user, "z-last")
			return lifecycleReadResult{r.Value, nil, r.Error}
		}, func(s *Store, ctx context.Context, user string, _ int64) lifecycleReadResult {
			v, err := s.baselineViewsSnapshotSessionRounds(ctx, user, "z-last")
			return lifecycleReadResult{v, nil, err}
		}},
		{"meditations", func(s *Store, ctx context.Context, user string, since int64) lifecycleReadResult {
			r := SyncViews_MeditationsSince(s.Database, ctx, user, since)
			return lifecycleReadResult{r.Value, nil, r.Error}
		}, func(s *Store, ctx context.Context, user string, since int64) lifecycleReadResult {
			v, err := s.baselineViewsSnapshotMeditationLogs(ctx, user, since)
			return lifecycleReadResult{v, nil, err}
		}},
		{"social", func(s *Store, ctx context.Context, user string, since int64) lifecycleReadResult {
			r := SyncViews_SocialSince(s.Database, ctx, user, since)
			return lifecycleReadResult{r.Value, nil, r.Error}
		}, func(s *Store, ctx context.Context, user string, since int64) lifecycleReadResult {
			v, err := s.baselineViewsSnapshotSocialCache(ctx, user, since)
			return lifecycleReadResult{v, nil, err}
		}},
		{"records", func(s *Store, ctx context.Context, user string, since int64) lifecycleReadResult {
			r := SyncViews_RecordsSince(s.Database, ctx, user, since)
			return lifecycleReadResult{r.Value, nil, r.Error}
		}, func(s *Store, ctx context.Context, user string, since int64) lifecycleReadResult {
			v, err := s.baselineViewsSnapshotEncryptedRecords(ctx, user, since)
			return lifecycleReadResult{v, nil, err}
		}},
		{"operations", func(s *Store, ctx context.Context, user string, since int64) lifecycleReadResult {
			v, err := s.OpsSince(ctx, user, since)
			return lifecycleReadResult{v, nil, err}
		}, func(s *Store, ctx context.Context, user string, since int64) lifecycleReadResult {
			v, err := s.baselineViewsOpsSince(ctx, user, since)
			return lifecycleReadResult{v, nil, err}
		}},
		{"clean habits", func(s *Store, ctx context.Context, user string, _ int64) lifecycleReadResult {
			r := SyncViews_CleanHabits(s.Database, ctx, user)
			return lifecycleReadResult{r.Value, nil, r.Error}
		}, func(s *Store, ctx context.Context, user string, _ int64) lifecycleReadResult {
			v, err := s.baselineViewsCleanHabits(ctx, user)
			return lifecycleReadResult{v, nil, err}
		}},
		{"clean days", func(s *Store, ctx context.Context, user string, _ int64) lifecycleReadResult {
			r := SyncViews_CleanHabitDays(s.Database, ctx, user)
			return lifecycleReadResult{r.Value, nil, r.Error}
		}, func(s *Store, ctx context.Context, user string, _ int64) lifecycleReadResult {
			v, err := s.baselineViewsCleanHabitDays(ctx, user)
			return lifecycleReadResult{v, nil, err}
		}},
		{"clean sessions", func(s *Store, ctx context.Context, user string, _ int64) lifecycleReadResult {
			r := SyncViews_CleanSessions(s.Database, ctx, user)
			return lifecycleReadResult{r.Value, nil, r.Error}
		}, func(s *Store, ctx context.Context, user string, _ int64) lifecycleReadResult {
			v, err := s.baselineViewsCleanSessions(ctx, user)
			return lifecycleReadResult{v, nil, err}
		}},
		{"clean meditations", func(s *Store, ctx context.Context, user string, _ int64) lifecycleReadResult {
			r := SyncViews_CleanMeditations(s.Database, ctx, user)
			return lifecycleReadResult{r.Value, nil, r.Error}
		}, func(s *Store, ctx context.Context, user string, _ int64) lifecycleReadResult {
			v, err := s.baselineViewsCleanMeditationLogs(ctx, user)
			return lifecycleReadResult{v, nil, err}
		}},
		{"changes", func(s *Store, ctx context.Context, user string, since int64) lifecycleReadResult {
			v, version, err := s.ChangesSince(ctx, user, since)
			return lifecycleReadResult{v, version, err}
		}, func(s *Store, ctx context.Context, user string, since int64) lifecycleReadResult {
			v, version, err := s.baselineViewsChangesSince(ctx, user, since)
			return lifecycleReadResult{v, version, err}
		}},
		{"hash", func(s *Store, ctx context.Context, user string, _ int64) lifecycleReadResult {
			v, err := s.StateHash(ctx, user)
			return lifecycleReadResult{v, nil, err}
		}, func(s *Store, ctx context.Context, user string, _ int64) lifecycleReadResult {
			v, err := s.baselineViewsStateHash(ctx, user)
			return lifecycleReadResult{v, nil, err}
		}},
	}
}

func compareViewsRead(t *testing.T, got, want lifecycleReadResult) {
	t.Helper()
	if !reflect.DeepEqual(got.Value, want.Value) || !reflect.DeepEqual(got.Extra, want.Extra) || !sameIdentityError(got.Error, want.Error) {
		t.Fatalf("result changed: %#v; original %#v", got, want)
	}
	gotJSON, gotError := json.Marshal(got.Value)
	wantJSON, wantError := json.Marshal(want.Value)
	if string(gotJSON) != string(wantJSON) || !sameIdentityError(gotError, wantError) {
		t.Fatalf("wire bytes changed: %q; original %q", gotJSON, wantJSON)
	}
}

func TestZiranSyncViewsAgainstBaseline(t *testing.T) {
	store := viewsFixture(t)
	for _, test := range viewsReadCases() {
		t.Run(test.name, func(t *testing.T) {
			for _, user := range []string{lifecycleAccounts[0], lifecycleAccounts[1], "missing", "' OR 1=1 --", "\x00\xff"} {
				for _, since := range []int64{-9223372036854775808, -1, 0, 1, 2, 3, 20, 9223372036854775807} {
					ctx, cancel := context.WithTimeout(t.Context(), time.Second)
					got := test.actual(store, ctx, user, since)
					want := test.baseline(store, ctx, user, since)
					compareViewsRead(t, got, want)
					if err := store.Database.PingContext(ctx); err != nil {
						t.Fatal("read retained the database connection", err)
					}
					cancel()
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			got := test.actual(store, ctx, lifecycleAccounts[0], 0)
			compareViewsRead(t, got, test.baseline(store, ctx, lifecycleAccounts[0], 0))
			if got.Error != context.Canceled {
				t.Fatal("cancelled context identity changed", got.Error)
			}
		})
	}
	changes, _, err := store.ChangesSince(t.Context(), lifecycleAccounts[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	var recovered bool
	for _, habit := range changes.Habits {
		if habit.ID == "orphan" {
			recovered = habit.Name == "Recovered orphan" && habit.ColorR == 99 && habit.SortOrder == 1000
		}
	}
	if !recovered {
		t.Fatal("orphan recovery projection was lost")
	}
	for _, day := range changes.HabitDays {
		if day.Completed && day.Count <= 0 {
			t.Fatal("completed counts were not normalized")
		}
	}
}

func TestZiranCleanDataAgainstBaseline(t *testing.T) {
	store := viewsFixture(t)
	for _, user := range []string{lifecycleAccounts[0], lifecycleAccounts[1], "missing"} {
		got, gotError := store.CleanData(t.Context(), user)
		want, wantError := store.baselineViewsCleanData(t.Context(), user)
		for _, value := range []*CleanData{got, want} {
			if value != nil {
				for index := range value.Social {
					if _, err := time.Parse(CanonicalTimestampLayout, value.Social[index].UpdatedAt); err != nil {
						t.Fatal("authoritative social timestamp changed", err)
					}
					value.Social[index].UpdatedAt = "<timestamp>"
				}
			}
		}
		compareViewsRead(t, lifecycleReadResult{got, nil, gotError}, lifecycleReadResult{want, nil, wantError})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	got, err := store.CleanData(ctx, lifecycleAccounts[0])
	if got != nil || err != context.Canceled {
		t.Fatal("clean data did not preserve cancellation", got, err)
	}
}

func TestZiranSyncViewsPartialFailuresAgainstBaseline(t *testing.T) {
	for _, table := range []string{"server_habits", "server_habit_days", "server_sessions", "server_session_rounds", "server_meditation_logs", "server_social_snapshots", "server_encrypted_records", "server_sync_state"} {
		t.Run(table, func(t *testing.T) {
			store := viewsFixture(t)
			lifecycleExecute(t, store, "DROP TABLE "+table)
			for _, test := range viewsReadCases() {
				compareViewsRead(t, test.actual(store, t.Context(), lifecycleAccounts[0], 0), test.baseline(store, t.Context(), lifecycleAccounts[0], 0))
			}
			got, gotError := store.CleanData(t.Context(), lifecycleAccounts[0])
			want, wantError := store.baselineViewsCleanData(t.Context(), lifecycleAccounts[0])
			if gotError != nil || wantError != nil {
				compareViewsRead(t, lifecycleReadResult{got, nil, gotError}, lifecycleReadResult{want, nil, wantError})
			}
		})
	}
}

func TestZiranStateHashIncludesDeletedRecordsAndRounds(t *testing.T) {
	store := viewsFixture(t)
	user := lifecycleAccounts[0]
	before, err := store.StateHash(t.Context(), user)
	if err != nil || len(before) != 64 || strings.ToLower(before) != before {
		t.Fatal("invalid state hash", before, err)
	}
	for _, query := range []string{
		"UPDATE server_sessions SET note='changed deleted note' WHERE user_id_hash=?1 AND id='deleted'",
		"UPDATE server_session_rounds SET breaths=breaths+1 WHERE user_id_hash=?1 AND session_id='z-last'",
		"UPDATE server_encrypted_records SET content_hash='changed' WHERE user_id_hash=?1 AND deleted_at>0",
	} {
		lifecycleExecute(t, store, query, user)
		after, err := store.StateHash(t.Context(), user)
		want, wantError := store.baselineViewsStateHash(t.Context(), user)
		if err != nil || wantError != nil || after != want || after == before {
			t.Fatal("state hash ignored changed data or changed bytes", after, want, before, err, wantError)
		}
		before = after
	}
}
