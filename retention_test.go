package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func retentionExecute(t *testing.T, store *Store, query string, arguments ...any) {
	t.Helper()
	if _, err := store.Database.Exec(query, arguments...); err != nil {
		t.Fatal(err)
	}
}

func retentionCount(t *testing.T, store *Store, query string, arguments ...any) int {
	t.Helper()
	var count int
	if err := store.Database.QueryRow(query, arguments...).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func retentionPrune(t *testing.T, store *Store, now time.Time) {
	t.Helper()
	if err := Retention_Prune(store.Database, t.Context(), now); err != nil {
		t.Fatal(err)
	}
}

func chatUsageRows(t *testing.T, store *Store) []string {
	t.Helper()
	rows, err := store.Database.Query("SELECT account_id,day FROM server_chat_usage")
	if err != nil {
		t.Fatal(err)
	}
	defer ignoreCleanupError(rows.Close)
	var result []string
	for rows.Next() {
		var account, day string
		if err := rows.Scan(&account, &day); err != nil {
			t.Fatal(err)
		}
		result = append(result, account+"/"+day)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	sort.Strings(result)
	return result
}

func TestRetentionDeletesOldAndOrphanedChatCounts(t *testing.T) {
	server, store, _ := testServer(t)
	handler := server.Routes()
	account := newTestIdentity(t, handler, 0xc1)
	deleted := strings.Repeat("e", 64)
	for _, row := range [][2]string{
		{account.UserID, "2026-10-13"}, {account.UserID, "2026-09-13"}, {account.UserID, "2026-09-12"},
		{"node", "2026-10-13"}, {"node", "2026-09-01"}, {deleted, "2026-10-13"},
	} {
		retentionExecute(t, store, "INSERT INTO server_chat_usage(account_id,day,used) VALUES(?1,?2,1)", row[0], row[1])
	}
	retentionPrune(t, store, time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC))
	want := []string{account.UserID + "/2026-09-13", account.UserID + "/2026-10-13", "node/2026-10-13"}
	sort.Strings(want)
	if got := chatUsageRows(t, store); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("chat counts after pruning: %v, want %v", got, want)
	}
	if retentionCount(t, store, "SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'server_lumi%'") != 0 {
		t.Fatal("pruning created Lumi tables on a node without Lumi")
	}
	// Deleting the account removes its counts at once; the node's total stays.
	if err := store.DeleteAccount(t.Context(), account.UserID); err != nil {
		t.Fatal(err)
	}
	if got := chatUsageRows(t, store); fmt.Sprint(got) != "[node/2026-10-13]" {
		t.Fatalf("chat counts after account deletion: %v", got)
	}
}

func TestRetentionRunPrunesAtStartAndEachInterval(t *testing.T) {
	_, store, _ := testServer(t)
	context, cancel := context.WithCancel(t.Context())
	defer cancel()
	finished := make(chan struct{})
	retentionExecute(t, store, "INSERT INTO server_chat_usage(account_id,day,used) VALUES('node','2000-01-01',1)")
	go func() {
		Retention_Run(store.Database, context, 20*time.Millisecond, filepath.Join(t.TempDir(), "node.sqlite"), 30)
		close(finished)
	}()
	for _, day := range []string{"2000-01-01", "2000-01-02"} {
		if day != "2000-01-01" {
			retentionExecute(t, store, "INSERT INTO server_chat_usage(account_id,day,used) VALUES('node',?1,1)", day)
		}
		deadline := time.Now().Add(5 * time.Second)
		for retentionCount(t, store, "SELECT COUNT(*) FROM server_chat_usage WHERE day=?1", day) != 0 {
			if time.Now().After(deadline) {
				t.Fatalf("retention job did not prune %s", day)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("retention job did not stop with its context")
	}
}

type lumiRetention struct {
	server  *Server
	store   *Store
	handler http.Handler
	owner   testIdentity
	client  string
}

func newLumiRetention(t *testing.T) lumiRetention {
	t.Helper()
	server, store, _ := testServer(t)
	server.Cfg.LumiBotToken = "fixture-token"
	server.Cfg.LumiWebhookSecret = "fixture-secret"
	telegram := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"ok":true}`)
	}))
	t.Cleanup(telegram.Close)
	original := TelegramAPIBase
	TelegramAPIBase = telegram.URL
	t.Cleanup(func() { TelegramAPIBase = original })
	handler := server.Routes()
	owner := newTestIdentity(t, handler, 0xc2)
	server.Cfg.LumiOwnerID = owner.UserID
	return lumiRetention{server: server, store: store, handler: handler, owner: owner, client: strings.Repeat("c", 64)}
}

func (lumi lumiRetention) poll(t *testing.T) LumiPoll {
	t.Helper()
	out := lumiRequest(lumi.handler, lumi.owner, "GET", "/api/v1/lumi/telegram/updates?client="+lumi.client, "")
	var result LumiPoll
	if out.Code != 200 || json.Unmarshal(out.Body.Bytes(), &result) != nil {
		t.Fatalf("poll: %d %s", out.Code, out.Body.String())
	}
	return result
}

func (lumi lumiRetention) ack(t *testing.T, id int64) {
	t.Helper()
	out := lumiRequest(lumi.handler, lumi.owner, "POST", "/api/v1/lumi/telegram/ack", fmt.Sprintf(`{"id":%d,"client":"%s"}`, id, lumi.client))
	if out.Code != 200 {
		t.Fatalf("ack: %d %s", out.Code, out.Body.String())
	}
}

func (lumi lumiRetention) report(t *testing.T, reporter testIdentity, id byte, message string) {
	t.Helper()
	report := `{"id":"` + strings.Repeat(string(id), 64) + `","app_id":"inbe","title":"Report","message":"` + message + `"}`
	if out := chatRequest(lumi.handler, reporter, "/api/v1/feedback", report); out.Code != 200 {
		t.Fatalf("feedback: %d %s", out.Code, out.Body.String())
	}
}

func TestRetentionDeletesHandledTelegramUpdatesAndExpiredLinks(t *testing.T) {
	lumi := newLumiRetention(t)
	code := lumiLink(t, lumi.handler, lumi.owner)
	if out := lumiWebhook(lumi.handler, "fixture-secret", 2, "private", "/start "+code); out.Code != 200 {
		t.Fatalf("link: %d %s", out.Code, out.Body.String())
	}
	unused := lumiLink(t, lumi.handler, lumi.owner)
	lumiWebhook(lumi.handler, "fixture-secret", 10, "private", "Add tea to my list")
	if update := lumi.poll(t).Update; update.ID != 10 || update.Text != "Add tea to my list" {
		t.Fatalf("queued update: %+v", update)
	}
	lumi.ack(t, 10)
	var text string
	var done, doneAt int64
	if err := lumi.store.Database.QueryRow("SELECT text,done,done_at FROM server_lumi_updates WHERE id=10").Scan(&text, &done, &doneAt); err != nil {
		t.Fatal(err)
	}
	if text != "" || done != 1 || doneAt <= 0 {
		t.Fatalf("acknowledged update kept its text: %q done %d at %d", text, done, doneAt)
	}
	// Telegram's retry of a handled update stays recognised until the job
	// deletes its ID a day later.
	lumiWebhook(lumi.handler, "fixture-secret", 10, "private", "Add tea to my list")
	if update := lumi.poll(t).Update; update.ID != 0 {
		t.Fatalf("retried update ran again: %+v", update)
	}
	now := time.Now()
	retentionPrune(t, lumi.store, now)
	if retentionCount(t, lumi.store, "SELECT COUNT(*) FROM server_lumi_updates WHERE id=10") != 1 {
		t.Fatal("handled update ID was deleted before a day passed")
	}
	if retentionCount(t, lumi.store, "SELECT COUNT(*) FROM server_lumi_link_codes WHERE code IN (?1,?2)", code, unused) != 2 {
		t.Fatal("unexpired link codes were deleted")
	}
	retentionPrune(t, lumi.store, now.Add(11*time.Minute))
	if retentionCount(t, lumi.store, "SELECT COUNT(*) FROM server_lumi_link_codes") != 0 {
		t.Fatal("expired link codes were kept")
	}
	if retentionCount(t, lumi.store, "SELECT COUNT(*) FROM server_lumi_telegram WHERE account_id=?1", lumi.owner.UserID) != 1 {
		t.Fatal("pruning removed the Telegram link")
	}
	lumiWebhook(lumi.handler, "fixture-secret", 11, "private", "Still waiting")
	retentionPrune(t, lumi.store, now.Add(25*time.Hour))
	if retentionCount(t, lumi.store, "SELECT COUNT(*) FROM server_lumi_updates WHERE id=10") != 0 {
		t.Fatal("handled update was kept after a day")
	}
	if update := lumi.poll(t).Update; update.ID != 11 || update.Text != "Still waiting" {
		t.Fatalf("pruning removed an unhandled update: %+v", update)
	}
}

func TestRetentionOwnerFeedbackCopies(t *testing.T) {
	lumi := newLumiRetention(t)
	reporter := newTestIdentity(t, lumi.handler, 0xc3)
	other := newTestIdentity(t, lumi.handler, 0xc4)
	lumi.report(t, reporter, 'a', "First report")
	first := lumi.poll(t).Update
	if first.Kind != "feedback" || !strings.Contains(first.Text, "First report") {
		t.Fatalf("owner copy: %+v", first)
	}
	lumi.ack(t, first.ID)
	if retentionCount(t, lumi.store, "SELECT owner_delivered FROM server_app_feedback WHERE account_id=?1", reporter.UserID) != 1 {
		t.Fatal("acknowledged report was not marked delivered")
	}
	retentionPrune(t, lumi.store, time.Now())
	if retentionCount(t, lumi.store, "SELECT COUNT(*) FROM server_lumi_updates WHERE kind='feedback'") != 0 {
		t.Fatal("acknowledged owner copy was kept")
	}
	if update := lumi.poll(t).Update; update.ID != 0 {
		t.Fatalf("delivered report was copied again: %+v", update)
	}
	// The reporter's account deletion removes the owner's copy at once.
	lumi.report(t, reporter, 'b', "Second report")
	lumi.report(t, other, 'c', "Other report")
	if update := lumi.poll(t).Update; update.Kind != "feedback" {
		t.Fatalf("new owner copy: %+v", update)
	}
	if retentionCount(t, lumi.store, "SELECT COUNT(*) FROM server_lumi_updates WHERE kind='feedback'") != 2 {
		t.Fatal("owner copies were not made")
	}
	if err := lumi.store.DeleteAccount(t.Context(), reporter.UserID); err != nil {
		t.Fatal(err)
	}
	if retentionCount(t, lumi.store, "SELECT COUNT(*) FROM server_lumi_updates WHERE text LIKE '%Second report%'") != 0 {
		t.Fatal("owner copy outlived the reporter's account")
	}
	retentionPrune(t, lumi.store, time.Now())
	if update := lumi.poll(t).Update; !strings.Contains(update.Text, "Other report") {
		t.Fatalf("another reporter's copy was removed: %+v", update)
	}
}

func TestRetentionCleansCopiesFromBeforeAcknowledgementsRecordedDelivery(t *testing.T) {
	lumi := newLumiRetention(t)
	reporter := newTestIdentity(t, lumi.handler, 0xc5)
	gone := newTestIdentity(t, lumi.handler, 0xc6)
	lumi.report(t, reporter, 'd', "Acknowledged earlier")
	lumi.report(t, gone, 'e', "Account deleted earlier")
	lumi.poll(t)
	// Acknowledgements used to mark copies done and keep them, and the copy of
	// a deleted account's report stayed behind.
	retentionExecute(t, lumi.store, "UPDATE server_lumi_updates SET done=1,executor=?1 WHERE text LIKE '%Acknowledged earlier%'", lumi.client)
	retentionExecute(t, lumi.store, "INSERT INTO server_lumi_updates(id,account_id,kind,text,done,executor) VALUES(77,?1,'message','Old action',1,?2)", lumi.owner.UserID, lumi.client)
	retentionExecute(t, lumi.store, "DROP TRIGGER server_lumi_forget_report")
	if err := lumi.store.DeleteAccount(t.Context(), gone.UserID); err != nil {
		t.Fatal(err)
	}
	if retentionCount(t, lumi.store, "SELECT COUNT(*) FROM server_lumi_updates") != 3 {
		t.Fatal("legacy fixture is incomplete")
	}
	retentionPrune(t, lumi.store, time.Now())
	if count := retentionCount(t, lumi.store, "SELECT COUNT(*) FROM server_lumi_updates"); count != 0 {
		t.Fatalf("legacy updates were kept: %d", count)
	}
	if retentionCount(t, lumi.store, "SELECT owner_delivered FROM server_app_feedback WHERE account_id=?1", reporter.UserID) != 1 {
		t.Fatal("legacy acknowledged report was not marked delivered")
	}
	if update := lumi.poll(t).Update; update.ID != 0 {
		t.Fatalf("legacy acknowledged report was copied again: %+v", update)
	}
	if retentionCount(t, lumi.store, "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name='server_lumi_forget_report'") != 1 {
		t.Fatal("the report trigger was not restored")
	}
}
