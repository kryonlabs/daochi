package main

import (
	"fmt"
	"strings"
	"testing"
)

// Independent billable-content calculation, separate from counter SQL.
const storageUsageReference = `SELECT
 (SELECT COALESCE(SUM(CASE WHEN deleted_at<>0 THEN 0 WHEN collection IN ('inbe.habits','inbe.habit_days','private.inbe.v1.habits','private.inbe.v1.habit-days','private.inbe.v1.habit-settings','private.inbe.v1.habit-changes','private.inbe.v1.habit-rewards','private.inbe.v1.habit-coins','private.inbe.v1.app-preferences','private.inbe.v1.app-order','private.inbe.v1.app-installs','private.inbe.v1.achievements','private.entity.v1.game-progress','private.entity.v1.profile') THEN 0 ELSE MAX(0,LENGTH(collection)+LENGTH(id)+LENGTH(key_id)+LENGTH(nonce)+LENGTH(ciphertext)+LENGTH(content_hash)+LENGTH(parent_id)-CASE WHEN collection IN ('inbe.sessions','private.inbe.v1.sessions','private.inbe.v1.habit-entries') THEN MIN(524288,MAX(0,free_bytes)) ELSE 0 END) END),0) FROM server_encrypted_records WHERE user_id_hash=?1)
+(SELECT COALESCE(SUM(LENGTH(client_id)+LENGTH(payload_json)),0) FROM server_encrypted_payloads WHERE user_id_hash=?1)
+(SELECT COALESCE(SUM(size),0) FROM server_blobs WHERE user_id_hash=?1 AND trashed_at=0)
+(SELECT COALESCE(SUM(LENGTH(id)+LENGTH(title)+LENGTH(items)),0) FROM server_shared_lists WHERE owner=?1)
+(SELECT COALESCE(SUM(LENGTH(i.id)+LENGTH(i.target)+LENGTH(i.status)),0) FROM server_list_invitations i JOIN server_shared_lists l ON l.id=i.list_id WHERE l.owner=?1)
+(SELECT COALESCE(SUM(LENGTH(p.access)),0) FROM server_list_permissions p JOIN server_shared_lists l ON l.id=p.list_id WHERE l.owner=?1)
+(SELECT COALESCE(SUM(LENGTH(request_id)+LENGTH(body)),0) FROM server_list_commands WHERE user_id=?1)
+(SELECT COALESCE(SUM(LENGTH(id)+LENGTH(format)+LENGTH(title)+LENGTH(document)),0) FROM server_publications WHERE author=?1)
+(SELECT COALESCE(SUM(LENGTH(nonce)+LENGTH(ciphertext)),0) FROM server_record_packing WHERE user_id_hash=?1 AND collection NOT IN ('inbe.habits','inbe.habit_days','private.inbe.v1.habits','private.inbe.v1.habit-days','private.inbe.v1.habit-settings','private.inbe.v1.habit-changes','private.inbe.v1.habit-rewards','private.inbe.v1.habit-coins','private.inbe.v1.app-preferences','private.inbe.v1.app-order','private.inbe.v1.app-installs','private.inbe.v1.achievements','private.entity.v1.game-progress','private.entity.v1.profile','inbe.sessions','private.inbe.v1.sessions','private.inbe.v1.habit-entries'))`

func assertStorageUsage(t *testing.T, store *Store, users ...string) {
	t.Helper()
	for _, user := range users {
		var want int64
		if err := store.Database.QueryRow(storageUsageReference, user).Scan(&want); err != nil {
			t.Fatal(err)
		}
		got := AccountStorage_Used(store.Database, t.Context(), user)
		if got.Error != nil || got.Value != want {
			t.Fatalf("usage for %q: got %d, want %d, error %v", user, got.Value, want, got.Error)
		}
	}
}

func TestStorageUsageTracksWritesRollbackOwnershipAndCascades(t *testing.T) {
	_, store, _ := testServer(t)
	users := []string{strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)}
	for _, user := range users {
		if err := store.RegisterUser(t.Context(), user, []byte("fixture")); err != nil {
			t.Fatal(err)
		}
	}
	a, b, c := users[0], users[1], users[2]
	statements := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO server_encrypted_records(user_id_hash,collection,id,ciphertext,updated_at) VALUES(?1,'private.inbe.v1.cells','record','héllo 世界','2026-10-25')`, []any{a}},
		{`INSERT INTO server_encrypted_payloads(user_id_hash,client_id,payload_json) VALUES(?1,'client','{"ciphertext":"opaque"}')`, []any{a}},
		{`INSERT INTO server_blobs(user_id_hash,app_id,hash,size) VALUES(?1,'entity','blob',1000)`, []any{a}},
		{`INSERT INTO server_shared_lists(id,owner,title,items,revision) VALUES('list',?1,'A list','[]',1)`, []any{a}},
		{`INSERT INTO server_list_invitations(id,list_id,target,status) VALUES('invitation','list',?1,'accepted')`, []any{b}},
		{`INSERT INTO server_list_permissions(list_id,target,access) VALUES('list',?1,'editor')`, []any{b}},
		{`INSERT INTO server_list_commands(user_id,request_id,body) VALUES(?1,'command','{"action":"save"}')`, []any{a}},
		{`INSERT INTO server_publications(id,author,format,title,visibility,document,created_at,updated_at) VALUES('publication',?1,'levels','My level','private','{"level":1}',1,1)`, []any{a}},
		{`UPDATE server_encrypted_records SET user_id_hash=?1,ciphertext='a longer value',key_id='key' WHERE id='record'`, []any{b}},
		{`INSERT OR REPLACE INTO server_encrypted_records(user_id_hash,collection,id,ciphertext,updated_at) VALUES(?1,'private.inbe.v1.cells','record','replacement','2026-10-25')`, []any{b}},
		{`UPDATE server_encrypted_payloads SET payload_json='a new envelope',user_id_hash=?1`, []any{b}},
		{`UPDATE server_blobs SET size=30,user_id_hash=?1`, []any{b}},
		{`UPDATE server_publications SET author=?1,title='Revised'`, []any{b}},
		{`UPDATE server_shared_lists SET owner=?1,title='Transferred list' WHERE id='list'`, []any{c}},
		{`UPDATE server_list_permissions SET access='viewer'`, nil},
		{`DELETE FROM server_users WHERE user_id_hash=?1`, []any{b}},
		{`DELETE FROM server_shared_lists WHERE id='list'`, nil},
		{`DELETE FROM server_list_commands`, nil},
	}
	for i, statement := range statements {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if _, err := store.Database.Exec(statement.sql, statement.args...); err != nil {
				t.Fatal(err)
			}
			assertStorageUsage(t, store, users...)
		})
	}
	tx, err := store.Database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO server_blobs(user_id_hash,app_id,hash,size) VALUES(?1,'entity','rolled-back',99)`, a); err != nil {
		t.Fatal(err)
	}
	used := AccountStorage_UsedTx(tx, t.Context(), a)
	if used.Error != nil || used.Value != 99 {
		t.Fatalf("transaction counter: %#v", used)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	assertStorageUsage(t, store, users...)
}

func TestStorageUsageBackfillsLegacyDatabaseAndReconciles(t *testing.T) {
	_, store, _ := testServer(t)
	rows, err := store.Database.Query(`SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE 'server_storage_usage_%'`)
	if err != nil {
		t.Fatal(err)
	}
	var triggers []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		triggers = append(triggers, name)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	for _, trigger := range triggers {
		if _, err := store.Database.Exec(`DROP TRIGGER "` + trigger + `"`); err != nil {
			t.Fatal(err)
		}
	}
	lifecycleExecute(t, store, `DROP TABLE server_storage_usage`)
	user := strings.Repeat("d", 64)
	if err := store.RegisterUser(t.Context(), user, []byte("legacy")); err != nil {
		t.Fatal(err)
	}
	lifecycleExecute(t, store, `INSERT INTO server_blobs(user_id_hash,app_id,hash,size) VALUES(?1,'entity','legacy',1234)`, user)
	lifecycleExecute(t, store, `INSERT INTO server_encrypted_records(user_id_hash,collection,id,ciphertext,updated_at) VALUES(?1,'private.inbe.v1.cells','legacy-record','legacy cipher','2026-10-25')`, user)
	lifecycleExecute(t, store, `INSERT INTO server_encrypted_payloads(user_id_hash,client_id,payload_json) VALUES(?1,'client','legacy envelope')`, user)
	lifecycleExecute(t, store, `INSERT INTO server_shared_lists(id,owner,title,items,revision) VALUES('legacy-list',?1,'Legacy','[]',1)`, user)
	lifecycleExecute(t, store, `INSERT INTO server_list_invitations(id,list_id,target,status) VALUES('legacy-invite','legacy-list',?1,'accepted')`, user)
	lifecycleExecute(t, store, `INSERT INTO server_list_permissions(list_id,target,access) VALUES('legacy-list',?1,'editor')`, user)
	lifecycleExecute(t, store, `INSERT INTO server_list_commands(user_id,request_id,body) VALUES(?1,'legacy-command','legacy body')`, user)
	lifecycleExecute(t, store, `INSERT INTO server_publications(id,author,format,title,visibility,document,created_at,updated_at) VALUES('legacy-publication',?1,'levels','Legacy','private','{}',1,1)`, user)
	lifecycleExecute(t, store, `INSERT INTO server_record_packing(user_id_hash,collection,id,nonce,ciphertext) VALUES(?1,'private.inbe.v1.cells','legacy-record','packed nonce','packed body')`, user)
	lifecycleExecute(t, store, `INSERT INTO game_maps(game,level,map_hash,map,created_at) VALUES('shovey.classic',1,'legacy-map','archived map',1)`)
	lifecycleExecute(t, store, `INSERT INTO game_completions(account_id,id,game,level,map_hash,moves,actions,trace,evidence_complete,payload,created_at) VALUES(?1,'legacy-completion','shovey.classic',1,'legacy-map',10,'0123','001002',1,'{"moves":10}',1)`, user)
	for i := 0; i < 2; i++ {
		if err := StoreSchema_Ensure(store.Database, t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := StorageUsage_Ensure(store.Database, t.Context()); err != nil {
			t.Fatal(err)
		}
		assertStorageUsage(t, store, user)
	}
	lifecycleExecute(t, store, `UPDATE server_storage_usage SET used_bytes=0 WHERE user_id_hash=?1`, user)
	if err := StorageUsage_Reconcile(store.Database, t.Context(), user); err != nil {
		t.Fatal(err)
	}
	assertStorageUsage(t, store, user)
	lifecycleExecute(t, store, `DELETE FROM server_users WHERE user_id_hash=?1`, user)
	var count int
	if err := store.Database.QueryRow(`SELECT COUNT(*) FROM server_storage_usage`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("account deletion retained a counter: %d %v", count, err)
	}
}

func TestStorageUsageUpgradeReplacesOldChargeTriggersForEveryAccount(t *testing.T) {
	_, store, _ := testServer(t)
	users := []string{strings.Repeat("1", 64), strings.Repeat("2", 64)}
	for _, user := range users {
		if err := store.RegisterUser(t.Context(), user, []byte("fixture")); err != nil {
			t.Fatal(err)
		}
		lifecycleExecute(t, store, `INSERT INTO server_encrypted_records(user_id_hash,collection,id,ciphertext,updated_at) VALUES(?1,'private.entity.v1.game-progress','progress','encrypted progress','2026-10-25')`, user)
		lifecycleExecute(t, store, `UPDATE server_storage_usage SET used_bytes=999 WHERE user_id_hash=?1`, user)
	}
	// Simulate an installed v3 counter and its old insert trigger.
	lifecycleExecute(t, store, `UPDATE server_storage_usage_version SET version=3`)
	lifecycleExecute(t, store, `DROP TRIGGER server_storage_usage_server_encrypted_records_insert`)
	lifecycleExecute(t, store, `CREATE TRIGGER server_storage_usage_server_encrypted_records_insert AFTER INSERT ON server_encrypted_records BEGIN UPDATE server_storage_usage SET used_bytes=used_bytes+999 WHERE user_id_hash=NEW.user_id_hash; END`)
	for i := 0; i < 2; i++ {
		if err := StorageUsage_Ensure(store.Database, t.Context()); err != nil {
			t.Fatal(err)
		}
		for _, user := range users {
			used := AccountStorage_Used(store.Database, t.Context(), user)
			if used.Error != nil || used.Value != 0 {
				t.Fatalf("upgrade retained a progress charge: %#v", used)
			}
		}
	}
	for _, user := range users {
		lifecycleExecute(t, store, `INSERT INTO server_encrypted_records(user_id_hash,collection,id,ciphertext,updated_at) VALUES(?1,'private.inbe.v1.habit-days','day','more progress','2026-10-25')`, user)
		lifecycleExecute(t, store, `UPDATE server_encrypted_records SET ciphertext='updated progress' WHERE user_id_hash=?1`, user)
		assertStorageUsage(t, store, user)
	}
}

func TestCompletionUsageExportDeletionKeepsPublicMapArchive(t *testing.T) {
	_, store, _ := testServer(t)
	first, second := strings.Repeat("e", 64), strings.Repeat("f", 64)
	for _, user := range []string{first, second} {
		if err := store.RegisterUser(t.Context(), user, []byte("fixture")); err != nil {
			t.Fatal(err)
		}
	}
	lifecycleExecute(t, store, `INSERT INTO game_maps(game,level,map_hash,map,created_at) VALUES('shovey.classic',1,'map-hash','immutable map',1)`)
	lifecycleExecute(t, store, `INSERT INTO game_map_sources(game,level,map_hash,source_version,created_at) VALUES('shovey.classic',1,'map-hash','source',1)`)
	for _, user := range []string{first, second} {
		lifecycleExecute(t, store, `INSERT INTO game_completions(account_id,id,game,level,map_hash,moves,actions,trace,evidence_complete,payload,created_at) VALUES(?1,'complete','shovey.classic',1,'map-hash',10,'0123','001002',1,'{"moves":10}',1)`, user)
	}
	assertStorageUsage(t, store, first, second)
	exported := AccountExport_Export(store.Database, t.Context(), first)
	if exported.Error != nil || len(exported.Value.Tables["game_completions"]) != 1 {
		t.Fatalf("completion export: %#v", exported)
	}
	if _, present := exported.Value.Tables["game_maps"]; present {
		t.Fatal("public maps became private account data")
	}
	lifecycleExecute(t, store, `UPDATE game_completions SET actions='01230123',trace='001002003004' WHERE account_id=?1`, first)
	assertStorageUsage(t, store, first, second)
	transaction, err := store.Database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(`DELETE FROM game_completions WHERE account_id=?1`, first); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Rollback(); err != nil {
		t.Fatal(err)
	}
	assertStorageUsage(t, store, first, second)
	lifecycleExecute(t, store, `DELETE FROM server_users WHERE user_id_hash=?1`, first)
	assertStorageUsage(t, store, first, second)
	for table, want := range map[string]int{"game_completions": 1, "game_maps": 1, "game_map_sources": 1} {
		var count int
		if err := store.Database.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != want {
			t.Fatalf("%s count %d want %d: %v", table, count, want, err)
		}
	}
	remaining := AccountExport_Export(store.Database, t.Context(), second)
	if remaining.Error != nil || len(remaining.Value.Tables["game_completions"]) != 1 {
		t.Fatal("deleting one account changed another account's history", remaining.Error)
	}
}
