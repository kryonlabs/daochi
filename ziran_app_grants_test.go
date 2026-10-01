package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func grantStoreFixture(t *testing.T) *Store {
	t.Helper()
	store := appStoreFixture(t)
	if _, err := store.Database.Exec(`
CREATE TABLE IF NOT EXISTS server_users (
	user_id_hash TEXT PRIMARY KEY,
	public_key BLOB NOT NULL,
	alias TEXT UNIQUE,
	profile_icon INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS server_sync_state (
	user_id_hash TEXT PRIMARY KEY REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	server_version INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS server_app_grants (
	id TEXT PRIMARY KEY,
	user_id_hash TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	source_app_id TEXT NOT NULL REFERENCES server_apps(app_id) ON DELETE CASCADE,
	target_app_id TEXT NOT NULL REFERENCES server_apps(app_id) ON DELETE CASCADE,
	collection_prefix TEXT NOT NULL,
	permission TEXT NOT NULL DEFAULT 'read',
	status TEXT NOT NULL DEFAULT 'active',
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	revoked_at TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS server_app_grant_audit (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	grant_id TEXT NOT NULL,
	user_id_hash TEXT NOT NULL,
	action TEXT NOT NULL,
	payload_json TEXT NOT NULL DEFAULT '{}',
	created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS server_encrypted_records (
	user_id_hash TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
	collection TEXT NOT NULL,
	id TEXT NOT NULL,
	key_id TEXT NOT NULL DEFAULT '',
	nonce TEXT NOT NULL DEFAULT '',
	ciphertext TEXT NOT NULL DEFAULT '',
	updated_at TEXT NOT NULL,
	deleted_at INTEGER NOT NULL DEFAULT 0,
	content_hash TEXT NOT NULL DEFAULT '',
	schema_version INTEGER NOT NULL DEFAULT 0,
	parent_id TEXT NOT NULL DEFAULT '',
	server_version INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY(user_id_hash, collection, id)
);


INSERT INTO server_users(user_id_hash,public_key,last_seen_at) VALUES('account',X'42','before'),('other',X'43','before');
INSERT INTO server_apps(app_id,display_name) VALUES('source','Source'),('target','Target');
INSERT INTO server_app_collections(app_id,collection_prefix,visibility) VALUES
('source','shared.source.v1.*','shared'),('source','private.source.v1.*','private'),
('source','shared.source.v1.exact','shared'),('source','shared.source_a.v1.*','shared');
INSERT INTO server_encrypted_records(user_id_hash,collection,id,key_id,nonce,ciphertext,updated_at,deleted_at,content_hash,schema_version,parent_id) VALUES
('account','shared.source.v1.z','z','key','n','cipher-z','2026-09-30T00:00:00Z',0,'hash-z',7,'parent'),
('account','shared.source.v1.a','b','key','n','cipher-b','2026-09-30T00:00:00Z',0,'hash-b',7,''),
('account','shared.source.v1.a','a','key','n','cipher-a','2026-09-30T00:00:00Z',1,'hash-a',7,''),
('account','shared.source.v1.exact','exact','key','n','cipher-exact','2026-09-30T00:00:00Z',0,'hash-exact',7,''),
('account','shared.source_a.v1.item','underscore','key','n','cipher','2026-09-30T00:00:00Z',0,'hash',7,''),
('account','shared.sourceXa.v1.item','escaped','key','n','cipher','2026-09-30T00:00:00Z',0,'hash',7,''),
('account','private.source.v1.item','private','key','n','private-cipher','2026-09-30T00:00:00Z',0,'hash',7,''),
('other','shared.source.v1.a','foreign','key','n','foreign-cipher','2026-09-30T00:00:00Z',0,'hash',7,'');
`); err != nil {
		t.Fatal(err)
	}
	return store
}

func grantSnapshot(t *testing.T, store *Store) map[string][][]string {
	t.Helper()
	result := make(map[string][][]string)
	queries := map[string]string{
		"users":  "SELECT user_id_hash,last_seen_at<>'before' FROM server_users ORDER BY user_id_hash",
		"state":  "SELECT user_id_hash,server_version FROM server_sync_state ORDER BY user_id_hash",
		"grants": "SELECT id,user_id_hash,source_app_id,target_app_id,collection_prefix,permission,status,revoked_at<>'' FROM server_app_grants ORDER BY id",
		"audit":  "SELECT grant_id,user_id_hash,action,payload_json FROM server_app_grant_audit ORDER BY id",
	}
	for name, query := range queries {
		rows, err := store.Database.Query(query)
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			values := make([]string, len(columns))
			pointers := make([]any, len(columns))
			for index := range values {
				pointers[index] = &values[index]
			}
			if err := rows.Scan(pointers...); err != nil {
				t.Fatal(err)
			}
			result[name] = append(result[name], values)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return result
}

func withoutGrantClocks(grant AppGrant) AppGrant {
	grant.CreatedAt = ""
	grant.UpdatedAt = ""
	if grant.RevokedAt != "" {
		grant.RevokedAt = "revoked"
	}
	return grant
}

func compareGrantCreate(t *testing.T, actual, expected *Store, ctx context.Context, user string, request AppGrantRequest, seed byte) GrantResult {
	t.Helper()
	original := rand.Reader
	defer func() { rand.Reader = original }()
	rand.Reader = bytes.NewReader(bytes.Repeat([]byte{seed}, 16))
	got := AppGrants_Create(actual.Database, ctx, user, request, ErrSyncUserNotFound)
	rand.Reader = bytes.NewReader(bytes.Repeat([]byte{seed}, 16))
	want, err := expected.baselineCreateAppGrant(ctx, user, request)
	if !sameIdentityError(got.Error, err) || !reflect.DeepEqual(withoutGrantClocks(got.Value), withoutGrantClocks(want)) {
		t.Fatalf("grant create = %#v, baseline = %#v, %v", got, want, err)
	}
	return got
}

func compareGrantState(t *testing.T, actual, expected *Store) {
	t.Helper()
	if got, want := grantSnapshot(t, actual), grantSnapshot(t, expected); !reflect.DeepEqual(got, want) {
		t.Fatalf("grant state = %#v, baseline = %#v", got, want)
	}
	for _, user := range []string{"account", "other", "missing"} {
		got := AppGrants_List(actual.Database, t.Context(), user)
		want, err := expected.baselineListAppGrants(t.Context(), user)
		for index := range got.Value {
			got.Value[index] = withoutGrantClocks(got.Value[index])
		}
		for index := range want {
			want[index] = withoutGrantClocks(want[index])
		}
		if !sameIdentityError(got.Error, err) || !reflect.DeepEqual(got.Value, want) {
			t.Fatalf("grant list %q = %#v, baseline = %#v, %v", user, got, want, err)
		}
	}
}

func compareGrantedRecords(t *testing.T, actual, expected *Store, ctx context.Context, user, source, target, prefix string) GrantedRecordsResult {
	t.Helper()
	got := AppGrants_AuthorizedRecords(actual.Database, ctx, user, source, target, prefix, errAppScopeNotOwned, ErrSyncUserNotFound)
	want, err := expected.baselineAuthorizedAppRecords(ctx, user, source, target, prefix)
	if !sameIdentityError(got.Error, err) || !reflect.DeepEqual(got.Value, want) {
		t.Fatalf("record access %q, %q, %q, %q = %#v, baseline = %#v, %v", user, source, target, prefix, got, want, err)
	}
	return got
}

func TestZiranAppGrantLifecycleAgainstBaseline(t *testing.T) {
	actual, expected := grantStoreFixture(t), grantStoreFixture(t)
	compareGrantState(t, actual, expected)
	denied := compareGrantedRecords(t, actual, expected, t.Context(), "account", "source", "target", "shared.source.v1.*")
	if denied.Error != ErrSyncUserNotFound || denied.Value != nil {
		t.Fatal("grant-free cross-app read was permitted", denied)
	}
	request := AppGrantRequest{SourceAppID: "source", TargetAppID: "target", CollectionPrefix: "shared.source.v1.*"}
	created := compareGrantCreate(t, actual, expected, t.Context(), "account", request, 0x42)
	if created.Error != nil || !Identity_ValidResourceID(created.Value.ID) || created.Value.Permission != "read" {
		t.Fatal("valid grant failed", created)
	}
	for _, user := range []string{"account", "other", "missing"} {
		got := AppGrants_ByID(actual.Database, t.Context(), user, created.Value.ID)
		want, err := expected.baselineAppGrantByID(t.Context(), user, created.Value.ID)
		if !sameIdentityError(got.Error, err) || !reflect.DeepEqual(withoutGrantClocks(got.Value), withoutGrantClocks(want)) {
			t.Fatalf("grant detail %q = %#v, baseline = %#v, %v", user, got, want, err)
		}
	}
	allowed := compareGrantedRecords(t, actual, expected, t.Context(), "account", "\u2003source\t", " target ", " shared.source.v1.* ")
	if allowed.Error != nil || len(allowed.Value) != 4 || allowed.Value[0].ID != "a" {
		t.Fatal("granted records lost scope or ordering", allowed)
	}
	compareGrantedRecords(t, actual, expected, t.Context(), "other", "source", "target", "shared.source.v1.*")
	for _, user := range []string{"other", "account", "account"} {
		got := AppGrants_Revoke(actual.Database, t.Context(), user, created.Value.ID)
		want := expected.baselineRevokeAppGrant(t.Context(), user, created.Value.ID)
		if !sameIdentityError(got, want) {
			t.Fatalf("grant revocation %q = %v, baseline = %v", user, got, want)
		}
		compareGrantState(t, actual, expected)
	}
	compareGrantedRecords(t, actual, expected, t.Context(), "account", "source", "target", "shared.source.v1.*")
	for _, prefix := range []string{"shared.source.v1.*", "shared.source.v1.exact", "private.source.v1.*", "shared.source_a.v1.*"} {
		own := compareGrantedRecords(t, actual, expected, t.Context(), "account", "source", "source", prefix)
		if own.Error != nil {
			t.Fatal("own-app read required a grant", own)
		}
		if prefix == "shared.source_a.v1.*" && (len(own.Value) != 1 || own.Value[0].ID != "underscore") {
			t.Fatal("SQL wildcard escaping leaked another scope", own)
		}
	}
	for _, prefix := range []string{"shared.source.v1.*", "shared.source.v1.exact", "nothing.*", "shared.source_a.v1.*", "shared.source%.v1.*", "shared.source\\.v1.*", ""} {
		got := AppGrants_Records(actual.Database, t.Context(), "account", prefix)
		want, err := expected.baselineSnapshotEncryptedRecordsByCollectionPrefix(t.Context(), "account", prefix)
		if !sameIdentityError(got.Error, err) || !reflect.DeepEqual(got.Value, want) {
			t.Fatalf("snapshot %q = %#v, baseline = %#v, %v", prefix, got, want, err)
		}
	}
}

func TestZiranAppGrantValidationOrderAgainstBaseline(t *testing.T) {
	for _, mode := range []string{"missing source", "missing target", "inactive source", "inactive target", "missing scope", "private scope", "missing user", "exact scope", "non-read permission", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			actual, expected := grantStoreFixture(t), grantStoreFixture(t)
			request := AppGrantRequest{SourceAppID: "source", TargetAppID: "target", CollectionPrefix: "shared.source.v1.*"}
			user := "account"
			ctx := t.Context()
			query := ""
			switch mode {
			case "missing source":
				request.SourceAppID = "missing"
			case "missing target":
				request.TargetAppID = "missing"
			case "inactive source":
				query = "UPDATE server_apps SET status='suspended' WHERE app_id='source'"
			case "inactive target":
				query = "UPDATE server_apps SET status='suspended' WHERE app_id='target'"
			case "missing scope":
				request.CollectionPrefix = "shared.source.v1.unregistered"
			case "private scope":
				request.CollectionPrefix = "private.source.v1.*"
			case "missing user":
				user = "missing"
			case "exact scope":
				request.CollectionPrefix = "shared.source.v1.exact"
			case "non-read permission":
				request.Permission = "write"
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			if query != "" {
				for _, store := range []*Store{actual, expected} {
					if _, err := store.Database.Exec(query); err != nil {
						t.Fatal(err)
					}
				}
			}
			got := compareGrantCreate(t, actual, expected, ctx, user, request, 0x42)
			if mode == "cancelled" && got.Error != context.Canceled {
				t.Fatal("native cancellation identity changed", got)
			}
			compareGrantState(t, actual, expected)
			compareGrantedRecords(t, actual, expected, ctx, user, request.SourceAppID, request.TargetAppID, request.CollectionPrefix)
		})
	}
	actual, expected := grantStoreFixture(t), grantStoreFixture(t)
	for _, query := range [][3]string{{"", "target", "shared.source.v1.*"}, {"source", "", "shared.source.v1.*"}, {"source", "target", ""}, {"source", "missing", "missing"}} {
		compareGrantedRecords(t, actual, expected, t.Context(), "account", query[0], query[1], query[2])
	}
}

func TestZiranAppGrantTransactionsRollbackAgainstBaseline(t *testing.T) {
	for _, mode := range []string{"touch", "sync state", "grant", "audit", "commit", "post-commit read"} {
		t.Run(mode, func(t *testing.T) {
			actual, expected := grantStoreFixture(t), grantStoreFixture(t)
			query := ""
			switch mode {
			case "touch":
				query = "CREATE TRIGGER reject_grant BEFORE UPDATE ON server_users BEGIN SELECT RAISE(ABORT,'touch rejected'); END"
			case "sync state":
				query = "CREATE TRIGGER reject_grant BEFORE INSERT ON server_sync_state BEGIN SELECT RAISE(ABORT,'sync rejected'); END"
			case "grant":
				query = "CREATE TRIGGER reject_grant BEFORE INSERT ON server_app_grants BEGIN SELECT RAISE(ABORT,'grant rejected'); END"
			case "audit":
				query = "CREATE TRIGGER reject_grant BEFORE INSERT ON server_app_grant_audit BEGIN SELECT RAISE(ABORT,'audit rejected'); END"
			case "commit":
				query = `CREATE TABLE parent(id INTEGER PRIMARY KEY);
CREATE TABLE pending(id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED);
CREATE TRIGGER reject_grant AFTER INSERT ON server_app_grant_audit BEGIN INSERT INTO pending VALUES(99); END`
			case "post-commit read":
				query = "CREATE TRIGGER reject_grant AFTER INSERT ON server_app_grant_audit BEGIN UPDATE server_app_grants SET user_id_hash='other' WHERE id=NEW.grant_id; END"
			}
			for _, store := range []*Store{actual, expected} {
				if _, err := store.Database.Exec(query); err != nil {
					t.Fatal(err)
				}
			}
			before := grantSnapshot(t, actual)
			request := AppGrantRequest{SourceAppID: "source", TargetAppID: "target", CollectionPrefix: "shared.source.v1.*"}
			got := compareGrantCreate(t, actual, expected, t.Context(), "account", request, 0x42)
			if got.Error == nil {
				t.Fatal("forced grant failure was ignored")
			}
			if mode != "post-commit read" && !reflect.DeepEqual(grantSnapshot(t, actual), before) {
				t.Fatal("failed grant left partial account, sync, grant or audit changes")
			}
			compareGrantState(t, actual, expected)
			if _, err := actual.Database.Exec("DROP TRIGGER reject_grant"); err != nil {
				t.Fatal(err)
			}
			original := rand.Reader
			rand.Reader = bytes.NewReader(bytes.Repeat([]byte{0x43}, 16))
			defer func() { rand.Reader = original }()
			if created := AppGrants_Create(actual.Database, t.Context(), "account", request, ErrSyncUserNotFound); created.Error != nil {
				t.Fatal("failed transaction left connection unusable", created)
			}
		})
	}
	for _, mode := range []string{"update", "audit", "commit"} {
		t.Run("revoke "+mode, func(t *testing.T) {
			actual, expected := grantStoreFixture(t), grantStoreFixture(t)
			request := AppGrantRequest{SourceAppID: "source", TargetAppID: "target", CollectionPrefix: "shared.source.v1.*"}
			created := compareGrantCreate(t, actual, expected, t.Context(), "account", request, 0x42)
			query := "CREATE TRIGGER reject_grant BEFORE UPDATE ON server_app_grants BEGIN SELECT RAISE(ABORT,'revoke rejected'); END"
			if mode == "audit" {
				query = "CREATE TRIGGER reject_grant BEFORE INSERT ON server_app_grant_audit BEGIN SELECT RAISE(ABORT,'audit rejected'); END"
			}
			if mode == "commit" {
				query = `CREATE TABLE parent(id INTEGER PRIMARY KEY);
CREATE TABLE pending(id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED);
CREATE TRIGGER reject_grant AFTER INSERT ON server_app_grant_audit BEGIN INSERT INTO pending VALUES(99); END`
			}
			for _, store := range []*Store{actual, expected} {
				if _, err := store.Database.Exec(query); err != nil {
					t.Fatal(err)
				}
			}
			before := grantSnapshot(t, actual)
			got := AppGrants_Revoke(actual.Database, t.Context(), "account", created.Value.ID)
			want := expected.baselineRevokeAppGrant(t.Context(), "account", created.Value.ID)
			if got == nil || !sameIdentityError(got, want) || !reflect.DeepEqual(grantSnapshot(t, actual), before) {
				t.Fatal("failed revoke changed grant or audit state", got, want)
			}
			compareGrantState(t, actual, expected)
			if _, err := actual.Database.Exec("DROP TRIGGER reject_grant"); err != nil {
				t.Fatal(err)
			}
			if err := AppGrants_Revoke(actual.Database, t.Context(), "account", created.Value.ID); err != nil {
				t.Fatal("failed revocation left connection unusable", err)
			}
		})
	}
}

func TestZiranAppGrantQueryErrorsAgainstBaseline(t *testing.T) {
	for _, mode := range []string{"cancelled", "closed", "grant scan", "record scan"} {
		t.Run(mode, func(t *testing.T) {
			actual, expected := grantStoreFixture(t), grantStoreFixture(t)
			request := AppGrantRequest{SourceAppID: "source", TargetAppID: "target", CollectionPrefix: "shared.source.v1.*"}
			created := compareGrantCreate(t, actual, expected, t.Context(), "account", request, 0x42)
			ctx := t.Context()
			if mode == "cancelled" {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			for _, store := range []*Store{actual, expected} {
				if mode == "closed" {
					if err := store.Database.Close(); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "grant scan" {
					if _, err := store.Database.Exec(`ALTER TABLE server_app_grants RENAME TO grants;
CREATE VIEW server_app_grants AS SELECT id,user_id_hash,source_app_id,target_app_id,collection_prefix,permission,NULL AS status,created_at,updated_at,revoked_at FROM grants`); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "record scan" {
					if _, err := store.Database.Exec("UPDATE server_encrypted_records SET schema_version='broken' WHERE id='b'"); err != nil {
						t.Fatal(err)
					}
				}
			}
			got := AppGrants_ByID(actual.Database, ctx, "account", created.Value.ID)
			want, err := expected.baselineAppGrantByID(ctx, "account", created.Value.ID)
			if !sameIdentityError(got.Error, err) || !reflect.DeepEqual(withoutGrantClocks(got.Value), withoutGrantClocks(want)) {
				t.Fatal("grant detail error or partial record changed", got, want, err)
			}
			listed := AppGrants_List(actual.Database, ctx, "account")
			grants, err := expected.baselineListAppGrants(ctx, "account")
			for index := range listed.Value {
				listed.Value[index] = withoutGrantClocks(listed.Value[index])
			}
			for index := range grants {
				grants[index] = withoutGrantClocks(grants[index])
			}
			if !sameIdentityError(listed.Error, err) || !reflect.DeepEqual(listed.Value, grants) {
				t.Fatal("grant list error changed", listed, grants, err)
			}
			compareGrantedRecords(t, actual, expected, ctx, "account", "source", "target", "shared.source.v1.*")
			if mode == "cancelled" && got.Error != context.Canceled {
				t.Fatal("grant query cancellation identity changed", got.Error)
			}
		})
	}
}

func TestZiranResourceIDsAndAccountTouchAgainstBaseline(t *testing.T) {
	original := rand.Reader
	defer func() { rand.Reader = original }()
	for _, data := range [][]byte{bytes.Repeat([]byte{0}, 16), bytes.Repeat([]byte{0xff}, 16), []byte("abcdefghijklmnop")} {
		rand.Reader = bytes.NewReader(data)
		got := ResourceId_New()
		rand.Reader = bytes.NewReader(data)
		want, err := baselineRandomResourceID()
		if !sameIdentityError(got.Error, err) || got.Value != want || got.Value != hex.EncodeToString(data) {
			t.Fatal("resource ID bytes changed", got, want, err)
		}
	}
	actual, expected := grantStoreFixture(t), grantStoreFixture(t)
	for _, user := range []string{"missing", "account", "account"} {
		transaction, err := actual.Database.BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		baseline, err := expected.Database.BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		got := AccountState_Touch(transaction, t.Context(), user, ErrSyncUserNotFound)
		want := baselineTouchUser(t.Context(), baseline, user)
		if !sameIdentityError(got, want) {
			t.Fatal("account touch error changed", got, want)
		}
		if got == nil {
			if err := transaction.Commit(); err != nil {
				t.Fatal(err)
			}
			if err := baseline.Commit(); err != nil {
				t.Fatal(err)
			}
		} else {
			_ = transaction.Rollback()
			_ = baseline.Rollback()
		}
		compareGrantState(t, actual, expected)
	}
	if _, err := actual.Database.Exec("INSERT OR IGNORE INTO server_sync_state VALUES('account',99)"); err != nil {
		t.Fatal(err)
	}
	if missing := AppGrants_ByID(actual.Database, t.Context(), "account", strings.Repeat("0", 32)); !errors.Is(missing.Error, sql.ErrNoRows) {
		t.Fatal("missing grant sentinel changed", missing)
	}
}

func TestZiranResourceIDFatalHelper(t *testing.T) {
	operation := os.Getenv("RESOURCE_ID_PORT_CASE")
	if operation == "" {
		t.Skip("subprocess helper")
	}
	original := rand.Reader
	defer func() { rand.Reader = original }()
	rand.Reader = identityEntropyReader{error: errors.New("resource entropy failed")}
	if operation == "short" {
		rand.Reader = bytes.NewReader(bytes.Repeat([]byte{0x42}, 15))
	}
	baseline := os.Getenv("RESOURCE_ID_PORT_BASELINE") == "1"
	if operation == "grant" {
		// Randomness is read before any app lookup, even on an invalid request.
		request := AppGrantRequest{SourceAppID: "missing"}
		if baseline {
			store := &Store{}
			_, _ = store.baselineCreateAppGrant(t.Context(), "account", request)
		} else {
			_ = AppGrants_Create(nil, t.Context(), "account", request, ErrSyncUserNotFound)
		}
	} else if baseline {
		_, _ = baselineRandomResourceID()
	} else {
		_ = ResourceId_New()
	}
	t.Fatal("entropy failure returned instead of stopping the process")
}

func TestZiranResourceIDEntropyFailureAgainstBaseline(t *testing.T) {
	for _, operation := range []string{"resource", "short", "grant"} {
		t.Run(operation, func(t *testing.T) {
			var firstLine string
			var exitCode int
			for _, implementation := range []string{"1", "0"} {
				command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestZiranResourceIDFatalHelper$")
				for _, variable := range os.Environ() {
					if strings.HasPrefix(variable, "RESOURCE_ID_PORT_") || strings.HasPrefix(variable, "DISPLAY=") || strings.HasPrefix(variable, "WAYLAND_DISPLAY=") {
						continue
					}
					command.Env = append(command.Env, variable)
				}
				command.Env = append(command.Env, "RESOURCE_ID_PORT_CASE="+operation, "RESOURCE_ID_PORT_BASELINE="+implementation)
				output, err := command.CombinedOutput()
				var terminated *exec.ExitError
				if !errors.As(err, &terminated) {
					t.Fatalf("entropy failure did not terminate subprocess: %v, %s", err, output)
				}
				line, _, _ := strings.Cut(string(output), "\n")
				if !strings.HasPrefix(line, "fatal error: crypto/rand: failed to read random data") {
					t.Fatalf("unexpected entropy failure: %s", output)
				}
				if implementation == "1" {
					firstLine = line
					exitCode = terminated.ExitCode()
				} else if line != firstLine || terminated.ExitCode() != exitCode {
					t.Fatalf("entropy failure = %q, exit %d; baseline = %q, exit %d", line, terminated.ExitCode(), firstLine, exitCode)
				}
			}
		})
	}
}
