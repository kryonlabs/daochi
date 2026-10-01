package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestZiranMeshRecordsKeepReleasedLayout(t *testing.T) {
	for _, pair := range [][2]any{
		{MeshEncryptedRecord{}, baselineMeshEncryptedRecord{}},
		{MeshEncryptedRecordDeletion{}, baselineMeshEncryptedRecordDeletion{}},
		{NodeMeshExportRequest{}, baselineNodeMeshExportRequest{}},
		{NodeMeshExportResponse{}, baselineNodeMeshExportResponse{}},
		{NodeMeshImportRequest{}, baselineNodeMeshImportRequest{}},
		{NodeMeshImportResponse{}, baselineNodeMeshImportResponse{}},
		{MeshCursor{}, baselineMeshCursor{}},
		{CollectionMatcher{}, baselineAppCollectionMatcher{}},
	} {
		actual, expected := reflect.TypeOf(pair[0]), reflect.TypeOf(pair[1])
		if actual.NumField() != expected.NumField() {
			t.Fatalf("%s field count changed", actual)
		}
		for index := 0; index < actual.NumField(); index++ {
			got, want := actual.Field(index), expected.Field(index)
			wantType := strings.ReplaceAll(want.Type.String(), "baseline", "")
			if got.Name != want.Name || got.Type.String() != wantType || got.Tag != want.Tag {
				t.Fatalf("%s field %d = %#v; baseline = %#v", actual, index, got, want)
			}
		}
		got, err := json.Marshal(pair[0])
		if err != nil {
			t.Fatal(err)
		}
		want, err := json.Marshal(pair[1])
		if err != nil || string(got) != string(want) {
			t.Fatalf("%s zero JSON = %q; baseline = %q, %v", actual, got, want, err)
		}
	}
}

func TestZiranMeshCursorAndLimitsAgainstBaseline(t *testing.T) {
	for _, sequence := range []int64{0, 1, -1, math.MinInt64, math.MaxInt64} {
		for _, value := range []string{"", "a\x00b", "\u2003你好\t", "<script>&", string([]byte{0xff, 0, 0xfe})} {
			cursor := MeshCursor{Seq: sequence, UpdatedAt: value, UserIDHash: value, Collection: value, ID: value}
			got := MeshCursor_Encode(cursor)
			want, err := baselineEncodeMeshCursor(baselineMeshCursor(cursor))
			if !sameIdentityError(got.Error, err) || got.Value != want {
				t.Fatalf("cursor encoding = %#v; baseline = %q, %v", got, want, err)
			}
			compareMeshCursor(t, "\u2003"+want+"\t")
		}
	}
	for _, value := range []string{"", " \u2003\n", "!", "e30=", "e30", "e3\r\n0", "null", "a", "___"} {
		compareMeshCursor(t, value)
	}
	for _, value := range []string{
		"null", "[]", "42", `{}`, `{"seq":-3,"unknown":true}`,
		`{"seq":9223372036854775808}`, `{"seq":"1"}`,
		`{"id":"first","seq":1,"id":false}`, `{"SEQ":10,"id":null}`,
	} {
		compareMeshCursor(t, base64.RawURLEncoding.EncodeToString([]byte(value)))
	}
	random := rand.New(rand.NewSource(430))
	for count := 0; count < 1000; count++ {
		bytes := make([]byte, random.Intn(150))
		_, _ = random.Read(bytes)
		compareMeshCursor(t, string(bytes))
		compareMeshCursor(t, base64.RawURLEncoding.EncodeToString(bytes))
	}
	for _, requested := range []int{math.MinInt, -1, 0, 1, 499, 500, 2000, 2001, math.MaxInt} {
		for _, configured := range []int{math.MinInt, -1, 0, 1, 500, 2000, 2001, math.MaxInt} {
			if got, want := MeshCursor_BatchLimit(requested, configured), baselineMeshBatchLimit(requested, configured); got != want {
				t.Fatalf("limits %d, %d = %d; baseline = %d", requested, configured, got, want)
			}
		}
	}
	for _, url := range []string{"", "https://node///", "\u2003https://node/ ", "\x00/", "\xff/"} {
		for _, policy := range []NodeSyncPolicy{{}, {Apps: []string{}}, {Apps: []string{"inbe", "<app>&"}, Direction: "PULL", Data: []string{"names"}}} {
			if got, want := MeshCursor_PeerKey(url, policy), baselineMeshPeerCursorKey(url, policy); got != want {
				t.Fatalf("peer cursor key %q, %#v = %q; baseline = %q", url, policy, got, want)
			}
		}
	}
}

func compareMeshCursor(t *testing.T, value string) {
	t.Helper()
	got := MeshCursor_Decode(value)
	want, err := baselineDecodeMeshCursor(value)
	if !sameIdentityError(got.Error, err) || got.Value != MeshCursor(want) {
		t.Fatalf("cursor %q = %#v; baseline = %#v, %v", value, got, want, err)
	}
}

func TestZiranMeshScopeAgainstBaseline(t *testing.T) {
	approved := NodeSyncPolicy{
		Apps: []string{" InBe ", "Source"}, Collections: []string{"inbe.*", "shared.source.v1.*"},
		Spaces: []string{"space"}, Data: []string{"encrypted_records", "names", "app_registry"},
	}
	for _, direction := range []string{"", "PUSH", "pull", "\u2003BIDIRECTIONAL\t", "none", "pushx"} {
		approved.Direction = direction
		for _, requested := range []NodeSyncPolicy{
			{}, approved, {Apps: []string{"INBE"}}, {Apps: []string{"foreign"}},
			{Collections: []string{"inbe.habits"}}, {Collections: []string{" inbe.* "}},
			{Spaces: []string{"SPACE"}}, {Data: []string{"plaintext"}},
		} {
			for _, operation := range []string{"import", "export", "IMPORT", ""} {
				if got, want := MeshPolicy_AllowsOperation(approved, requested, operation), baselinePolicyAllowsOperation(approved, requested, operation); got != want {
					t.Fatalf("policy %q, %#v, %q = %v; baseline = %v", direction, requested, operation, got, want)
				}
			}
			if got, want := MeshPolicy_AllowsPull(&requested), baselineNodePolicyAllowsPull(&requested); got != want {
				t.Fatal("pull direction changed", requested, got, want)
			}
		}
		if got, want := MeshPolicy_AllowsPull(&approved), baselineNodePolicyAllowsPull(&approved); got != want {
			t.Fatal("pull policy changed", approved, got, want)
		}
	}
	if MeshPolicy_AllowsPull(nil) {
		t.Fatal("unconfigured peer may pull")
	}
	matchers := []CollectionMatcher{
		{AppID: "source", MatchPrefix: "shared.source.v1.", Wildcard: true, Specificity: 17},
		{AppID: "other", MatchPrefix: "shared.source.v1.exact", Specificity: 22},
		{AppID: "tie", MatchPrefix: "shared.source.v1.exact", Specificity: 22},
	}
	baseline := make([]baselineAppCollectionMatcher, len(matchers))
	for index, matcher := range matchers {
		baseline[index] = baselineAppCollectionMatcher(matcher)
	}
	for _, collection := range []string{"", "shared.source.v1.", "shared.source.v1.exact", "shared.source.v1.item", " shared.source.v1.item", "inbe.habits", "shared.source.v1Xitem"} {
		for _, requested := range []NodeSyncPolicy{
			{}, {Apps: []string{"source"}}, {Apps: []string{"OTHER"}}, {Apps: []string{"tie"}},
			{Collections: []string{" shared.source.v1.* ", ""}}, {Collections: []string{"shared.source.v1.exact"}},
			{Collections: []string{"*"}}, {Apps: []string{"source"}, Collections: []string{"inbe.*"}},
		} {
			got := MeshPolicy_AllowsRecord(requested, matchers, collection)
			want := baselineMeshPolicyAllowsRecord(requested, baseline, collection)
			if got != want {
				t.Fatalf("record scope %q, %#v = %v; baseline = %v", collection, requested, got, want)
			}
		}
	}
}

func meshPortFixture(t *testing.T) *Store {
	t.Helper()
	store := grantStoreFixture(t)
	_, err := store.Database.Exec(`
CREATE TABLE server_account_tombstones(user_id_hash TEXT PRIMARY KEY);
CREATE TABLE node_sync_cursors(peer_key TEXT PRIMARY KEY,cursor TEXT NOT NULL,updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE server_mesh_changes(seq INTEGER PRIMARY KEY AUTOINCREMENT,op TEXT DEFAULT 'upsert',user_id_hash TEXT,collection TEXT,record_id TEXT,deleted_at TEXT DEFAULT '');
CREATE TRIGGER mesh_insert AFTER INSERT ON server_encrypted_records BEGIN
  INSERT INTO server_mesh_changes(user_id_hash,collection,record_id) VALUES(NEW.user_id_hash,NEW.collection,NEW.id);
END;
CREATE TRIGGER mesh_update AFTER UPDATE ON server_encrypted_records BEGIN
  INSERT INTO server_mesh_changes(user_id_hash,collection,record_id) VALUES(NEW.user_id_hash,NEW.collection,NEW.id);
END;
CREATE TRIGGER mesh_delete AFTER DELETE ON server_encrypted_records BEGIN
  INSERT INTO server_mesh_changes(op,user_id_hash,collection,record_id,deleted_at) VALUES('delete',OLD.user_id_hash,OLD.collection,OLD.id,OLD.updated_at);
END;
UPDATE server_users SET created_at='2026-09-01T00:00:00Z';
INSERT INTO server_mesh_changes(user_id_hash,collection,record_id) SELECT user_id_hash,collection,id FROM server_encrypted_records ORDER BY user_id_hash,collection,id;
`)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func meshPortRecord(id string, version int64) MeshEncryptedRecord {
	key := []byte{0x11, 0x22, 0x33}
	hash := sha256.Sum256(key)
	return MeshEncryptedRecord{
		UserIDHash: hex.EncodeToString(hash[:]), PublicKey: hex.EncodeToString(key),
		CreatedAt: "2026-09-01T00:00:00Z", LastSeenAt: "2026-09-02T00:00:00Z", MeshVersion: version,
		Record: EncryptedRecord{ID: id, Collection: "shared.source.v1.item", KeyID: "key", Nonce: "nonce",
			Ciphertext: "ciphertext", UpdatedAt: "2026-09-30T00:00:00Z", SchemaVersion: 1},
	}
}

func compareMeshImport(t *testing.T, actual, expected *Store, ctx context.Context, policy NodeSyncPolicy, records []MeshEncryptedRecord, deletions []MeshEncryptedRecordDeletion) MeshImportResult {
	t.Helper()
	var baselineRecords []baselineMeshEncryptedRecord
	var baselineDeletions []baselineMeshEncryptedRecordDeletion
	for _, item := range records {
		baselineRecords = append(baselineRecords, baselineMeshEncryptedRecord(item))
	}
	for _, item := range deletions {
		baselineDeletions = append(baselineDeletions, baselineMeshEncryptedRecordDeletion(item))
	}
	got := MeshStore_ImportEncryptedBatch(actual.Database, ctx, policy, records, deletions)
	want, err := expected.baselineImportMeshEncryptedBatch(ctx, policy, baselineRecords, baselineDeletions)
	if got.Value != want || !sameIdentityError(got.Error, err) {
		t.Fatalf("mesh import = %#v; baseline = %d, %v", got, want, err)
	}
	compareMeshState(t, actual, expected)
	return got
}

func meshPortSnapshot(t *testing.T, store *Store) map[string][][]any {
	t.Helper()
	result := make(map[string][][]any)
	queries := map[string]string{
		"users":   "SELECT user_id_hash,hex(public_key),created_at,last_seen_at FROM server_users ORDER BY user_id_hash",
		"state":   "SELECT user_id_hash,server_version FROM server_sync_state ORDER BY user_id_hash",
		"records": "SELECT user_id_hash,collection,id,key_id,nonce,ciphertext,updated_at,deleted_at,content_hash,schema_version,parent_id,server_version FROM server_encrypted_records ORDER BY user_id_hash,collection,id",
		"log":     "SELECT seq,op,user_id_hash,collection,record_id,deleted_at FROM server_mesh_changes ORDER BY seq",
		"cursors": "SELECT peer_key,cursor FROM node_sync_cursors ORDER BY peer_key",
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
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for index := range values {
				pointers[index] = &values[index]
			}
			if err := rows.Scan(pointers...); err != nil {
				t.Fatal(err)
			}
			// The two fixture databases have independently created seed users.
			if name == "users" && (values[0] == "account" || values[0] == "other") {
				values[2] = "seed clock"
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

func compareMeshState(t *testing.T, actual, expected *Store) {
	t.Helper()
	if got, want := meshPortSnapshot(t, actual), meshPortSnapshot(t, expected); !reflect.DeepEqual(got, want) {
		t.Fatalf("mesh stored state = %#v; baseline = %#v", got, want)
	}
}

func compareMeshExport(t *testing.T, actual, expected *Store, ctx context.Context, policy NodeSyncPolicy, cursor string, limit int) MeshExportResult {
	t.Helper()
	got := MeshStore_ExportEncryptedRecords(actual.Database, ctx, policy, cursor, limit)
	records, deletions, next, truncated, err := expected.baselineExportMeshEncryptedRecords(ctx, policy, cursor, limit)
	var converted []MeshEncryptedRecord
	if records != nil {
		converted = make([]MeshEncryptedRecord, len(records))
		for index, item := range records {
			converted[index] = MeshEncryptedRecord(item)
		}
	}
	var convertedDeletions []MeshEncryptedRecordDeletion
	if deletions != nil {
		convertedDeletions = make([]MeshEncryptedRecordDeletion, len(deletions))
		for index, item := range deletions {
			convertedDeletions[index] = MeshEncryptedRecordDeletion(item)
		}
	}
	if !reflect.DeepEqual(got.Records, converted) || !reflect.DeepEqual(got.Deletions, convertedDeletions) ||
		got.NextCursor != next || got.Truncated != truncated || !sameIdentityError(got.Error, err) {
		t.Fatalf("export %q, %d = %#v; baseline = %#v, %#v, %q, %v, %v", cursor, limit, got, records, deletions, next, truncated, err)
	}
	return got
}

func TestZiranMeshImportConvergenceAgainstBaseline(t *testing.T) {
	actual, expected := meshPortFixture(t), meshPortFixture(t)
	policy := NodeSyncPolicy{Apps: []string{"source"}, Data: []string{"encrypted_records"}}
	item := meshPortRecord("first", 1)
	if got := compareMeshImport(t, actual, expected, t.Context(), policy, []MeshEncryptedRecord{item}, nil); got.Error != nil || got.Value != 1 {
		t.Fatal("initial replication failed", got)
	}
	compareMeshImport(t, actual, expected, t.Context(), policy, []MeshEncryptedRecord{item}, nil)
	for _, update := range []struct{ timestamp, ciphertext string }{
		{"2020-01-01T00:00:00Z", "older"}, {item.Record.UpdatedAt, "a"},
		{item.Record.UpdatedAt, "z"}, {"2026-10-01T01:00:00+01:00", "next day"},
	} {
		item.Record.UpdatedAt, item.Record.Ciphertext = update.timestamp, update.ciphertext
		compareMeshImport(t, actual, expected, t.Context(), policy, []MeshEncryptedRecord{item}, nil)
	}
	deletion := MeshEncryptedRecordDeletion{UserIDHash: item.UserIDHash, Collection: item.Record.Collection, ID: item.Record.ID,
		DeletedAt: "2026-10-01T00:00:00Z", MeshVersion: 2}
	compareMeshImport(t, actual, expected, t.Context(), policy, nil, []MeshEncryptedRecordDeletion{deletion})
	item.MeshVersion = 3
	item.Record.Ciphertext = "recreated"
	compareMeshImport(t, actual, expected, t.Context(), policy, []MeshEncryptedRecord{item}, []MeshEncryptedRecordDeletion{deletion})
	item.MeshVersion = deletion.MeshVersion
	item.Record.Ciphertext = "z"
	compareMeshImport(t, actual, expected, t.Context(), policy, []MeshEncryptedRecord{item}, []MeshEncryptedRecordDeletion{deletion})
	for _, store := range []*Store{actual, expected} {
		var count int
		if err := store.Database.QueryRow("SELECT COUNT(*) FROM server_encrypted_records WHERE user_id_hash=?", item.UserIDHash).Scan(&count); err != nil || count != 0 {
			t.Fatal("equal-sequence deletion no longer follows the upsert", count, err)
		}
		if _, err := store.Database.Exec("INSERT INTO server_account_tombstones VALUES(?)", item.UserIDHash); err != nil {
			t.Fatal(err)
		}
	}
	if got := compareMeshImport(t, actual, expected, t.Context(), policy, []MeshEncryptedRecord{item}, []MeshEncryptedRecordDeletion{deletion}); got.Error != nil || got.Value != 0 {
		t.Fatal("deleted account accepted mesh changes", got)
	}
	for _, limit := range []int{-1, 0, 1, 2, 100, 5000} {
		compareMeshExport(t, actual, expected, t.Context(), policy, "", limit)
	}
}

func TestZiranMeshImportValidationAndRollbackAgainstBaseline(t *testing.T) {
	for _, mode := range []string{"invalid user", "invalid key", "wrong key", "invalid record", "invalid deletion user", "invalid deletion target", "scope", "no records", "tombstone", "cancelled", "user write", "state write", "record write", "version write", "delete write", "commit"} {
		t.Run(mode, func(t *testing.T) {
			actual, expected := meshPortFixture(t), meshPortFixture(t)
			policy := NodeSyncPolicy{Apps: []string{"source"}, Data: []string{"encrypted_records"}}
			item := meshPortRecord("existing", 1)
			compareMeshImport(t, actual, expected, t.Context(), policy, []MeshEncryptedRecord{item}, nil)
			before := meshPortSnapshot(t, actual)
			second := meshPortRecord("new", 2)
			deletion := MeshEncryptedRecordDeletion{UserIDHash: item.UserIDHash, Collection: item.Record.Collection, ID: item.Record.ID,
				DeletedAt: "2026-10-01T00:00:00Z", MeshVersion: 3}
			ctx := t.Context()
			query := ""
			switch mode {
			case "invalid user":
				second.UserIDHash = "invalid"
			case "invalid key":
				second.PublicKey = "zz"
			case "wrong key":
				second.PublicKey = "00"
			case "invalid record":
				second.Record.SchemaVersion = -1
			case "invalid deletion user":
				deletion.UserIDHash = "invalid"
			case "invalid deletion target":
				deletion.ID = "invalid/id"
			case "scope":
				policy.Apps = []string{"target"}
			case "no records":
				policy.Data = []string{"names"}
			case "tombstone":
				query = "INSERT INTO server_account_tombstones VALUES('" + item.UserIDHash + "')"
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			case "user write":
				query = "CREATE TRIGGER reject_mesh BEFORE INSERT ON server_users BEGIN SELECT RAISE(ABORT,'user rejected'); END"
			case "state write":
				query = "CREATE TRIGGER reject_mesh BEFORE INSERT ON server_sync_state BEGIN SELECT RAISE(ABORT,'state rejected'); END"
			case "record write":
				query = "CREATE TRIGGER reject_mesh BEFORE INSERT ON server_encrypted_records BEGIN SELECT RAISE(ABORT,'record rejected'); END"
			case "version write":
				query = "CREATE TRIGGER reject_mesh BEFORE UPDATE ON server_sync_state BEGIN SELECT RAISE(ABORT,'version rejected'); END"
			case "delete write":
				query = "CREATE TRIGGER reject_mesh BEFORE DELETE ON server_encrypted_records BEGIN SELECT RAISE(ABORT,'delete rejected'); END"
			case "commit":
				query = `CREATE TABLE parent(id INTEGER PRIMARY KEY);
CREATE TABLE pending(id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED);
CREATE TRIGGER reject_mesh AFTER INSERT ON server_encrypted_records BEGIN INSERT INTO pending VALUES(99); END`
			}
			if query != "" {
				for _, store := range []*Store{actual, expected} {
					if _, err := store.Database.Exec(query); err != nil {
						t.Fatal(err)
					}
				}
			}
			prefix := meshPortRecord("prefix", 0)
			got := compareMeshImport(t, actual, expected, ctx, policy, []MeshEncryptedRecord{prefix, second}, []MeshEncryptedRecordDeletion{deletion})
			if got.Error != nil && !reflect.DeepEqual(before, meshPortSnapshot(t, actual)) {
				t.Fatal("failed batch left partial user, record, version or mesh-log changes")
			}
			if mode == "cancelled" && got.Error != context.Canceled {
				t.Fatal("cancellation identity changed", got)
			}
			if strings.HasSuffix(mode, "write") || mode == "commit" {
				if got.Error == nil {
					t.Fatal("forced transaction failure was ignored")
				}
				for _, store := range []*Store{actual, expected} {
					if _, err := store.Database.Exec("DROP TRIGGER reject_mesh"); err != nil {
						t.Fatal(err)
					}
				}
				compareMeshImport(t, actual, expected, t.Context(), policy, []MeshEncryptedRecord{second}, nil)
			}
		})
	}
}

func TestZiranMeshExportPaginationAndQueryErrorsAgainstBaseline(t *testing.T) {
	actual, expected := meshPortFixture(t), meshPortFixture(t)
	policy := NodeSyncPolicy{Apps: []string{"source"}, Data: []string{"encrypted_records"}}
	for _, requested := range []NodeSyncPolicy{
		{}, policy, {Apps: []string{"target"}}, {Collections: []string{"shared.source.v1.*"}},
		{Data: []string{"names"}}, {Collections: []string{"private.source.v1.*"}},
	} {
		cursor := ""
		for page := 0; page < 20; page++ {
			got := compareMeshExport(t, actual, expected, t.Context(), requested, cursor, 2)
			if got.Error != nil {
				t.Fatal(got.Error)
			}
			if !got.Truncated {
				break
			}
			if got.NextCursor == cursor {
				t.Fatal("pagination made no progress")
			}
			cursor = got.NextCursor
		}
	}
	for _, mode := range []string{"invalid cursor", "cancelled", "matcher scan", "export scan", "missing log", "closed"} {
		t.Run(mode, func(t *testing.T) {
			actual, expected := meshPortFixture(t), meshPortFixture(t)
			ctx, cursor := t.Context(), ""
			query := ""
			switch mode {
			case "invalid cursor":
				cursor = "!"
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			case "matcher scan":
				query = "ALTER TABLE server_apps RENAME TO apps; CREATE VIEW server_apps AS SELECT app_id,NULL AS display_name FROM apps"
			case "export scan":
				query = "UPDATE server_encrypted_records SET schema_version='invalid' WHERE id='b'"
			case "missing log":
				query = "DROP TABLE server_mesh_changes"
			case "closed":
				for _, store := range []*Store{actual, expected} {
					_ = store.Database.Close()
				}
			}
			if query != "" {
				for _, store := range []*Store{actual, expected} {
					if _, err := store.Database.Exec(query); err != nil {
						t.Fatal(err)
					}
				}
			}
			got := compareMeshExport(t, actual, expected, ctx, policy, cursor, 100)
			if got.Error == nil {
				t.Fatal("query failure was ignored", mode)
			}
			if mode == "cancelled" && got.Error != context.Canceled {
				t.Fatal("export cancellation identity changed", got.Error)
			}
			if mode == "invalid cursor" {
				// Cursor decoding happens before data-type filtering.
				compareMeshExport(t, actual, expected, ctx, NodeSyncPolicy{Data: []string{"names"}}, cursor, 100)
			}
		})
	}
}

func TestZiranMeshCursorPersistenceAgainstBaseline(t *testing.T) {
	actual, expected := meshPortFixture(t), meshPortFixture(t)
	for _, value := range []string{"", "\u2003\t", "cursor", " cursor ", "replacement\x00cursor"} {
		got := MeshStore_SaveCursor(actual.Database, t.Context(), "peer", value)
		want := expected.baselineSaveNodeSyncCursor(t.Context(), "peer", value)
		if !sameIdentityError(got, want) {
			t.Fatal("cursor save error changed", got, want)
		}
		for _, key := range []string{"peer", "missing"} {
			got := MeshStore_LoadCursor(actual.Database, t.Context(), key)
			want, err := expected.baselineLoadNodeSyncCursor(t.Context(), key)
			if got.Value != want || !sameIdentityError(got.Error, err) {
				t.Fatal("cursor load changed", got, want, err)
			}
		}
		compareMeshState(t, actual, expected)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got := MeshStore_LoadCursor(actual.Database, ctx, "peer"); !errors.Is(got.Error, context.Canceled) {
		t.Fatal("cursor cancellation changed", got)
	}
	if err := MeshStore_SaveCursor(actual.Database, ctx, "peer", ""); err != nil {
		t.Fatal("blank cursor began a database operation", err)
	}
	if err := MeshStore_SaveCursor(actual.Database, ctx, "peer", "new"); !errors.Is(err, context.Canceled) {
		t.Fatal("cursor save cancellation changed", err)
	}
}

func TestZiranMeshStableOrderingMatchesGo(t *testing.T) {
	random := rand.New(rand.NewSource(312))
	for count := 0; count < 100; count++ {
		records := make([]MeshEncryptedRecord, random.Intn(100))
		deletions := make([]MeshEncryptedRecordDeletion, random.Intn(100))
		for index := range records {
			records[index].MeshVersion = random.Int63n(10) - 5
		}
		for index := range deletions {
			deletions[index].MeshVersion = random.Int63n(10) - 5
		}
		want := make([]MeshChange, 0, len(records)+len(deletions))
		for index := range records {
			want = append(want, MeshChange{Sequence: records[index].MeshVersion, Record: &records[index]})
		}
		for index := range deletions {
			want = append(want, MeshChange{Sequence: deletions[index].MeshVersion, Deletion: &deletions[index]})
		}
		sort.SliceStable(want, func(i, j int) bool { return want[i].Sequence < want[j].Sequence })
		if got := MeshStore_OrderedChanges(records, deletions); !reflect.DeepEqual(got, want) {
			t.Fatal("mesh sequence order or original record ownership changed", got, want)
		}
	}
}

// Native SQL result errors and integer narrowing retain the old count contract.
type meshAffectedResult struct {
	count int64
	err   error
}

func (result meshAffectedResult) LastInsertId() (int64, error) { return 0, nil }
func (result meshAffectedResult) RowsAffected() (int64, error) { return result.count, result.err }

func TestZiranMeshSharedRecordAndCountHelpersAgainstBaseline(t *testing.T) {
	for _, count := range []int64{0, -1, 1, math.MinInt64, math.MaxInt64} {
		for _, err := range []error{nil, sql.ErrTxDone} {
			result := meshAffectedResult{count: count, err: err}
			if got, want := AccountState_Affected(result), baselineMeshRowsAffected(result); got != want {
				t.Fatal("native affected count changed", got, want)
			}
		}
	}
	item := meshPortRecord("record", 1).Record
	for _, value := range []string{"", "a", "\u2003", "invalid/id", strings.Repeat("x", 257), strings.Repeat("x", 262145)} {
		for _, field := range []string{"Collection", "ID", "KeyID", "Nonce", "Ciphertext", "UpdatedAt", "ContentHash", "ParentID"} {
			changed := item
			reflect.ValueOf(&changed).Elem().FieldByName(field).SetString(value)
			for _, protocol := range []int{0, 4, 5, 6} {
				if got, want := EncryptedRecord_ValidForProtocol(changed, protocol), baselineValidEncryptedRecordForProtocol(changed, protocol); got != want {
					t.Fatal("record validation changed", changed, protocol, got, want)
				}
			}
		}
	}
}
