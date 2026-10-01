package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func deviceStoreFixture(t *testing.T) *Store {
	t.Helper()
	database, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = database.Close() })
	_, err = database.Exec(`
PRAGMA foreign_keys=ON;
CREATE TABLE server_users(user_id_hash TEXT PRIMARY KEY);
CREATE TABLE server_apps(app_id TEXT PRIMARY KEY);
INSERT INTO server_users VALUES('account');
INSERT INTO server_apps VALUES('inbe');
CREATE TABLE server_device_keys (
 account_id TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
 app_id TEXT NOT NULL REFERENCES server_apps(app_id) ON DELETE CASCADE,
 device_key_id TEXT NOT NULL,
 client_id TEXT NOT NULL,
 public_key TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 last_used_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 revoked_at TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(account_id,app_id,device_key_id)
);
CREATE TABLE server_device_registration_nonces (
 account_id TEXT NOT NULL REFERENCES server_users(user_id_hash) ON DELETE CASCADE,
 nonce TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(account_id,nonce)
);`)
	if err != nil {
		t.Fatal(err)
	}
	return &Store{Database: database}
}

func deviceSnapshot(t *testing.T, store *Store) map[string][][]string {
	t.Helper()
	result := make(map[string][][]string)
	for name, query := range map[string]string{
		"devices": "SELECT account_id,app_id,device_key_id,client_id,public_key,revoked_at<>'' FROM server_device_keys ORDER BY account_id,app_id,device_key_id",
		"nonces":  "SELECT account_id,nonce FROM server_device_registration_nonces ORDER BY account_id,nonce",
	} {
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

func withoutDeviceClock(device DeviceKey) DeviceKey {
	device.CreatedAt = ""
	device.LastUsedAt = ""
	if device.RevokedAt != "" {
		device.RevokedAt = "revoked"
	}
	return device
}

func compareDeviceQueries(t *testing.T, actual, expected *Store) {
	t.Helper()
	if got, want := deviceSnapshot(t, actual), deviceSnapshot(t, expected); !reflect.DeepEqual(got, want) {
		t.Fatalf("device state = %#v, baseline = %#v", got, want)
	}
	listed := DeviceKeys_List(actual.Database, t.Context(), "account")
	want, err := expected.baselineListDeviceKeys(t.Context(), "account")
	for index := range listed.Value {
		listed.Value[index] = withoutDeviceClock(listed.Value[index])
	}
	for index := range want {
		want[index] = withoutDeviceClock(want[index])
	}
	if !sameIdentityError(listed.Error, err) || !reflect.DeepEqual(listed.Value, want) {
		t.Fatalf("device list = %#v, baseline = %#v, %v", listed, want, err)
	}
	active := DeviceKeys_Active(actual.Database, t.Context(), "account", "inbe", "key")
	device, found, err := expected.baselineActiveDeviceKey(t.Context(), "account", "inbe", "key")
	if !sameIdentityError(active.Error, err) || active.Found != found ||
		!reflect.DeepEqual(withoutDeviceClock(active.Value), withoutDeviceClock(device)) {
		t.Fatalf("active device = %#v, baseline = %#v, %v, %v", active, device, found, err)
	}
}

func TestZiranDeviceRecordsAndCanonicalMessagesAgainstBaseline(t *testing.T) {
	for _, pair := range [][2]reflect.Type{
		{reflect.TypeOf(DeviceKey{}), reflect.TypeOf(baselineDeviceKey{})},
		{reflect.TypeOf(DeviceRegistrationRequest{}), reflect.TypeOf(baselineDeviceRegistrationRequest{})},
		{reflect.TypeOf(DeviceRevocationRequest{}), reflect.TypeOf(baselineDeviceRevocationRequest{})},
	} {
		if pair[0].NumField() != pair[1].NumField() {
			t.Fatal("device field count changed")
		}
		for index := 0; index < pair[0].NumField(); index++ {
			got, want := pair[0].Field(index), pair[1].Field(index)
			if got.Name != want.Name || got.Type != want.Type || got.Tag != want.Tag {
				t.Fatalf("device field %d = %#v, baseline = %#v", index, got, want)
			}
		}
	}
	for _, value := range []string{"", " key ", "\u2003日本語\t", "\x00\xff\nKEY\r", "a\nb"} {
		for _, expiry := range []int64{0, -1, 9223372036854775807, -9223372036854775808} {
			request := DeviceRegistrationRequest{AppID: value, KeyID: value, ClientID: value,
				PublicKey: value, Nonce: value, Signature: value, ExpiresAt: expiry}
			if got, want := DeviceKeys_RegistrationMessage(value, request), baselineDeviceRegistrationMessage(value, request); !bytes.Equal(got, want) {
				t.Fatalf("registration bytes = %q, baseline = %q", got, want)
			}
			want := request
			DeviceKeys_NormalizeRegistration(&request)
			baselineNormalizeDeviceRegistration(&want)
			if !reflect.DeepEqual(request, want) {
				t.Fatalf("registration normalization = %#v, baseline = %#v", request, want)
			}
			revocation := DeviceRevocationRequest{AppID: value, KeyID: value, Nonce: value, Signature: value, ExpiresAt: expiry}
			if got, want := DeviceKeys_RevocationMessage(value, revocation), baselineDeviceRevocationMessage(value, revocation); !bytes.Equal(got, want) {
				t.Fatalf("revocation bytes = %q, baseline = %q", got, want)
			}
			wantRevocation := revocation
			DeviceKeys_NormalizeRevocation(&revocation)
			baselineNormalizeDeviceRevocation(&wantRevocation)
			if !reflect.DeepEqual(revocation, wantRevocation) {
				t.Fatalf("revocation normalization = %#v, baseline = %#v", revocation, wantRevocation)
			}
		}
	}
	now := time.Now().Unix()
	for _, expiry := range []int64{now - 1, now, now + 1, now + 899, now + 901, -9223372036854775808, 9223372036854775807} {
		if got, want := DeviceKeys_ValidExpiry(expiry), baselineValidDeviceRequestExpiry(expiry); got != want {
			t.Fatalf("expiry %d = %v, baseline = %v", expiry, got, want)
		}
	}
	for _, key := range []string{strings.Repeat("ab", 32), strings.Repeat("AB", 32), strings.Repeat("ab", 31), "!", ""} {
		request := DeviceRegistrationRequest{AppID: "inbe", KeyID: "key", ClientID: "client", Nonce: "nonce", PublicKey: key, ExpiresAt: now + 60}
		if got, want := DeviceKeys_ValidRegistration(request), baselineValidDeviceRegistration(request); got != want {
			t.Fatalf("registration validity for %q = %v, baseline = %v", key, got, want)
		}
	}
}

func TestZiranDeviceStorageLifecycleAgainstBaseline(t *testing.T) {
	actual, expected := deviceStoreFixture(t), deviceStoreFixture(t)
	device := DeviceKey{AccountID: "account", AppID: "inbe", KeyID: "key", ClientID: "client", PublicKey: "public"}
	compareDeviceQueries(t, actual, expected)
	for _, nonce := range []string{"first", "first", "replace"} {
		got := DeviceKeys_Register(actual.Database, t.Context(), device, nonce, errSignedTxReplay)
		want := expected.baselineRegisterDeviceKey(t.Context(), device, nonce)
		if !sameIdentityError(got, want) {
			t.Fatalf("registration = %v, baseline = %v", got, want)
		}
		compareDeviceQueries(t, actual, expected)
		device.ClientID = "replacement"
		device.PublicKey = "replacement public key"
	}
	for _, nonce := range []string{"revoke", "revoke", "missing"} {
		request := DeviceRevocationRequest{AppID: "inbe", KeyID: "key", Nonce: nonce}
		got := DeviceKeys_Revoke(actual.Database, t.Context(), "account", request, errSignedTxReplay)
		want := expected.baselineRevokeDeviceKey(t.Context(), "account", request)
		if !sameIdentityError(got, want) {
			t.Fatalf("revocation = %v, baseline = %v", got, want)
		}
		compareDeviceQueries(t, actual, expected)
	}
	if err := DeviceKeys_Register(actual.Database, t.Context(), device, "missing", errSignedTxReplay); err != nil {
		t.Fatal("missing-device revocation consumed its nonce", err)
	}
	if err := expected.baselineRegisterDeviceKey(t.Context(), device, "missing"); err != nil {
		t.Fatal(err)
	}
	for _, store := range []*Store{actual, expected} {
		if _, err := store.Database.Exec("UPDATE server_device_keys SET created_at='2000-01-01T00:00:00.000000000Z',last_used_at=created_at"); err != nil {
			t.Fatal(err)
		}
	}
	if got, want := DeviceKeys_Touch(actual.Database, t.Context(), "account", "inbe", "key"), expected.baselineTouchDeviceKey(t.Context(), "account", "inbe", "key"); !sameIdentityError(got, want) {
		t.Fatalf("device touch = %v, baseline = %v", got, want)
	}
	active := DeviceKeys_Active(actual.Database, t.Context(), "account", "inbe", "key")
	if active.Value.CreatedAt != "2000-01-01T00:00:00.000000000Z" || active.Value.LastUsedAt == active.Value.CreatedAt {
		t.Fatal("touch changed creation time or did not update last use")
	}
	parsed, err := time.Parse(time.RFC3339Nano, active.Value.LastUsedAt)
	if err != nil || active.Value.LastUsedAt != parsed.UTC().Format("2006-01-02T15:04:05.000000000Z07:00") {
		t.Fatal("last use is not a canonical timestamp")
	}
	compareDeviceQueries(t, actual, expected)
}

func TestZiranDeviceTransactionRollbackAndConcurrentReplay(t *testing.T) {
	device := DeviceKey{AccountID: "account", AppID: "inbe", KeyID: "key", ClientID: "client", PublicKey: "key"}
	for _, mode := range []string{"write", "commit"} {
		t.Run(mode, func(t *testing.T) {
			actual, expected := deviceStoreFixture(t), deviceStoreFixture(t)
			query := "CREATE TRIGGER reject_device BEFORE INSERT ON server_device_keys BEGIN SELECT RAISE(ABORT,'device rejected'); END"
			if mode == "commit" {
				query = `CREATE TABLE parent(id INTEGER PRIMARY KEY);
CREATE TABLE pending(id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED);
CREATE TRIGGER reject_device AFTER INSERT ON server_device_keys BEGIN INSERT INTO pending VALUES(99); END`
			}
			for _, store := range []*Store{actual, expected} {
				if _, err := store.Database.Exec("INSERT INTO server_device_registration_nonces VALUES('account','expired','2000-01-01T00:00:00.000000000Z');" + query); err != nil {
					t.Fatal(err)
				}
			}
			before := deviceSnapshot(t, actual)
			got := DeviceKeys_Register(actual.Database, t.Context(), device, "new", errSignedTxReplay)
			want := expected.baselineRegisterDeviceKey(t.Context(), device, "new")
			if got == nil || !sameIdentityError(got, want) || !reflect.DeepEqual(deviceSnapshot(t, actual), before) {
				t.Fatalf("failed registration = %v, baseline = %v; writes or expiry cleanup leaked", got, want)
			}
			if _, err := actual.Database.Exec("DROP TRIGGER reject_device"); err != nil {
				t.Fatal(err)
			}
			if err := DeviceKeys_Register(actual.Database, t.Context(), device, "new", errSignedTxReplay); err != nil {
				t.Fatal("rollback left connection or nonce unusable", err)
			}
		})
	}
	store := deviceStoreFixture(t)
	var workers sync.WaitGroup
	results := make(chan error, 16)
	for index := 0; index < cap(results); index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			results <- DeviceKeys_Register(store.Database, context.Background(), device, "shared", errSignedTxReplay)
		}()
	}
	workers.Wait()
	close(results)
	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
		} else if !errors.Is(err, errSignedTxReplay) {
			t.Fatal("replay error lost identity", err)
		}
	}
	if accepted != 1 {
		t.Fatalf("shared device nonce accepted %d times", accepted)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := DeviceKeys_Register(store.Database, ctx, device, "canceled", errSignedTxReplay); err != context.Canceled {
		t.Fatal("registration lost cancellation identity", err)
	}
	if got := DeviceKeys_Active(store.Database, ctx, "account", "inbe", "key"); got.Error != context.Canceled || got.Found {
		t.Fatalf("canceled lookup = %#v", got)
	}
	if got := DeviceKeys_List(store.Database, ctx, "account"); got.Error != context.Canceled || got.Value != nil {
		t.Fatalf("canceled list = %#v", got)
	}
}
