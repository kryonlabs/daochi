package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectSummaryAndUser(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "ksync-inspect.db")
	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := bytes.Repeat([]byte{0x42}, mlDSA44PublicKeySize)
	sum := sha256.Sum256(publicKey)
	userID := hex.EncodeToString(sum[:])
	_, err = store.ApplySync(context.Background(), SyncRequest{
		UserIDHash: userID,
		Habits: []Habit{{
			ID:           "habit-1",
			Name:         "Meditate",
			SyncMode:     1,
			SyncActivity: 2,
			UpdatedAt:    "2026-06-19T00:00:00Z",
		}},
		Sessions: []Session{{
			ID:        "session-1",
			StartedAt: "2026-06-19T00:00:00Z",
			LocalDate: 20260619,
			Topic:     "0",
			Activity:  1,
			UpdatedAt: "2026-06-19T00:00:00Z",
		}},
	}, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.StoreEncryptedPayload(context.Background(), userID, "inspect-client", []byte(`{"v":1,"nonce":"n","ciphertext":"c"}`)); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordSyncAudit(context.Background(), SyncAuditEntry{
		UserIDHash:           userID,
		ClientID:             "inspect-client",
		AppID:                "inbe",
		ProtocolVersion:      5,
		ServerVersion:        2,
		Applied:              SyncResult{EncryptedRecords: 1},
		RemoteOps:            3,
		FullSnapshotRequired: true,
		SnapshotReason:       "test",
		EncryptedPayload:     true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordClientSync(context.Background(), userID, "legacy-client", 0, 2, 2, 0); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	var summary bytes.Buffer
	if err := runInspect(context.Background(), []string{"--db", dbPath, "summary"}, InspectOptions{Out: &summary}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(summary.String(), "server_users") || !strings.Contains(summary.String(), "server_sessions") {
		t.Fatalf("summary missing counts:\n%s", summary.String())
	}

	var user bytes.Buffer
	if err := runInspect(context.Background(), []string{"--db", dbPath, "user", userID}, InspectOptions{Out: &user}); err != nil {
		t.Fatal(err)
	}
	got := user.String()
	if !strings.Contains(got, "Meditate") || !strings.Contains(got, "session-1") {
		t.Fatalf("user output missing data:\n%s", got)
	}
	if strings.Contains(got, userID) {
		t.Fatalf("user id should be redacted by default:\n%s", got)
	}

	var doctor bytes.Buffer
	if err := runInspect(context.Background(), []string{"--db", dbPath, "doctor", userID}, InspectOptions{Out: &doctor}); err != nil {
		t.Fatal(err)
	}
	got = doctor.String()
	for _, want := range []string{"Daochi doctor", "Warnings", "legacy clients below protocol 5", "server_sync_audit", "server_encrypted_payloads", "protocol=5", "full_snapshot=true"} {
		if !strings.Contains(got, want) {
			t.Fatalf("doctor output missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, userID) {
		t.Fatalf("doctor user id should be redacted by default:\n%s", got)
	}
}

func TestInspectMissingUser(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "ksync-inspect.db")
	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	userID := strings.Repeat("a", 64)
	err = runInspect(context.Background(), []string{"--db", dbPath, "user", userID}, InspectOptions{Out: &bytes.Buffer{}})
	if err == nil || !strings.Contains(err.Error(), "user not found") {
		t.Fatalf("missing user error = %v", err)
	}
}
