//go:build daochi_embedded

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestEmbeddedNodePersistsIdentityAndDatabaseAcrossLifecycle(t *testing.T) {
	root := t.TempDir()
	handle, err := startEmbedded(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stopEmbedded(handle) })
	node := embeddedState.nodes[handle]
	id := node.core.Server.Node.ID
	url := node.core.Server.Cfg.BaseURL
	client := &http.Client{}
	response, err := client.Get(url + "/healthz")
	if err != nil || response.StatusCode != 200 {
		t.Fatal("local node unavailable", err)
	}
	response.Body.Close()
	key := []byte{1, 2, 3}
	digest := sha256.Sum256(key)
	account := hex.EncodeToString(digest[:])
	if err := node.core.Store.RegisterUser(context.Background(), account, key); err != nil {
		t.Fatal(err)
	}
	node.suspend()
	if _, err := client.Get(url + "/healthz"); err == nil {
		t.Fatal("suspended listener still active")
	}
	if err := node.resume(); err != nil {
		t.Fatal(err)
	}
	if node.core.Server.Node.ID != id {
		t.Fatal("suspend replaced identity")
	}
	stopEmbedded(handle)
	restarted, err := startEmbedded(root)
	if err != nil {
		t.Fatal(err)
	}
	defer stopEmbedded(restarted)
	next := embeddedState.nodes[restarted]
	if next.core.Server.Node.ID != id {
		t.Fatal("restart replaced identity")
	}
	var found int
	if err := next.core.Store.Database.QueryRow("SELECT COUNT(*) FROM server_users WHERE user_id_hash=?", account).Scan(&found); err != nil || found != 1 {
		t.Fatal("durable data lost", found, err)
	}
}

func TestEmbeddedNodeSharesProfileAndRejectsAnotherProcessOwner(t *testing.T) {
	root := t.TempDir()
	first, err := startEmbedded(root)
	if err != nil {
		t.Fatal(err)
	}
	defer stopEmbedded(first)
	second, err := startEmbedded(root)
	if err != nil || first != second {
		t.Fatal("profile not shared", err)
	}
	if !stopEmbedded(second) || embeddedState.nodes[first] == nil {
		t.Fatal("shared profile prematurely stopped")
	}
	lock, err := os.OpenFile(filepath.Join(root, "node.lock"), os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
		t.Fatal("second executor acquired profile")
	}
}

func TestEmbeddedNodeOmitsPublicSocialPaymentAndRejectsUnsafeState(t *testing.T) {
	handle, err := startEmbedded(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer stopEmbedded(handle)
	handler := embeddedHandler(embeddedState.nodes[handle].core)
	for _, route := range []string{"/api/v1/friends", "/api/v1/tokens/assets", "/api/v1/account/export", "/metrics", "/"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest("GET", route, nil))
		if recorder.Code != 404 {
			t.Fatalf("unrelated endpoint enabled: %s", route)
		}
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	if h, err := startEmbedded(root); err == nil {
		stopEmbedded(h)
		t.Fatal("public profile accepted")
	}
	root = t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "node-key"), []byte(strings.Repeat("00", 32)), 0644); err != nil {
		t.Fatal(err)
	}
	if h, err := startEmbedded(root); err == nil {
		stopEmbedded(h)
		t.Fatal("public identity file accepted")
	}
	root = t.TempDir()
	if err := os.Symlink("/tmp", filepath.Join(root, "node-key")); err != nil {
		t.Fatal(err)
	}
	if h, err := startEmbedded(root); err == nil {
		stopEmbedded(h)
		t.Fatal("identity symlink accepted")
	}
}
