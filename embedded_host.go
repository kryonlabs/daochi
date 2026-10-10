//go:build daochi_embedded

// Platform ABI for the generated node core. No application merge rules live here.
package main

/*
#include <stddef.h>
*/
import "C"

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

type embeddedRuntime struct {
	core       EmbeddedCore
	root       string
	http       *http.Server
	listener   net.Listener
	cancel     context.CancelFunc
	workers    sync.WaitGroup
	references int
	lease      *os.File
}

var embeddedState = struct {
	sync.Mutex
	next  int64
	nodes map[int64]*embeddedRuntime
	roots map[string]int64
}{nodes: make(map[int64]*embeddedRuntime), roots: make(map[string]int64)}

func embeddedSecret(path string) ([]byte, error) {
	contents, err := os.ReadFile(path)
	if err == nil {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || len(contents) != 32 {
			return nil, errors.New("invalid private node secret")
		}
		return contents, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	contents = make([]byte, 32)
	if _, err := rand.Read(contents); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	written, writeErr := file.Write(contents)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || written != len(contents) || syncErr != nil || closeErr != nil {
		return nil, errors.New("cannot persist node secret")
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return nil, err
	}
	return contents, nil
}

func embeddedHandler(core EmbeddedCore) http.Handler {
	routes := Server_Routes(core.Server)
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !Embedded_AllowedPath(request.URL.Path) {
			http.NotFound(writer, request)
			return
		}
		routes.ServeHTTP(writer, request)
	})
}

func (node *embeddedRuntime) resume() error {
	if node.listener != nil {
		return nil
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	node.listener = listener
	node.http = &http.Server{
		Handler: embeddedHandler(node.core), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: time.Minute,
	}
	node.core.Server.Cfg.Addr = listener.Addr().String()
	node.core.Server.Cfg.BaseURL = "http://" + listener.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	node.cancel = cancel
	node.workers.Add(2)
	go func() {
		defer node.workers.Done()
		_ = node.http.Serve(listener)
	}()
	go func() {
		defer node.workers.Done()
		Mesh_Run(Server_Mesh(node.core.Server), ctx)
	}()
	return nil
}

func (node *embeddedRuntime) suspend() {
	if node.listener == nil {
		return
	}
	node.cancel()
	_ = node.http.Close()
	node.workers.Wait()
	node.listener = nil
}

func startEmbedded(root string) (int64, error) {
	embeddedState.Lock()
	defer embeddedState.Unlock()
	if root == "" || !filepath.IsAbs(root) {
		return 0, errors.New("absolute private profile required")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return 0, err
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || resolved != filepath.Clean(root) {
		return 0, errors.New("profile symlinks are not allowed")
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return 0, errors.New("profile must be private")
	}
	if handle := embeddedState.roots[root]; handle != 0 {
		node := embeddedState.nodes[handle]
		if err := node.resume(); err != nil {
			return 0, err
		}
		node.references++
		return handle, nil
	}
	lease, err := os.OpenFile(filepath.Join(root, "node.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return 0, err
	}
	if err := syscall.Flock(int(lease.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lease.Close()
		return 0, errors.New("profile node already has an owner")
	}
	keepLease := false
	defer func() {
		if !keepLease {
			lease.Close()
		}
	}()
	secret, err := embeddedSecret(filepath.Join(root, "token-secret"))
	if err != nil {
		return 0, err
	}
	admin, err := embeddedSecret(filepath.Join(root, "admin-secret"))
	if err != nil {
		return 0, err
	}
	for _, name := range []string{"node-key", "daochi.sqlite"} {
		info, err := os.Lstat(filepath.Join(root, name))
		if err == nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0) {
			return 0, errors.New("private node state required")
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return 0, err
		}
	}
	identity := NodeIdentity_LoadOrCreateKey(filepath.Join(root, "node-key"))
	if identity.Error != nil {
		return 0, identity.Error
	}
	config := Config{
		Addr: "127.0.0.1:0", DBPath: filepath.Join(root, "daochi.sqlite"),
		TokenSecret: secret, AdminToken: hex.EncodeToString(admin),
		NodeIdentityPrivateKey: identity.Value, NodeDisplayName: "Private app node",
		ChallengeTTL: time.Minute, TokenTTL: time.Hour, MaxBodyBytes: 1 << 20,
		NodeSyncInterval: 30 * time.Second, NodeSyncBatchLimit: 128,
		NodeLANOnly: true, NodeLANNetworks: []string{"127.0.0.0/8", "::1/128"},
	}
	core := Embedded_Open(config)
	if core.Error != nil {
		return 0, core.Error
	}
	if _, err := core.Value.Store.Database.Exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL"); err != nil {
		_ = Embedded_Close(core.Value)
		return 0, err
	}
	if err := os.Chmod(config.DBPath, 0600); err != nil {
		_ = Embedded_Close(core.Value)
		return 0, err
	}
	node := &embeddedRuntime{core: core.Value, root: root, references: 1, lease: lease}
	if err := node.resume(); err != nil {
		_ = Embedded_Close(core.Value)
		return 0, err
	}
	keepLease = true
	embeddedState.next++
	handle := embeddedState.next
	embeddedState.nodes[handle] = node
	embeddedState.roots[root] = handle
	return handle, nil
}

func stopEmbedded(handle int64) bool {
	embeddedState.Lock()
	defer embeddedState.Unlock()
	node := embeddedState.nodes[handle]
	if node == nil {
		return false
	}
	node.references--
	if node.references > 0 {
		return true
	}
	node.suspend()
	_ = Embedded_Close(node.core)
	_ = node.lease.Close()
	delete(embeddedState.roots, node.root)
	delete(embeddedState.nodes, handle)
	return true
}

//export NodeStart
func NodeStart(root *C.char) C.longlong {
	if root == nil {
		return 0
	}
	handle, err := startEmbedded(C.GoString(root))
	if err != nil {
		// ABI failures never expose private key paths or secret values.
		return 0
	}
	return C.longlong(handle)
}

//export NodeStop
func NodeStop(handle C.longlong) C.int {
	if stopEmbedded(int64(handle)) {
		return 1
	}
	return 0
}

//export NodeSuspend
func NodeSuspend(handle C.longlong) C.int {
	embeddedState.Lock()
	defer embeddedState.Unlock()
	node := embeddedState.nodes[int64(handle)]
	if node == nil {
		return 0
	}
	node.suspend()
	return 1
}

//export NodeResume
func NodeResume(handle C.longlong) C.int {
	embeddedState.Lock()
	defer embeddedState.Unlock()
	node := embeddedState.nodes[int64(handle)]
	if node == nil || node.resume() != nil {
		return 0
	}
	return 1
}

//export NodeRequest
func NodeRequest(handle C.longlong, method *C.char, path *C.char, body *C.char, output *C.char, capacity C.int) C.int {
	if method == nil || path == nil || output == nil || capacity < 1 || capacity > (2<<20) {
		return 0
	}
	embeddedState.Lock()
	defer embeddedState.Unlock()
	node := embeddedState.nodes[int64(handle)]
	if node == nil {
		return 0
	}
	route := C.GoString(path)
	if !strings.HasPrefix(route, "/") || strings.Contains(route, "://") {
		return 0
	}
	data := ""
	if body != nil {
		data = C.GoString(body)
	}
	if len(data) > 1<<20 {
		return 0
	}
	request, err := http.NewRequest(C.GoString(method), "http://127.0.0.1"+route, strings.NewReader(data))
	if err != nil {
		return 0
	}
	request.RemoteAddr = "127.0.0.1:1"
	request.Header.Set("Content-Type", "application/json")
	// This in-process operator capability never crosses a peer transport.
	request.Header.Set("X-Daochi-Admin", node.core.Server.Cfg.AdminToken)
	recorder := httptest.NewRecorder()
	embeddedHandler(node.core).ServeHTTP(recorder, request)
	response := recorder.Result()
	defer response.Body.Close()
	encodedBody, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return 0
	}
	if !json.Valid(encodedBody) {
		encodedBody, _ = json.Marshal(string(encodedBody))
	}
	encoded, err := json.Marshal(struct {
		Status int             `json:"status"`
		Body   json.RawMessage `json:"body"`
	}{response.StatusCode, json.RawMessage(encodedBody)})
	if err != nil || len(encoded) >= int(capacity) {
		return 0
	}
	buffer := unsafe.Slice((*byte)(unsafe.Pointer(output)), int(capacity))
	copy(buffer, encoded)
	buffer[len(encoded)] = 0
	return C.int(len(encoded))
}
