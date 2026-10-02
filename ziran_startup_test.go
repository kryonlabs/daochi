package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func startupAwait[T any](t *testing.T, channel <-chan T) T {
	t.Helper()
	select {
	case value := <-channel:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("startup fixture did not complete")
		var zero T
		return zero
	}
}

func TestZiranStartupLocalHTTPURLAgainstBaseline(t *testing.T) {
	addresses := []string{"", ":8080", "0.0.0.0:0", "[::]:8080", "[::1]:8080", "[fe80::1%eth0]:http", "localhost:8080", "host", "host:", "https://host:443", "\x00:80"}
	random := rand.New(rand.NewSource(42))
	for index := 0; index < 2000; index++ {
		value := make([]byte, random.Intn(80))
		_, _ = random.Read(value)
		addresses = append(addresses, string(value))
	}
	for _, address := range addresses {
		if got, want := Startup_LocalHTTPURL(address), baselineLocalHTTPURL(address); got != want {
			t.Fatalf("local URL for %q: got %q, want %q", address, got, want)
		}
	}
}

func TestZiranStartupHTTPConfiguration(t *testing.T) {
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	server := Startup_NewHTTPServer("[::]:8080", handler)
	if server.Addr != "[::]:8080" || reflect.ValueOf(server.Handler).Pointer() != reflect.ValueOf(handler).Pointer() ||
		server.ReadHeaderTimeout != 5*time.Second || server.ReadTimeout != 15*time.Second ||
		server.WriteTimeout != 15*time.Second || server.IdleTimeout != time.Minute ||
		server.ErrorLog.Writer() != os.Stderr || server.ErrorLog.Prefix() != "http: " || server.ErrorLog.Flags() != log.LstdFlags {
		t.Fatal("HTTP startup changed handler identity, address, deadlines or error logging", server)
	}
}

func TestZiranStartupWorkerSelectionAndCancellationAgainstBaseline(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, wallet := range []string{"", " \t\n\u2003", "http://wallet", " \u2003http://wallet\t", "\xff"} {
			for implementation := 0; implementation < 2; implementation++ {
				t.Run(fmt.Sprintf("%t/%q/%d", enabled, wallet, implementation), func(t *testing.T) {
					server := &Server{Cfg: Config{TokenDirectPurchasesEnabled: enabled, MoneroWalletRPCURL: wallet}}
					ctx, cancel := context.WithCancel(context.WithValue(t.Context(), "startup", "identity"))
					defer cancel()
					started, canceled := make(chan string, 3), make(chan string, 3)
					release := make(chan struct{})
					callback := func(name string) Worker {
						return func(value *Server, workerContext context.Context) {
							if value != server || workerContext != ctx {
								t.Error("worker changed Server or context identity")
							}
							started <- name
							<-workerContext.Done()
							canceled <- name
							<-release
						}
					}
					workers := Workers{Invoices: callback("invoices"), Mesh: callback("mesh"), Discovery: callback("discovery")}
					var group WorkerGroup
					if implementation == 0 {
						Startup_StartWorkers(server, ctx, &group, workers)
					} else {
						baselineStartWorkers(server, ctx, &group, workers)
					}
					expected := []string{"discovery", "mesh"}
					if enabled || strings.TrimSpace(wallet) != "" {
						expected = append(expected, "invoices")
					}
					sort.Strings(expected)
					var actual []string
					for range expected {
						actual = append(actual, startupAwait(t, started))
					}
					sort.Strings(actual)
					if !reflect.DeepEqual(actual, expected) {
						t.Fatal("worker selection changed", actual, expected)
					}
					finished := make(chan struct{})
					go func() {
						group.Wait()
						close(finished)
					}()
					cancel()
					for range expected {
						startupAwait(t, canceled)
					}
					select {
					case <-finished:
						t.Fatal("worker group completed before callbacks returned")
					default:
					}
					close(release)
					startupAwait(t, finished)
				})
			}
		}
	}
}

func TestZiranStartupWorkerPanicCleanupAgainstBaseline(t *testing.T) {
	marker := &struct{ code int }{42}
	for _, nilCallback := range []bool{false, true} {
		var panics [2]any
		for implementation := range panics {
			var group WorkerGroup
			group.Add(1)
			task := WorkerTask{Group: &group, Callback: func(*Server, context.Context) { panic(marker) }}
			if nilCallback {
				task.Callback = nil
			}
			panics[implementation] = boundaryRecover(func() {
				if implementation == 0 {
					Startup_RunWorker(task)
				} else {
					defer group.Done()
					task.Callback(task.Server, task.Context)
				}
			})
			finished := make(chan struct{})
			go func() {
				group.Wait()
				close(finished)
			}()
			startupAwait(t, finished)
		}
		if panics[0] == nil || fmt.Sprint(panics[0]) != fmt.Sprint(panics[1]) || (!nilCallback && panics[0] != marker) {
			t.Fatal("worker cleanup changed native panic", panics)
		}
	}
}

type startupObservedContext struct {
	context.Context
	observed chan struct{}
	once     sync.Once
}

func (value *startupObservedContext) Done() <-chan struct{} {
	value.once.Do(func() { close(value.observed) })
	return value.Context.Done()
}

func TestZiranStartupShutdownAgainstBaseline(t *testing.T) {
	previous := slog.Default()
	defer slog.SetDefault(previous)
	marker := &struct{ code int }{42}
	nativeError := errors.New("native shutdown error")
	for _, mode := range []string{"success", "error", "callback panic", "logger panic"} {
		for implementation := 0; implementation < 2; implementation++ {
			t.Run(fmt.Sprintf("%s/%d", mode, implementation), func(t *testing.T) {
				base, cancel := context.WithCancel(context.WithValue(t.Context(), "parent", "must not inherit"))
				defer cancel()
				parent := &startupObservedContext{Context: base, observed: make(chan struct{})}
				server := &HTTPServer{}
				var observed context.Context
				logs := 0
				slog.SetDefault(slog.New(discoveryLogHandler{record: func(record slog.Record) {
					logs++
					if record.Message != "HTTP shutdown failed" || record.Level != slog.LevelError {
						t.Error("shutdown log changed", record)
					}
					record.Attrs(func(attribute slog.Attr) bool {
						if attribute.Key != "error" || attribute.Value.Any() != nativeError {
							t.Error("shutdown error identity changed", attribute)
						}
						return true
					})
					if mode == "logger panic" {
						panic(marker)
					}
				}}))
				shutdown := func(value *HTTPServer, ctx context.Context) error {
					observed = ctx
					deadline, present := ctx.Deadline()
					remaining := time.Until(deadline)
					if value != server || ctx.Value("parent") != nil || !present || remaining < 14*time.Second || remaining > 15*time.Second || ctx.Err() != nil {
						t.Error("shutdown changed HTTP identity, fresh context or deadline")
					}
					if mode == "callback panic" {
						panic(marker)
					}
					if mode == "error" || mode == "logger panic" {
						return nativeError
					}
					return nil
				}
				finished := make(chan any, 1)
				go func() {
					finished <- boundaryRecover(func() {
						if implementation == 0 {
							Startup_ShutdownOnCancel(server, parent, shutdown)
						} else {
							baselineShutdownOnCancel(server, parent, shutdown)
						}
					})
				}()
				startupAwait(t, parent.observed)
				select {
				case <-finished:
					t.Fatal("HTTP shutdown ran before runtime cancellation")
				default:
				}
				cancel()
				failure := startupAwait(t, finished)
				if (strings.Contains(mode, "panic") && failure != marker) || (!strings.Contains(mode, "panic") && failure != nil) ||
					observed == nil || observed.Err() != context.Canceled || logs != boolCount(mode == "error" || mode == "logger panic") {
					t.Fatal("shutdown cleanup, log or panic identity changed", failure, observed, logs)
				}
			})
		}
	}
}

func boolCount(value bool) int {
	if value {
		return 1
	}
	return 0
}

type startupLog struct {
	Message    string
	Level      slog.Level
	Attributes []any
}

func TestZiranStartupServeAgainstBaseline(t *testing.T) {
	previous := slog.Default()
	defer slog.SetDefault(previous)
	marker := &struct{ code int }{42}
	nativeError := errors.New("native listen error")
	wrappedClosed := fmt.Errorf("wrapped: %w", http.ErrServerClosed)
	for _, mode := range []string{"success", "closed", "error", "wrapped closed", "listen panic", "listening log panic", "error log panic"} {
		var records [2][]startupLog
		for implementation := range records {
			server := &HTTPServer{}
			cfg := Config{Addr: ":8080", BaseURL: "https://example.com", DBPath: "state.sqlite"}
			ctx, cancel := context.WithCancel(t.Context())
			var stopped atomic.Int32
			stop := func() {
				stopped.Add(1)
				cancel()
			}
			workerCanceled, releaseWorker, workersDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var group WorkerGroup
			group.Add(1)
			go func() {
				defer close(workersDone)
				defer group.Done()
				<-ctx.Done()
				close(workerCanceled)
				<-releaseWorker
			}()
			shutdownDone := make(chan struct{})
			shutdown := func(value *HTTPServer, shutdownContext context.Context) error {
				defer close(shutdownDone)
				if value != server || shutdownContext.Err() != nil {
					t.Error("Serve changed HTTP shutdown arguments")
				}
				return nil
			}
			listened := 0
			listen := func(value *HTTPServer) error {
				listened++
				if value != server {
					t.Error("Serve changed HTTP listen identity")
				}
				switch mode {
				case "closed":
					return http.ErrServerClosed
				case "error", "error log panic":
					return nativeError
				case "wrapped closed":
					return wrappedClosed
				case "listen panic":
					panic(marker)
				}
				return nil
			}
			slog.SetDefault(slog.New(discoveryLogHandler{record: func(record slog.Record) {
				entry := startupLog{Message: record.Message, Level: record.Level}
				record.Attrs(func(attribute slog.Attr) bool {
					entry.Attributes = append(entry.Attributes, attribute.Key, attribute.Value.Any())
					return true
				})
				records[implementation] = append(records[implementation], entry)
				if (mode == "listening log panic" && record.Level == slog.LevelInfo) || (mode == "error log panic" && record.Level == slog.LevelError) {
					panic(marker)
				}
			}}))
			finished := make(chan any, 1)
			go func() {
				finished <- boundaryRecover(func() {
					if implementation == 0 {
						Startup_Serve(server, cfg, ctx, stop, &group, listen, shutdown)
					} else {
						baselineServe(server, cfg, ctx, stop, &group, listen, shutdown)
					}
				})
			}()
			if strings.Contains(mode, "panic") {
				if failure := startupAwait(t, finished); failure != marker || stopped.Load() != 0 {
					t.Fatal("serve panic changed identity or reached normal cancellation", mode, failure, stopped.Load())
				}
				cancel()
				startupAwait(t, workerCanceled)
				close(releaseWorker)
			} else {
				startupAwait(t, workerCanceled)
				select {
				case <-finished:
					t.Fatal("Serve returned before supervised workers completed", mode)
				default:
				}
				close(releaseWorker)
				if failure := startupAwait(t, finished); failure != nil || stopped.Load() != 1 {
					t.Fatal("normal Serve did not cancel and wait", failure, stopped.Load())
				}
			}
			startupAwait(t, workersDone)
			startupAwait(t, shutdownDone)
			if listened != boolCount(mode != "listening log panic") {
				t.Fatal("Serve changed logging/listen ordering", mode, listened)
			}
		}
		if !reflect.DeepEqual(records[0], records[1]) {
			t.Fatal("listening/failure log fields or error identity changed", mode, records)
		}
	}
}

func startupStoreDescriptors(t *testing.T, path string) []string {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("native descriptor inspection is unavailable")
	}
	if err != nil {
		t.Fatal(err)
	}
	var result []string
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if err == nil && (target == path || strings.HasPrefix(target, path+"-")) {
			result = append(result, target)
		}
	}
	return result
}

func TestZiranStartupStoreCleanupOnPanicAgainstBaseline(t *testing.T) {
	marker := &struct{ code int }{42}
	for _, mode := range []string{"factory panic", "constructor panic"} {
		var failures [2]any
		for implementation := range failures {
			cfg := serverConfiguration(&Store{Path: filepath.Join(t.TempDir(), "startup.sqlite")})
			if mode == "constructor panic" {
				cfg.NodeIdentityPrivateKey = []byte{42}
			}
			factory := func() VerifierResult {
				if len(startupStoreDescriptors(t, cfg.DBPath)) == 0 {
					t.Error("startup did not open Store before verifier construction")
				}
				if mode == "factory panic" {
					panic(marker)
				}
				return VerifierResult{Value: Verifier_New(func([]byte, []byte, []byte) bool { return true })}
			}
			failures[implementation] = boundaryRecover(func() {
				if implementation == 0 {
					Startup_Run(cfg, []string{"daochi"}, factory, signAccountProof)
				} else {
					baselineStartupRun(cfg, []string{"daochi"}, factory, signAccountProof)
				}
			})
			if descriptors := startupStoreDescriptors(t, cfg.DBPath); len(descriptors) != 0 {
				t.Fatal("startup panic retained open database descriptors", descriptors)
			}
		}
		if failures[0] == nil || fmt.Sprint(failures[0]) != fmt.Sprint(failures[1]) || (mode == "factory panic" && failures[0] != marker) {
			t.Fatal("startup cleanup changed panic identity", mode, failures)
		}
	}
}
