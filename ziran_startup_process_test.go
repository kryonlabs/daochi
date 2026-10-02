package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	secureRandom "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type startupArgumentReader struct {
	source io.Reader
}

func (reader startupArgumentReader) Read(value []byte) (int, error) {
	os.Args = []string{"daochi", "inspect", "summary"}
	return reader.source.Read(value)
}

func TestZiranStartupProcessHelper(t *testing.T) {
	mode := os.Getenv("STARTUP_PORT_CASE")
	if mode == "" {
		return
	}
	log.SetFlags(0)
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, attribute slog.Attr) slog.Attr {
			if attribute.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return attribute
		},
	})))
	os.Args = []string{"daochi"}
	if strings.HasPrefix(mode, "inspect") || mode == "key error" || mode == "invalid key file" || mode == "configuration error" {
		os.Args = []string{"daochi", "inspect", "summary"}
	}
	if mode == "inspect invalid" {
		os.Args = []string{"daochi", "inspect", "unknown-command"}
	}
	if mode == "inspect argument timing" {
		os.Args = []string{"daochi"}
		secureRandom.Reader = startupArgumentReader{source: secureRandom.Reader}
	}
	baseline := os.Getenv("STARTUP_PORT_BASELINE") == "1"
	if strings.HasPrefix(mode, "verifier") {
		cfg := Config_Load()
		factory := func() VerifierResult {
			fmt.Println("factory called")
			var err error = errors.New("provider failure")
			if mode == "verifier unavailable" {
				err = ErrVerifierUnavailable
			} else if mode == "verifier wrapped unavailable" {
				err = fmt.Errorf("provider wrapper: %w", ErrVerifierUnavailable)
			}
			return VerifierResult{Error: err}
		}
		if baseline {
			baselineStartupRun(cfg, os.Args, factory, signAccountProof)
		} else {
			Startup_Run(cfg, os.Args, factory, signAccountProof)
		}
	} else if baseline {
		baselineStartupMain()
	} else {
		main()
	}
	fmt.Println("startup returned")
	os.Exit(0)
}

func startupProcess(t *testing.T, mode string, baseline bool, root string, address string) *exec.Cmd {
	t.Helper()
	childContext, cancel := context.WithTimeout(t.Context(), 12*time.Second)
	t.Cleanup(cancel)
	command := exec.CommandContext(childContext, os.Args[0], "-test.run=^TestZiranStartupProcessHelper$")
	// Use an explicit environment: children cannot inherit either desktop display
	// or the developer's configuration, secrets and peer/payment endpoints.
	command.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"STARTUP_PORT_CASE=" + mode,
		fmt.Sprintf("STARTUP_PORT_BASELINE=%d", boolCount(baseline)),
		"DAOCHI_TOKEN_SECRET_HEX=" + strings.Repeat("11", 32),
		"DAOCHI_NODE_IDENTITY_PRIVATE_KEY_HEX=" + hex.EncodeToString(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize))),
		"DAOCHI_NODE_IDENTITY_KEY_FILE=" + filepath.Join(root, "node.key"),
		"DAOCHI_DB=" + filepath.Join(root, "startup.sqlite"),
		"DAOCHI_ADDR=" + address,
		"DAOCHI_BASE_URL=https://example.com",
		"DAOCHI_LAN_DISCOVERY=0",
		"DAOCHI_NODE_SYNC_INTERVAL_SECONDS=0",
		"DAOCHI_TOKEN_DIRECT_PURCHASES_ENABLED=0",
	}
	// Each replacement is appended deliberately; exec.Cmd uses the final value.
	switch mode {
	case "signal":
		command.Env = append(command.Env, "DAOCHI_TOKEN_DIRECT_PURCHASES_ENABLED=1")
	case "key error":
		command.Env = append(command.Env, "DAOCHI_NODE_IDENTITY_PRIVATE_KEY_HEX=", "DAOCHI_NODE_IDENTITY_KEY_FILE= ")
	case "invalid key file", "inspect create key", "inspect argument timing":
		command.Env = append(command.Env, "DAOCHI_NODE_IDENTITY_PRIVATE_KEY_HEX=")
	case "configuration error":
		command.Env = append(command.Env, "DAOCHI_TOKEN_SECRET_HEX=11")
	case "store error":
		command.Env = append(command.Env, "DAOCHI_DB="+root)
	case "inspect missing":
		command.Env = append(command.Env, "DAOCHI_DB="+filepath.Join(root, "missing.sqlite"))
	}
	return command
}

func TestZiranStartupCLIAndFatalErrorsAgainstBaseline(t *testing.T) {
	for _, mode := range []string{"inspect", "inspect create key", "inspect argument timing", "inspect invalid", "inspect missing", "key error", "invalid key file", "configuration error", "store error", "verifier error", "verifier unavailable", "verifier wrapped unavailable", "listen error"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			opened := Store_Open(filepath.Join(root, "startup.sqlite"))
			if opened.Error != nil {
				t.Fatal(opened.Error)
			}
			if err := opened.Value.Close(); err != nil {
				t.Fatal(err)
			}
			var outputs [2][]byte
			for implementation := range outputs {
				keyPath := filepath.Join(root, "node.key")
				if mode == "inspect create key" || mode == "inspect argument timing" {
					if err := os.Remove(keyPath); err != nil && !errors.Is(err, os.ErrNotExist) {
						t.Fatal(err)
					}
				} else if mode == "invalid key file" {
					if err := os.WriteFile(keyPath, []byte("not hexadecimal"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				command := startupProcess(t, mode, implementation == 1, root, "invalid-address")
				output, err := command.CombinedOutput()
				expectedExit := 1
				if mode == "inspect" || mode == "inspect create key" || mode == "inspect argument timing" || mode == "listen error" {
					expectedExit = 0
				}
				var exit *exec.ExitError
				if (expectedExit == 0 && err != nil) || (expectedExit == 1 && (!errors.As(err, &exit) || exit.ExitCode() != expectedExit)) {
					t.Fatalf("startup %s exit: error=%v, output=%s", mode, err, output)
				}
				if strings.HasPrefix(mode, "verifier") != bytes.Contains(output, []byte("factory called")) {
					t.Fatal("startup changed verifier construction ordering", mode, string(output))
				}
				if mode == "inspect create key" || mode == "inspect argument timing" {
					info, err := os.Stat(keyPath)
					if err != nil || info.Mode().Perm() != 0600 {
						t.Fatal("inspection no longer prepares a private node key", info, err)
					}
					key := NodeIdentity_LoadOrCreateKey(keyPath)
					if key.Error != nil || len(key.Value) != ed25519.PrivateKeySize {
						t.Fatal("startup key is invalid", key.Error)
					}
				}
				if _, err := os.Stat(filepath.Join(root, "missing.sqlite")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("inspection created the missing database", err)
				}
				outputs[implementation] = output
			}
			if !bytes.Equal(outputs[0], outputs[1]) {
				t.Fatalf("CLI bytes differ: got %s, want %s", outputs[0], outputs[1])
			}
		})
	}
}

func TestZiranStartupSignalsAndHTTPAgainstBaseline(t *testing.T) {
	for _, stopSignal := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
		for implementation := 0; implementation < 2; implementation++ {
			t.Run(fmt.Sprintf("%s/%d", stopSignal, implementation), func(t *testing.T) {
				reservation, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				address := reservation.Addr().String()
				if err := reservation.Close(); err != nil {
					t.Fatal(err)
				}
				root := t.TempDir()
				command := startupProcess(t, "signal", implementation == 1, root, address)
				var output bytes.Buffer
				command.Stdout, command.Stderr = &output, &output
				if err := command.Start(); err != nil {
					t.Fatal(err)
				}
				finished := make(chan error, 1)
				go func() { finished <- command.Wait() }()
				defer func() { _ = command.Process.Kill() }()
				transport := &http.Transport{DialContext: (&net.Dialer{Timeout: 250 * time.Millisecond}).DialContext}
				defer transport.CloseIdleConnections()
				client := &http.Client{Transport: transport, Timeout: 250 * time.Millisecond}
				deadline := time.Now().Add(8 * time.Second)
				for {
					response, requestError := client.Get("http://" + address + "/healthz")
					if requestError == nil {
						_ = response.Body.Close()
						if response.StatusCode != http.StatusOK {
							t.Fatal("startup health endpoint is unavailable", response.StatusCode)
						}
						break
					}
					select {
					case childError := <-finished:
						t.Fatal("startup exited before serving HTTP", childError, output.String())
					case <-time.After(20 * time.Millisecond):
					}
					if time.Now().After(deadline) {
						t.Fatal("startup did not serve HTTP before the deadline", requestError)
					}
				}
				if err := command.Process.Signal(stopSignal); err != nil {
					t.Fatal(err)
				}
				if err := startupAwait(t, finished); err != nil {
					t.Fatal("signal did not shut down cleanly", err, output.String())
				}
				text := output.String()
				if !strings.Contains(text, "startup returned") || strings.Contains(text, "serve failed") || strings.Contains(text, "HTTP shutdown failed") {
					t.Fatal("startup reported an unexpected shutdown failure", text)
				}
				check := Store_Open(filepath.Join(root, "startup.sqlite"))
				if check.Error != nil {
					t.Fatal("startup database is unusable after shutdown", check.Error)
				}
				if err := check.Value.Close(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
