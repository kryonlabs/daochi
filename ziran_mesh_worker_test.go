package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestZiranMeshWorkerLifecycleAgainstBaseline(t *testing.T) {
	previous := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previous })
	sentinel := errors.New("mesh worker native panic")
	for _, mode := range []string{"disabled", "negative interval", "initial pull", "periodic pull", "transport failure", "response panic", "already cancelled"} {
		t.Run(mode, func(t *testing.T) {
			var traces [][]string
			var panics []any
			for implementation := 0; implementation < 2; implementation++ {
				server := meshHTTPFixture(t)
				policy := meshHTTPPolicy()
				server.Cfg.NodeSyncInterval = time.Hour
				server.Cfg.KnownNodes = []NodePeer{{Name: "worker", URL: "http://first.test", Sync: &policy}}
				switch mode {
				case "disabled":
					server.Cfg.NodeSyncInterval = 0
					server.Store = nil
				case "negative interval":
					server.Cfg.NodeSyncInterval = -1
					server.Store = nil
				case "periodic pull":
					server.Cfg.NodeSyncInterval = 5 * time.Millisecond
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				if mode == "already cancelled" {
					cancel()
				}
				var requests []string
				http.DefaultTransport = trustHTTPTransport(func(request *http.Request) (*http.Response, error) {
					requests = append(requests, request.URL.Host)
					if mode != "periodic pull" || len(requests) == 2 {
						cancel()
					}
					server.Cfg.KnownNodes[0].URL = "http://second.test"
					if mode == "transport failure" {
						return nil, sentinel
					}
					var body io.ReadCloser = io.NopCloser(strings.NewReader(`{"records":[]}`))
					if mode == "response panic" {
						body = &httpPortBody{panicValue: sentinel}
					}
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: body, Request: request}, nil
				})
				finished := make(chan any, 1)
				go func() {
					defer func() { finished <- recover() }()
					if mode == "disabled" || mode == "negative interval" {
						// No database or identity dependency is touched when disabled.
						if implementation == 0 {
							Mesh_Run(Mesh{Configuration: &server.Cfg}, ctx)
						} else {
							server.baselineMeshRunNodeSync(ctx)
						}
					} else if implementation == 0 {
						Mesh_Run(server.mesh(), ctx)
					} else {
						server.baselineMeshRunNodeSync(ctx)
					}
				}()
				select {
				case value := <-finished:
					panics = append(panics, value)
				case <-time.After(2 * time.Second):
					cancel()
					// Confirm termination before changing the global transport.
					select {
					case <-finished:
					case <-time.After(time.Second):
						t.Fatal("mesh worker did not terminate after cancellation")
					}
					t.Fatal("mesh worker did not complete its expected lifecycle")
				}
				traces = append(traces, requests)
			}
			if !reflect.DeepEqual(traces[0], traces[1]) {
				t.Fatal("mesh worker request sequence changed", traces)
			}
			if mode == "periodic pull" && !reflect.DeepEqual(traces[0], []string{"first.test", "second.test"}) {
				t.Fatal("mesh worker did not reload peers on its tick", traces[0])
			}
			if mode == "initial pull" && !reflect.DeepEqual(traces[0], []string{"first.test"}) {
				t.Fatal("mesh worker did not pull before its first tick", traces[0])
			}
			if mode == "response panic" {
				if panics[0] != sentinel || panics[1] != sentinel {
					t.Fatal("mesh worker lost native panic identity", panics)
				}
			} else if panics[0] != nil || panics[1] != nil {
				t.Fatal("mesh worker unexpectedly panicked", panics)
			}
		})
	}
}

func TestZiranMeshWorkerNilContextAgainstBaseline(t *testing.T) {
	implementation := os.Getenv("DAOCHI_MESH_WORKER_IMPLEMENTATION")
	if implementation != "" {
		server := meshHTTPFixture(t)
		server.Cfg.NodeSyncInterval = time.Hour
		// Native database/sql panics with its mutex held for a nil context.
		// Exit the isolated process before fixture cleanup tries to close it.
		defer func() {
			value := recover()
			if value == nil {
				os.Exit(2)
			}
			fmt.Printf("%T: %v\n", value, value)
			os.Exit(0)
		}()
		if implementation == "generated" {
			Mesh_Run(server.mesh(), nil)
		} else {
			server.baselineMeshRunNodeSync(nil)
		}
		return
	}
	var outputs []string
	for _, implementation := range []string{"generated", "baseline"} {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestZiranMeshWorkerNilContextAgainstBaseline$")
		for _, entry := range os.Environ() {
			if !strings.HasPrefix(entry, "DISPLAY=") && !strings.HasPrefix(entry, "WAYLAND_DISPLAY=") && !strings.HasPrefix(entry, "DAOCHI_MESH_WORKER_IMPLEMENTATION=") {
				command.Env = append(command.Env, entry)
			}
		}
		command.Env = append(command.Env, "DAOCHI_MESH_WORKER_IMPLEMENTATION="+implementation)
		output, err := command.CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("isolated nil-context worker failed: %v: %s", err, output)
		}
		outputs = append(outputs, string(output))
	}
	if outputs[0] != outputs[1] || !strings.Contains(outputs[0], "invalid memory address or nil pointer dereference") {
		t.Fatal("mesh worker nil-context panic changed", outputs)
	}
}
