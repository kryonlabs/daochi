package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/rand"
	"net"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/grandcat/zeroconf"
)

func TestZiranDiscoveryMetadataAgainstBaseline(t *testing.T) {
	values := []string{"", " \u2003\t", "Home", "日本語のノード", "<node>&\n", "0123456789ab", "0123456789abc", "\xff\x00"}
	random := rand.New(rand.NewSource(920))
	for index := 0; index < 1000; index++ {
		data := make([]byte, random.Intn(80))
		_, _ = random.Read(data)
		values = append(values, string(data))
	}
	for _, nodeID := range values {
		for _, name := range []string{"", " \u2003\t", " Home\n", "日本語のノード", nodeID} {
			if got, want := Discovery_InstanceName(name, nodeID), baselineDiscoveryInstanceName(name, nodeID); got != want {
				t.Fatalf("discovery name %q, %q = %q; baseline %q", name, nodeID, got, want)
			}
		}
		got, want := Discovery_Text(nodeID), baselineDiscoveryText(nodeID)
		if !reflect.DeepEqual(got, want) || cap(got) != cap(want) {
			t.Fatalf("discovery text %q = %#v; baseline %#v", nodeID, got, want)
		}
		got[0] = "changed"
		if next := Discovery_Text(nodeID); next[0] != want[0] {
			t.Fatal("discovery text shares a mutable result slice")
		}
	}
}

func TestZiranDiscoveryListenerPortAgainstBaseline(t *testing.T) {
	addresses := []string{"0.0.0.0:8080", ":0", "[::1]:443", "host:+12", "host:-12", "host:", "host:port", "missing", "::1:80", "[::1", "host:１２", "host: 80", "\xff:7", "host:08", "host:0x10"}
	for _, port := range []string{strconv.FormatInt(math.MinInt64, 10), strconv.FormatInt(math.MaxInt64, 10), "9223372036854775808", "-9223372036854775809"} {
		addresses = append(addresses, "host:"+port)
	}
	random := rand.New(rand.NewSource(921))
	for index := 0; index < 1000; index++ {
		data := make([]byte, random.Intn(80))
		_, _ = random.Read(data)
		addresses = append(addresses, string(data), "host:"+string(data))
	}
	for _, address := range addresses {
		got := Discovery_ListenerPort(address)
		want, err := baselineListenerPort(address)
		if got.Value != want || !sameIdentityError(got.Error, err) {
			t.Fatalf("listener %q = %#v; baseline %d, %v", address, got, want, err)
		}
		var gotNumber, wantNumber *strconv.NumError
		if errors.As(got.Error, &gotNumber) != errors.As(err, &wantNumber) || !reflect.DeepEqual(gotNumber, wantNumber) {
			t.Fatal("listener integer error details changed", got.Error, err)
		}
	}
}

type discoveryLogHandler struct {
	record func(slog.Record)
}

func (handler discoveryLogHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (handler discoveryLogHandler) Handle(_ context.Context, record slog.Record) error {
	handler.record(record)
	return nil
}

func (handler discoveryLogHandler) WithAttrs([]slog.Attr) slog.Handler {
	return handler
}

func (handler discoveryLogHandler) WithGroup(string) slog.Handler {
	return handler
}

type discoveryContext struct {
	context.Context
	done func() <-chan struct{}
}

func (value discoveryContext) Done() <-chan struct{} {
	return value.done()
}

func TestZiranDiscoveryLifecycleAgainstBaseline(t *testing.T) {
	logger := slog.Default()
	t.Cleanup(func() { slog.SetDefault(logger) })
	sentinel := errors.New("discovery native failure")
	for _, mode := range []string{"disabled", "invalid address", "invalid port", "register failure", "register panic", "warning panic", "info panic", "cancelled", "wait then cancel", "context panic", "nil context", "shutdown panic", "updated identity"} {
		t.Run(mode, func(t *testing.T) {
			var traces [][]string
			var panicValues []any
			for implementation := 0; implementation < 2; implementation++ {
				server := &Server{
					cfg:  Config{LANDiscovery: true, Addr: "[::1]:8080", NodeDisplayName: " \u2003Home\t"},
					node: NodeIdentity{ID: strings.Repeat("a", 64)},
				}
				switch mode {
				case "disabled":
					server.cfg.LANDiscovery = false
				case "invalid address":
					server.cfg.Addr = "invalid"
				case "invalid port":
					server.cfg.Addr = "localhost:port"
				}
				var events []string
				slog.SetDefault(slog.New(discoveryLogHandler{record: func(record slog.Record) {
					event := record.Level.String() + ":" + record.Message
					record.Attrs(func(attribute slog.Attr) bool {
						event += "|" + attribute.Key + "=" + attribute.Value.String()
						return true
					})
					events = append(events, event)
					if mode == "warning panic" || mode == "info panic" {
						panic(sentinel)
					}
				}}))
				service := &zeroconf.Server{}
				register := func(instance, name, domain string, port int, text []string, interfaces []net.Interface) (*zeroconf.Server, error) {
					events = append(events, fmt.Sprintf("register:%q:%s:%s:%d:%q", instance, name, domain, port, text))
					if interfaces != nil {
						t.Fatal("discovery changed default interface selection")
					}
					if mode == "register failure" || mode == "warning panic" {
						return nil, sentinel
					}
					if mode == "register panic" {
						panic(sentinel)
					}
					if mode == "updated identity" {
						server.node.ID = "updated-node"
					}
					return service, nil
				}
				shutdown := func(value *zeroconf.Server) {
					if value != service {
						t.Fatal("discovery shutdown changed native resource identity")
					}
					events = append(events, "shutdown")
					if mode == "shutdown panic" {
						panic(sentinel)
					}
				}
				done := make(chan struct{})
				if mode != "wait then cancel" {
					close(done)
				}
				var ctx context.Context = discoveryContext{
					Context: context.Background(),
					done: func() <-chan struct{} {
						events = append(events, "context")
						if mode == "context panic" {
							panic(sentinel)
						}
						if mode == "wait then cancel" {
							go func() {
								time.Sleep(5 * time.Millisecond)
								close(done)
							}()
						}
						return done
					},
				}
				if mode == "nil context" {
					ctx = nil
				}
				var panicValue any
				func() {
					defer func() { panicValue = recover() }()
					if implementation == 0 {
						Discovery_Run(&server.cfg, &server.node, ctx,
							func(instance, name, domain string, port int, text []string, interfaces []Interface) RegistrationResult {
								value, err := register(instance, name, domain, port, text, interfaces)
								return RegistrationResult{Value: value, Error: err}
							}, shutdown)
					} else {
						server.baselineRunLANDiscovery(ctx, register, shutdown)
					}
				}()
				traces = append(traces, events)
				panicValues = append(panicValues, panicValue)
			}
			if !reflect.DeepEqual(traces[0], traces[1]) {
				t.Fatal("discovery resource/log/cancellation order changed", traces)
			}
			switch mode {
			case "register panic", "warning panic", "info panic", "context panic", "shutdown panic":
				if panicValues[0] != sentinel || panicValues[1] != sentinel {
					t.Fatal("discovery lost native panic identity", panicValues)
				}
			case "nil context":
				actual, got := panicValues[0].(error)
				baseline, want := panicValues[1].(error)
				if !got || !want || !sameIdentityError(actual, baseline) {
					t.Fatal("discovery nil-context panic changed", panicValues)
				}
			default:
				if panicValues[0] != nil || panicValues[1] != nil {
					t.Fatal("discovery unexpectedly panicked", panicValues)
				}
			}
		})
	}
}

func TestZiranDiscoveryNativeRegistrationValidation(t *testing.T) {
	// These released validation failures occur before hostname/interface
	// lookup and socket creation, so the test never advertises on the LAN.
	for _, input := range []struct {
		instance, service, domain string
		port                      int
	}{
		{"", "_daochi._tcp", "local.", 8080},
		{"node", "", "local.", 8080},
		{"node", "_daochi._tcp", "local.", 0},
	} {
		got := Discovery_Register(input.instance, input.service, input.domain, input.port, nil, nil)
		want, err := zeroconf.Register(input.instance, input.service, input.domain, input.port, nil, nil)
		if got.Value != want || !sameIdentityError(got.Error, err) || got.Error == nil {
			t.Fatal("native discovery registration changed", got, want, err)
		}
	}
}
