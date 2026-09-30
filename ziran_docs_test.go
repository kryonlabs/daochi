package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
)

func TestZiranDocsSpecAgainstBaseline(t *testing.T) {
	actual, original := Docs_Spec(), baselineOpenAPISpec()
	if !reflect.DeepEqual(actual, original) {
		t.Fatal("OpenAPI spec changed its fields, values or concrete native types")
	}
	for _, fields := range []struct {
		name     string
		actual   []map[string]any
		original []map[string]any
	}{
		{"signed", Docs_SignedHeaderParameters(), baselineSignedHeaderParameters()},
		{"sync", Docs_SyncHeaderParameters(), baselineSyncHeaderParameters()},
		{"bearer", Docs_BearerHeaderParameters(), baselineBearerHeaderParameters()},
	} {
		if !reflect.DeepEqual(fields.actual, fields.original) || cap(fields.actual) != cap(fields.original) {
			t.Fatalf("%s header parameter fields or native storage changed", fields.name)
		}
	}
	encoded, err := json.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(original)
	if err != nil || !bytes.Equal(encoded, want) {
		t.Fatal("OpenAPI JSON bytes changed", err)
	}
	actual["info"].(map[string]any)["title"] = "changed"
	delete(actual["paths"].(map[string]any), "/healthz")
	if !reflect.DeepEqual(Docs_Spec(), original) {
		t.Fatal("spec builders share mutable maps across requests")
	}
	parameters := Docs_SignedHeaderParameters()
	parameters[0]["schema"].(map[string]any)["type"] = "changed"
	if !reflect.DeepEqual(Docs_SignedHeaderParameters(), baselineSignedHeaderParameters()) {
		t.Fatal("parameter builders share mutable nested maps")
	}
}

type docsWriter struct {
	header    http.Header
	events    []string
	body      []byte
	written   []byte
	failure   error
	panicAt   string
	panicWith any
	retain    bool
}

func (writer *docsWriter) Header() http.Header {
	writer.events = append(writer.events, "header")
	if writer.panicAt == "header" {
		panic(writer.panicWith)
	}
	return writer.header
}

func (writer *docsWriter) WriteHeader(status int) {
	writer.events = append(writer.events, fmt.Sprint("status:", status))
	if writer.panicAt == "status" {
		panic(writer.panicWith)
	}
}

func (writer *docsWriter) Write(data []byte) (int, error) {
	writer.events = append(writer.events, "write")
	writer.written = bytes.Clone(data)
	if writer.retain {
		writer.written = data
	}
	if writer.panicAt == "write" {
		panic(writer.panicWith)
	}
	if writer.failure != nil {
		return 0, writer.failure
	}
	writer.body = append(writer.body, data...)
	return len(data), nil
}

func TestZiranDocsOpenAPIAgainstBaseline(t *testing.T) {
	sentinel := errors.New("documentation writer failure")
	for _, mode := range []string{"success", "write error", "header", "status", "write"} {
		t.Run(mode, func(t *testing.T) {
			var writers []*docsWriter
			var panics []any
			for implementation := 0; implementation < 2; implementation++ {
				writer := &docsWriter{header: make(http.Header), panicAt: mode, panicWith: sentinel}
				if mode == "write error" {
					writer.failure = sentinel
				}
				writers = append(writers, writer)
				var panicValue any
				func() {
					defer func() { panicValue = recover() }()
					if implementation == 0 {
						Docs_OpenAPI(writer, nil)
					} else {
						(*Server)(nil).baselineHandleOpenAPI(writer, nil)
					}
				}()
				panics = append(panics, panicValue)
			}
			if !reflect.DeepEqual(writers[0], writers[1]) || panics[0] != panics[1] {
				t.Fatal("OpenAPI write order, bytes, errors or panic identity changed", panics)
			}
		})
	}
	first, second := &docsWriter{header: make(http.Header), retain: true}, &docsWriter{header: make(http.Header), retain: true}
	Docs_OpenAPI(first, nil)
	Docs_OpenAPI(second, nil)
	if len(first.written) == 0 || &first.written[0] != &second.written[0] {
		t.Fatal("OpenAPI requests rebuild their cached payload")
	}
	if first.written[len(first.written)-1] != '\n' {
		t.Fatal("OpenAPI lost its trailing newline")
	}
}

func TestZiranDocsHandlerAgainstBaseline(t *testing.T) {
	logger := slog.Default()
	t.Cleanup(func() { slog.SetDefault(logger) })
	sentinel := errors.New("documentation dependency failure")
	stats := []PublicStats{
		{},
		{UserCount: 42, StorageUsedBytes: 1, AvailableGB: 10},
		{UserCount: 7, StorageUsedBytes: 1 << 30, StorageUsedGB: 1, AvailableGB: 10},
		{UserCount: -1, StorageUsedBytes: -1, StorageUsedGB: -2, AvailableGB: -3},
		{UserCount: math.MaxInt64, StorageUsedGB: math.MaxInt64, AvailableGB: 1},
		{UserCount: math.MinInt64, StorageUsedGB: math.MinInt64, AvailableGB: -1},
	}
	for _, mode := range []string{"success", "unknown path", "query error", "query panic", "log panic", "header", "status", "write", "write error"} {
		t.Run(mode, func(t *testing.T) {
			for _, value := range stats {
				var writers []*docsWriter
				var traces [][]string
				var panics []any
				for implementation := 0; implementation < 2; implementation++ {
					var events []string
					writer := &docsWriter{header: make(http.Header), panicAt: mode, panicWith: sentinel}
					if mode == "write error" {
						writer.failure = sentinel
					}
					writers = append(writers, writer)
					slog.SetDefault(slog.New(discoveryLogHandler{record: func(record slog.Record) {
						event := record.Level.String() + ":" + record.Message
						record.Attrs(func(attribute slog.Attr) bool {
							event += "|" + attribute.Key + "=" + attribute.Value.String()
							return true
						})
						events = append(events, event)
						if mode == "log panic" {
							panic(sentinel)
						}
					}}))
					contextValue := context.WithValue(context.Background(), struct{}{}, "request identity")
					request := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(contextValue)
					if mode == "unknown path" {
						request.URL.Path = "/missing"
					}
					read := func(ctx context.Context, path string) (PublicStats, error) {
						if ctx != contextValue || path != "private/database.sqlite" {
							t.Fatal("stats query changed context or database path")
						}
						events = append(events, "stats")
						if mode == "query panic" {
							panic(sentinel)
						}
						if mode == "query error" || mode == "log panic" {
							return value, sentinel
						}
						return value, nil
					}
					var panicValue any
					func() {
						defer func() { panicValue = recover() }()
						if implementation == 0 {
							Docs_Handle(writer, request, "private/database.sqlite", func(ctx context.Context, path string) PublicStatsResult {
								value, err := read(ctx, path)
								return PublicStatsResult{Value: value, Error: err}
							})
						} else {
							server := &Server{cfg: Config{DBPath: "private/database.sqlite"}}
							server.baselineHandleDocs(writer, request, read)
						}
					}()
					traces = append(traces, events)
					panics = append(panics, panicValue)
				}
				if !reflect.DeepEqual(writers[0], writers[1]) || !reflect.DeepEqual(traces[0], traces[1]) || panics[0] != panics[1] {
					actual, original := writers[0].body, writers[1].body
					for index := 0; index < len(actual) && index < len(original); index++ {
						if actual[index] != original[index] {
							t.Fatalf("HTML differs at byte %d: actual %q; original %q", index, actual[index:min(index+100, len(actual))], original[index:min(index+100, len(original))])
						}
					}
					t.Fatalf("documentation handler differs for %#v: lengths %d/%d; headers %v/%v; writer events %v/%v; written %d/%d; traces %v; panics %v", value, len(actual), len(original), writers[0].header, writers[1].header, writers[0].events, writers[1].events, len(writers[0].written), len(writers[1].written), traces, panics)
				}
			}
		})
	}
}

func TestZiranDocsConcurrentOpenAPI(t *testing.T) {
	want := baselineOpenAPISpecJSON()
	var workers sync.WaitGroup
	for index := 0; index < 32; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			writer := httptest.NewRecorder()
			Docs_OpenAPI(writer, nil)
			if writer.Code != http.StatusOK || !bytes.Equal(writer.Body.Bytes(), want) {
				t.Error("concurrent OpenAPI response differs from the original")
			}
		}()
	}
	workers.Wait()
}
