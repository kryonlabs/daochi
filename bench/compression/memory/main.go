// Retained encoder memory, isolated from payload buffers and response storage.
package main

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func measure(data []byte, name string, count int) map[string]any {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	writers := make([]io.WriteCloser, 0, count)
	for i := 0; i < count; i++ {
		var w io.WriteCloser
		switch name {
		case "gzip-1":
			v, err := gzip.NewWriterLevel(io.Discard, 1)
			if err != nil {
				panic(err)
			}
			w = v
		case "brotli-4":
			w = brotli.NewWriterLevel(io.Discard, 4)
		default:
			level := 1
			if name == "zstd-3-entropy" {
				level = 3
			}
			v, err := zstd.NewWriter(io.Discard, zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(1<<20),
				zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(level)), zstd.WithAllLitEntropyCompression(true))
			if err != nil {
				panic(err)
			}
			w = v
		}
		for offset := 0; offset < len(data); offset += 32768 {
			if _, err := w.Write(data[offset:min(offset+32768, len(data))]); err != nil {
				panic(err)
			}
		}
		if err := w.Close(); err != nil {
			panic(err)
		}
		writers = append(writers, w)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(writers)
	runtime.KeepAlive(data)
	return map[string]any{"profile": name, "retained_writers": count,
		"retained_heap_bytes": int64(after.HeapAlloc) - int64(before.HeapAlloc),
		"allocated_bytes":     after.TotalAlloc - before.TotalAlloc}
}

func main() {
	runtime.GOMAXPROCS(1)
	out := os.Args[1]
	data, err := os.ReadFile(filepath.Join(out, "corpus", "page-large.bin"))
	if err != nil {
		panic(err)
	}
	rows := []map[string]any{}
	for _, name := range []string{"gzip-1", "zstd-1-entropy", "zstd-3-entropy", "brotli-4"} {
		for _, count := range []int{1, 4} {
			rows = append(rows, measure(data, name, count))
		}
	}
	encoded, err := json.MarshalIndent(map[string]any{"go": runtime.Version(), "method": "Retained Go heap increase after GC for closed reusable writers, private 1 MiB zstd window, output io.Discard; payload already resident; excludes decoder, HTTP buffers, database and full process RSS.", "results": rows}, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(out, "memory-results.json"), append(encoded, '\n'), 0644); err != nil {
		panic(err)
	}
}
