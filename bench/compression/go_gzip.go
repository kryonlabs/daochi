// Benchmark tooling only: the production encoder is authored in response.zi.
package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

type Corpus struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	Path string `json:"path"`
}

type Timing struct {
	Median      float64 `json:"median_ms"`
	P95         float64 `json:"p95_ms"`
	Samples     int     `json:"samples"`
	Allocated   float64 `json:"allocated_bytes_per_op"`
	Allocations float64 `json:"allocations_per_op"`
}

func measure(fn func() []byte) Timing {
	fn()
	runtime.GC()
	var before, after runtime.MemStats
	samples := make([]float64, 0, 2000)
	runtime.ReadMemStats(&before)
	started := time.Now()
	for len(samples) < 9 || (time.Since(started) < 45*time.Millisecond && len(samples) < cap(samples)) {
		at := time.Now()
		out := fn()
		samples = append(samples, float64(time.Since(at).Nanoseconds())/1e6)
		runtime.KeepAlive(out)
	}
	runtime.ReadMemStats(&after)
	sort.Float64s(samples)
	n := len(samples)
	return Timing{samples[n/2], samples[min(n-1, int(float64(n)*.95))], n,
		float64(after.TotalAlloc-before.TotalAlloc) / float64(n),
		float64(after.Mallocs-before.Mallocs) / float64(n)}
}

func main() {
	runtime.GOMAXPROCS(1)
	out := os.Args[1]
	index, err := os.ReadFile(filepath.Join(out, "corpus.json"))
	if err != nil {
		panic(err)
	}
	var corpora []Corpus
	if err := json.Unmarshal(index, &corpora); err != nil {
		panic(err)
	}
	results := []map[string]any{}
	for _, item := range corpora {
		data, err := os.ReadFile(item.Path)
		if err != nil {
			panic(err)
		}
		for _, level := range []int{1, 3, 6, 9} {
			for _, pooled := range []bool{false, true} {
				var buffer bytes.Buffer
				writer, err := gzip.NewWriterLevel(&buffer, level)
				if err != nil {
					panic(err)
				}
				encode := func() []byte {
					buffer.Reset()
					if pooled {
						writer.Reset(&buffer)
					} else {
						writer, err = gzip.NewWriterLevel(&buffer, level)
						if err != nil {
							panic(err)
						}
					}
					if _, err := writer.Write(data); err != nil {
						panic(err)
					}
					if err := writer.Close(); err != nil {
						panic(err)
					}
					return buffer.Bytes()
				}
				encoded := append([]byte(nil), encode()...)
				decode := func() []byte {
					reader, err := gzip.NewReader(bytes.NewReader(encoded))
					if err != nil {
						panic(err)
					}
					decoded, err := io.ReadAll(reader)
					if err != nil {
						panic(err)
					}
					if err := reader.Close(); err != nil {
						panic(err)
					}
					return decoded
				}
				if !bytes.Equal(decode(), data) {
					panic("gzip roundtrip mismatch")
				}
				kind := "gzip-go-fresh"
				if pooled {
					kind = "gzip-go-reuse"
				}
				results = append(results, map[string]any{"corpus": item.Name, "kind": item.Kind,
					"codec": kind, "level": level, "input_bytes": len(data), "compressed_bytes": len(encoded),
					"encode": measure(encode), "decode": measure(decode), "roundtrip": true})
			}
		}
		for _, level := range []int{1, 3, 7, 11} {
			for _, entropy := range []bool{false, true} {
				for _, pooled := range []bool{false, true} {
					factory := func(dst io.Writer) io.WriteCloser {
						opts := []zstd.EOption{zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(level)), zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(1 << 20)}
						if entropy {
							opts = append(opts, zstd.WithAllLitEntropyCompression(true))
						}
						w, err := zstd.NewWriter(dst, opts...)
						if err != nil {
							panic(err)
						}
						return w
					}
					decode := func(encoded []byte) []byte {
						r, err := zstd.NewReader(bytes.NewReader(encoded), zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(8<<20))
						if err != nil {
							panic(err)
						}
						defer r.Close()
						v, err := io.ReadAll(r)
						if err != nil {
							panic(err)
						}
						return v
					}
					name := "zstd-go"
					if entropy {
						name = "zstd-go-entropy"
					}
					results = append(results, streamCase(out, item, data, name, level, pooled, factory, decode))
				}
			}
		}
		for _, level := range []int{1, 4, 6} {
			for _, pooled := range []bool{false, true} {
				factory := func(dst io.Writer) io.WriteCloser { return brotli.NewWriterLevel(dst, level) }
				decode := func(encoded []byte) []byte {
					v, err := io.ReadAll(brotli.NewReader(bytes.NewReader(encoded)))
					if err != nil {
						panic(err)
					}
					return v
				}
				results = append(results, streamCase(out, item, data, "brotli-go", level, pooled, factory, decode))
			}
		}
		fmt.Println("Go codec benchmark completed", item.Name)
	}
	encoded, err := json.MarshalIndent(map[string]any{"go": runtime.Version(), "zstd_module": "github.com/klauspost/compress@v1.20.3", "brotli_module": "github.com/andybalholm/brotli@v1.2.4", "zstd_window_bytes": 1 << 20, "results": results}, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(out, "go-results.json"), append(encoded, '\n'), 0644); err != nil {
		panic(err)
	}
}

type resetWriter interface{ Reset(io.Writer) }

func streamCase(out string, item Corpus, data []byte, name string, level int, pooled bool,
	factory func(io.Writer) io.WriteCloser, decode func([]byte) []byte) map[string]any {
	var buffer bytes.Buffer
	var writer io.WriteCloser
	encode := func() []byte {
		buffer.Reset()
		if pooled && writer != nil {
			writer.(resetWriter).Reset(&buffer)
		} else {
			writer = factory(&buffer)
		}
		// Model streaming response writes without forcing per-chunk flushes.
		for offset := 0; offset < len(data); offset += 32768 {
			if _, err := writer.Write(data[offset:min(offset+32768, len(data))]); err != nil {
				panic(err)
			}
		}
		if err := writer.Close(); err != nil {
			panic(err)
		}
		return buffer.Bytes()
	}
	encoded := append([]byte(nil), encode()...)
	if !bytes.Equal(decode(encoded), data) {
		panic("candidate stream roundtrip mismatch")
	}
	mode := "fresh"
	if pooled {
		mode = "reuse"
	}
	path := filepath.Join(out, "cross-decode", item.Name)
	if err := os.MkdirAll(path, 0755); err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(path, fmt.Sprintf("%s-%d-%s.bin", name, level, mode)), encoded, 0644); err != nil {
		panic(err)
	}
	return map[string]any{"corpus": item.Name, "kind": item.Kind, "codec": name + "-" + mode, "level": level,
		"input_bytes": len(data), "compressed_bytes": len(encoded), "encode": measure(encode),
		"decode": measure(func() []byte { return decode(encoded) }), "roundtrip": true}
}
