// Private loopback transport benchmark; no production service or account data.
package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

type resetWriter interface{ Reset(io.Writer) }
type profile struct {
	name, encoding string
	level          int
	reuse          bool
}

func factory(p profile, dst io.Writer) io.WriteCloser {
	switch p.encoding {
	case "gzip":
		w, err := gzip.NewWriterLevel(dst, p.level)
		if err != nil {
			panic(err)
		}
		return w
	case "zstd":
		opts := []zstd.EOption{zstd.WithEncoderConcurrency(1), zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(p.level)), zstd.WithWindowSize(1 << 20)}
		if p.name == "zstd-1-entropy-reuse" || p.name == "zstd-3-entropy-reuse" {
			opts = append(opts, zstd.WithAllLitEntropyCompression(true))
		}
		w, err := zstd.NewWriter(dst, opts...)
		if err != nil {
			panic(err)
		}
		return w
	case "br":
		return brotli.NewWriterLevel(dst, p.level)
	}
	panic("unknown codec")
}

func run(data []byte, p profile, concurrency int) map[string]any {
	var pool sync.Pool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.encoding == "identity" {
			_, _ = w.Write(data)
			return
		}
		w.Header().Set("Content-Encoding", p.encoding)
		var encoder io.WriteCloser
		if p.reuse {
			if v := pool.Get(); v != nil {
				encoder = v.(io.WriteCloser)
				encoder.(resetWriter).Reset(w)
			}
		}
		if encoder == nil {
			encoder = factory(p, w)
		}
		for start := 0; start < len(data); start += 32768 {
			if _, err := encoder.Write(data[start:min(start+32768, len(data))]); err != nil {
				panic(err)
			}
		}
		if err := encoder.Close(); err != nil {
			panic(err)
		}
		if p.reuse {
			pool.Put(encoder)
		}
	}))
	defer srv.Close()
	transport := &http.Transport{DisableCompression: true, MaxIdleConns: concurrency, MaxIdleConnsPerHost: concurrency, MaxConnsPerHost: concurrency}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	type sample struct {
		ms, first float64
		wire      int
	}
	one := func() sample {
		started := time.Now()
		first := 0.0
		req, _ := http.NewRequest("GET", srv.URL, nil)
		req.Header.Set("Accept-Encoding", p.encoding)
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotFirstResponseByte: func() { first = float64(time.Since(started).Nanoseconds()) / 1e6 }}))
		response, err := client.Do(req)
		if err != nil {
			panic(err)
		}
		body, err := io.ReadAll(response.Body)
		if err != nil {
			panic(err)
		}
		_ = response.Body.Close()
		wire := len(body)
		var decoded []byte
		switch p.encoding {
		case "identity":
			decoded = body
		case "gzip":
			r, err := gzip.NewReader(bytes.NewReader(body))
			if err != nil {
				panic(err)
			}
			decoded, err = io.ReadAll(r)
			if err != nil {
				panic(err)
			}
			_ = r.Close()
		case "br":
			decoded, err = io.ReadAll(brotli.NewReader(bytes.NewReader(body)))
			if err != nil {
				panic(err)
			}
		case "zstd":
			r, err := zstd.NewReader(bytes.NewReader(body), zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(8<<20))
			if err != nil {
				panic(err)
			}
			decoded, err = io.ReadAll(r)
			if err != nil {
				panic(err)
			}
			r.Close()
		}
		if !bytes.Equal(decoded, data) {
			panic("HTTP roundtrip mismatch")
		}
		return sample{float64(time.Since(started).Nanoseconds()) / 1e6, first, wire}
	}
	for i := 0; i < 4; i++ {
		one()
	}
	jobs := make(chan int)
	results := make(chan sample, 24)
	var workers sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range jobs {
				results <- one()
			}
		}()
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	started := time.Now()
	go func() {
		defer close(jobs)
		for i := 0; i < 24; i++ {
			jobs <- i
		}
	}()
	workers.Wait()
	close(results)
	elapsed := time.Since(started).Seconds()
	runtime.ReadMemStats(&after)
	latency, first := []float64{}, []float64{}
	wire := 0
	for s := range results {
		latency = append(latency, s.ms)
		first = append(first, s.first)
		wire = s.wire
	}
	sort.Float64s(latency)
	sort.Float64s(first)
	return map[string]any{"profile": p.name, "concurrency": concurrency, "requests": len(latency), "input_bytes": len(data), "compressed_bytes": wire,
		"median_ms": latency[len(latency)/2], "p95_ms": latency[22], "first_response_byte_median_ms": first[len(first)/2],
		"uncompressed_mib_per_second": float64(len(data)*len(latency)) / elapsed / 1048576,
		"allocated_bytes_per_request": float64(after.TotalAlloc-before.TotalAlloc) / float64(len(latency)), "roundtrip": true}
}

func main() {
	runtime.GOMAXPROCS(1)
	out := os.Args[1]
	results := []map[string]any{}
	profiles := []profile{{"identity", "identity", 0, false}, {"gzip-1-fresh", "gzip", 1, false}, {"gzip-1-reuse", "gzip", 1, true},
		{"zstd-1-reuse", "zstd", 1, true}, {"zstd-3-reuse", "zstd", 3, true},
		{"zstd-1-entropy-reuse", "zstd", 1, true}, {"zstd-3-entropy-reuse", "zstd", 3, true}, {"brotli-4-reuse", "br", 4, true}}
	for _, corpus := range []string{"control", "page-medium", "page-large"} {
		data, err := os.ReadFile(filepath.Join(out, "corpus", corpus+".bin"))
		if err != nil {
			panic(err)
		}
		for _, p := range profiles {
			for _, concurrency := range []int{1, 4} {
				r := run(data, p, concurrency)
				r["corpus"] = corpus
				results = append(results, r)
			}
		}
		fmt.Println("HTTP benchmark completed", corpus)
	}
	value, err := json.MarshalIndent(map[string]any{"go": runtime.Version(), "method": "Private loopback HTTP, warm keepalive, 24 requests per case, GOMAXPROCS=1; completion includes decompression and byte comparison. Not production, TLS, database or device latency. First response byte is HTTP headers, not first decoded record.", "results": results}, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(out, "http-results.json"), append(value, '\n'), 0644); err != nil {
		panic(err)
	}
}
