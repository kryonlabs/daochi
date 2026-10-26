package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
)

func zstdFixture(t *testing.T, plain []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer, err := zstd.NewWriter(&buffer, zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestContentCodingSelectsNegotiatedRepresentation(t *testing.T) {
	for header, want := range map[string]string{
		"": "identity", "br": "identity", "gzip": "gzip", "zstd": "zstd",
		"gzip, zstd": "zstd", "gzip;q=1,zstd;q=0.5": "gzip",
		"gzip;q=0.4,zstd;q=0.5": "zstd", "ZsTd ; Q=0.5": "zstd",
		"*;q=0.5,zstd;q=0": "gzip", "*;q=0.5,gzip;q=0": "zstd",
		"gzip;q=0,zstd;q=0": "identity", "*;q=0": "",
		"gzip;q=0,zstd;q=0,identity;q=0": "",
		"identity;q=1,zstd;q=0.5":        "identity",
		"identity;q=0,zstd;q=0.2":        "zstd",
		"zstd;q=0,zstd;q=1":              "identity", "zstd;q=1.001": "identity",
		"zstd;q=1;q=0": "identity", "gzip;q=garbage,zstd;q=0.2": "zstd",
	} {
		if got := ContentCoding_SelectEncoding(header); got != want {
			t.Errorf("%q: got %q, want %q", header, got, want)
		}
	}
	if got := ContentCoding_SelectEncoding(strings.Repeat("z", 4097)); got != "" {
		t.Fatal("oversized negotiation accepted")
	}
	t.Setenv("DAOCHI_HTTP_ZSTD_RESPONSES", "0")
	if got := ContentCoding_SelectEncoding("zstd,gzip"); got != "gzip" {
		t.Fatal("response rollback switch ignored", got)
	}
	if got := ContentCoding_SelectEncoding("zstd,identity;q=0"); got != "" {
		t.Fatal("disabled representation selected", got)
	}
}

func TestContentCodingZstdBoundsAndCorruption(t *testing.T) {
	plain := []byte(`{"value":"` + strings.Repeat("x", 4096) + `"}`)
	encoded := zstdFixture(t, plain)
	for _, trial := range []struct {
		name  string
		body  []byte
		limit int64
		valid bool
	}{
		{"valid", encoded, 8192, true},
		{"exact", encoded, int64(len(plain)), true},
		{"expansion", encoded, 512, false},
		{"wire", encoded, 8, false},
		{"truncated", encoded[:len(encoded)-1], 8192, false},
		{"trailing", append(append([]byte{}, encoded...), 'x'), 8192, false},
		{"empty", nil, 8192, false},
		{"window", []byte{0x28, 0xb5, 0x2f, 0xfd, 0, 0x98, 1, 0, 0}, 8192, false},
	} {
		t.Run(trial.name, func(t *testing.T) {
			request := httptest.NewRequest("POST", "/api/v1/sync", bytes.NewReader(trial.body))
			request.Header.Set("Content-Encoding", "zstd")
			got := HttpBody_ReadJSON(httptest.NewRecorder(), request, trial.limit)
			if (got.Error == nil) != trial.valid {
				t.Fatalf("valid=%v error=%v", trial.valid, got.Error)
			}
			if trial.valid && !bytes.Equal(got.Value, plain) {
				t.Fatal("decoded JSON changed")
			}
		})
	}
	t.Setenv("DAOCHI_HTTP_ZSTD_REQUESTS", "0")
	request := httptest.NewRequest("POST", "/", bytes.NewReader(encoded))
	request.Header.Set("Content-Encoding", "zstd")
	if got := HttpBody_ReadJSON(httptest.NewRecorder(), request, 8192); got.Error == nil {
		t.Fatal("request rollback switch ignored")
	}
	for _, capability := range NodeInfo_Capabilities() {
		if capability == "http-zstd-v1" {
			t.Fatal("disabled decoder advertised")
		}
	}
}

func TestContentCodingZstdResponseAndLiteralEntropy(t *testing.T) {
	raw := make([]byte, 3<<20)
	rand.New(rand.NewSource(407)).Read(raw)
	value := map[string]string{"ciphertext": base64.RawURLEncoding.EncodeToString(raw)}
	for attempt := 0; attempt < 8; attempt++ {
		request := httptest.NewRequest("GET", "/", nil)
		request.Header.Set("Accept-Encoding", "gzip, zstd")
		recorder := httptest.NewRecorder()
		recorder.Header().Set("Vary", "Origin")
		recorder.Header().Set("Content-Length", "1")
		Response_JSONRequest(recorder, request, 200, value)
		if recorder.Code != 200 || recorder.Header().Get("Content-Encoding") != "zstd" {
			t.Fatal("response negotiation", recorder.Code, recorder.Header())
		}
		if recorder.Header().Get("Vary") != "Origin, Accept-Encoding" || recorder.Header().Get("Content-Length") != "" {
			t.Fatal("representation headers", recorder.Header())
		}
		if recorder.Body.Len() >= len(value["ciphertext"])*80/100 {
			t.Fatal("large base64 page bypassed entropy compression")
		}
		reader, err := zstd.NewReader(bytes.NewReader(recorder.Body.Bytes()), zstd.WithDecoderConcurrency(1))
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]string
		if err := json.Unmarshal(decoded, &got); err != nil || got["ciphertext"] != value["ciphertext"] {
			t.Fatal("pooled response changed", err)
		}
	}
	for _, trial := range []struct {
		method string
		status int
	}{{"HEAD", 200}, {"GET", 204}, {"GET", 304}} {
		request := httptest.NewRequest(trial.method, "/", nil)
		request.Header.Set("Accept-Encoding", "zstd")
		recorder := httptest.NewRecorder()
		Response_JSONRequest(recorder, request, trial.status, value)
		if recorder.Body.Len() != 0 || recorder.Header().Get("Content-Encoding") != "" {
			t.Fatal("bodyless response encoded", trial)
		}
	}
	request := httptest.NewRequest("GET", "/", nil)
	request.Header.Set("Accept-Encoding", "gzip;q=0,zstd;q=0,identity;q=0")
	recorder := httptest.NewRecorder()
	Response_JSONRequest(recorder, request, 200, value)
	if recorder.Code != 406 {
		t.Fatal("unacceptable identity fallback", recorder.Code)
	}
}

func TestContentCodingEncoderPoolIsBoundedAndCancelable(t *testing.T) {
	leases := []EncoderLease{}
	for i := 0; i < 4; i++ {
		lease := ContentCoding_AcquireEncoder(context.Background(), io.Discard, "zstd")
		if lease.Error != nil {
			t.Fatal(lease.Error)
		}
		leases = append(leases, lease)
	}
	defer func() {
		for i := range leases {
			ContentCoding_ReleaseEncoder(&leases[i])
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan EncoderLease, 1)
	go func() { result <- ContentCoding_AcquireEncoder(ctx, io.Discard, "zstd") }()
	cancel()
	select {
	case lease := <-result:
		if !errors.Is(lease.Error, context.Canceled) || lease.Slot != -1 {
			t.Fatal("fifth encoder allocated or cancellation lost", lease.Error)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting encoder ignored cancellation")
	}
}

type compressionFailureWriter struct {
	header     http.Header
	panicWrite bool
}

func (w *compressionFailureWriter) Header() http.Header { return w.header }
func (w *compressionFailureWriter) WriteHeader(int)     {}
func (w *compressionFailureWriter) Write([]byte) (int, error) {
	if w.panicWrite {
		panic("compression writer panic")
	}
	return 0, io.ErrClosedPipe
}

func TestContentCodingEncoderPoolRecoversFromWriteFailureAndPanic(t *testing.T) {
	for _, encoding := range []string{"gzip", "zstd"} {
		for _, panicWrite := range []bool{false, true} {
			func() {
				defer func() {
					if recovered := recover(); panicWrite && recovered != "compression writer panic" {
						t.Errorf("native panic changed: %v", recovered)
					}
				}()
				request := httptest.NewRequest("GET", "/", nil)
				request.Header.Set("Accept-Encoding", encoding)
				Response_JSONRequest(&compressionFailureWriter{make(http.Header), panicWrite}, request, 200, map[string]string{"value": "record"})
			}()
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	leases := []EncoderLease{}
	for i := 0; i < 4; i++ {
		lease := ContentCoding_AcquireEncoder(ctx, io.Discard, "gzip")
		if lease.Error != nil {
			t.Fatal("pool permit leaked", lease.Error)
		}
		leases = append(leases, lease)
	}
	for i := range leases {
		ContentCoding_ReleaseEncoder(&leases[i])
	}
}

func TestContentCodingConcurrentResponseOwnership(t *testing.T) {
	var workers sync.WaitGroup
	for index := 0; index < 24; index++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			for attempt := 0; attempt < 4; attempt++ {
				request := httptest.NewRequest("GET", "/", nil)
				request.Header.Set("Accept-Encoding", "zstd")
				recorder := httptest.NewRecorder()
				value := fmt.Sprintf("request-%d-%d", index, attempt)
				Response_JSONRequest(recorder, request, 200, value)
				got := ContentCoding_DecodeZstd(recorder.Body.Bytes(), 1024)
				var decoded string
				if got.Error != nil || json.Unmarshal(got.Value, &decoded) != nil || decoded != value {
					t.Errorf("cross-request response: %v %q", got.Error, decoded)
				}
			}
		}(index)
	}
	workers.Wait()
}

func TestRecordPagesZstdKeepsDecodedTransactionSignatures(t *testing.T) {
	server, store, identity, key := recordPageFixture(t)
	insertPageRecord(t, store, identity.UserID, "private.pageapp.v1.records.media", "one", strings.Repeat("opaque", 64), 1)
	lifecycleExecute(t, store, `UPDATE server_sync_state SET server_version=1 WHERE user_id_hash=?1`, identity.UserID)
	body, err := json.Marshal(map[string]any{
		"protocol_version": 6, "app_id": "pageapp", "user_id_hash": identity.UserID,
		"client_id": "page-client", "encrypted_records_only": true,
		"record_limit": 1, "include_metadata": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	wire := zstdFixture(t, body)
	for trial := 0; trial < 2; trial++ {
		signedBody := body
		if trial == 1 {
			signedBody = wire
		}
		header := signedTxHeader(t, identity.UserID, "pageapp", "page-key", "POST", "/api/v1/sync", signedBody, key, fmt.Sprintf("zstd-page-tx-%d", trial))
		request := httptest.NewRequest("POST", "/api/v1/sync", bytes.NewReader(wire))
		request.Header.Set("Authorization", "Bearer "+identity.Token)
		request.Header.Set("X-Daochi-User", identity.UserID)
		request.Header.Set("X-Daochi-Tx", header)
		request.Header.Set("Content-Encoding", "zstd")
		request.Header.Set("Accept-Encoding", "zstd")
		recorder := httptest.NewRecorder()
		server.Routes().ServeHTTP(recorder, request)
		if trial == 1 {
			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("signature of compressed bytes accepted: %d", recorder.Code)
			}
			continue
		}
		if recorder.Code != 200 || recorder.Header().Get("Content-Encoding") != "zstd" {
			t.Fatal("signed zstd sync", recorder.Code, recorder.Body.String())
		}
		decoded := ContentCoding_DecodeZstd(recorder.Body.Bytes(), 1<<20)
		if decoded.Error != nil || !json.Valid(decoded.Value) {
			t.Fatal("zstd sync response", decoded.Error)
		}
	}
}

func TestNodeInfoNegotiatesZstdAndIdentifiesBuild(t *testing.T) {
	server, _, _, _ := recordPageFixture(t)
	request := httptest.NewRequest("GET", "/api/v1/node", nil)
	request.Header.Set("Accept-Encoding", "zstd,gzip")
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != 200 || recorder.Header().Get("Content-Encoding") != "zstd" {
		t.Fatal("node response", recorder.Code, recorder.Body.String())
	}
	decoded := ContentCoding_DecodeZstd(recorder.Body.Bytes(), 1<<20)
	var node map[string]any
	if decoded.Error != nil || json.Unmarshal(decoded.Value, &node) != nil || node["build_version"] != BuildVersion {
		t.Fatal("installed build identity missing", decoded.Error)
	}
}

func BenchmarkContentCodingResponse(b *testing.B) {
	for _, size := range []int{192 << 10, 3 << 20} {
		raw := make([]byte, size)
		rand.New(rand.NewSource(407)).Read(raw)
		value := map[string]string{"ciphertext": base64.RawURLEncoding.EncodeToString(raw)}
		for _, encoding := range []string{"gzip-fresh", "gzip", "zstd"} {
			b.Run(fmt.Sprintf("bytes-%d/%s", size, encoding), func(b *testing.B) {
				request := httptest.NewRequest("GET", "/", nil)
				request.Header.Set("Accept-Encoding", encoding)
				b.ReportAllocs()
				for i := 0; i < 4; i++ {
					Response_JSONRequest(httptest.NewRecorder(), request, 200, value)
				}
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					recorder := httptest.NewRecorder()
					if encoding == "gzip-fresh" {
						writer, err := gzip.NewWriterLevel(recorder, 1)
						if err != nil {
							b.Fatal(err)
						}
						if err := json.NewEncoder(writer).Encode(value); err != nil {
							b.Fatal(err)
						}
						if err := writer.Close(); err != nil {
							b.Fatal(err)
						}
					} else {
						Response_JSONRequest(recorder, request, 200, value)
					}
				}
			})
		}
	}
}

func TestNodeInfoNativeCurlZstdInterop(t *testing.T) {
	curl, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("native curl is not installed")
	}
	version, err := exec.Command(curl, "--version").Output()
	if err != nil || !bytes.Contains(version, []byte("zstd/")) {
		t.Skip("native curl has no Zstandard decoder")
	}
	server, _, _, _ := recordPageFixture(t)
	private := httptest.NewServer(server.Routes())
	defer private.Close()
	body, err := exec.Command(curl, "--fail", "--silent", "--show-error", "--compressed", "--noproxy", "*", "--max-time", "10", "-H", "Accept-Encoding: zstd", private.URL+"/api/v1/node").Output()
	if err != nil {
		t.Fatal("native client transport failed", err)
	}
	var node map[string]any
	if err := json.Unmarshal(body, &node); err != nil || node["build_version"] != BuildVersion {
		t.Fatal("native client did not decode node JSON", err)
	}
}

func TestContentCodingRepeatedHeadersAndRange(t *testing.T) {
	request := httptest.NewRequest("GET", "/", nil)
	request.Header.Add("Accept-Encoding", "gzip;q=0.5")
	request.Header.Add("Accept-Encoding", "zstd;q=1")
	recorder := httptest.NewRecorder()
	Response_JSONRequest(recorder, request, 200, "record")
	if recorder.Header().Get("Content-Encoding") != "zstd" {
		t.Fatal("repeated negotiation fields ignored")
	}
	recorder = httptest.NewRecorder()
	recorder.Header().Add("Vary", "Origin")
	recorder.Header().Add("Vary", "X-Client")
	Response_JSONRequest(recorder, request, 200, "record")
	if recorder.Header().Get("Vary") != "Origin, X-Client, Accept-Encoding" {
		t.Fatal("repeated Vary selectors lost", recorder.Header())
	}
	request = httptest.NewRequest("POST", "/", bytes.NewReader(zstdFixture(t, []byte(`{"ok":true}`))))
	request.Header.Add("Content-Encoding", "zstd")
	request.Header.Add("Content-Encoding", "gzip")
	if got := HttpBody_ReadJSON(httptest.NewRecorder(), request, 4096); got.Error == nil {
		t.Fatal("stacked request encodings accepted")
	}
	for _, accepted := range []string{"zstd", "zstd,identity;q=0"} {
		request := httptest.NewRequest("GET", "/", nil)
		request.Header.Set("Accept-Encoding", accepted)
		recorder := httptest.NewRecorder()
		Response_JSONRequest(recorder, request, 206, "range")
		want := 206
		if strings.Contains(accepted, "identity;q=0") {
			want = 406
		}
		if recorder.Code != want || recorder.Header().Get("Content-Encoding") != "" {
			t.Fatal("partial representation encoded or identity exclusion ignored", accepted)
		}
	}
}
