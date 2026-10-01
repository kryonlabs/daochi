package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestZiranSyncRequestParsingAgainstBaseline(t *testing.T) {
	bodies := [][]byte{
		nil, {}, []byte("null"), []byte("{}"), []byte("[]"), []byte("true"),
		[]byte(`{"user_id_hash":" \u2003ABCD ","app_id":" App ","client_id":" Client ","public_key":" ff ","encrypted_records":[{"collection":" private.App ","id":" ID ","key_id":" Key ","nonce":" AA ","updated_at":" Date ","content_hash":" FF ","parent_id":" Parent "}]}`),
		[]byte(`{"user_id_hash":" RAW ","protocol_version":"bad","client_id":" STILL RAW "}`),
		[]byte(`{"user_id_hash":" A ","user_id_hash":" B ","client_clock":9223372036854775807,"ops":[{"payload":{"raw":[1,2]}}]}`),
		[]byte(`{"user_id_hash":" A ","client_clock":9223372036854775808}`),
		[]byte(`{"encrypted_records":[null,{}, {"id":3,"collection":" RAW "}]}`),
		[]byte(`{"encrypted_records":[],"habits":[],"sessions":null}`),
		[]byte(`{"user_id_hash":"\ufffd\u0000\u2003A"}`),
		[]byte(`{"user_id_hash":"unterminated`),
		[]byte(`{"v":1,"nonce":"AA","ciphertext":"BB"}`),
		[]byte(`{"v":2,"nonce":" \u2003AA ","ciphertext":"BB"}`),
		[]byte(`{"V":2,"NONCE":"AA","Ciphertext":"BB"}`),
		[]byte(`{"v":0,"nonce":"AA","ciphertext":"BB"}`),
		[]byte(`{"v":2,"nonce":"\u2003","ciphertext":"BB"}`),
		[]byte(`{"v":2,"nonce":"AA","ciphertext":42}`),
		[]byte(`{"v":2,"v":3,"nonce":"AA","ciphertext":"BB"}`),
	}
	random := rand.New(rand.NewSource(20261001))
	for index := 0; index < 200; index++ {
		value := make([]byte, random.Intn(160))
		_, _ = random.Read(value)
		bodies = append(bodies, value)
	}
	for _, body := range bodies {
		got := SyncRequest_ParseSync(body)
		want, err := baselineBoundaryParseSyncRequestBody(body)
		if !reflect.DeepEqual(got.Value, want) || !sameIdentityError(got.Error, err) || got.Body != nil {
			t.Fatalf("sync parse differs for %q: %#v, baseline %#v, %v", body, got, want, err)
		}
		if got := SyncRequest_IsEncryptedEnvelope(body); got != baselineBoundaryIsEncryptedSyncEnvelope(body) {
			t.Fatalf("encrypted envelope detection differs for %q", body)
		}
	}
}

func TestZiranSyncRequestHeaderPrecedenceAgainstBaseline(t *testing.T) {
	values := []string{"", " \t\u2003", " A ", "\xff", "\u2003B\u00a0"}
	for _, current := range values {
		for _, legacy := range values {
			for _, oldest := range values {
				request := httptest.NewRequest(http.MethodPost, "/api/v1/login", nil)
				request.Header.Set("X-Daochi-User", current)
				request.Header.Set("X-Ksync-User", legacy)
				request.Header.Set("X-Inbe-User", oldest)
				request.Header.Set("X-Daochi-Signature", current)
				request.Header.Set("X-Ksync-Signature", legacy)
				request.Header.Set("X-Inbe-Signature", oldest)
				for _, body := range values {
					actual, expected := body, body
					got := SyncRequest_ApplyHeaderUser(request, &actual)
					want := baselineBoundaryApplyHeaderUser(request, &expected)
					if actual != expected || !sameIdentityError(got, want) {
						t.Fatalf("header user differs: %q, %v; baseline %q, %v", actual, got, expected, want)
					}
				}
				signed := SyncRequest_SignatureHeader(request)
				value, context := baselineBoundaryRequestSignatureHeader(request)
				if signed.Value != value || signed.Context != context {
					t.Fatalf("signature header differs: %#v, baseline %q, %q", signed, value, context)
				}
				for _, limit := range []string{current, "0", "-1", "+2", "02", "9223372036854775808", " 2 ", "42"} {
					request.Header.Set("X-Daochi-Limit", limit)
					request.Header.Set("X-Ksync-Limit", legacy)
					for _, maximum := range []int{-1, 0, 1, 10, 100} {
						got := SyncRequest_EncryptedPayloadLimit(request, maximum)
						want, err := baselineBoundaryEncryptedPayloadLimit(request, maximum)
						if got.Value != want || !sameIdentityError(got.Error, err) {
							t.Fatalf("payload limit differs for %q/%q, %d: %#v, baseline %d, %v", limit, legacy, maximum, got, want, err)
						}
					}
				}
			}
		}
	}
}

type boundaryBody struct {
	reader io.Reader
	closed int
}

func (body *boundaryBody) Read(value []byte) (int, error) {
	return body.reader.Read(value)
}

func (body *boundaryBody) Close() error {
	body.closed++
	return nil
}

type boundaryReadFailure struct{ err error }

func (reader boundaryReadFailure) Read([]byte) (int, error) {
	return 0, reader.err
}

type boundaryReadPanic struct{ value any }

func (reader boundaryReadPanic) Read([]byte) (int, error) {
	panic(reader.value)
}

func boundaryRecover(call func()) (value any) {
	defer func() { value = recover() }()
	call()
	return nil
}

func TestZiranSyncRequestReadersAgainstBaseline(t *testing.T) {
	bodies := []string{
		"", "{invalid", "null", "[]", "{}",
		`{"user_id_hash":" \u2003ABCD ","client_id":" Client ","public_key":" FF ","exported_key":" Key "}`,
		`{"user_id_hash":" RAW ","client_id":42,"public_key":" STILL RAW ","exported_key":" RAW "}`,
		`{"user_id_hash":"` + strings.Repeat("A", 64) + `","exported_key":" \u2003Key \u00a0"}`,
		`{"user_id_hash":"` + strings.Repeat("a", 64) + `","exported_key":"\u2003"}`,
	}
	type readResult struct {
		body  []byte
		value any
		err   error
	}
	type readerCase struct {
		name     string
		actual   func(http.ResponseWriter, *http.Request, int64) readResult
		baseline func(http.ResponseWriter, *http.Request, int64) readResult
	}
	readers := []readerCase{
		{"sync", func(w http.ResponseWriter, r *http.Request, limit int64) readResult {
			result := SyncRequest_ReadSync(w, r, limit)
			return readResult{result.Body, result.Value, result.Error}
		}, func(w http.ResponseWriter, r *http.Request, limit int64) readResult {
			body, value, err := baselineBoundaryReadSyncRequest(w, r, limit)
			return readResult{body, value, err}
		}},
		{"login", func(w http.ResponseWriter, r *http.Request, limit int64) readResult {
			result := SyncRequest_ReadLogin(w, r, limit)
			return readResult{result.Body, result.Value, result.Error}
		}, func(w http.ResponseWriter, r *http.Request, limit int64) readResult {
			body, value, err := baselineBoundaryReadLoginRequest(w, r, limit)
			return readResult{body, value, err}
		}},
		{"delete", func(w http.ResponseWriter, r *http.Request, limit int64) readResult {
			result := SyncRequest_ReadDelete(w, r, limit)
			return readResult{result.Body, result.Value, result.Error}
		}, func(w http.ResponseWriter, r *http.Request, limit int64) readResult {
			body, value, err := baselineBoundaryReadDeleteRequest(w, r, limit)
			return readResult{body, value, err}
		}},
		{"delete key", func(w http.ResponseWriter, r *http.Request, limit int64) readResult {
			result := SyncRequest_ReadDeleteWithKey(w, r, limit)
			return readResult{nil, result.Value, result.Error}
		}, func(w http.ResponseWriter, r *http.Request, limit int64) readResult {
			value, err := baselineBoundaryReadDeleteWithKeyRequest(w, r, limit)
			return readResult{nil, value, err}
		}},
	}
	for _, reader := range readers {
		t.Run(reader.name, func(t *testing.T) {
			for _, input := range bodies {
				for _, limit := range []int64{-1, 0, 1, int64(len(input)), int64(len(input) + 1), 4096} {
					actualBody := &boundaryBody{reader: strings.NewReader(input)}
					expectedBody := &boundaryBody{reader: strings.NewReader(input)}
					actualRequest := httptest.NewRequest(http.MethodPost, "/", nil)
					expectedRequest := httptest.NewRequest(http.MethodPost, "/", nil)
					actualRequest.Body = actualBody
					expectedRequest.Body = expectedBody
					got := reader.actual(httptest.NewRecorder(), actualRequest, limit)
					want := reader.baseline(httptest.NewRecorder(), expectedRequest, limit)
					if !reflect.DeepEqual(got.body, want.body) || !reflect.DeepEqual(got.value, want.value) || !sameIdentityError(got.err, want.err) {
						t.Fatalf("reader differs for %q with limit %d: %#v, baseline %#v", input, limit, got, want)
					}
					if actualBody.closed != 1 || expectedBody.closed != 1 {
						t.Fatal("request body was not closed exactly once")
					}
				}
			}
			for _, failure := range []io.Reader{boundaryReadFailure{errors.New("read failure")}, boundaryReadPanic{errors.New("read panic")}} {
				var results [2]readResult
				var panics [2]any
				for index, call := range []func(http.ResponseWriter, *http.Request, int64) readResult{reader.actual, reader.baseline} {
					body := &boundaryBody{reader: failure}
					request := httptest.NewRequest(http.MethodPost, "/", nil)
					request.Body = body
					panics[index] = boundaryRecover(func() { results[index] = call(httptest.NewRecorder(), request, 4096) })
					if body.closed != 1 {
						t.Fatal("read error or panic retained the request body")
					}
				}
				if panics[0] != panics[1] || !sameIdentityError(results[0].err, results[1].err) || !reflect.DeepEqual(results[0].value, results[1].value) {
					t.Fatal("read error or panic identity changed")
				}
			}
		})
	}
}

func TestZiranExportedAccountKeyAgainstBaseline(t *testing.T) {
	key := bytes.Repeat([]byte{0xff}, mlDSA44PrivateKeySize)
	publicID := strings.Repeat("a", 64)
	inputs := []string{"", "\n", "unknown\nalgorithm=ML-DSA-44", "ksync-account-key-v1", "ksync-account-key-v1\nalgorithm=other"}
	for _, header := range []string{"ksync-account-key-v1", "lyra-account-key-v1", "account-key-v1", "inbe-sync-key-v1", " \u2003ksync-account-key-v1 "} {
		for _, encoded := range []string{"", "invalid=", "00", hex.EncodeToString(key), base64.StdEncoding.EncodeToString(key), base64.RawStdEncoding.EncodeToString(key), base64.URLEncoding.EncodeToString(key), base64.RawURLEncoding.EncodeToString(key)} {
			for _, id := range []string{"", publicID, " \u2003" + strings.ToUpper(publicID) + " ", "invalid", "\xff", strings.Repeat("a", 65)} {
				for _, newline := range []string{"\n", "\r\n"} {
					lines := []string{header, "ignored", "unknown=value", " algorithm = ML-DSA-44 ", " public_id = " + id, " private_key = " + encoded, ""}
					inputs = append(inputs, strings.Join(lines, newline))
				}
			}
		}
	}
	valid := "ksync-account-key-v1\nalgorithm=ML-DSA-44\npublic_id=" + publicID + "\nprivate_key=" + hex.EncodeToString(key)
	for _, suffix := range []string{"\nalgorithm=wrong", "\nalgorithm=wrong\nalgorithm=ML-DSA-44", "\npublic_id=invalid", "\npublic_id=", "\nprivate_key=wrong", "\nprivate_key=" + base64.StdEncoding.EncodeToString(key)} {
		inputs = append(inputs, valid+suffix)
	}
	for _, input := range inputs {
		got := SyncRequest_ParseExportedKey(input)
		want, err := baselineBoundaryParseExportedSyncKey(input)
		if !reflect.DeepEqual(got.Value, want) || !sameIdentityError(got.Error, err) {
			t.Fatalf("exported key parse differs: actual %q/%d/%v, baseline %q/%d/%v", got.Value.PublicID, len(got.Value.PrivateKey), got.Error, want.PublicID, len(want.PrivateKey), err)
		}
	}
}

func TestZiranSyncRequestHelpersAgainstBaseline(t *testing.T) {
	gotChanges := SyncRequest_EmptyChanges()
	wantChanges := baselineBoundaryEmptySyncChanges()
	if !reflect.DeepEqual(gotChanges, wantChanges) {
		t.Fatal("empty sync changes lost allocated slices")
	}
	gotJSON, _ := json.Marshal(gotChanges)
	wantJSON, _ := json.Marshal(wantChanges)
	if !bytes.Equal(gotJSON, wantJSON) {
		t.Fatal("empty sync change JSON changed")
	}
	for protocol := -1; protocol <= 7; protocol++ {
		for _, legacy := range []bool{false, true} {
			for changed := 0; changed < 10; changed++ {
				request := SyncRequest{ProtocolVersion: protocol, IncludeLegacyData: legacy}
				switch changed {
				case 1:
					request.FullSyncRequested = true
				case 2:
					request.MeditationLogs = []MeditationLog{{}}
				case 3:
					request.Habits = []Habit{{}}
				case 4:
					request.HabitDays = []HabitDay{{}}
				case 5:
					request.Sessions = []Session{{}}
				case 6:
					request.EncryptedRecords = []EncryptedRecord{{}}
				case 7:
					request.Ops = []SyncOp{{}}
				case 8:
					request.SocialCache = []SocialSnapshot{{}}
				case 9:
					request.Habits = []Habit{}
				}
				if SyncRequest_TransitionMode(request) != baselineBoundarySyncTransitionMode(request) ||
					SyncRequest_IncludeLegacyPrivateData(request) != baselineBoundaryIncludeLegacyPrivateData(request) ||
					SyncRequest_HasLocalChanges(request) != baselineBoundarySyncRequestHasLocalChanges(request) {
					t.Fatal("sync transition or local-change policy changed")
				}
			}
		}
	}
	for _, logs := range [][]MeditationLog{nil, {}, {{Duration: 10}}, {{DurationSeconds: 20, Duration: 10}}, {{Duration: -1}, {DurationSeconds: -2}, {DurationSeconds: 10, Duration: -1}}} {
		actual := append([]MeditationLog(nil), logs...)
		expected := append([]MeditationLog(nil), logs...)
		SyncRequest_NormalizeMeditationDurations(actual)
		baselineBoundaryNormalizeMeditationDurations(expected)
		if !reflect.DeepEqual(actual, expected) {
			t.Fatal("legacy meditation durations changed")
		}
	}
	key := bytes.Repeat([]byte{0x42}, mlDSA44PublicKeySize)
	user := Signing_SHA256Hex(key)
	for _, encoded := range []string{"", " \u2003", "invalid=", "00", hex.EncodeToString(key), base64.StdEncoding.EncodeToString(key), hex.EncodeToString(key[:len(key)-1])} {
		for _, account := range []string{user, strings.ToUpper(user), strings.Repeat("a", 64), "", "invalid"} {
			request := SyncRequest{UserIDHash: account, PublicKey: encoded}
			got := SyncRequest_PublicKey(request)
			want, err := baselineBoundarySyncRequestPublicKey(request)
			if !reflect.DeepEqual(got.Value, want) || !sameIdentityError(got.Error, err) {
				t.Fatalf("sync public key changed for user %q: %v, baseline %v", account, got.Error, err)
			}
		}
	}
}
