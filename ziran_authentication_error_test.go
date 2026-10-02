package main

import (
	"errors"
	"fmt"
	"log"
	"log/slog"
	"math"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

var _ error = AuthError{}
var _ error = (*AuthError)(nil)

type authenticationNativeError struct{}

func (*authenticationNativeError) Error() string {
	return "native authentication error"
}

func TestZiranAuthenticationErrorConversion(t *testing.T) {
	var typedNil *authenticationNativeError
	sentinel := errors.New("native authentication error")
	nativeErrors := []error{
		nil, sentinel, fmt.Errorf("wrapped: %w", sentinel), typedNil,
		AuthError{Status: 409, Message: "native auth value"},
		&AuthError{Status: 401, Message: "native auth pointer"},
	}
	statuses := []int{math.MinInt, -1, 0, 1, 100, 401, 500, 999, 1000, math.MaxInt}
	messages := []string{"", "authentication failed", "\x00\xff\n\"<>&", "你好\u2003拒绝"}
	for _, native := range nativeErrors {
		for _, status := range statuses {
			for _, message := range messages {
				result := AuthenticationResult{Status: status, Message: message, Error: native}
				got := AuthenticationError_Convert(result)
				want := baselineAuthenticationError(result)
				if native != nil {
					if got != native || want != native {
						t.Fatal("conversion changed native error identity", native, got, want)
					}
					continue
				}
				if status == 0 {
					if got != nil || want != nil {
						t.Fatal("successful authentication must return a nil interface", result, got, want)
					}
					continue
				}
				var generated AuthError
				var baseline authError
				if !errors.As(got, &generated) || !errors.As(want, &baseline) ||
					generated.Status != baseline.status || generated.Message != baseline.message ||
					got.Error() != want.Error() || AuthenticationError_Message(generated) != want.Error() {
					t.Fatal("authentication error conversion changed status or message", result, got, want)
				}
				var pointer *AuthError
				if errors.As(got, &pointer) {
					t.Fatal("conversion changed the value error to a pointer", got)
				}
			}
		}
	}

	random := rand.New(rand.NewSource(6241))
	for index := 0; index < 2000; index++ {
		bytes := make([]byte, random.Intn(512))
		_, _ = random.Read(bytes)
		message := string(bytes)
		got := AuthError{Status: 401, Message: message}
		want := authError{status: 401, message: message}
		if got.Error() != want.Error() || AuthenticationError_Message(got) != message {
			t.Fatalf("message bytes changed: %x", bytes)
		}
	}
}

type authenticationMatchingError struct {
	status  int
	message string
	match   bool
	events  *[]string
	action  func()
	panic   any
}

func (*authenticationMatchingError) Error() string {
	return "custom authentication matching"
}

func (err *authenticationMatchingError) As(target any) bool {
	*err.events = append(*err.events, "as")
	if err.action != nil {
		err.action()
	}
	if err.panic != nil {
		panic(err.panic)
	}
	if !err.match {
		return false
	}
	switch value := target.(type) {
	case *AuthError:
		*value = AuthError{Status: err.status, Message: err.message}
	case *authError:
		*value = authError{status: err.status, message: err.message}
	default:
		panic("unexpected authentication matching target")
	}
	return true
}

type authenticationUnwrappingError struct {
	error  error
	events *[]string
	panic  any
}

func (*authenticationUnwrappingError) Error() string {
	return "custom authentication unwrap"
}

func (err *authenticationUnwrappingError) Unwrap() error {
	*err.events = append(*err.events, "unwrap")
	if err.panic != nil {
		panic(err.panic)
	}
	return err.error
}

func authenticationLogValue(value any) string {
	if value == nil {
		return "<nil>"
	}
	native := reflect.ValueOf(value)
	if native.Kind() == reflect.Pointer && native.IsNil() {
		return "<typed nil>"
	}
	if err, ok := value.(error); ok {
		return err.Error()
	}
	return fmt.Sprint(value)
}

func TestZiranAuthenticationErrorResponseAgainstBaseline(t *testing.T) {
	logger, logWriter, logFlags := slog.Default(), log.Writer(), log.Flags()
	t.Cleanup(func() {
		slog.SetDefault(logger)
		log.SetOutput(logWriter)
		log.SetFlags(logFlags)
	})
	for _, mode := range []string{
		"nil", "native", "typed nil", "value", "pointer", "nil pointer",
		"wrapped", "joined", "nested join", "first match", "zero status", "negative status",
		"too large status", "informational", "empty message", "raw message",
		"custom match", "custom no match", "custom as panic", "custom unwrap",
		"custom unwrap panic", "as replaces metrics", "log replaces metrics", "nil metrics",
		"log panic", "header panic", "status panic", "write panic", "write error",
	} {
		t.Run(mode, func(t *testing.T) {
			marker := &struct{ mode string }{mode}
			sentinel := errors.New("native authentication error")
			type observation struct {
				status          int
				headers         http.Header
				body            string
				writerEvents    []string
				errorEvents     []string
				logs            []string
				panic           any
				originalCount   uint64
				currentCount    uint64
				originalReasons map[string]uint64
				currentReasons  map[string]uint64
			}
			var observations [2]observation
			for index := range observations {
				original := &ServerMetrics{}
				server := &Server{metrics: original}
				if mode == "nil metrics" {
					server.metrics = nil
				}
				status, message := 401, "Bearer Token Required!"
				switch mode {
				case "zero status":
					status = 0
				case "negative status":
					status = -1
				case "too large status":
					status = 1000
				case "informational":
					status = 100
				case "empty message":
					message = ""
				case "raw message":
					message = "\x00\xff\n\"<>&你好"
				}
				var failure error = AuthError{Status: status, Message: message}
				if index == 1 {
					failure = authError{status: status, message: message}
				}
				var errorEvents, logs []string
				switch mode {
				case "nil":
					failure = nil
				case "native", "log replaces metrics", "log panic":
					failure = sentinel
				case "typed nil":
					failure = (*authenticationNativeError)(nil)
				case "pointer":
					failure = &AuthError{Status: status, Message: message}
					if index == 1 {
						failure = &authError{status: status, message: message}
					}
				case "nil pointer":
					failure = (*AuthError)(nil)
					if index == 1 {
						failure = (*authError)(nil)
					}
				case "wrapped":
					failure = fmt.Errorf("outer: %w", failure)
				case "joined":
					failure = errors.Join(sentinel, failure)
				case "nested join":
					failure = errors.Join(sentinel, fmt.Errorf("outer: %w", errors.Join(sentinel, failure)))
				case "first match":
					var second error = AuthError{Status: 403, Message: "second"}
					if index == 1 {
						second = authError{status: 403, message: "second"}
					}
					failure = errors.Join(failure, second)
				case "custom match", "custom no match", "custom as panic", "as replaces metrics":
					custom := &authenticationMatchingError{
						status: status, message: message, match: mode != "custom no match", events: &errorEvents,
					}
					if mode == "custom as panic" {
						custom.panic = marker
					}
					if mode == "as replaces metrics" {
						custom.action = func() { server.metrics = &ServerMetrics{} }
					}
					failure = custom
				case "custom unwrap", "custom unwrap panic":
					custom := &authenticationUnwrappingError{error: failure, events: &errorEvents}
					if mode == "custom unwrap panic" {
						custom.panic = marker
					}
					failure = custom
				}
				slog.SetDefault(slog.New(discoveryLogHandler{record: func(record slog.Record) {
					entry := fmt.Sprintf("%s:%s", record.Level, record.Message)
					record.Attrs(func(attribute slog.Attr) bool {
						entry += "|" + attribute.Key + "=" + authenticationLogValue(attribute.Value.Any())
						return true
					})
					logs = append(logs, entry)
					if mode == "log replaces metrics" {
						server.metrics = &ServerMetrics{}
					}
					if mode == "log panic" {
						panic(marker)
					}
				}}))
				recorder := httptest.NewRecorder()
				writer := &middlewareWriter{recorder: recorder, panic: marker}
				switch mode {
				case "header panic":
					writer.fail = "header"
				case "status panic":
					writer.fail = "status"
				case "write panic":
					writer.fail = "write"
				case "write error":
					writer.error = sentinel
				}
				var panicValue any
				func() {
					defer func() { panicValue = recover() }()
					if index == 0 {
						AuthenticationError_Respond(writer, &server.metrics, failure)
					} else {
						server.baselineWriteAuthError(writer, failure)
					}
				}()
				observations[index] = observation{
					status: recorder.Code, headers: recorder.Header(), body: recorder.Body.String(),
					writerEvents: writer.events, errorEvents: errorEvents, logs: logs, panic: panicValue,
					originalCount: original.AuthFailures.Load(), originalReasons: original.AuthFailuresBy,
				}
				if server.metrics != nil {
					observations[index].currentCount = server.metrics.AuthFailures.Load()
					observations[index].currentReasons = server.metrics.AuthFailuresBy
				}
			}
			if !reflect.DeepEqual(observations[0], observations[1]) {
				t.Fatalf("response changed:\nactual %#v\nbaseline %#v", observations[0], observations[1])
			}
			if strings.HasSuffix(mode, "panic") && observations[0].panic != marker {
				t.Fatal("native panic identity changed", observations[0].panic)
			}
		})
	}
}

func TestZiranHTTPAuthenticationErrorResponse(t *testing.T) {
	for _, mode := range []string{"success", "failure", "native", "native auth", "wrapped native auth", "native precedence", "zero native status"} {
		t.Run(mode, func(t *testing.T) {
			var results [2]AuthenticationResult
			for index := range results {
				var native error = AuthError{Status: 403, Message: "native auth"}
				if index == 1 {
					native = authError{status: 403, message: "native auth"}
				}
				switch mode {
				case "failure":
					results[index] = AuthenticationResult{Status: 401, Message: "bearer token required"}
				case "native":
					results[index].Error = errors.New("database unavailable")
				case "native auth":
					results[index].Error = native
				case "wrapped native auth":
					results[index].Error = fmt.Errorf("wrapped: %w", native)
				case "native precedence":
					results[index] = AuthenticationResult{Status: 401, Message: "ignored", Error: native}
				case "zero native status":
					results[index].Error = AuthError{Message: "zero native status"}
					if index == 1 {
						results[index].Error = authError{message: "zero native status"}
					}
				}
			}
			actual, expected := httptest.NewRecorder(), httptest.NewRecorder()
			actualMetrics, expectedMetrics := &ServerMetrics{}, &ServerMetrics{}
			var panics [2]any
			for index := range panics {
				func() {
					defer func() { panics[index] = recover() }()
					if index == 0 {
						HttpAuth_Respond(actual, actualMetrics, results[index])
					} else {
						server := &Server{metrics: expectedMetrics}
						server.baselineWriteAuthError(expected, baselineAuthenticationError(results[index]))
					}
				}()
			}
			if actual.Code != expected.Code || actual.Body.String() != expected.Body.String() ||
				!reflect.DeepEqual(actual.Header(), expected.Header()) || !reflect.DeepEqual(panics[0], panics[1]) ||
				actualMetrics.AuthFailures.Load() != expectedMetrics.AuthFailures.Load() ||
				!reflect.DeepEqual(actualMetrics.AuthFailuresBy, expectedMetrics.AuthFailuresBy) {
				t.Fatal("HTTP authentication result changed response, panic or metrics", actual, expected, panics)
			}
		})
	}
}

func TestZiranAuthenticationErrorConcurrentResponses(t *testing.T) {
	counters := &ServerMetrics{}
	var group sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for iteration := 0; iteration < 100; iteration++ {
				writer := httptest.NewRecorder()
				AuthenticationError_Respond(writer, &counters, AuthError{Status: 401, Message: "bearer token required"})
				if writer.Code != 401 || writer.Body.String() != "{\"error\":\"bearer token required\"}\n" {
					t.Error("concurrent authentication response changed", writer.Code, writer.Body.String())
					return
				}
			}
		}()
	}
	group.Wait()
	if counters.AuthFailures.Load() != 1600 || counters.AuthFailuresBy["401|bearer_token_required"] != 1600 {
		t.Fatal("concurrent authentication failures lost metrics", counters.AuthFailures.Load(), counters.AuthFailuresBy)
	}
}
