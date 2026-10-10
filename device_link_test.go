package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func deviceLinkCall(t *testing.T, handler func(ResponseWriter, *Request), remote string, body string) (int, map[string]any) {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/link", strings.NewReader(body))
	request.RemoteAddr = remote
	recorder := httptest.NewRecorder()
	handler(recorder, request)
	result := map[string]any{}
	if recorder.Body.Len() > 0 {
		if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
			t.Fatalf("response is not JSON: %q", recorder.Body.String())
		}
	}
	return recorder.Code, result
}

func TestDeviceLinkRelaysOneRequestAndOneResponse(t *testing.T) {
	remote := "198.51.100.10:4000"
	id := "0123456789abcdef0123456789abcdef"
	status, _ := deviceLinkCall(t, DeviceLink_Get, remote, `{"id":"`+id+`","slot":"request"}`)
	if status != http.StatusNotFound {
		t.Fatalf("empty link status = %d, want 404", status)
	}
	status, _ = deviceLinkCall(t, DeviceLink_Put, remote, `{"id":"`+id+`","slot":"request","data":"sealed-request"}`)
	if status != http.StatusOK {
		t.Fatalf("request status = %d, want 200", status)
	}
	// A sent message cannot be replaced by anyone else who learns the ID.
	status, _ = deviceLinkCall(t, DeviceLink_Put, remote, `{"id":"`+id+`","slot":"request","data":"forged"}`)
	if status != http.StatusConflict {
		t.Fatalf("second request status = %d, want 409", status)
	}
	status, body := deviceLinkCall(t, DeviceLink_Get, remote, `{"id":"`+id+`","slot":"request"}`)
	if status != http.StatusOK || body["data"] != "sealed-request" {
		t.Fatalf("read request = %d %v", status, body)
	}
	status, _ = deviceLinkCall(t, DeviceLink_Get, remote, `{"id":"`+id+`","slot":"response"}`)
	if status != http.StatusNotFound {
		t.Fatalf("unanswered response status = %d, want 404", status)
	}
	status, _ = deviceLinkCall(t, DeviceLink_Put, remote, `{"id":"`+id+`","slot":"response","data":"sealed-response"}`)
	if status != http.StatusOK {
		t.Fatalf("response status = %d, want 200", status)
	}
	status, body = deviceLinkCall(t, DeviceLink_Get, remote, `{"id":"`+id+`","slot":"response"}`)
	if status != http.StatusOK || body["data"] != "sealed-response" {
		t.Fatalf("read response = %d %v", status, body)
	}
	status, _ = deviceLinkCall(t, DeviceLink_Close, remote, `{"id":"`+id+`"}`)
	if status != http.StatusOK {
		t.Fatalf("close status = %d, want 200", status)
	}
	status, _ = deviceLinkCall(t, DeviceLink_Get, remote, `{"id":"`+id+`","slot":"response"}`)
	if status != http.StatusNotFound {
		t.Fatalf("closed link status = %d, want 404", status)
	}
}

func TestDeviceLinkRejectsMalformedInput(t *testing.T) {
	remote := "198.51.100.11:4000"
	cases := []string{
		`{"id":"short","slot":"request","data":"x"}`,
		`{"id":"0123456789ABCDEF0123456789ABCDEF","slot":"request","data":"x"}`,
		`{"id":"0123456789abcdef0123456789abcdef","slot":"other","data":"x"}`,
		`{"id":"0123456789abcdef0123456789abcdef","slot":"request","data":""}`,
		`{"id":"0123456789abcdef0123456789abcdef","slot":"request","data":"x","extra":1}`,
		`not json`,
		`{"id":"0123456789abcdef0123456789abcdef","slot":"request","data":"` + strings.Repeat("a", 16385) + `"}`,
	}
	for _, body := range cases {
		status, _ := deviceLinkCall(t, DeviceLink_Put, remote, body)
		if status != http.StatusBadRequest {
			t.Errorf("put %.60q status = %d, want 400", body, status)
		}
	}
}

func TestDeviceLinkLimitsRequestsPerAddress(t *testing.T) {
	remote := "198.51.100.12:4000"
	id := "fedcba9876543210fedcba9876543210"
	limited := false
	for attempt := 0; attempt < 400; attempt++ {
		status, _ := deviceLinkCall(t, DeviceLink_Get, remote, `{"id":"`+id+`","slot":"request"}`)
		if status == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("polling never reached the per-address limit")
	}
	status, _ := deviceLinkCall(t, DeviceLink_Get, "198.51.100.13:4000", `{"id":"`+id+`","slot":"request"}`)
	if status != http.StatusNotFound {
		t.Fatalf("another address status = %d, want 404", status)
	}
}
