package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Use a real loopback HTTP server and the fixture's isolated on-disk SQLite
// database. No request reaches a public node or a real feedback inbox.
func TestFeedbackExpandedReportHTTPRoundtrip(t *testing.T) {
	server, store, _ := testServer(t)
	server.Cfg.FeedbackToken = "local-feedback-test"
	host := httptest.NewServer(server.Routes())
	t.Cleanup(host.Close)
	client := host.Client()
	owner := newTestIdentityAt(t, client, host.URL, 0x91)
	other := newTestIdentityAt(t, client, host.URL, 0x92)

	request := func(method, path string, identity testIdentity, operator bool, payload []byte, want int) []byte {
		t.Helper()
		req, err := http.NewRequest(method, host.URL+path, bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if identity.Token != "" {
			req.Header.Set("Authorization", "Bearer "+identity.Token)
			req.Header.Set("X-Daochi-User", identity.UserID)
		}
		if operator {
			req.Header.Set("X-Daochi-Admin", "local-feedback-test")
		}
		out, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = out.Body.Close() }()
		data, err := io.ReadAll(out.Body)
		if err != nil {
			t.Fatal(err)
		}
		if out.StatusCode != want {
			t.Fatalf("%s %s: status %d, want %d", method, path, out.StatusCode, want)
		}
		return data
	}
	encode := func(report Feedback) []byte {
		t.Helper()
		data, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	read := func(identity testIdentity, operator bool) []Feedback {
		t.Helper()
		path := "/api/v1/feedback"
		if operator {
			path = "/api/v1/admin/feedback"
		}
		data := request(http.MethodGet, path, identity, operator, nil, http.StatusOK)
		var list FeedbackList
		if err := json.Unmarshal(data, &list); err != nil {
			t.Fatal(err)
		}
		return list.Feedback
	}
	multilingual := strings.Repeat("Apps: 日本語 / Español / العربية 🙂\n", 350)
	maximum := multilingual + strings.Repeat("x", 32768-len(multilingual))
	reports := []Feedback{
		{ID: fmt.Sprintf("%064x", 1), AppId: "inbe", Title: "Expanded Apps report", Message: multilingual, Context: "local fixture"},
		{ID: fmt.Sprintf("%064x", 2), AppId: "inbe", Title: strings.Repeat("t", 160), Message: maximum, Context: strings.Repeat("c", 2048)},
		{ID: fmt.Sprintf("%064x", 3), AppId: "inbe", Title: strings.Repeat("\x01", 160), Message: "x" + strings.Repeat("\x01", 32767), Context: strings.Repeat("\x01", 2048)},
	}
	for _, report := range reports {
		payload := encode(report)
		request(http.MethodPost, "/api/v1/feedback", testIdentity{}, false, payload, http.StatusUnauthorized)
		request(http.MethodPost, "/api/v1/feedback", owner, false, payload, http.StatusOK)
		request(http.MethodPost, "/api/v1/feedback", owner, false, payload, http.StatusOK)
		changed := report
		changed.Message = "Attempted replacement"
		request(http.MethodPost, "/api/v1/feedback", owner, false, encode(changed), http.StatusOK)
		var stored string
		if err := store.Database.QueryRow("SELECT message FROM server_app_feedback WHERE account_id=? AND id=?", owner.UserID, report.ID).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if stored != report.Message {
			t.Fatal("SQLite changed or truncated the report on submission/retry")
		}
	}
	for _, operator := range []bool{false, true} {
		list := read(owner, operator)
		if len(list) != len(reports) {
			t.Fatalf("readback count %d, want %d", len(list), len(reports))
		}
		for _, expected := range reports {
			found := false
			for _, got := range list {
				if got.ID == expected.ID {
					found = got.Message == expected.Message && got.Title == expected.Title && got.Context == expected.Context
				}
			}
			if !found {
				t.Fatal("HTTP readback changed or truncated report text/metadata")
			}
		}
	}
	if len(read(other, false)) != 0 {
		t.Fatal("another account can read private reports")
	}
	request(http.MethodGet, "/api/v1/admin/feedback", owner, false, nil, http.StatusUnauthorized)

	for _, field := range []string{"message-byte", "message-rune", "title", "context", "id", "app"} {
		t.Run(field, func(t *testing.T) {
			report := reports[1]
			switch field {
			case "message-byte":
				report.Message += "x"
			case "message-rune":
				report.Message += "界"
			case "title":
				report.Title += "t"
			case "context":
				report.Context += "c"
			case "id":
				report.ID = "short"
			case "app":
				report.AppId = "unknown"
			}
			request(http.MethodPost, "/api/v1/feedback", owner, false, encode(report), http.StatusBadRequest)
		})
	}
	// A legal JSON body at the cap succeeds; one extra byte is rejected.
	payload := encode(reports[0])
	payload = append(payload, bytes.Repeat([]byte(" "), 262144-len(payload))...)
	request(http.MethodPost, "/api/v1/feedback", owner, false, payload, http.StatusOK)
	request(http.MethodPost, "/api/v1/feedback", owner, false, append(payload, ' '), http.StatusBadRequest)

	for index := len(reports); index < 20; index++ {
		report := reports[0]
		report.ID = fmt.Sprintf("%064x", index+1)
		request(http.MethodPost, "/api/v1/feedback", owner, false, encode(report), http.StatusOK)
	}
	report := reports[0]
	report.ID = fmt.Sprintf("%064x", 21)
	request(http.MethodPost, "/api/v1/feedback", owner, false, encode(report), http.StatusTooManyRequests)
	request(http.MethodPost, "/api/v1/feedback", owner, false, encode(reports[0]), http.StatusOK)
	if len(read(owner, false)) != 20 {
		t.Fatal("invalid/duplicate requests consumed allowance or overflow was stored")
	}
	t.Logf("Exact multilingual HTTP/SQLite readback: %d bytes and %d bytes; escaped maximum: 32768 decoded bytes; overflow rejected; 20-report quota and retry preserved", len(multilingual), len(maximum))
}
