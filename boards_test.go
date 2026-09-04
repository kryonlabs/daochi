package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Full membership + permission lifecycle: two friends share a board, a
// non-friend is rejected, permissions gate reads/writes, members can leave,
// and owners can change permissions.
func TestBoardSharingLifecycle(t *testing.T) {
	server, store, _ := testServer(t)
	handler := server.Routes()
	alice := newTestIdentity(t, handler, 0x51)
	bob := newTestIdentity(t, handler, 0x52)
	carol := newTestIdentity(t, handler, 0x53)

	befriend(t, handler, alice, bob)

	// Carol is not a friend: invite must be rejected even though her
	// account exists.
	res := boardJSONRequest(t, handler, http.MethodPost, "/api/v1/boards", alice, []byte(`{"title":"Neon Levels"}`))
	if res.Code != http.StatusCreated {
		t.Fatalf("create board status = %d body=%s", res.Code, res.Body.String())
	}
	var created BoardDetailResponse
	if err := json.Unmarshal(res.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Board.ID == "" || created.Board.Title != "Neon Levels" ||
		created.Board.MyPermission != boardPermissionOwner || created.Board.MemberCount != 1 {
		t.Fatalf("unexpected created board: %#v", created.Board)
	}
	boardPath := "/api/v1/boards/" + created.Board.ID

	res = boardJSONRequest(t, handler, http.MethodPost, boardPath+"/members", alice,
		[]byte(`{"target":"`+carol.UserID+`","permission":"read"}`))
	if res.Code != http.StatusForbidden {
		t.Fatalf("non-friend invite status = %d body=%s", res.Code, res.Body.String())
	}

	// Invite Bob as a reader.
	res = boardJSONRequest(t, handler, http.MethodPost, boardPath+"/members", alice,
		[]byte(`{"target":"`+bob.UserID+`","permission":"read"}`))
	if res.Code != http.StatusCreated {
		t.Fatalf("friend invite status = %d body=%s", res.Code, res.Body.String())
	}

	// Bob can read but not write.
	res = boardJSONRequest(t, handler, http.MethodGet, boardPath, bob, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("member read status = %d body=%s", res.Code, res.Body.String())
	}
	var detail BoardDetailResponse
	if err := json.Unmarshal(res.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Board.MyPermission != boardPermissionRead || len(detail.Members) != 2 {
		t.Fatalf("unexpected bob view: board=%#v members=%d", detail.Board, len(detail.Members))
	}
	res = boardJSONRequest(t, handler, http.MethodPut, boardPath+"/records/card-1", bob,
		[]byte(`{"payload":{"title":"Fix jump"}`+")"+`}`))
	if res.Code != http.StatusForbidden {
		t.Fatalf("reader write status = %d body=%s", res.Code, res.Body.String())
	}

	// Promote Bob to writer; now he can upsert and delete records.
	res = boardJSONRequest(t, handler, http.MethodPatch, boardPath+"/members/"+bob.UserID, alice,
		[]byte(`{"permission":"write"}`))
	if res.Code != http.StatusOK {
		t.Fatalf("promote status = %d body=%s", res.Code, res.Body.String())
	}
	res = boardJSONRequest(t, handler, http.MethodPut, boardPath+"/records/card-1", bob,
		[]byte(`{"payload":{"title":"Fix jump","body":"hero sinks through floor"}}`))
	if res.Code != http.StatusOK {
		t.Fatalf("writer put status = %d body=%s", res.Code, res.Body.String())
	}
	res = boardJSONRequest(t, handler, http.MethodGet, boardPath+"/records?since=0", alice, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("records list status = %d body=%s", res.Code, res.Body.String())
	}
	var records BoardRecordsResponse
	if err := json.Unmarshal(res.Body.Bytes(), &records); err != nil {
		t.Fatal(err)
	}
	if len(records.Records) != 1 || records.Records[0].ID != "card-1" ||
		records.Records[0].AuthorUserID != bob.UserID {
		t.Fatalf("unexpected records: %#v", records.Records)
	}
	var payload map[string]any
	if err := json.Unmarshal(records.Records[0].Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["title"] != "Fix jump" {
		t.Fatalf("unexpected payload: %#v", payload)
	}

	// Bob cannot manage members (owner-only).
	res = boardJSONRequest(t, handler, http.MethodPost, boardPath+"/members", bob,
		[]byte(`{"target":"`+carol.UserID+`","permission":"write"}`))
	if res.Code != http.StatusForbidden {
		t.Fatalf("writer invite status = %d body=%s", res.Code, res.Body.String())
	}

	// Non-members see nothing.
	res = boardJSONRequest(t, handler, http.MethodGet, boardPath, carol, nil)
	if res.Code != http.StatusNotFound {
		t.Fatalf("outsider read status = %d body=%s", res.Code, res.Body.String())
	}

	// Bob leaves; he loses access.
	res = boardJSONRequest(t, handler, http.MethodDelete, boardPath+"/members/"+bob.UserID, bob, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("leave status = %d body=%s", res.Code, res.Body.String())
	}
	res = boardJSONRequest(t, handler, http.MethodGet, boardPath, bob, nil)
	if res.Code != http.StatusNotFound {
		t.Fatalf("after leave status = %d body=%s", res.Code, res.Body.String())
	}

	// Owner archives the board; it disappears from lists.
	res = boardJSONRequest(t, handler, http.MethodDelete, boardPath, alice, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("archive status = %d body=%s", res.Code, res.Body.String())
	}
	res = boardJSONRequest(t, handler, http.MethodGet, "/api/v1/boards", alice, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("list boards status = %d body=%s", res.Code, res.Body.String())
	}
	var listed BoardsResponse
	if err := json.Unmarshal(res.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Boards) != 0 {
		t.Fatalf("archived board still listed: %#v", listed.Boards)
	}

	assertCount(t, store, "server_boards", 1)
	assertCount(t, store, "server_board_records", 1)
}

func TestBoardRecordSyncAndTombstones(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()
	alice := newTestIdentity(t, handler, 0x61)
	bob := newTestIdentity(t, handler, 0x62)
	befriend(t, handler, alice, bob)

	res := boardJSONRequest(t, handler, http.MethodPost, "/api/v1/boards", alice, []byte(`{"title":"Sync board"}`))
	if res.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", res.Code, res.Body.String())
	}
	var created BoardDetailResponse
	if err := json.Unmarshal(res.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	boardPath := "/api/v1/boards/" + created.Board.ID

	for i := 0; i < 3; i++ {
		res = boardJSONRequest(t, handler, http.MethodPut,
			boardPath+"/records/card-"+string(rune('a'+i)), alice,
			[]byte(`{"payload":{"n":`+string(rune('0'+i))+`}}`))
		if res.Code != http.StatusOK {
			t.Fatalf("put %d status = %d body=%s", i, res.Code, res.Body.String())
		}
	}
	res = boardJSONRequest(t, handler, http.MethodDelete, boardPath+"/records/card-b", alice, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("delete status = %d body=%s", res.Code, res.Body.String())
	}

	res = boardJSONRequest(t, handler, http.MethodGet, boardPath+"/records?since=0", alice, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s", res.Code, res.Body.String())
	}
	var all BoardRecordsResponse
	if err := json.Unmarshal(res.Body.Bytes(), &all); err != nil {
		t.Fatal(err)
	}
	if len(all.Records) != 3 {
		t.Fatalf("expected 3 records incl tombstone: %#v", all.Records)
	}
	for _, record := range all.Records {
		if record.ID == "card-b" && record.DeletedAt == 0 {
			t.Fatalf("missing tombstone: %#v", record)
		}
	}

	// since= at the newest record returns nothing new; since=0 returns all.
	res = boardJSONRequest(t, handler, http.MethodGet,
		boardPath+"/records?since="+jsonInt64(t, all.Records[len(all.Records)-1].UpdatedAt), alice, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("since list status = %d body=%s", res.Code, res.Body.String())
	}
	var newer BoardRecordsResponse
	if err := json.Unmarshal(res.Body.Bytes(), &newer); err != nil {
		t.Fatal(err)
	}
	if len(newer.Records) != 0 {
		t.Fatalf("since=newest still returned records: %#v", newer.Records)
	}

	res = boardJSONRequest(t, handler, http.MethodPut, boardPath+"/records/bad", alice,
		[]byte(`{"payload":[1,2,3]}`))
	if res.Code != http.StatusBadRequest {
		t.Fatalf("array payload status = %d body=%s", res.Code, res.Body.String())
	}
	res = boardJSONRequest(t, handler, http.MethodGet, boardPath+"/records/bad/extra", alice, nil)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("malformed record subpath status = %d body=%s", res.Code, res.Body.String())
	}
}

func TestBoardRequiresAuth(t *testing.T) {
	server, _, _ := testServer(t)
	handler := server.Routes()

	res := httptest.NewRecorder()
	handler.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/api/v1/boards", nil))
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous list status = %d body=%s", res.Code, res.Body.String())
	}
	res = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/boards", bytes.NewReader([]byte(`{"title":"x"}`)))
	req.Header.Set("Authorization", "Bearer bogus")
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("bogus token create status = %d body=%s", res.Code, res.Body.String())
	}
}

/* helpers */

func boardJSONRequest(t *testing.T, handler http.Handler, method, path string, id testIdentity, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		reader = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+id.Token)
	req.Header.Set("X-Daochi-User", id.UserID)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	return res
}

func befriend(t *testing.T, handler http.Handler, a, b testIdentity) {
	t.Helper()
	res := friendJSONRequest(t, handler, http.MethodPost, "/api/v1/friends/requests", a,
		[]byte(`{"target":"`+b.UserID+`"}`))
	if res.Code != http.StatusCreated {
		t.Fatalf("befriend request status = %d body=%s", res.Code, res.Body.String())
	}
	var created FriendRequestResponse
	if err := json.Unmarshal(res.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	res = friendJSONRequest(t, handler, http.MethodPost,
		"/api/v1/friends/requests/"+created.Request.ID+"/accept", b, []byte(`{}`))
	if res.Code != http.StatusOK {
		t.Fatalf("befriend accept status = %d body=%s", res.Code, res.Body.String())
	}
}

func jsonInt64(t *testing.T, value int64) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
