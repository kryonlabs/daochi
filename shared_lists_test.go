package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSharedListsInvitationsAndCollaboration(t *testing.T) {
	server, users := socialHTTPFixture(t)
	call := func(user int, command *Command, want int) Snapshot {
		t.Helper()
		method := "GET"
		var body []byte
		if command != nil {
			method = "POST"
			var err error
			body, err = json.Marshal(command)
			if err != nil {
				t.Fatal(err)
			}
		}
		request := httptest.NewRequest(method, "/api/v1/lists", bytes.NewReader(body))
		request.Header.Set("X-Daochi-User", users[user])
		request.Header.Set("Authorization", "Bearer "+Token_IssueAuthToken(server.Cfg.TokenSecret, users[user], time.Now().Add(time.Hour).Unix()).Value)
		result := httptest.NewRecorder()
		SharedLists_Handle(server.accounts(), result, request)
		if result.Code != want {
			t.Fatalf("%s %s: got %d %s, want %d", method, body, result.Code, result.Body, want)
		}
		var snapshot Snapshot
		if want == 200 {
			if err := json.Unmarshal(result.Body.Bytes(), &snapshot); err != nil {
				t.Fatal(err)
			}
		}
		return snapshot
	}
	list := List{ID: "list-0001", Title: "Weekend", Items: []Item{{ID: "task-0001", Title: "Pack bag", Comment: "For Saturday"}}}
	invite := Command{RequestId: "request-0001", Action: "invite", Target: users[1], List: list}
	owner := call(0, &invite, 200)
	if len(owner.Lists) != 1 || len(owner.Invitations) != 1 || owner.Lists[0].Revision != 1 {
		t.Fatalf("invite did not create one canonical list: %+v", owner)
	}
	// Retrying an uncertain delivery must not duplicate invitations or saves.
	again := call(0, &invite, 200)
	if len(again.Lists) != 1 || len(again.Invitations) != 1 {
		t.Fatal("duplicate invitation after retry")
	}
	changed := invite
	changed.List.Title = "different body"
	call(0, &changed, 409)
	pending := call(1, nil, 200)
	if len(pending.Lists) != 0 || len(pending.Invitations) != 1 || pending.Invitations[0].Status != "pending" {
		t.Fatalf("invitee received content before accepting: %+v", pending)
	}
	outsider := call(2, nil, 200)
	if len(outsider.Lists) != 0 || len(outsider.Invitations) != 0 {
		t.Fatal("unrelated account can see shared data")
	}
	accept := Command{RequestId: "accept-0001", Action: "accept", InvitationId: pending.Invitations[0].ID}
	call(0, &accept, 404)
	call(2, &accept, 404)
	stolen := Command{RequestId: "stolen-save", Action: "save", List: owner.Lists[0]}
	call(1, &stolen, 404)
	call(2, &stolen, 404)
	accepted := call(1, &accept, 200)
	if len(accepted.Lists) != 1 || len(accepted.Invitations) != 1 || accepted.Lists[0].Items[0].Title != "Pack bag" {
		t.Fatalf("accept did not grant content: %+v", accepted)
	}
	call(1, &accept, 200)
	edit := Command{RequestId: "edit-0001", Action: "save", List: accepted.Lists[0]}
	edit.List.Items[0].Done = 1
	edit.List.Items = append(edit.List.Items, Item{ID: "task-0002", Title: "Buy fruit"})
	updated := call(1, &edit, 200)
	if updated.Lists[0].Revision != 2 {
		t.Fatal("save did not advance revision")
	}
	call(1, &edit, 200)
	owner = call(0, nil, 200)
	if owner.Lists[0].Revision != 2 || owner.Lists[0].Items[0].Done != 1 || len(owner.Lists[0].Items) != 2 {
		t.Fatal("collaborator's edit was not delivered to owner")
	}
	stale := edit
	stale.RequestId = "stale-0001"
	call(1, &stale, 409)
	// A person the list was shared with may rename it; only the owner deletes.
	current := call(1, nil, 200)
	rename := Command{RequestId: "rename-0001", Action: "save", List: current.Lists[0]}
	rename.List.Title = "Renamed by a member"
	renamed := call(1, &rename, 200)
	if renamed.Lists[0].Title != "Renamed by a member" {
		t.Fatal("a member could not rename the list")
	}
	// Accepted members see collaborator states and can share with mutual friends.
	for _, pair := range [][2]string{{users[0], users[2]}, {users[1], users[2]}} {
		if _, err := server.Store.Database.Exec("INSERT INTO server_friendships VALUES(?,?,CURRENT_TIMESTAMP)", pair[0], pair[1]); err != nil {
			t.Fatal(err)
		}
	}
	memberInvite := Command{RequestId: "member-invite", Action: "invite", Target: users[2], List: renamed.Lists[0]}
	memberView := call(1, &memberInvite, 200)
	if len(memberView.Invitations) != 2 {
		t.Fatal("member cannot see existing accepted and pending collaborators")
	}
	inviteOwner := memberInvite
	inviteOwner.RequestId = "invite-owner"
	inviteOwner.Target = users[0]
	call(1, &inviteOwner, 403)
	third := call(2, nil, 200)
	if len(third.Lists) != 0 || len(third.Invitations) != 1 {
		t.Fatal("pending invite reveals another person's collaborators or list content")
	}
	call(2, &Command{RequestId: "third-accept", Action: "accept", InvitationId: third.Invitations[0].ID}, 200)
	memberView = call(1, nil, 200)
	if len(memberView.Invitations) != 2 || memberView.Invitations[0].Status != "accepted" || memberView.Invitations[1].Status != "accepted" {
		t.Fatal("accepted collaborator state is missing")
	}
	if _, err := server.Store.Database.Exec("DELETE FROM server_friendships WHERE (user_id_a=?1 AND user_id_b=?2) OR (user_id_b=?1 AND user_id_a=?2)", users[0], users[2]); err != nil {
		t.Fatal(err)
	}
	owner = call(0, nil, 200)
	remove := Command{RequestId: "delete-0001", Action: "delete", List: owner.Lists[0]}
	call(1, &remove, 403)
	call(2, &remove, 404)
	deleted := call(0, &remove, 200)
	if len(deleted.Lists) != 1 || deleted.Lists[0].Deleted != 1 {
		t.Fatal("owner deletion tombstone is missing")
	}
	if len(call(1, nil, 200).Lists) != 0 {
		t.Fatal("deleted list still accessible")
	}
	// A nonfriend cannot be invited, and data validation is enforced on writes.
	invite.RequestId = "stranger-0001"
	invite.Target = users[2]
	invite.List.ID = "list-0002"
	call(0, &invite, 403)
	invite.Target = users[1]
	invite.RequestId = "invalid-0001"
	invite.List.Title = strings.Repeat("x", 128)
	call(0, &invite, 403)
	invite.List.Title = "Valid title"
	invite.List.Items = []Item{{ID: "same-id", Title: "One"}, {ID: "same-id", Title: "Two"}}
	call(0, &invite, 403)
	invite.List.Items = []Item{{ID: "task-0003", Title: "One"}}
	invite.RequestId = "decline-invite"
	call(0, &invite, 200)
	pending = call(1, nil, 200)
	decline := Command{RequestId: "decline-0001", Action: "decline", InvitationId: pending.Invitations[0].ID}
	call(1, &decline, 200)
	decline.RequestId = "accept-declined"
	decline.Action = "accept"
	call(1, &decline, 409)
	invite.RequestId = "reinvite-0001"
	call(0, &invite, 200)
	if got := call(1, nil, 200); len(got.Invitations) != 1 || got.Invitations[0].ID != "reinvite-0001" {
		t.Fatal("re-invitation did not replace the declined attempt")
	}
	// Authentication must be required at the real registered route too.
	request := httptest.NewRequest("GET", "/api/v1/lists", nil)
	result := httptest.NewRecorder()
	server.Routes().ServeHTTP(result, request)
	if result.Code == 200 {
		t.Fatal("unauthenticated route exposed lists")
	}
}

func TestSharedListsQuotaRollbackAndFriendRevocation(t *testing.T) {
	server, users := socialHTTPFixture(t)
	post := func(user int, command Command, want int) Snapshot {
		t.Helper()
		raw, err := json.Marshal(command)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest("POST", "/api/v1/lists", bytes.NewReader(raw))
		request.Header.Set("X-Daochi-User", users[user])
		request.Header.Set("Authorization", "Bearer "+Token_IssueAuthToken(server.Cfg.TokenSecret, users[user], time.Now().Add(time.Hour).Unix()).Value)
		result := httptest.NewRecorder()
		SharedLists_Handle(server.accounts(), result, request)
		if result.Code != want {
			t.Fatalf("%s: got %d %s, want %d", raw, result.Code, result.Body, want)
		}
		var snapshot Snapshot
		if want == 200 && json.Unmarshal(result.Body.Bytes(), &snapshot) != nil {
			t.Fatal("invalid snapshot")
		}
		return snapshot
	}
	invite := Command{RequestId: "quota-invite", Action: "invite", Target: users[1], List: List{ID: "quota-list", Title: "Weekend", Items: []Item{{ID: "quota-item", Title: "Pack"}}}}
	owner := post(0, invite, 200)
	accepted := post(1, Command{RequestId: "quota-accept", Action: "accept", InvitationId: owner.Invitations[0].ID}, 200)
	used := AccountStorage_Used(server.Store.Database, context.Background(), users[0])
	if used.Error != nil {
		t.Fatal(used.Error)
	}
	server.Cfg.AccountStorageLimitBytes = used.Value
	save := Command{RequestId: "quota-save", Action: "save", List: accepted.Lists[0]}
	save.List.Items[0].Comment = strings.Repeat("x", 500)
	post(1, save, 413)
	var revision int64
	var receipts int
	if err := server.Store.Database.QueryRow("SELECT revision FROM server_shared_lists WHERE id=?", save.List.ID).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	if err := server.Store.Database.QueryRow("SELECT COUNT(*) FROM server_list_commands WHERE request_id=?", save.RequestId).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if revision != 1 || receipts != 0 {
		t.Fatal("quota rejection partially committed content or receipt")
	}
	server.Cfg.AccountStorageLimitBytes = 0
	post(1, save, 200)
	if _, err := server.Store.Database.Exec("DELETE FROM server_friendships"); err != nil {
		t.Fatal(err)
	}
	save.RequestId = "revoked-save"
	save.List.Revision = 2
	post(1, save, 404)
	got := SharedLists_Read(server.Store.Database, context.Background(), users[1])
	if got.Error != nil || len(got.Lists) != 0 {
		t.Fatal("removed friend retained access")
	}
}
