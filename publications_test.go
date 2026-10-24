package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

type publicationReply struct {
	Publication    PublicationMeta   `json:"publication"`
	Publications   []PublicationMeta `json:"publications"`
	Document       json.RawMessage   `json:"document"`
	Deleted        bool              `json:"deleted"`
	Error          string            `json:"error"`
	Code           string            `json:"code"`
	AccountStorage AccountStorage    `json:"account_storage"`
}

type publicationClient struct {
	t       *testing.T
	server  *Server
	handler http.Handler
	// The raw body of the latest reply.
	last string
}

func newPublicationClient(t *testing.T) (*publicationClient, []string) {
	server, users := socialHTTPFixture(t)
	return &publicationClient{t: t, server: server, handler: server.Routes()}, users
}

// call sends body as JSON, or a string body as it is, and decodes the reply.
// An empty user sends no bearer token.
func (c *publicationClient) call(user, method, path string, body any, want int) publicationReply {
	c.t.Helper()
	var raw []byte
	switch value := body.(type) {
	case nil:
	case string:
		raw = []byte(value)
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			c.t.Fatal(err)
		}
		raw = encoded
	}
	token := ""
	if user != "" {
		token = Token_IssueAuthToken(c.server.Cfg.TokenSecret, user, time.Now().Add(time.Hour).Unix()).Value
	}
	res := tokenJSONRequest(c.t, c.handler, method, path, token, raw)
	c.last = res.Body.String()
	if res.Code != want {
		c.t.Fatalf("%s %s %.200s: got %d %s, want %d", method, path, raw, res.Code, c.last, want)
	}
	// Anonymous reads of public publications may be cached briefly; every
	// other answer is private to the caller.
	cache := "private, no-store"
	if user == "" && method == http.MethodGet {
		cache = "public, max-age=15"
	}
	if res.Header().Get("Cache-Control") != cache {
		c.t.Fatalf("%s %s cache control: %q", method, path, res.Header().Get("Cache-Control"))
	}
	var reply publicationReply
	if err := json.Unmarshal(res.Body.Bytes(), &reply); err != nil {
		c.t.Fatalf("%s %s: %v in %s", method, path, err, c.last)
	}
	return reply
}

func (c *publicationClient) publish(user string, body any, want int) publicationReply {
	c.t.Helper()
	return c.call(user, http.MethodPost, "/api/v1/publications", body, want)
}

func (c *publicationClient) fetch(user, id string, want int) publicationReply {
	c.t.Helper()
	return c.call(user, http.MethodGet, "/api/v1/publications/"+id, nil, want)
}

func (c *publicationClient) unpublish(user, id string, want int) publicationReply {
	c.t.Helper()
	return c.call(user, http.MethodDelete, "/api/v1/publications/"+id, nil, want)
}

func (c *publicationClient) list(user, query string, want int) []PublicationMeta {
	c.t.Helper()
	path := "/api/v1/publications"
	if query != "" {
		path += "?" + query
	}
	listed := c.call(user, http.MethodGet, path, nil, want).Publications
	if want == http.StatusOK && !strings.Contains(c.last, `"publications":[`) {
		c.t.Fatalf("listing is not an array: %s", c.last)
	}
	return listed
}

func publicationDraft(format, title, visibility string, document any) map[string]any {
	return map[string]any{"format": format, "title": title, "visibility": visibility, "document": document}
}

func publicationTitles(values []PublicationMeta) string {
	titles := make([]string, 0, len(values))
	for _, value := range values {
		titles = append(titles, value.Title)
	}
	return strings.Join(titles, "|")
}

func samePublicationDocument(t *testing.T, got []byte, want any) {
	t.Helper()
	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var left, right any
	if err := json.Unmarshal(got, &left); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &right); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(left, right) {
		t.Fatalf("document %s, want %s", got, encoded)
	}
}

func countPublications(t *testing.T, server *Server, author string) int {
	t.Helper()
	var count int
	if err := server.Store.Database.QueryRow("SELECT COUNT(*) FROM server_publications WHERE author=?", author).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestPublicationsShareLevelCollectionsByVisibility(t *testing.T) {
	client, users := newPublicationClient(t)
	author, friend, stranger := users[0], users[1], users[2]
	database := client.server.Store.Database

	classic := map[string]any{"name": "Classic", "levels": []any{map[string]any{"w": 1}, map[string]any{"w": 2}, map[string]any{"w": 3}}}
	before := AccountStorage_Used(database, t.Context(), author)
	created := client.publish(author, publicationDraft("pushy.levels", "Classic", "public", classic), 200).Publication
	if len(created.ID) != 32 || strings.Trim(created.ID, "0123456789abcdef") != "" {
		t.Fatalf("publication id %q", created.ID)
	}
	if created.Author.Alias != "user0" || created.Author.PublicId != author || created.Format != "pushy.levels" ||
		created.Title != "Classic" || created.Levels != 3 || created.Visibility != "public" || !created.Mine ||
		created.UpdatedAt < time.Now().Add(-time.Minute).Unix() {
		t.Fatalf("created publication: %+v", created)
	}
	// The id, format, title and document count toward the author's storage.
	after := AccountStorage_Used(database, t.Context(), author)
	document, err := json.Marshal(classic)
	if err != nil {
		t.Fatal(err)
	}
	if before.Error != nil || after.Error != nil ||
		after.Value-before.Value != int64(32+len("pushy.levels")+len("Classic")+len(document)) {
		t.Fatalf("storage usage %d -> %d", before.Value, after.Value)
	}

	friendsOnly := client.publish(author, publicationDraft("pushy.levels", "For friends", "friends", map[string]any{"levels": []any{1}}), 200).Publication
	private := client.publish(author, publicationDraft("pushy.levels", "Drafts", "private", map[string]any{"levels": 5}), 200).Publication
	other := client.publish(author, publicationDraft("other.format-2", "Other", "public", map[string]any{}), 200).Publication
	theirs := client.publish(stranger, publicationDraft("pushy.levels", "Stranger's", "public", map[string]any{"levels": []any{}}), 200).Publication
	if friendsOnly.Levels != 1 || private.Levels != 0 || other.Levels != 0 || theirs.Levels != 0 ||
		theirs.Author.Alias != "user2" || theirs.Author.PublicId != stranger {
		t.Fatalf("levels or authors: %+v %+v %+v %+v", friendsOnly, private, other, theirs)
	}

	// Only the author replaces a publication; to anyone else it is missing.
	replacement := publicationDraft("pushy.levels", "Classic, revised", "public", map[string]any{"levels": []any{1, 2}})
	replacement["id"] = created.ID
	for _, user := range []string{friend, stranger} {
		if reply := client.publish(user, replacement, 404); reply.Error != "publication not found" {
			t.Fatalf("replace by another account: %+v", reply)
		}
	}
	missing := publicationDraft("pushy.levels", "Missing", "public", map[string]any{})
	missing["id"] = strings.Repeat("0", 32)
	client.publish(author, missing, 404)
	missing["id"] = "not-a-publication"
	client.publish(author, missing, 404)
	if unchanged := client.fetch(author, created.ID, 200); unchanged.Publication.Title != "Classic" {
		t.Fatalf("someone else replaced the publication: %+v", unchanged.Publication)
	}
	replaced := client.publish(author, replacement, 200).Publication
	if replaced.ID != created.ID || replaced.Title != "Classic, revised" || replaced.Levels != 2 || !replaced.Mine {
		t.Fatalf("replaced publication: %+v", replaced)
	}
	if count := countPublications(t, client.server, author); count != 4 {
		t.Fatalf("author has %d publications, want 4", count)
	}
	fetched := client.fetch(friend, created.ID, 200)
	samePublicationDocument(t, fetched.Document, replacement["document"])
	if fetched.Publication.Mine || fetched.Publication.Title != "Classic, revised" || fetched.Publication.Author.Alias != "user0" {
		t.Fatalf("fetched by a friend: %+v", fetched.Publication)
	}

	// Public for everyone, friends-only for friends, private for the author.
	for _, check := range []struct {
		viewer string
		id     string
		want   int
	}{
		{author, created.ID, 200}, {author, friendsOnly.ID, 200}, {author, private.ID, 200},
		{friend, created.ID, 200}, {friend, friendsOnly.ID, 200}, {friend, private.ID, 404},
		{stranger, created.ID, 200}, {stranger, friendsOnly.ID, 404}, {stranger, private.ID, 404},
		{author, strings.Repeat("f", 32), 404}, {author, "", 404}, {author, created.ID + "/extra", 404},
	} {
		reply := client.fetch(check.viewer, check.id, check.want)
		if check.want == 200 && (reply.Publication.ID != check.id || reply.Publication.Mine != (check.viewer == author)) {
			t.Fatalf("fetch %s as %s: %+v", check.id, check.viewer[:1], reply.Publication)
		}
		if check.want == 404 && reply.Error != "publication not found" {
			t.Fatalf("hidden publication answered %q", reply.Error)
		}
	}
	samePublicationDocument(t, client.fetch(author, private.ID, 200).Document, map[string]any{"levels": 5})

	// Fix the times so the newest-first listings are deterministic.
	for index, id := range []string{created.ID, friendsOnly.ID, private.ID, other.ID, theirs.ID} {
		if _, err := database.Exec("UPDATE server_publications SET updated_at=? WHERE id=?", 1000+index, id); err != nil {
			t.Fatal(err)
		}
	}
	for _, check := range []struct {
		viewer string
		query  string
		want   string
	}{
		{author, "author=user0", "Other|Drafts|For friends|Classic, revised"},
		{friend, "author=user0", "Other|For friends|Classic, revised"},
		{stranger, "author=user0", "Other|Classic, revised"},
		{friend, "author=%40user0", "Other|For friends|Classic, revised"},
		{friend, "author=USER0", "Other|For friends|Classic, revised"},
		{friend, "author=" + author, "Other|For friends|Classic, revised"},
		{stranger, "author=" + author, "Other|Classic, revised"},
		{friend, "author=" + author + "&format=pushy.levels", "For friends|Classic, revised"},
		{author, "author=" + stranger, "Stranger's"},
		{friend, "author=nobody", ""},
		{friend, "author=" + strings.Repeat("d", 64), ""},
		{stranger, "", "Stranger's|Other|Classic, revised"},
		{stranger, "format=pushy.levels", "Stranger's|Classic, revised"},
		{stranger, "format=other.format-2", "Other"},
		{stranger, "format=unknown", ""},
	} {
		listed := client.list(check.viewer, check.query, 200)
		if got := publicationTitles(listed); got != check.want {
			t.Fatalf("%s as %s: %q, want %q", check.query, check.viewer[:1], got, check.want)
		}
		for _, meta := range listed {
			if meta.Mine != (meta.Author.PublicId == check.viewer) || meta.UpdatedAt < 1000 || meta.Author.Alias == "" {
				t.Fatalf("listing metadata: %+v", meta)
			}
		}
	}
	client.list(stranger, "format=Bad_Format", 400)

	// Friends-only work is hidden again once the friendship ends.
	if _, err := database.Exec("DELETE FROM server_friendships"); err != nil {
		t.Fatal(err)
	}
	client.fetch(friend, friendsOnly.ID, 404)
	if got := publicationTitles(client.list(friend, "author=user0", 200)); got != "Other|Classic, revised" {
		t.Fatalf("a former friend still lists %q", got)
	}

	// Only the author unpublishes; missing and others' publications answer alike.
	for _, user := range []string{friend, stranger} {
		if reply := client.unpublish(user, created.ID, 404); reply.Error != "publication not found" {
			t.Fatalf("delete by another account: %+v", reply)
		}
	}
	client.unpublish(author, strings.Repeat("0", 32), 404)
	client.unpublish(author, "", 404)
	if reply := client.unpublish(author, created.ID, 200); !reply.Deleted || !strings.Contains(client.last, `"deleted":true`) {
		t.Fatalf("delete reply: %s", client.last)
	}
	client.fetch(author, created.ID, 404)
	client.unpublish(author, created.ID, 404)
	if got := publicationTitles(client.list(stranger, "", 200)); got != "Stranger's|Other" {
		t.Fatalf("after unpublishing: %q", got)
	}
	if count := countPublications(t, client.server, author); count != 3 {
		t.Fatalf("author has %d publications after unpublishing, want 3", count)
	}

	// Publishing and unpublishing need an account.
	for _, request := range []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodPost, "/api/v1/publications", publicationDraft("pushy.levels", "Classic", "public", map[string]any{})},
		{http.MethodDelete, "/api/v1/publications/" + other.ID, nil},
	} {
		client.call("", request.method, request.path, request.body, 401)
	}

	// Anyone may read public publications, and only those.
	if got := publicationTitles(client.list("", "", 200)); got != "Stranger's|Other" {
		t.Fatalf("anonymous newest public: %q", got)
	}
	anonymous := client.list("", "author=user0", 200)
	if got := publicationTitles(anonymous); got != "Other" {
		t.Fatalf("anonymous author listing: %q", got)
	}
	for _, meta := range anonymous {
		if meta.Mine || meta.Visibility != "public" {
			t.Fatalf("anonymous listing metadata: %+v", meta)
		}
	}
	if reply := client.fetch("", other.ID, 200); reply.Publication.ID != other.ID || reply.Publication.Mine {
		t.Fatalf("anonymous fetch: %+v", reply.Publication)
	}
	for _, id := range []string{friendsOnly.ID, private.ID} {
		if reply := client.fetch("", id, 404); reply.Error != "publication not found" {
			t.Fatalf("anonymous fetch of a hidden publication: %+v", reply)
		}
	}
	// A reader who sends credentials must still sign in.
	if res := tokenJSONRequest(t, client.handler, http.MethodGet, "/api/v1/publications", "not-a-token", nil); res.Code != 401 {
		t.Fatalf("invalid token read: %d", res.Code)
	}
	expired := Token_IssueAuthToken(client.server.Cfg.TokenSecret, author, time.Now().Add(-time.Hour).Unix()).Value
	if res := tokenJSONRequest(t, client.handler, http.MethodDelete, "/api/v1/publications/"+other.ID, expired, nil); res.Code != 401 {
		t.Fatalf("expired token: %d", res.Code)
	}
	if count := countPublications(t, client.server, author); count != 3 {
		t.Fatal("an unauthenticated request changed publications")
	}

	// Deleting an account removes its publications.
	if err := client.server.Store.DeleteAccount(t.Context(), author); err != nil {
		t.Fatal(err)
	}
	if count := countPublications(t, client.server, author); count != 0 {
		t.Fatalf("a deleted account kept %d publications", count)
	}
	if got := publicationTitles(client.list(stranger, "", 200)); got != "Stranger's" {
		t.Fatalf("after deleting the author: %q", got)
	}
}

func TestPublicationsRejectInvalidDrafts(t *testing.T) {
	client, users := newPublicationClient(t)
	user := users[2]
	valid := map[string]any{"levels": []any{}}
	for _, body := range []any{
		publicationDraft("", "Title", "public", valid),
		publicationDraft("Pushy", "Title", "public", valid),
		publicationDraft("pushy_levels", "Title", "public", valid),
		publicationDraft("pushy levels", "Title", "public", valid),
		publicationDraft(strings.Repeat("a", 65), "Title", "public", valid),
		publicationDraft("pushy.levels", "", "public", valid),
		publicationDraft("pushy.levels", "   ", "public", valid),
		publicationDraft("pushy.levels", strings.Repeat("a", 81), "public", valid),
		publicationDraft("pushy.levels", strings.Repeat("é", 41), "public", valid),
		publicationDraft("pushy.levels", "Line\nbreak", "public", valid),
		publicationDraft("pushy.levels", "Tab\there", "public", valid),
		publicationDraft("pushy.levels", "Delete\x7f", "public", valid),
		publicationDraft("pushy.levels", "Next\u0085line", "public", valid),
		publicationDraft("pushy.levels", "Title", "everyone", valid),
		publicationDraft("pushy.levels", "Title", "", valid),
		publicationDraft("pushy.levels", "Title", "Public", valid),
		publicationDraft("pushy.levels", "Title", "public", []any{1, 2}),
		publicationDraft("pushy.levels", "Title", "public", "levels"),
		publicationDraft("pushy.levels", "Title", "public", 7),
		publicationDraft("pushy.levels", "Title", "public", nil),
		map[string]any{"format": "pushy.levels", "title": "Title", "visibility": "public"},
		map[string]any{"format": "pushy.levels", "title": 7, "visibility": "public", "document": valid},
		`not json`,
		``,
	} {
		if reply := client.publish(user, body, 400); reply.Error != "invalid publication" {
			t.Fatalf("invalid draft answered %q", reply.Error)
		}
	}
	// The longest format and title, multibyte text and a document of several
	// megabytes are accepted: only the author's storage limits its size.
	largest := map[string]any{"levels": []any{}, "padding": strings.Repeat("x", 4<<20)}
	accepted := client.publish(user, publicationDraft(strings.Repeat("a", 64), strings.Repeat("é", 40), "public", largest), 200).Publication
	if accepted.Title != strings.Repeat("é", 40) || accepted.Levels != 0 {
		t.Fatalf("largest publication: %+v", accepted)
	}
	if fetched := client.fetch(user, accepted.ID, 200); fetched.Publication.Title != accepted.Title {
		t.Fatalf("large publication read back as %+v", fetched.Publication)
	}
	if count := countPublications(t, client.server, user); count != 1 {
		t.Fatalf("invalid drafts stored publications: %d", count)
	}
}

func TestPublicationsLimitStorageAndRate(t *testing.T) {
	client, users := newPublicationClient(t)
	author, other := users[1], users[2]
	database := client.server.Store.Database
	// An author keeps as many publications as their storage holds.
	for index := 1; index <= 150; index++ {
		if _, err := database.Exec("INSERT INTO server_publications(id,author,format,title,visibility,levels,document,created_at,updated_at) VALUES(?,?,'pushy.levels','Bulk','private',0,'{}',1,1)",
			fmt.Sprintf("%032x", index), author); err != nil {
			t.Fatal(err)
		}
	}
	draft := publicationDraft("pushy.levels", "One more", "public", map[string]any{"levels": []any{1}})
	if added := client.publish(author, draft, 200).Publication; added.Title != "One more" || added.Levels != 1 {
		t.Fatalf("publication past 150: %+v", added)
	}
	if count := countPublications(t, client.server, author); count != 151 {
		t.Fatalf("author has %d publications", count)
	}

	// A publication may not grow an account past its storage limit.
	used := AccountStorage_Used(database, t.Context(), other)
	if used.Error != nil {
		t.Fatal(used.Error)
	}
	client.server.Cfg.AccountStorageLimitBytes = used.Value + 200
	small := client.publish(other, publicationDraft("pushy.levels", "Small", "public", map[string]any{"levels": []any{}}), 200).Publication
	large := publicationDraft("pushy.levels", "Large", "public", map[string]any{"levels": []any{}, "padding": strings.Repeat("x", 300)})
	reply := client.publish(other, large, 413)
	if reply.Error != "account storage limit reached" || reply.Code != "storage_full" ||
		reply.AccountStorage.LimitBytes != used.Value+200 || reply.AccountStorage.UsedBytes <= used.Value {
		t.Fatalf("storage limit answered %s", client.last)
	}
	large["id"] = small.ID
	client.publish(other, large, 413)
	if fetched := client.fetch(other, small.ID, 200); fetched.Publication.Title != "Small" {
		t.Fatalf("a refused replacement changed the publication: %+v", fetched.Publication)
	}
	client.server.Cfg.AccountStorageLimitBytes = 0
	client.publish(other, large, 200)

	// Publishing and unpublishing share an hourly allowance; reads have their own.
	for attempt := 0; attempt < 60-4; attempt++ {
		client.publish(other, `not json`, 400)
	}
	if reply := client.publish(other, draft, 429); reply.Error != "publication rate limit exceeded" {
		t.Fatalf("write rate limit answered %+v", reply)
	}
	client.unpublish(other, small.ID, 429)
	for attempt := 0; attempt < 119; attempt++ {
		client.list(other, "", 200)
	}
	client.list(other, "", 429)
	client.fetch(other, small.ID, 429)
	// Other accounts keep their own allowances.
	client.fetch(author, small.ID, 200)
	client.unpublish(author, fmt.Sprintf("%032x", 3), 200)
}
