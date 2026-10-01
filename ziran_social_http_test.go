package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func socialHTTPFixture(t *testing.T) (*Server, []string) {
	t.Helper()
	server, store, _ := testServer(t)
	store.db.SetMaxOpenConns(1)
	users := []string{strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)}
	for index, user := range users {
		if _, err := store.db.Exec("INSERT INTO server_users(user_id_hash,public_key,alias,profile_icon,created_at,last_seen_at) VALUES(?,?,?,?,?,?)",
			user, []byte{byte(index + 1)}, fmt.Sprintf("user%d", index), index, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.Exec("INSERT INTO server_sync_state VALUES(?,7)", user); err != nil {
			t.Fatal(err)
		}
	}
	queries := []string{
		"INSERT INTO server_friendships VALUES('" + users[0] + "','" + users[1] + "','2026-01-01T00:00:00Z')",
		"INSERT INTO server_friend_requests VALUES('" + strings.Repeat("e", 32) + "','" + users[0] + "','" + users[2] + "','pending','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
		"CREATE TRIGGER social_http_user_clock AFTER UPDATE ON server_users BEGIN UPDATE server_users SET last_seen_at='2026-01-01T00:00:00Z' WHERE user_id_hash=NEW.user_id_hash; END",
		"CREATE TRIGGER social_http_friendship_clock AFTER INSERT ON server_friendships BEGIN UPDATE server_friendships SET created_at='2026-01-01T00:00:00Z' WHERE rowid=NEW.rowid; END",
	}
	for _, table := range []string{"server_friend_requests", "server_profile_stats", "server_social_snapshots"} {
		for _, event := range []string{"INSERT", "UPDATE"} {
			query := fmt.Sprintf("CREATE TRIGGER clock_%s_%s AFTER %s ON %s BEGIN UPDATE %s SET updated_at='2026-01-01T00:00:00Z' WHERE rowid=NEW.rowid; END", table, event, event, table, table)
			if table == "server_friend_requests" {
				query = strings.Replace(query, "SET updated_at=", "SET created_at='2026-01-01T00:00:00Z',updated_at=", 1)
			}
			queries = append(queries, query)
		}
	}
	for _, query := range queries {
		if _, err := store.db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	return server, users
}

func socialHTTPResponseTimes(t *testing.T, endpoint string, response []byte, started, finished time.Time) []byte {
	t.Helper()
	if len(response) == 0 || endpoint != "create" && endpoint != "accept" && endpoint != "decline" {
		return response
	}
	var decoded struct {
		Request FriendRequest `json:"request"`
	}
	if err := json.Unmarshal(response, &decoded); err != nil {
		t.Fatal("successful friend response is not valid JSON", err)
	}
	fields := map[string]string{"updated_at": decoded.Request.UpdatedAt}
	if endpoint == "create" {
		if decoded.Request.CreatedAt != decoded.Request.UpdatedAt {
			t.Fatal("new friend request creation and update times differ")
		}
		fields["created_at"] = decoded.Request.CreatedAt
	}
	for field, value := range fields {
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil || parsed.UTC().Format(time.RFC3339) != value ||
			parsed.Before(started.Truncate(time.Second)) || parsed.After(finished.Truncate(time.Second)) {
			t.Fatalf("friend response %s is not the request's current UTC timestamp: %q", field, value)
		}
		original := []byte(`"` + field + `":"` + value + `"`)
		if bytes.Count(response, original) != 1 {
			t.Fatalf("friend response has an unexpected %s field", field)
		}
		normalized := []byte(`"` + field + `":"2026-01-01T00:00:00Z"`)
		response = bytes.Replace(response, original, normalized, 1)
	}
	return response
}

func TestZiranSocialHTTPAgainstBaseline(t *testing.T) {
	type endpoint struct {
		name, method, path, body string
		user                     int
		generated                func(*Server, http.ResponseWriter, *http.Request)
		baseline                 func(*Server, http.ResponseWriter, *http.Request)
	}
	endpoints := []endpoint{
		{"alias", "POST", "/api/v1/account/alias", `{"alias":" @@Alice "}`, 0,
			func(s *Server, w http.ResponseWriter, r *http.Request) { AccountHttp_Alias(s.accounts(), w, r) }, (*Server).baselineSocialHttpHandleAlias},
		{"icon", "POST", "/api/v1/account/profile-icon", `{"profile_icon":11}`, 0,
			func(s *Server, w http.ResponseWriter, r *http.Request) { AccountHttp_ProfileIcon(s.accounts(), w, r) }, (*Server).baselineSocialHttpHandleProfileIcon},
		{"friends", "GET", "/api/v1/friends", "", 0,
			func(s *Server, w http.ResponseWriter, r *http.Request) { SocialHttp_Friends(s.social(), w, r) }, (*Server).baselineSocialHttpHandleFriends},
		{"remove", "DELETE", "/api/v1/friends/" + strings.Repeat("b", 64) + "/", "", 0,
			func(s *Server, w http.ResponseWriter, r *http.Request) { SocialHttp_RemoveFriend(s.social(), w, r) }, (*Server).baselineSocialHttpHandleFriendRoute},
		{"requests", "GET", "/api/v1/friends/requests", "", 0,
			func(s *Server, w http.ResponseWriter, r *http.Request) { SocialHttp_Requests(s.social(), w, r) }, (*Server).baselineSocialHttpHandleFriendRequests},
		{"create", "POST", "/api/v1/friends/requests", `{"target":" @user2 "}`, 0,
			func(s *Server, w http.ResponseWriter, r *http.Request) { SocialHttp_CreateRequest(s.social(), w, r) }, (*Server).baselineSocialHttpHandleFriendRequestCreate},
		{"accept", "POST", "/api/v1/friends/requests/" + strings.Repeat("e", 32) + "/accept", "{}", 2,
			func(s *Server, w http.ResponseWriter, r *http.Request) { SocialHttp_RequestAction(s.social(), w, r) }, (*Server).baselineSocialHttpHandleFriendRequestRoute},
		{"decline", "POST", "/api/v1/friends/requests/" + strings.Repeat("e", 32) + "/decline", "{}", 0,
			func(s *Server, w http.ResponseWriter, r *http.Request) { SocialHttp_RequestAction(s.social(), w, r) }, (*Server).baselineSocialHttpHandleFriendRequestRoute},
		{"stats write", "PUT", "/api/v1/profile/stats", `{"app":" inbe ","metrics":[{"practice":" whm ","metric":" streak ","value":4,"label":" four "}]}`, 0,
			func(s *Server, w http.ResponseWriter, r *http.Request) { SocialHttp_PutStats(s.social(), w, r) }, (*Server).baselineSocialHttpHandleProfileStatsPut},
		{"stats read", "GET", "/api/v1/friends/stats?app=inbe&practice=whm&metric=streak", "", 0,
			func(s *Server, w http.ResponseWriter, r *http.Request) { SocialHttp_FriendStats(s.social(), w, r) }, (*Server).baselineSocialHttpHandleFriendStats},
	}
	for _, endpoint := range endpoints {
		for _, mode := range []string{"normal", "legacy header", "missing user header", "missing bearer", "mismatched bearer", "invalid body", "body limit", "cancelled", "body panic", "response panic", "database failure", "write failure"} {
			t.Run(endpoint.name+"/"+mode, func(t *testing.T) {
				actual, users := socialHTTPFixture(t)
				expected, _ := socialHTTPFixture(t)
				failure := errors.New("HTTP panic sentinel")
				type observation struct {
					status     int
					header     http.Header
					body       []byte
					closed     int
					panicValue any
					accounts   []AccountExportResponse
					events     [][]SyncEvent
				}
				run := func(server *Server, handler func(*Server, http.ResponseWriter, *http.Request)) observation {
					user := users[endpoint.user]
					bodyText := endpoint.body
					if mode == "invalid body" {
						bodyText = `{"alias":42,"profile_icon":"bad","target":false,"metrics":[42]}`
					}
					body := &httpPortBody{Reader: strings.NewReader(bodyText)}
					request := httptest.NewRequest(endpoint.method, endpoint.path, body)
					request.Header.Set("Authorization", "Bearer "+Token_IssueAuthToken(server.cfg.TokenSecret, user, time.Now().Add(time.Hour).Unix()).Value)
					request.Header.Set("X-Daochi-User", user)
					switch mode {
					case "legacy header":
						request.Header.Del("X-Daochi-User")
						request.Header.Set("X-Ksync-User", " \u2003"+strings.ToUpper(user)+"\n")
					case "missing user header":
						request.Header.Del("X-Daochi-User")
					case "missing bearer":
						request.Header.Del("Authorization")
					case "mismatched bearer":
						request.Header.Set("X-Daochi-User", strings.Repeat("f", 64))
					case "body limit":
						server.cfg.MaxBodyBytes = 1
					case "cancelled":
						context, cancel := context.WithCancel(context.Background())
						cancel()
						request = request.WithContext(context)
					case "body panic":
						body.panicValue = failure
					case "database failure":
						if _, err := server.store.db.Exec("DROP TABLE server_social_snapshots; DROP TABLE server_friend_requests; DROP TABLE server_friendships; DROP TABLE server_profile_stats; DROP TABLE server_sessions"); err != nil {
							t.Fatal(err)
						}
					case "write failure":
						for _, table := range []string{"server_users", "server_friend_requests", "server_friendships", "server_profile_stats", "server_social_snapshots"} {
							for _, event := range []string{"INSERT", "UPDATE", "DELETE"} {
								query := fmt.Sprintf("CREATE TRIGGER reject_%s_%s BEFORE %s ON %s BEGIN SELECT RAISE(ABORT,'write rejected'); END", table, event, event, table)
								if _, err := server.store.db.Exec(query); err != nil {
									t.Fatal(err)
								}
							}
						}
					}
					var channels []chan SyncEvent
					for _, user := range users {
						subscription := SyncHub_Subscribe(server.syncHub, user)
						channels = append(channels, StdChannelGo_Interface(subscription.Channel).(chan SyncEvent))
						defer SyncHub_Unsubscribe(server.syncHub, user, subscription)
					}
					writer := &httpPortWriter{header: make(http.Header)}
					if mode == "response panic" {
						writer.panicValue = failure
					}
					observed := observation{}
					started := time.Now()
					func() {
						defer func() { observed.panicValue = recover() }()
						original := rand.Reader
						rand.Reader = bytes.NewReader(bytes.Repeat([]byte{0x71}, 1024))
						defer func() { rand.Reader = original }()
						handler(server, writer, request)
					}()
					finished := time.Now()
					observed.status, observed.header, observed.body, observed.closed = writer.status, writer.header, writer.data, body.closed
					if observed.status == http.StatusOK {
						observed.body = socialHTTPResponseTimes(t, endpoint.name, observed.body, started, finished)
					}
					if err := server.store.db.Ping(); err != nil {
						t.Fatal("HTTP path retained the database connection", err)
					}
					for _, user := range users {
						exported := AccountExport_Export(server.store.db, context.Background(), user)
						observed.accounts = append(observed.accounts, exported.Value)
					}
					for _, channel := range channels {
						var events []SyncEvent
						for len(channel) > 0 {
							events = append(events, <-channel)
						}
						observed.events = append(observed.events, events)
					}
					return observed
				}
				got := run(actual, endpoint.generated)
				want := run(expected, endpoint.baseline)
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("generated HTTP differs from baseline:\ngot  %#v\nwant %#v", got, want)
				}
			})
		}
	}
}

func TestZiranSocialDecodersAgainstBaseline(t *testing.T) {
	inputs := []string{"", "null", "[]", "{}", "false", "{", "{}[]", "\xff", `{"target":" \u2003@User \u2003 "}`, `{"target":false}`, `{"app":" inbe ","metrics":[{"practice":" whm ","metric":" streak ","label":" four "}]}`, `{"app":"inbe","metrics":[{"practice":"good","metric":"bad-name"}]}`}
	tooMany, _ := json.Marshal(ProfileStatsRequest{App: "inbe", Metrics: make([]ProfileMetric, 101)})
	inputs = append(inputs, string(tooMany))
	for _, input := range inputs {
		for _, limit := range []int64{0, 1, 100000} {
			request := func() *http.Request { return httptest.NewRequest("POST", "/", strings.NewReader(input)) }
			created := SocialHttp_ReadCreate(httptest.NewRecorder(), request(), limit)
			wantCreated, createdError := baselineSocialHttpReadFriendRequestCreateRequest(httptest.NewRecorder(), request(), limit)
			if !reflect.DeepEqual(created.Value, wantCreated) || !sameIdentityError(created.Error, createdError) {
				t.Fatalf("create decoder differs for %q, %d", input, limit)
			}
			stats := SocialHttp_ReadStats(httptest.NewRecorder(), request(), limit)
			wantStats, statsError := baselineSocialHttpReadProfileStatsRequest(httptest.NewRecorder(), request(), limit)
			if !reflect.DeepEqual(stats.Value, wantStats) || !sameIdentityError(stats.Error, statsError) {
				t.Fatalf("stats decoder differs for %q, %d", input, limit)
			}
		}
	}
	for _, practice := range []string{"whm", "meditation", "sun_salutation", "", "WHM", "\xff"} {
		for _, metric := range []string{"streak", "avg_hold", "avg_time", "", "\xff"} {
			if SocialHttp_ValidMetric(practice, metric) != baselineSocialHttpValidLeaderboardMetric(practice, metric) {
				t.Fatal("leaderboard query policy changed")
			}
		}
	}
	for _, path := range []string{"", "/api/v1/friends/requests/", "/api/v1/friends/requests//" + strings.Repeat("a", 32) + "/accept//", "/api/v1/friends/requests/" + strings.Repeat("a", 32) + "/decline", "/api/v1/friends/requests/" + strings.Repeat("A", 32) + "/accept", "/api/v1/friends/requests/a/accept", "/api/v1/friends/requests/" + strings.Repeat("a", 32) + "/accept/extra"} {
		got := SocialHttp_ParseRequestPath(path)
		id, action, valid := baselineSocialHttpParseFriendRequestPath(path)
		if got.ID != id || got.Action != action || got.Valid != valid {
			t.Fatalf("friend path changed: %q", path)
		}
	}
	for _, icon := range []int{math.MinInt, -1, 0, 1, 11, 12, math.MaxInt} {
		if AccountHttp_ValidIcon(icon) != baselineSocialHttpValidProfileIcon(icon) {
			t.Fatal("profile icon bounds changed")
		}
	}
}
