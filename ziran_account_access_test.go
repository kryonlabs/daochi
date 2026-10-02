package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql/driver"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

type accessVerifier struct {
	transactionVerifier
	panicValue any
}

func (verifier *accessVerifier) Verify(key, message, signature []byte) bool {
	accepted := verifier.transactionVerifier.Verify(key, message, signature)
	if verifier.panicValue != nil {
		panic(verifier.panicValue)
	}
	return accepted
}

func accessIdentity() (string, []byte, string) {
	key := bytes.Repeat([]byte{0x42}, mlDSA44PublicKeySize)
	hash := sha256.Sum256(key)
	return hex.EncodeToString(hash[:]), key, hex.EncodeToString(bytes.Repeat([]byte{0x35}, mlDSA44SignatureSize))
}

func accessChallenge(server *Server, user string) {
	server.Challenges.ByUser[user] = Challenge{
		Nonce: bytes.Repeat([]byte{0x71}, 32), ExpiresAt: time.Unix(4_000_000_000, 0),
	}
}

func TestZiranAccountSignatureAgainstBaseline(t *testing.T) {
	modes := []string{"registered", "new account", "normalized user", "invalid user", "missing challenge", "expired challenge",
		"missing public key", "malformed public key", "short public key", "wrong account hash", "registered key supplied",
		"registered malformed key", "registered mismatched key", "empty stored key", "malformed signature", "short signature",
		"base64 signature", "rejected", "cancelled", "closed", "callback panic"}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			user, key, signature := accessIdentity()
			actual, _, _ := testServer(t)
			expected, _, _ := testServer(t)
			servers := []*Server{actual, expected}
			verifiers := [2]*accessVerifier{}
			newAccount := strings.Contains(mode, "public key") || mode == "new account" || mode == "wrong account hash"
			for index, server := range servers {
				verifiers[index] = &accessVerifier{transactionVerifier: transactionVerifier{accept: mode != "rejected"}}
				server.Verifier = testVerifier(verifiers[index])
				accessChallenge(server, user)
				if !newAccount {
					if err := server.Store.RegisterUser(t.Context(), user, key); err != nil {
						t.Fatal(err)
					}
				}
			}
			publicKeyText := ""
			if newAccount || mode == "registered key supplied" {
				publicKeyText = hex.EncodeToString(key)
			}
			ctx := t.Context()
			sentinel := errors.New("account signature callback panic")
			switch mode {
			case "normalized user":
				user = " \u2003" + strings.ToUpper(user) + "\t"
			case "invalid user":
				user = "!"
			case "missing challenge":
				for _, server := range servers {
					delete(server.Challenges.ByUser, user)
				}
			case "expired challenge":
				for _, server := range servers {
					item := server.Challenges.ByUser[user]
					item.ExpiresAt = time.Unix(1, 0)
					server.Challenges.ByUser[user] = item
				}
			case "missing public key":
				publicKeyText = ""
			case "malformed public key", "registered malformed key":
				publicKeyText = "!"
			case "short public key", "registered mismatched key":
				publicKeyText = "00"
			case "wrong account hash":
				publicKeyText = hex.EncodeToString(bytes.Repeat([]byte{0x43}, mlDSA44PublicKeySize))
			case "empty stored key":
				for _, server := range servers {
					lifecycleExecute(t, server.Store, "UPDATE server_users SET public_key=x'' WHERE user_id_hash=?1", user)
				}
			case "malformed signature":
				signature = "!"
			case "short signature":
				signature = "00"
			case "base64 signature":
				signature = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x35}, mlDSA44SignatureSize))
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			case "closed":
				for _, server := range servers {
					if err := server.Store.Close(); err != nil {
						t.Fatal(err)
					}
				}
			case "callback panic":
				for _, verifier := range verifiers {
					verifier.panicValue = sentinel
				}
			}
			var values [2][]byte
			var failures [2]error
			var panics [2]any
			for index, server := range servers {
				panics[index] = boundaryRecover(func() {
					if index == 0 {
						values[index], failures[index] = server.authenticateSignature(ctx, user, publicKeyText, signature, "inbe-sync-v1", "POST", "/a/b", []byte("\x00\xff日本語"))
					} else {
						values[index], failures[index] = server.baselineAccessAuthenticateSignature(ctx, user, publicKeyText, signature, "inbe-sync-v1", "POST", "/a/b", []byte("\x00\xff日本語"))
					}
				})
			}
			if !reflect.DeepEqual(values[0], values[1]) || !equalAuthenticationError(failures[0], failures[1]) || panics[0] != panics[1] ||
				!reflect.DeepEqual(verifiers[0].calls, verifiers[1].calls) || !reflect.DeepEqual(actual.Challenges.ByUser, expected.Challenges.ByUser) {
				t.Fatal("account signature result, callback, panic or challenge state changed", failures, panics)
			}
			if mode == "registered" || mode == "new account" || mode == "normalized user" || mode == "registered key supplied" || mode == "base64 signature" || mode == "empty stored key" {
				if failures[0] != nil || len(verifiers[0].calls) != 1 {
					t.Fatal("valid account signature was rejected", failures)
				}
			}
			if mode == "cancelled" && failures[0] != context.Canceled {
				t.Fatal("native cancellation identity changed", failures)
			}
			if mode == "callback panic" && panics[0] != sentinel {
				t.Fatal("verifier panic identity changed", panics)
			}
			if mode != "invalid user" && len(actual.Challenges.ByUser) != 0 {
				t.Fatal("a used or expired challenge survived authentication")
			}
			if mode != "invalid user" {
				_, replay := actual.authenticateSignature(ctx, user, publicKeyText, signature, "inbe-sync-v1", "POST", "/a/b", nil)
				if !equalAuthenticationError(replay, authError{400, "missing or expired challenge"}) {
					t.Fatal("challenge was reusable after authentication", replay)
				}
			}
			for _, server := range servers {
				if server.Store.Database.Stats().InUse != 0 {
					t.Fatal("account signature retained a database connection")
				}
			}
		})
	}
}

func TestZiranAccountSignatureNativeFailuresAgainstBaseline(t *testing.T) {
	for _, mode := range []string{"query", "scan", "next", "close", "rows panic"} {
		t.Run(mode, func(t *testing.T) {
			user, key, signature := accessIdentity()
			sentinel := errors.New("account key native failure")
			var values [2][]byte
			var failures [2]error
			var panics [2]any
			var plans [2]*lifecycleDriverPlan
			for index := range plans {
				plan := &lifecycleDriverPlan{columns: []string{"public_key"}, rows: [][]driver.Value{{key}}}
				plans[index] = plan
				switch mode {
				case "query":
					plan.queryError = sentinel
				case "scan":
					plan.rows = [][]driver.Value{{func() {}}}
				case "next":
					plan.rows, plan.nextError = nil, sentinel
				case "close":
					plan.closeError = sentinel
				case "rows panic":
					plan.rowsPanic = sentinel
				}
				server := &Server{Store: lifecycleDriverStore(t, plan), Challenges: Challenge_New(time.Minute), Verifier: testVerifier(&transactionVerifier{accept: true}), Signer: signAccountProof}
				accessChallenge(server, user)
				panics[index] = boundaryRecover(func() {
					if index == 0 {
						values[index], failures[index] = server.authenticateSignature(t.Context(), user, "", signature, "daochi-sync-v1", "POST", "/login", nil)
					} else {
						values[index], failures[index] = server.baselineAccessAuthenticateSignature(t.Context(), user, "", signature, "daochi-sync-v1", "POST", "/login", nil)
					}
				})
				if len(server.Challenges.ByUser) != 0 || server.Store.Database.Stats().InUse != 0 {
					t.Fatal("native failure retained a challenge or connection")
				}
			}
			if !reflect.DeepEqual(values[0], values[1]) || !equalAuthenticationError(failures[0], failures[1]) || panics[0] != panics[1] ||
				!reflect.DeepEqual(plans[0].trace, plans[1].trace) || plans[0].closed != plans[1].closed {
				t.Fatal("native SQL failure, panic or row cleanup changed", failures, panics)
			}
			if (mode == "query" || mode == "next" || mode == "close") && failures[0] != sentinel {
				t.Fatal("native SQL error lost identity", failures)
			}
		})
	}
}

func accessStoreState(t *testing.T, store *Store) [][][]any {
	t.Helper()
	queries := []string{
		"SELECT user_id_hash,public_key,alias,profile_icon FROM server_users ORDER BY user_id_hash",
		"SELECT user_id_hash,client_id,protocol_version,last_client_clock,last_login_at IS NOT NULL FROM server_clients ORDER BY user_id_hash,client_id",
		"SELECT user_id_hash,server_version FROM server_sync_state ORDER BY user_id_hash",
		"SELECT user_id_hash FROM server_account_tombstones ORDER BY user_id_hash",
	}
	result := make([][][]any, len(queries))
	for index, query := range queries {
		rows, err := store.Database.Query(query)
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			_ = rows.Close()
			t.Fatal(err)
		}
		for rows.Next() {
			values := make([]any, len(columns))
			destinations := make([]any, len(columns))
			for field := range values {
				destinations[field] = &values[field]
			}
			if err := rows.Scan(destinations...); err != nil {
				_ = rows.Close()
				t.Fatal(err)
			}
			result[index] = append(result[index], values)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			t.Fatal(err)
		}
		_ = rows.Close()
	}
	return result
}

func accessNormalizeLogin(t *testing.T, recorder *httptest.ResponseRecorder, server *Server, user string, before, after time.Time) {
	t.Helper()
	if recorder.Code != http.StatusOK {
		return
	}
	var response LoginResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(response.AuthToken, ".")
	if len(parts) != 2 {
		t.Fatal("login did not return a bearer token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Split(string(payload), "\n")
	if len(fields) != 4 || fields[0] != "v1" || fields[1] != user || fields[3] != "" {
		t.Fatal("login token payload changed", string(payload))
	}
	expiry, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || expiry < before.Add(server.Cfg.TokenTTL).Unix() || expiry > after.Add(server.Cfg.TokenTTL).Unix() {
		t.Fatal("token expiration changed", expiry, err)
	}
	verified := Token_VerifyAuthToken(server.Cfg.TokenSecret, response.AuthToken, before.Unix())
	issued := Token_IssueAuthToken(server.Cfg.TokenSecret, user, expiry)
	if verified.Error != "" || verified.Value != user || issued.Value != response.AuthToken || response.ServerTime < before.Unix() || response.ServerTime > after.Unix() ||
		response.ExpiresIn != int64(server.Cfg.TokenTTL.Seconds()) {
		t.Fatal("login token or timestamps are invalid", response)
	}
	response.AuthToken, response.ServerTime = "<validated token>", 0
	recorder.Body.Reset()
	if err := json.NewEncoder(recorder.Body).Encode(response); err != nil {
		t.Fatal(err)
	}
}

func TestZiranAccountAccessHTTPAgainstBaseline(t *testing.T) {
	logger, logWriter, logFlags, randomReader := slog.Default(), log.Writer(), log.Flags(), rand.Reader
	restore := func() {
		slog.SetDefault(logger)
		log.SetOutput(logWriter)
		log.SetFlags(logFlags)
		rand.Reader = randomReader
	}
	t.Cleanup(restore)
	cases := []struct {
		name  string
		modes []string
	}{
		{"challenge", []string{"valid", "invalid user", "ip limit", "user limit", "nil limiter", "nil verifier", "entropy panic", "response panic"}},
		{"login", []string{"valid", "new account", "malformed body", "oversized body", "body panic", "missing header", "header mismatch", "legacy header", "invalid client", "ip limit", "user limit", "nil limiter", "missing challenge", "expired challenge", "bad signature", "rejected", "register failure", "client failure", "token failure", "cancelled", "closed", "callback panic", "response panic", "log panic"}},
		{"delete", []string{"valid", "malformed body", "oversized body", "body panic", "missing header", "header mismatch", "legacy header", "missing challenge", "expired challenge", "bad signature", "rejected", "delete failure", "cancelled", "closed", "callback panic", "response panic", "log panic"}},
		{"delete key", []string{"valid", "malformed body", "oversized body", "body panic", "invalid user", "missing key", "ip limit", "user limit", "nil limiter", "missing account", "malformed key", "wrong public ID", "no public ID", "sign failure", "sign panic", "rejected", "delete failure", "cancelled", "closed", "callback panic", "response panic", "log panic"}},
	}
	for _, test := range cases {
		for _, mode := range test.modes {
			t.Run(test.name+"/"+mode, func(t *testing.T) {
				t.Cleanup(restore)
				user, key, signature := accessIdentity()
				sentinel := errors.New("account access panic")
				var responses [2]*httptest.ResponseRecorder
				var events [2][]string
				var panics [2]any
				var states [2][][][]any
				var counters [2]string
				var verifiers [2]*accessVerifier
				var windows [2]map[string]int
				var challenges [2]int
				var bodyClosed [2]int
				var proofs [2][]signatureObservation
				for index := range responses {
					restore()
					server, store, _ := testServer(t)
					verifier := &accessVerifier{transactionVerifier: transactionVerifier{accept: mode != "rejected"}}
					verifiers[index], server.Verifier = verifier, testVerifier(verifier)
					server.Cfg.ChallengeTTL = time.Minute + 500*time.Millisecond
					server.Challenges.Ttl = server.Cfg.ChallengeTTL
					server.Cfg.TokenTTL = time.Hour + 1300*time.Millisecond
					if mode == "callback panic" {
						verifier.panicValue = sentinel
					}
					newAccount := test.name == "login" && (mode == "new account" || mode == "register failure" || mode == "client failure" || mode == "token failure")
					if test.name != "challenge" && !newAccount && mode != "missing account" {
						if err := store.RegisterUser(t.Context(), user, key); err != nil {
							t.Fatal(err)
						}
						lifecycleExecute(t, store, "UPDATE server_users SET alias='Account 日本語',profile_icon=3 WHERE user_id_hash=?1", user)
						if err := store.RecordClientLogin(t.Context(), user, "existing-client"); err != nil {
							t.Fatal(err)
						}
					}
					if newAccount {
						lifecycleExecute(t, store, "INSERT INTO server_account_tombstones(user_id_hash) VALUES(?1)", user)
					}
					other := strings.Repeat("b", 64)
					if err := store.RegisterUser(t.Context(), other, []byte("unrelated key")); err != nil {
						t.Fatal(err)
					}
					accessChallenge(server, user)
					if mode == "missing challenge" {
						delete(server.Challenges.ByUser, user)
					}
					if mode == "expired challenge" {
						item := server.Challenges.ByUser[user]
						item.ExpiresAt = time.Unix(1, 0)
						server.Challenges.ByUser[user] = item
					}
					if mode == "nil limiter" {
						server.Limiter = nil
					}
					if mode == "nil verifier" {
						server.Verifier = testVerifier(nil)
					}
					if mode == "register failure" {
						lifecycleExecute(t, store, "CREATE TRIGGER fail_registration BEFORE INSERT ON server_users BEGIN SELECT RAISE(ABORT,'registration failed'); END")
					}
					if mode == "client failure" {
						lifecycleExecute(t, store, "CREATE TRIGGER fail_login BEFORE INSERT ON server_clients BEGIN SELECT RAISE(ABORT,'client login failed'); END")
					}
					if mode == "delete failure" {
						lifecycleExecute(t, store, "CREATE TRIGGER fail_deletion BEFORE DELETE ON server_users BEGIN SELECT RAISE(ABORT,'deletion failed'); END")
					}
					if mode == "token failure" {
						server.Cfg.TokenSecret = nil
					}
					if mode == "closed" || mode == "log panic" {
						if err := store.Close(); err != nil {
							t.Fatal(err)
						}
					}
					path, prefix, limit := "/api/v1/sync/login", "login", 40
					switch test.name {
					case "challenge":
						path, prefix, limit = "/api/v1/sync/challenge?user_id="+url.QueryEscape(" \u2003"+strings.ToUpper(user)+"\t"), "challenge", 60
					case "delete":
						path = "/api/v1/sync/account/delete"
					case "delete key":
						path, prefix, limit = "/api/v1/sync/account/delete-with-key", "delete-key", 8
					}
					if mode == "ip limit" || mode == "user limit" {
						subject := "ip:192.0.2.1"
						if mode == "user limit" {
							subject = "user:" + user
							limit = 20
							if test.name == "delete key" {
								limit = 4
							}
						}
						server.Limiter.Windows[prefix+":"+subject] = RateWindow{Count: limit, ResetAt: time.Unix(4_000_000_000, 0)}
					}
					exported := "inbe-sync-key-v1\nalgorithm=ML-DSA-44\npublic_id=" + user + "\nprivate_key=" + hex.EncodeToString(bytes.Repeat([]byte{0x23}, mlDSA44PrivateKeySize))
					if mode == "wrong public ID" {
						exported = strings.Replace(exported, user, other, 1)
					}
					if mode == "no public ID" {
						exported = strings.Replace(exported, "public_id="+user+"\n", "", 1)
					}
					if mode == "malformed key" {
						exported = "bad key"
					}
					if mode == "missing key" {
						exported = ""
					}
					bodyUser := " \u2003" + strings.ToUpper(user) + "\t"
					if mode == "invalid user" {
						bodyUser = "!"
						if test.name == "challenge" {
							path = "/api/v1/sync/challenge?user_id=!"
						}
					}
					client := "test-client-1"
					if mode == "invalid client" {
						client = "bad/"
					}
					body, err := json.Marshal(map[string]string{"user_id_hash": bodyUser, "public_key": hex.EncodeToString(key), "client_id": client, "exported_key": exported})
					if err != nil {
						t.Fatal(err)
					}
					if mode == "malformed body" {
						body = []byte("{bad")
					}
					if mode == "oversized body" {
						server.Cfg.MaxBodyBytes = 3
					}
					request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
					request.RemoteAddr = "192.0.2.1:1234"
					request.Header.Set("X-Daochi-User", user)
					request.Header.Set("X-Daochi-Signature", signature)
					if mode == "missing header" {
						request.Header.Del("X-Daochi-User")
					}
					if mode == "header mismatch" {
						request.Header.Set("X-Daochi-User", other)
					}
					if mode == "legacy header" {
						request.Header.Del("X-Daochi-User")
						request.Header.Del("X-Daochi-Signature")
						request.Header.Set("X-Inbe-User", user)
						request.Header.Set("X-Inbe-Signature", signature)
					}
					if mode == "bad signature" {
						request.Header.Set("X-Daochi-Signature", "!")
					}
					if mode == "cancelled" {
						ctx, cancel := context.WithCancel(t.Context())
						cancel()
						request = request.WithContext(ctx)
					}
					reader := &httpPortBody{Reader: bytes.NewReader(body)}
					request.Body = reader
					if mode == "body panic" {
						reader.panicValue = sentinel
					}
					slog.SetDefault(slog.New(discoveryLogHandler{record: func(record slog.Record) {
						event := record.Level.String() + ":" + record.Message
						record.Attrs(func(attribute slog.Attr) bool {
							event += "|" + attribute.Key + "=" + attribute.Value.String()
							return true
						})
						events[index] = append(events[index], event)
						if mode == "log panic" {
							panic(sentinel)
						}
					}}))
					rand.Reader = bytes.NewReader(bytes.Repeat([]byte{0x52}, 64))
					if mode == "entropy panic" {
						rand.Reader = boundaryReadPanic{value: sentinel}
					}
					sign := func(message, privateKey []byte) ([]byte, error) {
						proofs[index] = append(proofs[index], signatureObservation{key: append([]byte(nil), privateKey...), message: append([]byte(nil), message...)})
						if mode == "sign panic" {
							panic(sentinel)
						}
						if mode == "sign failure" {
							return nil, sentinel
						}
						return []byte("proof signature"), nil
					}
					recorder := httptest.NewRecorder()
					responses[index] = recorder
					var writer http.ResponseWriter = recorder
					if mode == "response panic" {
						writer = &httpPortWriter{header: make(http.Header), panicValue: sentinel}
					}
					before := time.Now()
					panics[index] = boundaryRecover(func() {
						if index == 0 {
							switch test.name {
							case "challenge":
								server.handleChallenge(writer, request)
							case "login":
								server.handleLogin(writer, request)
							case "delete":
								server.handleDeleteAccount(writer, request)
							case "delete key":
								access := server.access()
								access.Sign = func(message, privateKey []byte) PrivateKeySignatureResult {
									value, err := sign(message, privateKey)
									return PrivateKeySignatureResult{Value: value, Error: err}
								}
								AccountAccess_DeleteWithKey(access, writer, request)
							}
						} else {
							switch test.name {
							case "challenge":
								server.baselineAccessHandleChallenge(writer, request)
							case "login":
								server.baselineAccessHandleLogin(writer, request)
							case "delete":
								server.baselineAccessHandleDeleteAccount(writer, request)
							case "delete key":
								server.baselineAccessHandleDeleteAccountWithKey(writer, request, sign)
							}
						}
					})
					after := time.Now()
					if test.name == "login" && panics[index] == nil {
						accessNormalizeLogin(t, recorder, server, user, before, after)
					}
					if test.name == "challenge" && recorder.Code == http.StatusOK && panics[index] == nil {
						var response ChallengeResponse
						if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
							t.Fatal(err)
						}
						issued := server.Challenges.ByUser[user]
						if response.UserIDHash != user || response.Nonce != hex.EncodeToString(bytes.Repeat([]byte{0x52}, 32)) || response.Nonce != hex.EncodeToString(issued.Nonce) ||
							response.ExpiresIn != int64(server.Cfg.ChallengeTTL.Seconds()) || issued.ExpiresAt.Before(before.Add(server.Cfg.ChallengeTTL)) || issued.ExpiresAt.After(after.Add(server.Cfg.ChallengeTTL)) {
							t.Fatal("challenge nonce, account or expiration changed", response)
						}
					}
					bodyClosed[index], challenges[index] = reader.closed, len(server.Challenges.ByUser)
					windows[index] = map[string]int{}
					if server.Limiter != nil {
						for windowKey, window := range server.Limiter.Windows {
							windows[index][windowKey] = window.Count
						}
					}
					metrics := httptest.NewRecorder()
					Metrics_Prometheus(server.Metrics, metrics, NodeUsage{}, NodeStorageUsage{}, "fixture")
					counters[index] = metrics.Body.String()
					if mode != "closed" && mode != "log panic" {
						states[index] = accessStoreState(t, store)
					}
					if store.Database.Stats().InUse != 0 {
						t.Fatal("account access retained a database connection")
					}
				}
				compareHTTPResponse(t, responses[0], responses[1])
				if !reflect.DeepEqual(events[0], events[1]) || panics[0] != panics[1] || counters[0] != counters[1] ||
					!reflect.DeepEqual(verifiers[0].calls, verifiers[1].calls) || !reflect.DeepEqual(proofs[0], proofs[1]) ||
					!reflect.DeepEqual(states[0], states[1]) || !reflect.DeepEqual(windows[0], windows[1]) || challenges[0] != challenges[1] || bodyClosed[0] != bodyClosed[1] {
					t.Fatal("account access logs, panic, counters, callbacks, state, limits or body cleanup changed", events, panics, bodyClosed)
				}
				if strings.Contains(mode, "panic") && panics[0] != sentinel {
					t.Fatal("account access panic identity changed", panics)
				}
				if test.name != "challenge" && bodyClosed[0] != 1 {
					t.Fatal("request body was not closed exactly once", bodyClosed)
				}
				if mode == "ip limit" && windows[0][prefixForAccess(test.name)+":user:"+user] != 0 {
					t.Fatal("user rate limit ran after the IP limit rejected the request")
				}
				if test.name == "delete key" && mode == "sign failure" && len(verifiers[0].calls) != 0 {
					t.Fatal("verification ran after private-key signing failed")
				}
				if mode == "valid" && responses[0].Code != http.StatusOK {
					t.Fatal("valid account request failed", responses[0].Body.String())
				}
				if test.name == "login" {
					switch mode {
					case "register failure":
						if len(states[0][0]) != 1 || len(states[0][1]) != 0 || len(states[0][3]) != 1 {
							t.Fatal("failed registration did not roll back account/tombstone writes", states[0])
						}
					case "client failure":
						if len(states[0][0]) != 2 || len(states[0][1]) != 0 || len(states[0][3]) != 0 {
							t.Fatal("client failure changed previously committed registration", states[0])
						}
					case "token failure":
						if len(states[0][0]) != 2 || len(states[0][1]) != 1 || len(states[0][3]) != 0 {
							t.Fatal("token failure changed previously committed account/client writes", states[0])
						}
					}
				}
				if (test.name == "delete" || test.name == "delete key") && mode == "valid" &&
					(len(states[0][0]) != 1 || len(states[0][1]) != 0 || len(states[0][3]) != 1) {
					t.Fatal("account deletion did not cascade or preserve its tombstone", states[0])
				}
			})
		}
	}
}

func prefixForAccess(handler string) string {
	if handler == "delete key" {
		return "delete-key"
	}
	return handler
}
