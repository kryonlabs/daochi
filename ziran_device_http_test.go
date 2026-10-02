package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

type deviceHTTPReadFailure struct {
	failure error
}

func (reader deviceHTTPReadFailure) Read([]byte) (int, error) {
	return 0, reader.failure
}

func deviceHTTPFixture(t *testing.T) (*Server, string, *transactionVerifier) {
	t.Helper()
	server, user, _ := registryHTTPFixture(t)
	verifier := &transactionVerifier{accept: true}
	server.Verifier = testVerifier(verifier)
	if _, err := server.Store.Database.Exec(`
UPDATE server_device_keys SET created_at='fixture',last_used_at='fixture';
CREATE TRIGGER device_clock_insert AFTER INSERT ON server_device_keys BEGIN
 UPDATE server_device_keys SET created_at='fixture',last_used_at='fixture'
 WHERE account_id=NEW.account_id AND app_id=NEW.app_id AND device_key_id=NEW.device_key_id;
END;
CREATE TRIGGER device_clock_update AFTER UPDATE ON server_device_keys BEGIN
 UPDATE server_device_keys SET last_used_at='fixture',
 revoked_at=CASE WHEN NEW.revoked_at='' THEN '' ELSE 'revoked' END
 WHERE account_id=NEW.account_id AND app_id=NEW.app_id AND device_key_id=NEW.device_key_id;
END;`); err != nil {
		t.Fatal(err)
	}
	return server, user, verifier
}

func TestZiranDeviceHTTPAgainstBaseline(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		modes := []string{"valid", "missing token", "user mismatch", "closed", "cancelled", "response panic", "other account"}
		if method == http.MethodGet {
			modes = append(modes, "empty", "list failure")
		} else {
			modes = append(modes, "normalized", "bad JSON", "wrong shape", "null", "body limit", "read failure", "invalid fields", "expired", "invalid signature", "rejected signature", "replay", "storage failure", "missing resource")
		}
		for _, mode := range modes {
			t.Run(method+"/"+mode, func(t *testing.T) {
				actual, user, actualVerifier := deviceHTTPFixture(t)
				expected, _, expectedVerifier := deviceHTTPFixture(t)
				registration := DeviceRegistrationRequest{
					AppID: "target", KeyID: "new-device", ClientID: "client-test",
					PublicKey: strings.Repeat("ab", 32), Nonce: "device-http-nonce",
					ExpiresAt: time.Now().Add(time.Minute).Unix(),
					Signature: hex.EncodeToString(bytes.Repeat([]byte{0x33}, mlDSA44SignatureSize)),
				}
				revocation := DeviceRevocationRequest{
					AppID: registration.AppID, KeyID: "device-key", Nonce: registration.Nonce,
					ExpiresAt: registration.ExpiresAt, Signature: registration.Signature,
				}
				status := http.StatusOK
				switch mode {
				case "missing token", "user mismatch", "rejected signature":
					status = http.StatusUnauthorized
				case "closed", "cancelled", "list failure", "storage failure", "missing resource":
					status = http.StatusInternalServerError
				case "bad JSON", "wrong shape", "null", "body limit", "read failure", "invalid fields", "expired", "invalid signature":
					status = http.StatusBadRequest
				case "replay":
					status = http.StatusConflict
				}
				if mode == "other account" && method == http.MethodDelete {
					status = http.StatusInternalServerError
				}
				switch mode {
				case "normalized":
					registration.AppID = "\u2003target\t"
					registration.KeyID = " new-device "
					registration.ClientID = " client-test "
					registration.PublicKey = "\t" + strings.ToUpper(registration.PublicKey) + "\u2003"
					registration.Nonce = " " + registration.Nonce + " "
					registration.Signature = "\t" + registration.Signature + " "
					revocation.AppID = "\u2003target\t"
					revocation.KeyID = " device-key "
					revocation.Nonce = registration.Nonce
					revocation.Signature = registration.Signature
				case "invalid fields":
					registration.AppID, revocation.AppID = "!", "!"
				case "expired":
					registration.ExpiresAt, revocation.ExpiresAt = 1, 1
				case "invalid signature":
					registration.Signature, revocation.Signature = "!", "!"
				case "missing resource":
					registration.AppID = "missing-app"
					revocation.KeyID = "missing-key"
				case "rejected signature":
					actualVerifier.accept, expectedVerifier.accept = false, false
				}
				payload := any(registration)
				if method == http.MethodDelete {
					payload = revocation
				}
				encoded, err := json.Marshal(payload)
				if err != nil {
					t.Fatal(err)
				}
				switch mode {
				case "bad JSON":
					encoded = []byte("{")
				case "wrong shape":
					encoded = []byte("[]")
				case "null":
					encoded = []byte("null")
				}
				panicValue := errors.New("device HTTP writer panicked")
				var responses []*httptest.ResponseRecorder
				var closeCounts []int
				for index, server := range []*Server{actual, expected} {
					account := user
					query := ""
					switch mode {
					case "empty":
						query = "DELETE FROM server_device_keys"
					case "list failure":
						query = "DROP TABLE server_device_keys"
					case "storage failure":
						if method == http.MethodPost {
							query = "CREATE TRIGGER reject_device_http BEFORE INSERT ON server_device_keys BEGIN SELECT RAISE(ABORT,'device rejected'); END"
						} else {
							query = "CREATE TRIGGER reject_device_http BEFORE UPDATE ON server_device_keys BEGIN SELECT RAISE(ABORT,'revocation rejected'); END"
						}
					case "replay":
						if _, err := server.Store.Database.Exec("INSERT INTO server_device_registration_nonces(account_id,nonce,created_at) VALUES(?1,?2,?3)", user, registration.Nonce, Timestamp_CanonicalNow()); err != nil {
							t.Fatal(err)
						}
					case "other account":
						account = strings.Repeat("b", 64)
						if _, err := server.Store.Database.Exec("INSERT INTO server_users(user_id_hash,public_key) VALUES(?1,?2)", account, bytes.Repeat([]byte{0x35}, mlDSA44PublicKeySize)); err != nil {
							t.Fatal(err)
						}
					}
					if query != "" {
						if _, err := server.Store.Database.Exec(query); err != nil {
							t.Fatal(err)
						}
					}
					body := &httpPortBody{Reader: bytes.NewReader(encoded)}
					if mode == "read failure" {
						body.Reader = deviceHTTPReadFailure{failure: errors.New("device body read failed")}
					}
					request := httptest.NewRequest(method, "/api/v1/account/devices", body)
					token := Token_IssueAuthToken(server.Cfg.TokenSecret, account, time.Now().Add(time.Hour).Unix()).Value
					request.Header.Set("Authorization", "Bearer "+token)
					switch mode {
					case "missing token":
						request.Header.Del("Authorization")
					case "user mismatch":
						request.Header.Set("X-Daochi-User", strings.Repeat("b", 64))
					case "body limit":
						server.Cfg.MaxBodyBytes = 1
					case "closed":
						if err := server.Store.Database.Close(); err != nil {
							t.Fatal(err)
						}
					case "cancelled":
						ctx, cancel := context.WithCancel(t.Context())
						cancel()
						request = request.WithContext(ctx)
					}
					writer := httptest.NewRecorder()
					var output http.ResponseWriter = writer
					if mode == "response panic" {
						output = &httpPortWriter{header: make(http.Header), panicValue: panicValue}
					}
					func() {
						defer func() {
							caught := recover()
							if mode == "response panic" {
								if caught != panicValue {
									t.Fatalf("device HTTP panic = %v, expected original sentinel", caught)
								}
							} else if caught != nil {
								t.Fatalf("unexpected device HTTP panic: %v", caught)
							}
						}()
						if index == 0 {
							DeviceHttp_Route(server.devices(), output, request)
						} else {
							server.baselineHandleAccountDevices(output, request)
						}
					}()
					responses = append(responses, writer)
					closeCounts = append(closeCounts, body.closed)
				}
				compareHTTPResponse(t, responses[0], responses[1])
				if mode != "response panic" && responses[0].Code != status {
					t.Fatalf("device HTTP status = %d, expected %d; body = %s", responses[0].Code, status, responses[0].Body.String())
				}
				if closeCounts[0] != closeCounts[1] || !reflect.DeepEqual(actualVerifier.calls, expectedVerifier.calls) {
					t.Fatal("device HTTP body closure or signature arguments changed")
				}
				if actual.Metrics.AuthFailures.Load() != expected.Metrics.AuthFailures.Load() || !reflect.DeepEqual(actual.Metrics.AuthFailuresBy, expected.Metrics.AuthFailuresBy) {
					t.Fatal("device HTTP authentication counters changed")
				}
				if mode != "closed" && mode != "list failure" {
					got, want := deviceSnapshot(t, actual.Store), deviceSnapshot(t, expected.Store)
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("device HTTP database state = %#v, baseline = %#v", got, want)
					}
					if mode == "other account" {
						original := DeviceKeys_Active(actual.Store.Database, t.Context(), user, "target", "device-key")
						if original.Error != nil || !original.Found {
							t.Fatal("a request from another account changed the original device", original)
						}
						if method == http.MethodGet && responses[0].Body.String() != "{\"devices\":null}\n" {
							t.Fatal("device listing exposed another account's keys", responses[0].Body.String())
						}
					}
					if method != http.MethodGet && (mode == "valid" || mode == "normalized" || mode == "response panic") {
						if len(actualVerifier.calls) != 1 {
							t.Fatal("successful device HTTP request did not verify exactly one signature")
						}
						if len(got["nonces"]) != 2 {
							t.Fatalf("successful device request did not consume its nonce: %#v", got)
						}
					}
				}
			})
		}
	}
}
