package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// Exercise the shipped wire formats with real ML-DSA keys, not the permissive
// recording verifier used by request-shape tests.
func TestReleasedClientRealKeyLoginAndSync(t *testing.T) {
	for _, format := range []struct{ header, context string }{
		{"X-Inbe", "inbe-sync-v1"},
		{"X-Ksync", "ksync-sync-v1"},
		{"X-Daochi", "daochi-sync-v1"},
	} {
		t.Run(format.header, func(t *testing.T) {
			server, _, _ := testServer(t)
			server.verifier = OQSVerifier{}
			handler := server.Routes()
			publicKey, privateKey, err := generateMLDSA44Keypair()
			if err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(publicKey)
			userID := hex.EncodeToString(hash[:])
			body, err := json.Marshal(LoginRequest{UserIDHash: userID, PublicKey: hex.EncodeToString(publicKey), ClientID: "released-client"})
			if err != nil {
				t.Fatal(err)
			}
			for _, valid := range []bool{false, true} {
				nonce := issueChallenge(t, handler, "", userID)
				message := canonicalMessageWithContext(format.context, mustDecodeHex(t, nonce), http.MethodPost, "/api/v1/sync/login", body)
				signature, err := signWithPrivateKey(message, privateKey)
				if err != nil {
					t.Fatal(err)
				}
				if !valid {
					signature[0] ^= 1
				}
				request := httptest.NewRequest(http.MethodPost, "/api/v1/sync/login", bytes.NewReader(body))
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set(format.header+"-User", userID)
				request.Header.Set(format.header+"-Signature", hex.EncodeToString(signature))
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if !valid {
					if response.Code != http.StatusUnauthorized {
						t.Fatalf("invalid signature status = %d", response.Code)
					}
					continue
				}
				if response.Code != http.StatusOK {
					t.Fatalf("login status = %d: %s", response.Code, response.Body.String())
				}
				var login LoginResponse
				if err := json.Unmarshal(response.Body.Bytes(), &login); err != nil {
					t.Fatal(err)
				}
				for protocol := minSupportedProtocol; protocol <= 5; protocol++ {
					payload := []byte(`{"protocol_version":` + strconv.Itoa(protocol) + `,"user_id_hash":"` + userID + `","client_id":"released-client"}`)
					result := syncWithBody(t, handler, "", userID, login.AuthToken, payload)
					var synced SyncResponse
					if err := json.Unmarshal(result.Body.Bytes(), &synced); err != nil {
						t.Fatal(err)
					}
					if synced.LatestProtocol > protocol || synced.UpgradeNotice != "" {
						t.Fatalf("released protocol %d received an upgrade warning", protocol)
					}
				}
			}
		})
	}
}
