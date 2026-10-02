// Released token oracle extracted from ziran_port_test.go before test migration.
package token_oracle

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"strconv"
	"strings"
)

type AuthTokenResult struct {
	Value string
	Error string
}

func referenceToken(secret []byte, payload string) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func referenceVerifyToken(secret []byte, token string, now int64) AuthTokenResult {
	parts := strings.Split(token, ".")
	if len(parts) != 2 || len(secret) == 0 {
		return AuthTokenResult{Error: "invalid token"}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return AuthTokenResult{Error: "invalid token payload"}
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return AuthTokenResult{Error: "invalid token signature"}
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return AuthTokenResult{Error: "invalid token signature"}
	}
	fields := strings.Split(string(payload), "\n")
	if len(fields) < 4 || fields[0] != "v1" ||
		!regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(fields[1]) {
		return AuthTokenResult{Error: "invalid token payload"}
	}
	expires, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || now > expires {
		return AuthTokenResult{Error: "token expired"}
	}
	return AuthTokenResult{Value: fields[1]}
}

// Issue exposes the unchanged reference implementation to canonical tests.
func Issue(secret []byte, payload string) string {
	return referenceToken(secret, payload)
}

// Verify exposes the unchanged result fields through native multiple results.
func Verify(secret []byte, token string, now int64) (string, string) {
	result := referenceVerifyToken(secret, token, now)
	return result.Value, result.Error
}
