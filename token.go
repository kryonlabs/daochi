package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"
)

func issueAuthToken(secret []byte, userID string, ttl time.Duration) (string, error) {
	if len(secret) == 0 || !validUserID(userID) {
		return "", errors.New("invalid token input")
	}
	expiresAt := time.Now().Add(ttl).Unix()
	payload := "v1\n" + userID + "\n" + strconv.FormatInt(expiresAt, 10) + "\n"
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func verifyAuthToken(secret []byte, token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 || len(secret) == 0 {
		return "", errors.New("invalid token")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", errors.New("invalid token payload")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("invalid token signature")
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(payloadBytes)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return "", errors.New("invalid token signature")
	}
	fields := strings.Split(string(payloadBytes), "\n")
	if len(fields) < 4 || fields[0] != "v1" || !validUserID(fields[1]) {
		return "", errors.New("invalid token payload")
	}
	expiresAt, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || time.Now().Unix() > expiresAt {
		return "", errors.New("token expired")
	}
	return fields[1], nil
}
