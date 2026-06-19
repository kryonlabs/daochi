package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

const (
	mlDSA44PublicKeySize  = 1312
	mlDSA44PrivateKeySize = 2560
	mlDSA44SignatureSize  = 2420
)

func decodeBinaryField(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("empty binary field")
	}
	if isHex(value) && len(value)%2 == 0 {
		out, err := hex.DecodeString(value)
		if err == nil {
			return out, nil
		}
	}
	if out, err := base64.StdEncoding.DecodeString(value); err == nil {
		return out, nil
	}
	if out, err := base64.RawStdEncoding.DecodeString(value); err == nil {
		return out, nil
	}
	if out, err := base64.URLEncoding.DecodeString(value); err == nil {
		return out, nil
	}
	return nil, errors.New("field is neither hex nor base64")
}

func isHex(value string) bool {
	for _, c := range value {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			continue
		}
		return false
	}
	return true
}
