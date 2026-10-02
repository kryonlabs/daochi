// Released binary decoder extracted before its canonical test migration.
package binary_field_oracle

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

// This oracle preserves the removed Go implementation, including its order
// of encodings, Unicode trimming, and intentionally non-strict base64 bits.
func referenceBinaryField(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("empty binary field")
	}
	if len(value)%2 == 0 {
		if decoded, err := hex.DecodeString(value); err == nil {
			return decoded, nil
		}
	}
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding,
	} {
		if decoded, err := encoding.DecodeString(value); err == nil {
			return decoded, nil
		}
	}
	return nil, errors.New("field is neither hex nor base64")
}

// Decode exposes the unchanged reference result without sharing Daochi code.
func Decode(input string) (string, string) {
	value, err := referenceBinaryField(input)
	if err != nil {
		return "", err.Error()
	}
	return string(value), ""
}

// DecodeBytes retains the released byte/error contract for other Go fixtures.
func DecodeBytes(input string) ([]byte, error) {
	return referenceBinaryField(input)
}
