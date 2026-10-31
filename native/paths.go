package native

import (
	"errors"
	"path/filepath"
	"strings"
)

// PathComponent returns the canonical component used for on-disk addressing.
// Reject normalization changes so two protocol identities never alias one path.
func PathComponent(value string) (string, error) {
	cleaned := strings.TrimPrefix(filepath.Clean("/"+value), "/")
	if cleaned != value || value == "." || !filepath.IsLocal(value) || strings.ContainsAny(value, `/\`) || strings.ContainsRune(value, 0) {
		return "", errors.New("invalid filesystem component")
	}
	return cleaned, nil
}
