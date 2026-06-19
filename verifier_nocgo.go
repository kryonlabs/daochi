//go:build !cgo

package main

func NewVerifier() (Verifier, error) {
	return nil, ErrVerifierUnavailable
}
