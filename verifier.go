package main

import "errors"

type Verifier interface {
	Verify(publicKey, message, signature []byte) bool
}

var ErrVerifierUnavailable = errors.New("ML-DSA-44 verifier unavailable")
