package main

import "errors"

type Verifier interface {
	Verify(publicKey, message, signature []byte) bool
}

var ErrVerifierUnavailable = errors.New("ML-DSA-44 verifier unavailable")

func signAccountProof(message, privateKey []byte) PrivateKeySignatureResult {
	value, err := signWithPrivateKey(message, privateKey)
	return PrivateKeySignatureResult{Value: value, Error: err}
}
