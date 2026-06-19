//go:build !cgo

package main

func NewVerifier() (Verifier, error) {
	return nil, ErrVerifierUnavailable
}

func signWithPrivateKey(message, privateKey []byte) ([]byte, error) {
	return nil, ErrVerifierUnavailable
}

func generateMLDSA44Keypair() ([]byte, []byte, error) {
	return nil, nil, ErrVerifierUnavailable
}
