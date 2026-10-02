package main

func signAccountProof(message, privateKey []byte) PrivateKeySignatureResult {
	value, err := signWithPrivateKey(message, privateKey)
	return PrivateKeySignatureResult{Value: value, Error: err}
}
