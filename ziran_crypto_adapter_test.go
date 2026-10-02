package main

type OQSVerifier struct{}

func (OQSVerifier) Verify(publicKey, message, signature []byte) bool {
	return MlDsa44_Verify(publicKey, message, signature)
}

func NewVerifier() (*Verifier, error) {
	result := MlDsa44_New()
	return result.Value, result.Error
}

func createVerifier() VerifierResult {
	return MlDsa44_New()
}

func signAccountProof(message, privateKey []byte) PrivateKeySignatureResult {
	return MlDsa44_Sign(message, privateKey)
}

func signWithPrivateKey(message, privateKey []byte) ([]byte, error) {
	result := MlDsa44_Sign(message, privateKey)
	return result.Value, result.Error
}

func generateMLDSA44Keypair() ([]byte, []byte, error) {
	result := MlDsa44_KeyPair()
	return result.PublicKey, result.PrivateKey, result.Error
}
