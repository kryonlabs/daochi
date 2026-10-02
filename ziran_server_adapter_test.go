package main

// Native test fixtures retain their original verifier implementations.
func testVerifier(value any) *Verifier {
	if value == nil {
		return nil
	}
	if verifier, ok := value.(*Verifier); ok {
		return verifier
	}
	return Verifier_New(value.(baselineVerifier).Verify)
}

func NewServer(configuration Config, store *Store, verifier any) *Server {
	return Server_New(configuration, store, testVerifier(verifier), signAccountProof)
}
