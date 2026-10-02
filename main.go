package main

func main() {
	Startup_Main(createVerifier, signAccountProof)
}

func createVerifier() VerifierResult {
	verifier, err := NewVerifier()
	return VerifierResult{Value: verifier, Error: err}
}
