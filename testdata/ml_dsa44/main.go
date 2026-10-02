// Independent original Go/C provider used only for port comparisons.
package main

import (
	"encoding/json"
	"errors"
	"os"
)

const (
	mlDSA44PublicKeySize  = 1312
	mlDSA44PrivateKeySize = 2560
	mlDSA44SignatureSize  = 2420
)

var ErrVerifierUnavailable = errors.New("ML-DSA-44 verifier unavailable")

type Verifier struct {
	verify func([]byte, []byte, []byte) bool
}

func Verifier_New(verify func([]byte, []byte, []byte) bool) *Verifier {
	return &Verifier{verify: verify}
}

type request struct {
	Operation  string
	PublicKey  []byte
	PrivateKey []byte
	Message    []byte
	Signature  []byte
}

type response struct {
	Available    bool
	Verified     bool
	Signature    []byte
	PublicKey    []byte
	PrivateKey   []byte
	Error        string
	ErrorIsExact bool
}

func main() {
	var inputs []request
	if err := json.NewDecoder(os.Stdin).Decode(&inputs); err != nil {
		panic(err)
	}
	outputs := make([]response, len(inputs))
	for index, input := range inputs {
		output := &outputs[index]
		var err error
		switch input.Operation {
		case "new":
			var verifier *Verifier
			verifier, err = NewVerifier()
			output.Available = verifier != nil && verifier.verify != nil
		case "verify":
			var verifier *Verifier
			verifier, err = NewVerifier()
			if err == nil {
				output.Verified = verifier.verify(input.PublicKey, input.Message, input.Signature)
			}
		case "sign":
			output.Signature, err = signWithPrivateKey(input.Message, input.PrivateKey)
		case "keypair":
			output.PublicKey, output.PrivateKey, err = generateMLDSA44Keypair()
		default:
			panic("unknown provider operation")
		}
		if err != nil {
			output.Error = err.Error()
			output.ErrorIsExact = err == ErrVerifierUnavailable
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(outputs); err != nil {
		panic(err)
	}
}
