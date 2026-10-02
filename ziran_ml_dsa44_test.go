package main

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
)

type cryptoRequest struct {
	Operation  string
	PublicKey  []byte
	PrivateKey []byte
	Message    []byte
	Signature  []byte
}

type cryptoResponse struct {
	Available    bool
	Verified     bool
	Signature    []byte
	PublicKey    []byte
	PrivateKey   []byte
	Error        string
	ErrorIsExact bool
}

func cryptoEnvironment(t *testing.T) []string {
	t.Helper()
	environment := make([]string, 0, len(os.Environ()))
	for _, value := range os.Environ() {
		name, _, _ := bytes.Cut([]byte(value), []byte("="))
		if string(name) != "DISPLAY" && string(name) != "WAYLAND_DISPLAY" {
			environment = append(environment, value)
		}
	}
	return environment
}

func buildCryptoBaseline(t *testing.T, cgo string, extraEnvironment ...string) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "original-provider")
	command := exec.Command("go", "build", "-o", binary, "./testdata/ml_dsa44")
	command.Env = append(cryptoEnvironment(t), "GOFLAGS=-mod=mod", "CGO_ENABLED="+cgo)
	command.Env = append(command.Env, extraEnvironment...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build independent provider: %v\n%s", err, output)
	}
	return binary
}

func runCryptoBaseline(t *testing.T, binary string, inputs []cryptoRequest, extraEnvironment ...string) []cryptoResponse {
	t.Helper()
	encoded, err := json.Marshal(inputs)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary)
	command.Env = append(cryptoEnvironment(t), extraEnvironment...)
	command.Stdin = bytes.NewReader(encoded)
	var diagnostics bytes.Buffer
	command.Stderr = &diagnostics
	output, err := command.Output()
	if err != nil {
		t.Fatalf("original provider: %v\n%s", err, &diagnostics)
	}
	var results []cryptoResponse
	if err := json.Unmarshal(output, &results); err != nil {
		t.Fatalf("original provider output: %v", err)
	}
	if len(results) != len(inputs) {
		t.Fatalf("provider returned %d results for %d inputs", len(results), len(inputs))
	}
	return results
}

func runZiranCrypto(input cryptoRequest) cryptoResponse {
	var output cryptoResponse
	var err error
	switch input.Operation {
	case "new":
		result := MlDsa44_New()
		output.Available = result.Value != nil && result.Value.Verify != nil
		err = result.Error
	case "verify":
		output.Verified = MlDsa44_Verify(input.PublicKey, input.Message, input.Signature)
	case "sign":
		result := MlDsa44_Sign(input.Message, input.PrivateKey)
		output.Signature = result.Value
		err = result.Error
	case "keypair":
		result := MlDsa44_KeyPair()
		output.PublicKey, output.PrivateKey = result.PublicKey, result.PrivateKey
		err = result.Error
	default:
		panic("unknown crypto operation")
	}
	if err != nil {
		output.Error = err.Error()
		output.ErrorIsExact = err == ErrVerifierUnavailable
	}
	return output
}

func TestZiranMLDSA44NativeCompatibility(t *testing.T) {
	if !MlDsa44_NativeAvailable() {
		t.Skip("requires liboqs")
	}
	baseline := buildCryptoBaseline(t, "1")
	pair := runCryptoBaseline(t, baseline, []cryptoRequest{{Operation: "keypair"}})[0]
	if pair.Error != "" || len(pair.PublicKey) != mlDSA44PublicKeySize || len(pair.PrivateKey) != mlDSA44PrivateKeySize {
		t.Fatal("original provider keypair failed")
	}
	generated := MlDsa44_KeyPair()
	if generated.Error != nil || len(generated.PublicKey) != mlDSA44PublicKeySize || len(generated.PrivateKey) != mlDSA44PrivateKeySize {
		t.Fatal("Ziran keypair failed")
	}
	verifier := MlDsa44_New()
	if verifier.Error != nil || verifier.Value == nil || verifier.Value.Verify == nil {
		t.Fatal("Ziran verifier creation failed")
	}
	random := rand.New(rand.NewSource(441312))
	for _, length := range []int{1, 2, 31, 255, 4096, 65536} {
		t.Run(strconv.Itoa(length), func(t *testing.T) {
			message := make([]byte, length)
			_, _ = random.Read(message)
			originalMessage, originalKey := bytes.Clone(message), bytes.Clone(pair.PrivateKey)
			signed := MlDsa44_Sign(message, pair.PrivateKey)
			if signed.Error != nil || len(signed.Value) != mlDSA44SignatureSize {
				t.Fatal("Ziran signing failed")
			}
			if !bytes.Equal(message, originalMessage) || !bytes.Equal(pair.PrivateKey, originalKey) {
				t.Fatal("signing changed caller input")
			}
			inputs := []cryptoRequest{
				{Operation: "verify", PublicKey: pair.PublicKey, Message: message, Signature: signed.Value},
				{Operation: "sign", PrivateKey: generated.PrivateKey, Message: message},
			}
			results := runCryptoBaseline(t, baseline, inputs)
			if !results[0].Verified || results[1].Error != "" || len(results[1].Signature) != mlDSA44SignatureSize {
				t.Fatal("original provider rejected Ziran output")
			}
			if !MlDsa44_Verify(generated.PublicKey, message, results[1].Signature) ||
				!verifier.Value.Verify(generated.PublicKey, message, results[1].Signature) {
				t.Fatal("Ziran rejected original provider output")
			}
			altered := bytes.Clone(signed.Value)
			altered[len(altered)/2] ^= 1
			checks := []cryptoRequest{
				{Operation: "verify", PublicKey: pair.PublicKey, Message: message, Signature: altered},
				{Operation: "verify", PublicKey: generated.PublicKey, Message: message, Signature: signed.Value},
			}
			for index, expected := range runCryptoBaseline(t, baseline, checks) {
				if actual := runZiranCrypto(checks[index]); !reflect.DeepEqual(actual, expected) || actual.Verified {
					t.Fatal("tampered or different-account signature accepted")
				}
			}
		})
	}
	inputs := []cryptoRequest{{Operation: "new"}}
	for _, length := range []int{0, 1, mlDSA44PrivateKeySize - 1, mlDSA44PrivateKeySize + 1} {
		inputs = append(inputs, cryptoRequest{Operation: "sign", Message: []byte{1}, PrivateKey: make([]byte, length)})
	}
	inputs = append(inputs, cryptoRequest{Operation: "sign", PrivateKey: pair.PrivateKey})
	inputs = append(inputs, cryptoRequest{Operation: "sign", Message: []byte{}, PrivateKey: pair.PrivateKey})
	for _, length := range []int{0, 1, mlDSA44PublicKeySize - 1, mlDSA44PublicKeySize + 1} {
		inputs = append(inputs, cryptoRequest{Operation: "verify", PublicKey: make([]byte, length), Message: []byte{1}, Signature: make([]byte, mlDSA44SignatureSize)})
	}
	for _, length := range []int{0, 1, mlDSA44SignatureSize - 1, mlDSA44SignatureSize + 1} {
		inputs = append(inputs, cryptoRequest{Operation: "verify", PublicKey: pair.PublicKey, Message: []byte{1}, Signature: make([]byte, length)})
	}
	inputs = append(inputs, cryptoRequest{Operation: "verify", PublicKey: pair.PublicKey, Signature: make([]byte, mlDSA44SignatureSize)})
	for index, expected := range runCryptoBaseline(t, baseline, inputs) {
		if actual := runZiranCrypto(inputs[index]); !reflect.DeepEqual(actual, expected) {
			t.Fatalf("validation case %d differs: actual=%+v expected=%+v", index, actual, expected)
		}
	}
}

func buildCryptoProcess(t *testing.T, extraEnvironment ...string) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "ziran-provider-tests")
	command := exec.Command("go", "test", "-c", "-o", binary, ".")
	command.Env = append(cryptoEnvironment(t), "GOFLAGS=-mod=mod")
	command.Env = append(command.Env, extraEnvironment...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build provider process: %v\n%s", err, output)
	}
	return binary
}

func runCryptoProcess(t *testing.T, binary string, inputs []cryptoRequest, extraEnvironment ...string) []cryptoResponse {
	t.Helper()
	encoded, err := json.Marshal(inputs)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "-test.run=^TestZiranMLDSA44ProviderProcess$")
	command.Env = append(cryptoEnvironment(t), "ZIRAN_CRYPTO_PROVIDER_PROCESS=1")
	command.Env = append(command.Env, extraEnvironment...)
	command.Stdin = bytes.NewReader(encoded)
	var diagnostics bytes.Buffer
	command.Stderr = &diagnostics
	output, err := command.Output()
	if err != nil {
		t.Fatalf("Ziran provider process: %v\n%s", err, &diagnostics)
	}
	var results []cryptoResponse
	if err := json.Unmarshal(output, &results); err != nil {
		t.Fatalf("Ziran provider output: %v", err)
	}
	return results
}

func TestZiranMLDSA44ProviderProcess(t *testing.T) {
	if os.Getenv("ZIRAN_CRYPTO_PROVIDER_PROCESS") != "1" {
		t.Skip("isolated provider process")
	}
	var inputs []cryptoRequest
	if err := json.NewDecoder(os.Stdin).Decode(&inputs); err != nil {
		t.Fatal(err)
	}
	outputs := make([]cryptoResponse, len(inputs))
	for index, input := range inputs {
		outputs[index] = runZiranCrypto(input)
	}
	if err := json.NewEncoder(os.Stdout).Encode(outputs); err != nil {
		t.Fatal(err)
	}
	os.Exit(0)
}

func TestZiranMLDSA44NoCGO(t *testing.T) {
	baseline := buildCryptoBaseline(t, "0")
	provider := buildCryptoProcess(t, "CGO_ENABLED=0")
	inputs := []cryptoRequest{
		{Operation: "new"},
		{Operation: "keypair"},
		{Operation: "sign", Message: []byte{17}, PrivateKey: make([]byte, mlDSA44PrivateKeySize)},
		{Operation: "sign"},
	}
	expected := runCryptoBaseline(t, baseline, inputs)
	actual := runCryptoProcess(t, provider, inputs)
	if !reflect.DeepEqual(actual, expected) {
		t.Fatal("no-cgo availability, nil results or native error identity changed")
	}
	for _, result := range actual {
		if result.Available || result.Error != ErrVerifierUnavailable.Error() || !result.ErrorIsExact {
			t.Fatal("no-cgo path did not return the original unavailable error")
		}
	}
}

func TestZiranMLDSA44LibraryFailures(t *testing.T) {
	if !MlDsa44_NativeAvailable() {
		t.Skip("requires C header definitions")
	}
	library := t.TempDir()
	include, err := filepath.Abs("build/liboqs/install/include")
	if err != nil {
		t.Fatal(err)
	}
	object := filepath.Join(library, "stub.o")
	command := exec.Command("cc", "-I"+include, "-c", "testdata/ml_dsa44_stub/stub.c", "-o", object)
	command.Env = cryptoEnvironment(t)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile failure-injection library: %v\n%s", err, output)
	}
	command = exec.Command("ar", "rcs", filepath.Join(library, "liboqs.a"), object)
	command.Env = cryptoEnvironment(t)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("archive failure-injection library: %v\n%s", err, output)
	}
	link := "CGO_LDFLAGS=-L" + library + " -loqs"
	baseline := buildCryptoBaseline(t, "1", link)
	provider := buildCryptoProcess(t, "CGO_ENABLED=1", link)
	valid := cryptoRequest{
		Operation:  "verify",
		PublicKey:  bytes.Repeat([]byte{44}, mlDSA44PublicKeySize),
		PrivateKey: bytes.Repeat([]byte{33}, mlDSA44PrivateKeySize),
		Message:    bytes.Repeat([]byte{17}, 257),
		Signature:  bytes.Repeat([]byte{55}, mlDSA44SignatureSize),
	}
	sign := valid
	sign.Operation = "sign"
	inputs := []cryptoRequest{{Operation: "new"}, {Operation: "keypair"}, sign, valid}
	invalidSign := sign
	invalidSign.PrivateKey = invalidSign.PrivateKey[:mlDSA44PrivateKeySize-1]
	invalidMessage := sign
	invalidMessage.Message = nil
	invalidPublicKey := valid
	invalidPublicKey.PublicKey = valid.PublicKey[:mlDSA44PublicKeySize-1]
	invalidSignature := valid
	invalidSignature.Signature = valid.Signature[:mlDSA44SignatureSize-1]
	inputs = append(inputs, invalidSign, invalidMessage, invalidPublicKey, invalidSignature)
	for _, mode := range []string{
		"success", "allocation_failure", "public_key_size", "private_key_size",
		"signature_large", "signature_small", "sign_failure", "signature_length",
		"verify_failure", "keypair_failure",
	} {
		t.Run(mode, func(t *testing.T) {
			originalTrace := filepath.Join(t.TempDir(), "original.trace")
			ziranTrace := filepath.Join(t.TempDir(), "ziran.trace")
			environment := "ZIRAN_OQS_MODE=" + mode
			expected := runCryptoBaseline(t, baseline, inputs, environment, "ZIRAN_OQS_TRACE="+originalTrace)
			actual := runCryptoProcess(t, provider, inputs, environment, "ZIRAN_OQS_TRACE="+ziranTrace)
			if !reflect.DeepEqual(actual, expected) {
				t.Fatal("C library failure changed result bytes, nil values or error identity")
			}
			original, err := os.ReadFile(originalTrace)
			if err != nil {
				t.Fatal(err)
			}
			generated, err := os.ReadFile(ziranTrace)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(original, generated) {
				t.Fatalf("native allocation, calls or cleanup changed:\noriginal: %s\nZiran: %s", original, generated)
			}
		})
	}
}
