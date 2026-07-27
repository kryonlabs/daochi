//go:build cgo

package main

/*
#cgo LDFLAGS: -loqs
#include <stdlib.h>
#include <oqs/oqs.h>

static int ksync_mldsa44_verify(const unsigned char *message, size_t message_len,
	const unsigned char *signature, size_t signature_len,
	const unsigned char *public_key) {
	OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
	int ok = 0;
	if (sig == NULL) {
		return 0;
	}
	if (sig->length_public_key == 1312 && sig->length_signature == signature_len) {
		ok = OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key) == OQS_SUCCESS;
	}
	OQS_SIG_free(sig);
	return ok;
}

static int ksync_mldsa44_sign(const unsigned char *message, size_t message_len,
	const unsigned char *private_key,
	unsigned char *signature, size_t *signature_len) {
	OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
	int ok = 0;
	if (sig == NULL) {
		return 0;
	}
	if (sig->length_secret_key == 2560 && sig->length_signature <= *signature_len) {
		ok = OQS_SIG_sign(sig, signature, signature_len, message, message_len, private_key) == OQS_SUCCESS;
	}
	OQS_SIG_free(sig);
	return ok;
}

static int ksync_mldsa44_keypair(unsigned char *public_key, unsigned char *private_key) {
	OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
	int ok = 0;
	if (sig == NULL) {
		return 0;
	}
	if (sig->length_public_key == 1312 && sig->length_secret_key == 2560) {
		ok = OQS_SIG_keypair(sig, public_key, private_key) == OQS_SUCCESS;
	}
	OQS_SIG_free(sig);
	return ok;
}
*/
import "C"
import "unsafe"

type OQSVerifier struct{}

func NewVerifier() (Verifier, error) {
	return OQSVerifier{}, nil
}

func (OQSVerifier) Verify(publicKey, message, signature []byte) bool {
	if len(publicKey) != mlDSA44PublicKeySize || len(signature) != mlDSA44SignatureSize || len(message) == 0 {
		return false
	}
	return C.ksync_mldsa44_verify(
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.size_t(len(message)),
		(*C.uchar)(unsafe.Pointer(&signature[0])),
		C.size_t(len(signature)),
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
	) == 1
}

func signWithPrivateKey(message, privateKey []byte) ([]byte, error) {
	if len(privateKey) != mlDSA44PrivateKeySize || len(message) == 0 {
		return nil, ErrVerifierUnavailable
	}
	signature := make([]byte, mlDSA44SignatureSize)
	signatureLen := C.size_t(len(signature))
	ok := C.ksync_mldsa44_sign(
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.size_t(len(message)),
		(*C.uchar)(unsafe.Pointer(&privateKey[0])),
		(*C.uchar)(unsafe.Pointer(&signature[0])),
		&signatureLen,
	) == 1
	if !ok || int(signatureLen) != mlDSA44SignatureSize {
		return nil, ErrVerifierUnavailable
	}
	return signature[:signatureLen], nil
}

func generateMLDSA44Keypair() ([]byte, []byte, error) {
	publicKey := make([]byte, mlDSA44PublicKeySize)
	privateKey := make([]byte, mlDSA44PrivateKeySize)
	ok := C.ksync_mldsa44_keypair(
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
		(*C.uchar)(unsafe.Pointer(&privateKey[0])),
	) == 1
	if !ok {
		return nil, nil, ErrVerifierUnavailable
	}
	return publicKey, privateKey, nil
}
