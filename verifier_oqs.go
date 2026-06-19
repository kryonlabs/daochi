//go:build cgo

package main

/*
#cgo LDFLAGS: -loqs
#include <stdlib.h>
#include <oqs/oqs.h>

static int inbe_mldsa44_verify(const unsigned char *message, size_t message_len,
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
	return C.inbe_mldsa44_verify(
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.size_t(len(message)),
		(*C.uchar)(unsafe.Pointer(&signature[0])),
		C.size_t(len(signature)),
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
	) == 1
}
