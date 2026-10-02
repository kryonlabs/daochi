/* Separate failure-injection library for original-provider/Ziran comparisons. */
#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int mode_is(const char *name) {
    const char *mode = getenv("ZIRAN_OQS_MODE");
    return mode && strcmp(mode, name) == 0;
}

static void trace(const char *operation) {
    const char *path = getenv("ZIRAN_OQS_TRACE");
    if (!path) {
        return;
    }
    FILE *file = fopen(path, "a");
    if (!file) {
        abort();
    }
    fprintf(file, "%s\n", operation);
    if (fclose(file)) {
        abort();
    }
}

OQS_SIG *OQS_SIG_new(const char *algorithm) {
    trace("new");
    if (strcmp(algorithm, OQS_SIG_alg_ml_dsa_44)) {
        abort();
    }
    if (mode_is("allocation_failure")) {
        return NULL;
    }
    OQS_SIG *signature = calloc(1, sizeof(*signature));
    if (!signature) {
        abort();
    }
    signature->length_public_key = mode_is("public_key_size") ? 1311 : 1312;
    signature->length_secret_key = mode_is("private_key_size") ? 2559 : 2560;
    signature->length_signature = mode_is("signature_large") ? 2421 :
        mode_is("signature_small") ? 2419 : 2420;
    return signature;
}

void OQS_SIG_free(OQS_SIG *signature) {
    trace("free");
    if (!signature) {
        abort();
    }
    free(signature);
}

OQS_STATUS OQS_SIG_keypair(const OQS_SIG *signature, uint8_t *public_key,
                          uint8_t *private_key) {
    trace("keypair");
    if (!signature || !public_key || !private_key) {
        abort();
    }
    memset(public_key, 44, 1312);
    memset(private_key, 33, 2560);
    return mode_is("keypair_failure") ? OQS_ERROR : OQS_SUCCESS;
}

OQS_STATUS OQS_SIG_sign(const OQS_SIG *signature, uint8_t *output,
                       size_t *output_length, const uint8_t *message,
                       size_t message_length, const uint8_t *private_key) {
    trace("sign");
    if (!signature || !output || !output_length || *output_length != 2420 ||
        !message || message_length != 257 || message[0] != 17 ||
        !private_key || private_key[0] != 33) {
        abort();
    }
    memset(output, 55, 2420);
    *output_length = mode_is("signature_length") ? 2419 : 2420;
    return mode_is("sign_failure") ? OQS_ERROR : OQS_SUCCESS;
}

OQS_STATUS OQS_SIG_verify(const OQS_SIG *signature, const uint8_t *message,
                         size_t message_length, const uint8_t *input,
                         size_t input_length, const uint8_t *public_key) {
    trace("verify");
    if (!signature || !message || message_length != 257 || message[0] != 17 ||
        !input || input_length != 2420 || input[0] != 55 ||
        !public_key || public_key[0] != 44) {
        abort();
    }
    return mode_is("verify_failure") ? OQS_ERROR : OQS_SUCCESS;
}
