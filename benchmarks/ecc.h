#ifndef ECC_H
#define ECC_H
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/sha.h>

static inline int get_shared_key(uint8_t *out, int key_size) {
    int           ret        = 0;
    EVP_PKEY_CTX *kctx       = NULL;
    EVP_PKEY_CTX *dctx       = NULL;
    EVP_PKEY     *key_a      = NULL;
    EVP_PKEY     *key_b      = NULL;
    uint8_t      *secret     = NULL;
    size_t        secret_len = 0;
    uint8_t       hash[SHA256_DIGEST_LENGTH];

    kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!kctx) goto cleanup;
    if (EVP_PKEY_keygen_init(kctx) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, NID_X9_62_prime256v1) <= 0) goto cleanup;
    if (EVP_PKEY_keygen(kctx, &key_a) <= 0) goto cleanup;
    EVP_PKEY_CTX_free(kctx); kctx = NULL;

    kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!kctx) goto cleanup;
    if (EVP_PKEY_keygen_init(kctx) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, NID_X9_62_prime256v1) <= 0) goto cleanup;
    if (EVP_PKEY_keygen(kctx, &key_b) <= 0) goto cleanup;
    EVP_PKEY_CTX_free(kctx); kctx = NULL;

    dctx = EVP_PKEY_CTX_new(key_a, NULL);
    if (!dctx) goto cleanup;
    if (EVP_PKEY_derive_init(dctx) <= 0) goto cleanup;
    if (EVP_PKEY_derive_set_peer(dctx, key_b) <= 0) goto cleanup;
    if (EVP_PKEY_derive(dctx, NULL, &secret_len) <= 0) goto cleanup;
    secret = (uint8_t *)malloc(secret_len);
    if (!secret) goto cleanup;
    if (EVP_PKEY_derive(dctx, secret, &secret_len) <= 0) goto cleanup;

    SHA256(secret, secret_len, hash);

    if (key_size > SHA256_DIGEST_LENGTH) key_size = SHA256_DIGEST_LENGTH;
    memcpy(out, hash, key_size);
    ret = 1;

cleanup:
    if (secret) { memset(secret, 0, secret_len); free(secret); }
    if (dctx)   EVP_PKEY_CTX_free(dctx);
    if (kctx)   EVP_PKEY_CTX_free(kctx);
    if (key_a)  EVP_PKEY_free(key_a);
    if (key_b)  EVP_PKEY_free(key_b);
    return ret;
}

#endif