#ifndef ECC_H
#define ECC_H
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/*
 * get_shared_keys_hkdf(): performs ONE ECDH exchange (EC P-256 keygen x2 +
 * ECDH derive), then HKDF-Expands the resulting shared secret into n_keys
 * independent keys — one per cascade layer. The expensive elliptic-curve
 * work happens exactly once regardless of n_keys; each additional key only
 * costs one cheap HKDF-Expand (HMAC-SHA256) call.
 *
 * out_keys[i]   : destination buffer for key i
 * key_sizes[i]  : desired length in bytes for key i
 * n_keys        : how many independent keys to derive (1, 2, 3, ...)
 *
 * Returns 1 on success, 0 on failure.
 */
static inline int get_shared_keys_hkdf(uint8_t *out_keys[], const int key_sizes[], int n_keys) {
    int ret = 0;
    EVP_PKEY_CTX *kctx = NULL, *dctx = NULL;
    EVP_PKEY *key_a = NULL, *key_b = NULL;
    uint8_t *secret = NULL;
    size_t secret_len = 0;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx_hkdf = NULL;
    char info_label[16];

    /* Generate both local EC keypairs (P-256) */
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

    /* ONE ECDH derive */
    dctx = EVP_PKEY_CTX_new(key_a, NULL);
    if (!dctx) goto cleanup;
    if (EVP_PKEY_derive_init(dctx) <= 0) goto cleanup;
    if (EVP_PKEY_derive_set_peer(dctx, key_b) <= 0) goto cleanup;
    if (EVP_PKEY_derive(dctx, NULL, &secret_len) <= 0) goto cleanup;
    secret = (uint8_t *)malloc(secret_len);
    if (!secret) goto cleanup;
    if (EVP_PKEY_derive(dctx, secret, &secret_len) <= 0) goto cleanup;

    /* HKDF-Expand once per requested key, distinct info label each time */
    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) goto cleanup;

    for (int i = 0; i < n_keys; i++) {
        snprintf(info_label, sizeof(info_label), "stage%d-key", i + 1);
        kctx_hkdf = EVP_KDF_CTX_new(kdf);
        if (!kctx_hkdf) goto cleanup;

        OSSL_PARAM params[4], *p = params;
        *p++ = OSSL_PARAM_construct_utf8_string("digest", (char *)"sha256", 6);
        *p++ = OSSL_PARAM_construct_octet_string("key", secret, secret_len);
        *p++ = OSSL_PARAM_construct_octet_string("info", (void *)info_label, strlen(info_label));
        *p = OSSL_PARAM_construct_end();

        if (EVP_KDF_CTX_set_params(kctx_hkdf, params) <= 0) goto cleanup;
        if (EVP_KDF_derive(kctx_hkdf, out_keys[i], key_sizes[i], NULL) <= 0) goto cleanup;

        EVP_KDF_CTX_free(kctx_hkdf); kctx_hkdf = NULL;
    }

    ret = 1;

cleanup:
    if (secret) { memset(secret, 0, secret_len); free(secret); }
    if (kctx_hkdf) EVP_KDF_CTX_free(kctx_hkdf);
    if (kdf) EVP_KDF_free(kdf);
    if (dctx) EVP_PKEY_CTX_free(dctx);
    if (kctx) EVP_PKEY_CTX_free(kctx);
    if (key_a) EVP_PKEY_free(key_a);
    if (key_b) EVP_PKEY_free(key_b);
    return ret;
}

#endif
