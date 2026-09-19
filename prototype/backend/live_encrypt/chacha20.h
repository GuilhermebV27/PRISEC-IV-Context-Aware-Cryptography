#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define CC20_NONCE_SIZE  12
#define CC20_TAG_SIZE    16
#define CC20_OVERHEAD    (CC20_NONCE_SIZE + CC20_TAG_SIZE)

static inline int chacha20_encrypt(const uint8_t *key, int key_len,
                                    const uint8_t *plain, size_t plain_len,
                                    uint8_t *out, size_t *out_len) {
    (void)key_len; /* ChaCha20 usa sempre 32 bytes — parâmetro ignorado */
    uint8_t nonce[CC20_NONCE_SIZE];
    uint8_t tag[CC20_TAG_SIZE];

    if (!RAND_bytes(nonce, CC20_NONCE_SIZE)) return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    int ok = 1, len = 0, final_len = 0;

    ok &= EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL);
    ok &= EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);
    ok &= EVP_EncryptUpdate(ctx, out + CC20_OVERHEAD, &len, plain, (int)plain_len);
    ok &= EVP_EncryptFinal_ex(ctx, out + CC20_OVERHEAD + len, &final_len);
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, CC20_TAG_SIZE, tag);

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return 0;

    memcpy(out, nonce, CC20_NONCE_SIZE);
    memcpy(out + CC20_NONCE_SIZE, tag, CC20_TAG_SIZE);
    *out_len = CC20_OVERHEAD + (size_t)(len + final_len);
    return 1;
}

static inline int chacha20_decrypt(const uint8_t *key, int key_len,
                                    const uint8_t *in, size_t in_len,
                                    uint8_t *out, size_t *out_len) {
    (void)key_len;
    if (in_len < CC20_OVERHEAD) return 0;

    const uint8_t *nonce = in;
    const uint8_t *tag   = in + CC20_NONCE_SIZE;
    const uint8_t *ct    = in + CC20_OVERHEAD;
    size_t ct_len        = in_len - CC20_OVERHEAD;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    int ok = 1, len = 0, final_len = 0;

    ok &= EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL);
    ok &= EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);
    ok &= EVP_DecryptUpdate(ctx, out, &len, ct, (int)ct_len);
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, CC20_TAG_SIZE, (void *)tag);
    int ret = EVP_DecryptFinal_ex(ctx, out + len, &final_len);

    EVP_CIPHER_CTX_free(ctx);
    if (!ok || ret <= 0) { *out_len = 0; return 0; }
    *out_len = (size_t)(len + final_len);
    return 1;
}
#endif