#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define AES_NONCE_SIZE  8
#define AES_TAG_SIZE   16
#define AES_OVERHEAD   (AES_NONCE_SIZE + AES_TAG_SIZE) 

static inline int aes_encrypt(const uint8_t *key, int key_len,
                                const uint8_t *plain, size_t plain_len,
                                uint8_t *out, size_t *out_len) {

    const EVP_CIPHER *cipher;
    switch (key_len) {
        case 16: cipher = EVP_aes_128_ccm(); break;
        case 24: cipher = EVP_aes_192_ccm(); break;
        case 32: cipher = EVP_aes_256_ccm(); break;
        default: return 0;
    }

    uint8_t nonce[AES_NONCE_SIZE];
    uint8_t tag[AES_TAG_SIZE];
    if (!RAND_bytes(nonce, AES_NONCE_SIZE)) return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    int ok = 1;
    int len = 0;

    ok &= EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL);

    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, AES_NONCE_SIZE, NULL);

    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, AES_TAG_SIZE, NULL);

    ok &= EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);

    ok &= EVP_EncryptUpdate(ctx, NULL, &len, NULL, (int)plain_len);

    uint8_t *ct_ptr = out + AES_NONCE_SIZE + AES_TAG_SIZE;
    ok &= EVP_EncryptUpdate(ctx, ct_ptr, &len, plain, (int)plain_len);

    int final_len = 0;
    ok &= EVP_EncryptFinal_ex(ctx, ct_ptr + len, &final_len);

    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, AES_TAG_SIZE, tag);

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return 0;

    memcpy(out,                  nonce, AES_NONCE_SIZE);
    memcpy(out + AES_NONCE_SIZE, tag,   AES_TAG_SIZE);
    *out_len = AES_NONCE_SIZE + AES_TAG_SIZE + (size_t)(len + final_len);
    return 1;
}

static inline int aes_decrypt(const uint8_t *key, int key_len,
                                const uint8_t *in,  size_t in_len,
                                uint8_t *out, size_t *out_len) {

    if (in_len < AES_OVERHEAD) return 0;

    const EVP_CIPHER *cipher;
    switch (key_len) {
        case 16: cipher = EVP_aes_128_ccm(); break;
        case 24: cipher = EVP_aes_192_ccm(); break;
        case 32: cipher = EVP_aes_256_ccm(); break;
        default: return 0;
    }

    const uint8_t *nonce = in;
    const uint8_t *tag   = in + AES_NONCE_SIZE;
    const uint8_t *ct    = in + AES_NONCE_SIZE + AES_TAG_SIZE;
    size_t ct_len        = in_len - AES_OVERHEAD;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    int ok = 1;
    int len = 0;

    ok &= EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL);
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, AES_NONCE_SIZE, NULL);
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, AES_TAG_SIZE, (void *)tag);
    ok &= EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);

    ok &= EVP_DecryptUpdate(ctx, NULL, &len, NULL, (int)ct_len);

    int ret = EVP_DecryptUpdate(ctx, out, &len, ct, (int)ct_len);

    EVP_CIPHER_CTX_free(ctx);

    if (!ok || ret <= 0) { *out_len = 0; return 0; }
    *out_len = (size_t)len;
    return 1;
}

#endif