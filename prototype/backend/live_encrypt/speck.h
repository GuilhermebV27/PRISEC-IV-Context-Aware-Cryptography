#ifndef SPECK_H
#define SPECK_H
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

#define SPECK_BLOCK_SIZE 16
#define SPECK_KEY_SIZE   16
#define SPECK_ROUNDS     32

static inline uint64_t _speck_rotr64(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

static inline uint64_t _speck_rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

static inline void _key_schedule(uint64_t A, uint64_t B,
                                   uint64_t rks[SPECK_ROUNDS]) {
    for (int i = 0; i < 31; i++) {
        rks[i] = A;
        B = _speck_rotr64(B, 8) + A;
        B ^= (uint64_t)i;
        A = _speck_rotl64(A, 3) ^ B;
    }
    rks[31] = A;
}

static inline void _key_words(const uint8_t *key,
                                uint64_t *A, uint64_t *B) {
    memcpy(A, key,     8);
    memcpy(B, key + 8, 8);
}

static inline void _speck_enc_block(uint64_t *y, uint64_t *x,
                                     const uint64_t rks[SPECK_ROUNDS]) {
    for (int i = 0; i < SPECK_ROUNDS; i++) {
        *x = _speck_rotr64(*x, 8) + *y;
        *x ^= rks[i];
        *y = _speck_rotl64(*y, 3) ^ *x;
    }
}

static inline void _speck_dec_block(uint64_t *y, uint64_t *x,
                                     const uint64_t rks[SPECK_ROUNDS]) {
    for (int i = SPECK_ROUNDS - 1; i >= 0; i--) {
        *y ^= *x;
        *y = _speck_rotr64(*y, 3);
        *x ^= rks[i];
        *x -= *y;
        *x = _speck_rotl64(*x, 8);
    }
}

static inline uint8_t *speck_encrypt(const uint8_t *key,
                                      const uint8_t *plain, size_t plain_len,
                                      size_t *out_len) {
    uint64_t A, B;
    _key_words(key, &A, &B);
    uint64_t rks[SPECK_ROUNDS];
    _key_schedule(A, B, rks);
    uint8_t *buf = pkcs7_pad(plain, plain_len, SPECK_BLOCK_SIZE, out_len);
    if (!buf) return NULL;
    size_t n_blocks = *out_len / SPECK_BLOCK_SIZE;
    for (size_t i = 0; i < n_blocks; i++) {
        uint64_t y, x;
        memcpy(&y, buf + i * 16,     8);
        memcpy(&x, buf + i * 16 + 8, 8);
        _speck_enc_block(&y, &x, rks);
        memcpy(buf + i * 16,     &y, 8);
        memcpy(buf + i * 16 + 8, &x, 8);
    }
    return buf;
}

static inline uint8_t *speck_decrypt(const uint8_t *key,
                                      const uint8_t *ct, size_t ct_len,
                                      size_t *out_len) {
    uint64_t A, B;
    _key_words(key, &A, &B);
    uint64_t rks[SPECK_ROUNDS];
    _key_schedule(A, B, rks);
    uint8_t *buf = (uint8_t *)malloc(ct_len);
    if (!buf) return NULL;
    memcpy(buf, ct, ct_len);
    size_t n_blocks = ct_len / SPECK_BLOCK_SIZE;
    for (size_t i = 0; i < n_blocks; i++) {
        uint64_t y, x;
        memcpy(&y, buf + i * 16,     8);
        memcpy(&x, buf + i * 16 + 8, 8);
        _speck_dec_block(&y, &x, rks);
        memcpy(buf + i * 16,     &y, 8);
        memcpy(buf + i * 16 + 8, &x, 8);
    }
    *out_len = pkcs7_unpad_len(buf, ct_len);
    return buf;
}

#endif