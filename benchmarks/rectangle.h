#ifndef RECTANGLE_H
#define RECTANGLE_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

#define RECT_BLOCK_SIZE  8
#define RECT_KEY_SIZE   16
#define RECT_ROUNDS     25

static const uint16_t RECT_SBOX[16] = {
    0x6, 0x5, 0xC, 0xA, 0x1, 0xE, 0x7, 0x9,
    0xB, 0x0, 0x3, 0xD, 0x8, 0xF, 0x4, 0x2
};

static const uint16_t RECT_SBOX_INV[16] = {
    0x9, 0x4, 0xF, 0xA, 0xE, 0x1, 0x0, 0x6,
    0xC, 0x7, 0x3, 0x8, 0x2, 0xB, 0x5, 0xD
};

static const uint8_t RECT_RC[25] = {
    0x01, 0x02, 0x04, 0x09, 0x12, 0x05, 0x0B, 0x16,
    0x0C, 0x19, 0x13, 0x07, 0x0F, 0x1F, 0x1E, 0x1C,
    0x18, 0x11, 0x03, 0x06, 0x0D, 0x1B, 0x17, 0x0E, 0x1D
};

static inline uint16_t _rect_sub_nibbles_16(uint16_t row, const uint16_t sbox[16]) {
    uint16_t out = 0;
    for (int i = 0; i < 4; i++) {
        uint16_t nibble = (row >> (4 * i)) & 0xF;
        out |= (uint16_t)(sbox[nibble] << (4 * i));
    }
    return out;
}

static inline uint32_t _rect_sub_nibbles_32(uint32_t row, const uint16_t sbox[16]) {
    uint32_t out = row;
    for (int i = 0; i < 8; i++) {
        uint32_t nibble = (row >> (4 * i)) & 0xF;
        out = (out & ~((uint32_t)0xF << (4 * i)))
            | ((uint32_t)sbox[nibble] << (4 * i));
    }
    return out;
}

static inline void _rect_key_schedule(uint32_t k0, uint32_t k1,
                                       uint32_t k2, uint32_t k3,
                                       uint16_t rks[RECT_ROUNDS + 1][4]) {
    uint32_t r0 = k0, r1 = k1, r2 = k2, r3 = k3;

    for (int i = 0; i < RECT_ROUNDS; i++) {
        rks[i][0] = (uint16_t)(r0 & 0xFFFF);
        rks[i][1] = (uint16_t)(r1 & 0xFFFF);
        rks[i][2] = (uint16_t)(r2 & 0xFFFF);
        rks[i][3] = (uint16_t)(r3 & 0xFFFF);

        r0 = _rect_sub_nibbles_32(r0, RECT_SBOX);
        r1 = _rect_sub_nibbles_32(r1, RECT_SBOX);
        r2 = _rect_sub_nibbles_32(r2, RECT_SBOX);
        r3 = _rect_sub_nibbles_32(r3, RECT_SBOX);

        uint32_t new_r0 = ((r0 << 8) | (r0 >> 24)) ^ r1;
        uint32_t new_r1 = r2;
        uint32_t new_r2 = ((r2 << 16) | (r2 >> 16)) ^ r3;
        uint32_t new_r3 = r0;
        r0 = new_r0; r1 = new_r1; r2 = new_r2; r3 = new_r3;

        r0 ^= (uint32_t)RECT_RC[i];
    }

    rks[RECT_ROUNDS][0] = (uint16_t)(r0 & 0xFFFF);
    rks[RECT_ROUNDS][1] = (uint16_t)(r1 & 0xFFFF);
    rks[RECT_ROUNDS][2] = (uint16_t)(r2 & 0xFFFF);
    rks[RECT_ROUNDS][3] = (uint16_t)(r3 & 0xFFFF);
}

static inline void _rect_key_words(const uint8_t *key,
                                    uint32_t *k0, uint32_t *k1,
                                    uint32_t *k2, uint32_t *k3) {
    memcpy(k0, key,      4);
    memcpy(k1, key +  4, 4);
    memcpy(k2, key +  8, 4);
    memcpy(k3, key + 12, 4);
}

static inline uint8_t *rectangle_encrypt(const uint8_t *key,
                                           const uint8_t *plain, size_t plain_len,
                                           size_t *out_len) {
    uint32_t k0, k1, k2, k3;
    _rect_key_words(key, &k0, &k1, &k2, &k3);

    uint16_t rks[RECT_ROUNDS + 1][4];
    _rect_key_schedule(k0, k1, k2, k3, rks);

    uint8_t *buf = pkcs7_pad(plain, plain_len, RECT_BLOCK_SIZE, out_len);
    if (!buf) return NULL;
    size_t n_blocks = *out_len / RECT_BLOCK_SIZE;

    for (size_t b = 0; b < n_blocks; b++) {
        uint16_t s0, s1, s2, s3;
        memcpy(&s0, buf + b * 8,     2);
        memcpy(&s1, buf + b * 8 + 2, 2);
        memcpy(&s2, buf + b * 8 + 4, 2);
        memcpy(&s3, buf + b * 8 + 6, 2);

        for (int r = 0; r < RECT_ROUNDS; r++) {
            s0 ^= rks[r][0];
            s1 ^= rks[r][1];
            s2 ^= rks[r][2];
            s3 ^= rks[r][3];

            s0 = _rect_sub_nibbles_16(s0, RECT_SBOX);
            s1 = _rect_sub_nibbles_16(s1, RECT_SBOX);
            s2 = _rect_sub_nibbles_16(s2, RECT_SBOX);
            s3 = _rect_sub_nibbles_16(s3, RECT_SBOX);

            s1 = (uint16_t)((s1 << 1)  | (s1 >> 15));
            s2 = (uint16_t)((s2 << 12) | (s2 >> 4));
            s3 = (uint16_t)((s3 << 13) | (s3 >> 3));
        }

        s0 ^= rks[RECT_ROUNDS][0];
        s1 ^= rks[RECT_ROUNDS][1];
        s2 ^= rks[RECT_ROUNDS][2];
        s3 ^= rks[RECT_ROUNDS][3];

        memcpy(buf + b * 8,     &s0, 2);
        memcpy(buf + b * 8 + 2, &s1, 2);
        memcpy(buf + b * 8 + 4, &s2, 2);
        memcpy(buf + b * 8 + 6, &s3, 2);
    }

    return buf;
}

static inline uint8_t *rectangle_decrypt(const uint8_t *key,
                                           const uint8_t *ct, size_t ct_len,
                                           size_t *out_len) {
    uint32_t k0, k1, k2, k3;
    _rect_key_words(key, &k0, &k1, &k2, &k3);

    uint16_t rks[RECT_ROUNDS + 1][4];
    _rect_key_schedule(k0, k1, k2, k3, rks);

    uint8_t *buf = (uint8_t *)malloc(ct_len);
    if (!buf) return NULL;
    memcpy(buf, ct, ct_len);
    size_t n_blocks = ct_len / RECT_BLOCK_SIZE;

    for (size_t b = 0; b < n_blocks; b++) {
        uint16_t s0, s1, s2, s3;
        memcpy(&s0, buf + b * 8,     2);
        memcpy(&s1, buf + b * 8 + 2, 2);
        memcpy(&s2, buf + b * 8 + 4, 2);
        memcpy(&s3, buf + b * 8 + 6, 2);

        s0 ^= rks[RECT_ROUNDS][0];
        s1 ^= rks[RECT_ROUNDS][1];
        s2 ^= rks[RECT_ROUNDS][2];
        s3 ^= rks[RECT_ROUNDS][3];

        for (int r = RECT_ROUNDS - 1; r >= 0; r--) {
            s1 = (uint16_t)((s1 >> 1)  | (s1 << 15));
            s2 = (uint16_t)((s2 >> 12) | (s2 << 4));
            s3 = (uint16_t)((s3 >> 13) | (s3 << 3));

            s0 = _rect_sub_nibbles_16(s0, RECT_SBOX_INV);
            s1 = _rect_sub_nibbles_16(s1, RECT_SBOX_INV);
            s2 = _rect_sub_nibbles_16(s2, RECT_SBOX_INV);
            s3 = _rect_sub_nibbles_16(s3, RECT_SBOX_INV);

            s0 ^= rks[r][0];
            s1 ^= rks[r][1];
            s2 ^= rks[r][2];
            s3 ^= rks[r][3];
        }

        memcpy(buf + b * 8,     &s0, 2);
        memcpy(buf + b * 8 + 2, &s1, 2);
        memcpy(buf + b * 8 + 4, &s2, 2);
        memcpy(buf + b * 8 + 6, &s3, 2);
    }

    *out_len = pkcs7_unpad_len(buf, ct_len);
    return buf;
}

#endif