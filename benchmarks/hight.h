#ifndef HIGHT_H
#define HIGHT_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

#define HIGHT_BLOCK_SIZE 8
#define HIGHT_KEY_SIZE  16

static uint8_t _DELTA[128];
static int     _delta_ready = 0;

static inline void _gen_delta(void) {
    uint8_t s[134] = {0};
    s[0]=0; s[1]=1; s[2]=0; s[3]=1; s[4]=1; s[5]=0; s[6]=1;

    _DELTA[0] = s[6]*64 + s[5]*32 + s[4]*16 + s[3]*8 + s[2]*4 + s[1]*2 + s[0];

    for (int i = 1; i < 128; i++) {
        s[i+6] = s[i+2] ^ s[i-1];
        _DELTA[i] = s[i+6]*64 + s[i+5]*32 + s[i+4]*16
                  + s[i+3]*8  + s[i+2]*4  + s[i+1]*2 + s[i];
    }
    _delta_ready = 1;
}

static inline uint8_t _rol8(uint8_t x, int n) {
    return (uint8_t)(((x << n) | (x >> (8 - n))) & 0xFF);
}

static inline uint8_t _F0(uint8_t x) {
    return (_rol8(x,1) ^ _rol8(x,2) ^ _rol8(x,7)) & 0xFF;
}

static inline uint8_t _F1(uint8_t x) {
    return (_rol8(x,3) ^ _rol8(x,4) ^ _rol8(x,6)) & 0xFF;
}

static inline void _hight_key_schedule(const uint8_t *mk,
                                   uint8_t wk[8], uint8_t sk[128]) {
    if (!_delta_ready) _gen_delta();

    uint8_t K[16];
    for (int i = 0; i < 16; i++) K[i] = mk[15 - i];

    memcpy(wk,     K + 12, 4);
    memcpy(wk + 4, K,      4);

    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            sk[16*i + j]     = (K[((j - i) % 8 + 8) % 8]     + _DELTA[16*i + j])     & 0xFF;
            sk[16*i + j + 8] = (K[((j - i) % 8 + 8) % 8 + 8] + _DELTA[16*i + j + 8]) & 0xFF;
        }
    }
}

static inline void _enc_core(uint8_t x[8],
                               const uint8_t wk[8], const uint8_t sk[128]) {
    x[0] = (x[0] + wk[0]) & 0xFF;
    x[2] = x[2] ^ wk[1];
    x[4] = (x[4] + wk[2]) & 0xFF;
    x[6] = x[6] ^ wk[3];

    for (int i = 0; i < 31; i++) {
        uint8_t t0 = x[7] ^ ((uint8_t)((_F0(x[6]) + sk[4*i+3]) & 0xFF));
        uint8_t t1 = x[0];
        uint8_t t2 = (x[1] + (_F1(x[0]) ^ sk[4*i]))   & 0xFF;
        uint8_t t3 = x[2];
        uint8_t t4 = x[3] ^ ((uint8_t)((_F0(x[2]) + sk[4*i+1]) & 0xFF));
        uint8_t t5 = x[4];
        uint8_t t6 = (x[5] + (_F1(x[4]) ^ sk[4*i+2])) & 0xFF;
        uint8_t t7 = x[6];
        x[0]=t0; x[1]=t1; x[2]=t2; x[3]=t3;
        x[4]=t4; x[5]=t5; x[6]=t6; x[7]=t7;
    }

    x[1] = (x[1] + (_F1(x[0]) ^ sk[124])) & 0xFF;
    x[3] =  x[3] ^ ((uint8_t)((_F0(x[2]) + sk[125]) & 0xFF));
    x[5] = (x[5] + (_F1(x[4]) ^ sk[126])) & 0xFF;
    x[7] =  x[7] ^ ((uint8_t)((_F0(x[6]) + sk[127]) & 0xFF));

    x[0] = (x[0] + wk[4]) & 0xFF;
    x[2] =  x[2] ^ wk[5];
    x[4] = (x[4] + wk[6]) & 0xFF;
    x[6] =  x[6] ^ wk[7];
}

static inline void _dec_core(uint8_t x[8],
                               const uint8_t wk[8], const uint8_t sk[128]) {
    x[0] = (x[0] - wk[4]) & 0xFF;
    x[2] =  x[2] ^ wk[5];
    x[4] = (x[4] - wk[6]) & 0xFF;
    x[6] =  x[6] ^ wk[7];

    x[1] = (x[1] - (_F1(x[0]) ^ sk[124])) & 0xFF;
    x[3] =  x[3] ^ ((uint8_t)((_F0(x[2]) + sk[125]) & 0xFF));
    x[5] = (x[5] - (_F1(x[4]) ^ sk[126])) & 0xFF;
    x[7] =  x[7] ^ ((uint8_t)((_F0(x[6]) + sk[127]) & 0xFF));

    for (int i = 30; i >= 0; i--) {
        uint8_t t0 = x[1];
        uint8_t t1 = (x[2] - (_F1(x[1]) ^ sk[4*i]))   & 0xFF;
        uint8_t t2 = x[3];
        uint8_t t3 =  x[4] ^ ((uint8_t)((_F0(x[3]) + sk[4*i+1]) & 0xFF));
        uint8_t t4 = x[5];
        uint8_t t5 = (x[6] - (_F1(x[5]) ^ sk[4*i+2])) & 0xFF;
        uint8_t t6 = x[7];
        uint8_t t7 =  x[0] ^ ((uint8_t)((_F0(x[7]) + sk[4*i+3]) & 0xFF));
        x[0]=t0; x[1]=t1; x[2]=t2; x[3]=t3;
        x[4]=t4; x[5]=t5; x[6]=t6; x[7]=t7;
    }

    x[0] = (x[0] - wk[0]) & 0xFF;
    x[2] =  x[2] ^ wk[1];
    x[4] = (x[4] - wk[2]) & 0xFF;
    x[6] =  x[6] ^ wk[3];
}

static inline void hight_encrypt(const uint8_t *key,
                                   const uint8_t *plain, size_t plain_len,
                                   uint8_t **out, size_t *out_len) {
    uint8_t wk[8], sk[128];
    _hight_key_schedule(key, wk, sk);
    uint8_t *buf = pkcs7_pad(plain, plain_len, HIGHT_BLOCK_SIZE, out_len);

    for (size_t b = 0; b < *out_len; b += HIGHT_BLOCK_SIZE) {
        uint8_t state[8];
        for (int i = 0; i < 8; i++) state[i] = buf[b + 7 - i];
        _enc_core(state, wk, sk);
        for (int i = 0; i < 8; i++) buf[b + i] = state[7 - i];
    }

    *out = buf;
}

static inline uint8_t *hight_decrypt(const uint8_t *key,
                                      const uint8_t *ct, size_t ct_len,
                                      size_t *out_len) {
    uint8_t wk[8], sk[128];
    _hight_key_schedule(key, wk, sk);

    uint8_t *buf = (uint8_t *)malloc(ct_len);
    memcpy(buf, ct, ct_len);

    for (size_t b = 0; b < ct_len; b += HIGHT_BLOCK_SIZE) {
        uint8_t state[8];
        for (int i = 0; i < 8; i++) state[i] = buf[b + 7 - i];
        _dec_core(state, wk, sk);
        for (int i = 0; i < 8; i++) buf[b + i] = state[7 - i];
    }

    *out_len = pkcs7_unpad_len(buf, ct_len);
    return buf;
}

#endif