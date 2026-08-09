#ifndef RECTANGLE_AVX2_H
#define RECTANGLE_AVX2_H
/*
* rectangle_avx2.h - AVX2 bit-slicing for RECTANGLE (256 blocks per batch)
*
* This is the "genuinely hardware-gated" version of rectangle.h's existing
* rectangle_bitslice_encrypt()/rectangle_bitslice_decrypt(), which uses
* plain uint64_t planes (64 blocks/batch, works on any 64-bit CPU, no
* feature detection needed). Here, a plane becomes a __m256i (256 blocks/
* batch), which does require AVX2 and does need runtime detection.
*
* Implementation approach: rather than writing a new 256-bit bit-transpose
* from scratch, this reuses rectangle.h's existing scalar
* words_to_planes()/planes_to_words() four times per batch — once per
* 64-block "group" — to build four uint64_t planes per (word position,
* bit position) pair, then packs those four uint64_t values into one
* __m256i lane-wise (group g's plane -> lane g). The S-box and
* permutation logic then run once on the combined __m256i, correctly
* processing all 4 groups (256 blocks) at once, since AVX2's bitwise ops
* act independently and identically on every 64-bit lane.
*
* Requires rectangle.h to already be included (reuses RECT_ROUNDS,
* RECT_BLOCK_SIZE, RECT_BS_BLOCKS, _rect_key_words, _rect_key_schedule,
* words_to_planes, planes_to_words).
*
* Build: add -mavx2 to your compiler flags.
*/

#include <immintrin.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define RECT_BS_GROUPS 4
#define RECT_BS_BLOCKS_AVX2 (RECT_BS_GROUPS * RECT_BS_BLOCKS) /* 256 */

static inline int rectangle_avx2_available(void) {
    __builtin_cpu_init();
    return __builtin_cpu_supports("avx2");
}

static inline __m256i _rect_avx2_not(__m256i x) {
    return _mm256_xor_si256(x, _mm256_set1_epi32(-1));
}

#define A3(a,b,c)     _mm256_and_si256(_mm256_and_si256(a,b),c)
#define A4(a,b,c,d)   _mm256_and_si256(A3(a,b,c),d)
#define OR2(a,b)      _mm256_or_si256(a,b)
#define OR3(a,b,c)    OR2(OR2(a,b),c)
#define OR4(a,b,c,d)  OR2(OR3(a,b,c),d)
#define OR5(a,b,c,d,e)      OR2(OR4(a,b,c,d),e)
#define OR6(a,b,c,d,e,f)    OR2(OR5(a,b,c,d,e),f)

static inline void _rect_sbox_planes_avx2(__m256i p[16]) {
    for (int n = 0; n < 4; n++) {
        __m256i x0 = p[4*n+0], x1 = p[4*n+1], x2 = p[4*n+2], x3 = p[4*n+3];
        __m256i nx0 = _rect_avx2_not(x0), nx1 = _rect_avx2_not(x1),
                nx2 = _rect_avx2_not(x2), nx3 = _rect_avx2_not(x3);

        __m256i y0 = OR6(A3(x1,x2,nx3), A3(x1,x3,nx2), A3(x2,nx0,nx3), A3(x3,nx0,nx2),
                          A4(x0,x2,x3,nx1), A4(x0,nx1,nx2,nx3));
        __m256i y1 = OR6(A3(x0,x2,x3), A3(x0,x2,nx1), A3(x3,nx0,nx2), A3(nx0,nx1,nx2),
                          A4(x0,x1,nx2,nx3), A4(x1,x2,nx0,nx3));
        __m256i y2 = OR5(A3(x0,x2,nx1), A3(x1,x2,nx0), A4(x0,x1,x3,nx2),
                          A3(nx0,nx2,nx3), A3(nx1,nx2,nx3));
        __m256i y3 = OR5(A3(x0,x1,nx2), A3(x0,x2,nx1), A3(x0,x2,nx3),
                          A3(x1,nx2,nx3), A3(x3,nx0,nx1));

        p[4*n+0] = y0; p[4*n+1] = y1; p[4*n+2] = y2; p[4*n+3] = y3;
    }
}

static inline void _rect_sbox_inv_planes_avx2(__m256i p[16]) {
    for (int n = 0; n < 4; n++) {
        __m256i x0 = p[4*n+0], x1 = p[4*n+1], x2 = p[4*n+2], x3 = p[4*n+3];
        __m256i nx0 = _rect_avx2_not(x0), nx1 = _rect_avx2_not(x1),
                nx2 = _rect_avx2_not(x2), nx3 = _rect_avx2_not(x3);

        __m256i y0 = OR5(A3(x1,x2,x3), A3(x0,x2,nx1), A3(x0,x3,nx1), A3(x1,x3,nx0), A3(nx0,nx2,nx3));
        __m256i y1 = OR4(A3(x0,x1,nx3), A3(x0,x3,nx1), A3(x1,nx0,nx2), A3(x2,nx0,nx1));
        __m256i y2 = OR6(A3(x0,x1,x2), A3(x1,x2,x3), A3(x0,nx1,nx2), A3(x3,nx1,nx2),
                          A4(x1,nx0,nx2,nx3), A4(x2,nx0,nx1,nx3));
        __m256i y3 = OR5(A3(x0,x2,x3), A3(x0,x1,nx2), A3(x1,nx2,nx3), A3(nx0,nx1,nx2), A3(nx0,nx1,nx3));

        p[4*n+0] = y0; p[4*n+1] = y1; p[4*n+2] = y2; p[4*n+3] = y3;
    }
}

#undef A3
#undef A4
#undef OR2
#undef OR3
#undef OR4
#undef OR5
#undef OR6

static inline void _rotl_planes_avx2(__m256i dst[16], const __m256i src[16], int r) {
    for (int p = 0; p < 16; p++) dst[p] = src[(p - r + 16) % 16];
}
static inline void _rotr_planes_avx2(__m256i dst[16], const __m256i src[16], int r) {
    for (int p = 0; p < 16; p++) dst[p] = src[(p + r) % 16];
}
static inline void _xor_roundkey_avx2(__m256i p[16], uint16_t rk) {
    __m256i ones = _mm256_set1_epi32(-1);
    for (int i = 0; i < 16; i++) if ((rk >> i) & 1) p[i] = _mm256_xor_si256(p[i], ones);
}

/* Runs the full RECTANGLE round schedule on 4 word-positions worth of
 * combined 256-block planes (P0..P3, each __m256i[16]). Shared by
 * encrypt and decrypt via the `encrypt` flag. */
static inline void _rect_avx2_crypt_planes(__m256i P0[16], __m256i P1[16], __m256i P2[16], __m256i P3[16],
                                            uint16_t rks[RECT_ROUNDS + 1][4], int encrypt) {
    __m256i tmp[16];
    if (encrypt) {
        for (int r = 0; r < RECT_ROUNDS; r++) {
            _xor_roundkey_avx2(P0, rks[r][0]); _xor_roundkey_avx2(P1, rks[r][1]);
            _xor_roundkey_avx2(P2, rks[r][2]); _xor_roundkey_avx2(P3, rks[r][3]);

            _rect_sbox_planes_avx2(P0); _rect_sbox_planes_avx2(P1);
            _rect_sbox_planes_avx2(P2); _rect_sbox_planes_avx2(P3);

            _rotl_planes_avx2(tmp, P1, 1);  memcpy(P1, tmp, sizeof(tmp));
            _rotl_planes_avx2(tmp, P2, 12); memcpy(P2, tmp, sizeof(tmp));
            _rotl_planes_avx2(tmp, P3, 13); memcpy(P3, tmp, sizeof(tmp));
        }
        _xor_roundkey_avx2(P0, rks[RECT_ROUNDS][0]); _xor_roundkey_avx2(P1, rks[RECT_ROUNDS][1]);
        _xor_roundkey_avx2(P2, rks[RECT_ROUNDS][2]); _xor_roundkey_avx2(P3, rks[RECT_ROUNDS][3]);
    } else {
        _xor_roundkey_avx2(P0, rks[RECT_ROUNDS][0]); _xor_roundkey_avx2(P1, rks[RECT_ROUNDS][1]);
        _xor_roundkey_avx2(P2, rks[RECT_ROUNDS][2]); _xor_roundkey_avx2(P3, rks[RECT_ROUNDS][3]);

        for (int r = RECT_ROUNDS - 1; r >= 0; r--) {
            _rotr_planes_avx2(tmp, P1, 1);  memcpy(P1, tmp, sizeof(tmp));
            _rotr_planes_avx2(tmp, P2, 12); memcpy(P2, tmp, sizeof(tmp));
            _rotr_planes_avx2(tmp, P3, 13); memcpy(P3, tmp, sizeof(tmp));

            _rect_sbox_inv_planes_avx2(P0); _rect_sbox_inv_planes_avx2(P1);
            _rect_sbox_inv_planes_avx2(P2); _rect_sbox_inv_planes_avx2(P3);

            _xor_roundkey_avx2(P0, rks[r][0]); _xor_roundkey_avx2(P1, rks[r][1]);
            _xor_roundkey_avx2(P2, rks[r][2]); _xor_roundkey_avx2(P3, rks[r][3]);
        }
    }
}

/* Shared engine for both encrypt and decrypt: transposes up to 256 blocks
 * (4 groups of <=64) into planes, packs 4 groups' scalar planes into one
 * __m256i per (word, bit) pair, runs the round schedule, then unpacks and
 * transposes back. `buf` already holds either padded plaintext or raw
 * ciphertext of length n_blocks * RECT_BLOCK_SIZE. */
static inline void _rectangle_avx2_process(uint8_t *buf, size_t n_blocks,
                                            uint16_t rks[RECT_ROUNDS + 1][4], int encrypt) {
    uint16_t words[64];

    for (size_t base = 0; base < n_blocks; base += RECT_BS_BLOCKS_AVX2) {
        size_t remaining = n_blocks - base;
        size_t group_n[RECT_BS_GROUPS];
        for (int g = 0; g < RECT_BS_GROUPS; g++) {
            size_t take = (remaining < RECT_BS_BLOCKS) ? remaining : RECT_BS_BLOCKS;
            group_n[g] = take;
            remaining -= take;
        }

        /* scalar_planes[word][group][bit] */
        uint64_t scalar_planes[4][RECT_BS_GROUPS][16];

        for (int w = 0; w < 4; w++) {
            for (int g = 0; g < RECT_BS_GROUPS; g++) {
                size_t n = group_n[g];
                if (n == 0) { memset(scalar_planes[w][g], 0, sizeof(scalar_planes[w][g])); continue; }
                size_t offset = base + g * RECT_BS_BLOCKS;
                for (size_t i = 0; i < n; i++) {
                    memcpy(&words[i], buf + (offset + i) * RECT_BLOCK_SIZE + w * 2, 2);
                }
                words_to_planes(words, n, scalar_planes[w][g]);
            }
        }

        __m256i P0[16], P1[16], P2[16], P3[16];
        __m256i *Pw[4] = { P0, P1, P2, P3 };
        for (int w = 0; w < 4; w++) {
            for (int i = 0; i < 16; i++) {
                uint64_t lanes[4] = {
                    scalar_planes[w][0][i], scalar_planes[w][1][i],
                    scalar_planes[w][2][i], scalar_planes[w][3][i]
                };
                Pw[w][i] = _mm256_loadu_si256((const __m256i *)lanes);
            }
        }

        _rect_avx2_crypt_planes(P0, P1, P2, P3, rks, encrypt);

        for (int w = 0; w < 4; w++) {
            for (int i = 0; i < 16; i++) {
                uint64_t lanes[4];
                _mm256_storeu_si256((__m256i *)lanes, Pw[w][i]);
                for (int g = 0; g < RECT_BS_GROUPS; g++) scalar_planes[w][g][i] = lanes[g];
            }
        }

        for (int w = 0; w < 4; w++) {
            for (int g = 0; g < RECT_BS_GROUPS; g++) {
                size_t n = group_n[g];
                if (n == 0) continue;
                size_t offset = base + g * RECT_BS_BLOCKS;
                planes_to_words(scalar_planes[w][g], words, n);
                for (size_t i = 0; i < n; i++) {
                    memcpy(buf + (offset + i) * RECT_BLOCK_SIZE + w * 2, &words[i], 2);
                }
            }
        }
    }
}

static inline uint8_t *rectangle_avx2_encrypt(const uint8_t *key,
        const uint8_t *plain, size_t plain_len, size_t *out_len) {
    uint32_t k0, k1, k2, k3;
    _rect_key_words(key, &k0, &k1, &k2, &k3);
    uint16_t rks[RECT_ROUNDS + 1][4];
    _rect_key_schedule(k0, k1, k2, k3, rks);

    uint8_t *buf = pkcs7_pad(plain, plain_len, RECT_BLOCK_SIZE, out_len);
    if (!buf) return NULL;
    size_t n_blocks = *out_len / RECT_BLOCK_SIZE;

    _rectangle_avx2_process(buf, n_blocks, rks, 1);
    return buf;
}

static inline uint8_t *rectangle_avx2_decrypt(const uint8_t *key,
        const uint8_t *ct, size_t ct_len, size_t *out_len) {
    uint32_t k0, k1, k2, k3;
    _rect_key_words(key, &k0, &k1, &k2, &k3);
    uint16_t rks[RECT_ROUNDS + 1][4];
    _rect_key_schedule(k0, k1, k2, k3, rks);

    uint8_t *buf = (uint8_t *)malloc(ct_len);
    if (!buf) return NULL;
    memcpy(buf, ct, ct_len);
    size_t n_blocks = ct_len / RECT_BLOCK_SIZE;

    _rectangle_avx2_process(buf, n_blocks, rks, 0);

    *out_len = pkcs7_unpad_len(buf, ct_len);
    return buf;
}

#endif
