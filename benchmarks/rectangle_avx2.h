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
* === Transpose vectorization (partial - read before trusting this file) ===
*
* Encrypting with bit-slicing has two phases: (1) TRANSPOSE - reorganizing
* data from normal byte layout into bit-plane layout and back, done by
* rectangle.h's words_to_planes()/planes_to_words(); and (2) ROUND FUNCTION
* - the actual S-box/permutation math, done once data is in plane form.
*
* The original version of this file only vectorized phase (2): it called
* the SCALAR words_to_planes()/planes_to_words() four times per batch (once
* per 64-block group) to build the input, then ran one genuinely-AVX2
* round function across all 4 groups combined, then called the scalar
* planes_to_words() four times again to unpack the output. Since phase (1)
* never got any faster, and typically dominates a bit-sliced cipher's
* total runtime, this capped the real-world speedup far below the
* theoretical 4x AVX2 register-width advantage (Amdahl's Law: speeding up
* only part of a job caps the overall speedup at how large that part was).
*
* This version vectorizes HALF of phase (1): words_to_planes_avx2_fast()
* below replaces the scalar bit-by-bit extraction loop with a per-16-word
* chunk vectorized compare + movemask + bit-compress, using the
* well-documented "compress bits" algorithm (see e.g. Sean Eron Anderson's
* Bit Twiddling Hacks, "Interleave bits by Binary Magic Numbers", inverse
* direction) - not a novel bit-shuffle network, which is what makes this
* safe enough to ship: every step is a standard, independently-verifiable
* primitive, and the test harness (test_rectangle_avx2.c) checks this
* function's output bit-for-bit against the scalar words_to_planes() it
* replaces, for many random inputs, in isolation - not just "does the
* whole cipher still work."
*
* planes_to_words() (the OUTPUT/unpack direction) is NOT vectorized here.
* Doing so safely requires the inverse "bit-expand" operation, which needs
* an additional cross-lane byte-shuffle step to turn a compacted bitmask
* back into a per-lane predicate vector - a meaningfully more complex and
* higher-risk piece of SIMD code to hand-derive without a compiler
* available to test against. Shipping that unverified risked exactly the
* failure mode this whole exercise was trying to avoid: code that looks
* right, compiles, runs, and silently produces wrong ciphertext. Leaving
* planes_to_words() scalar is the honest, safer trade-off - this is a
* partial win, not the full 4x fix.
*
* Small-input fallback (unchanged from the previous revision): the AVX2
* batch machinery always builds a full 256-block-sized scratch workspace
* even when the input is far smaller than one batch. Below a full-batch
* threshold (256 blocks = 2048 bytes), rectangle_avx2_encrypt()/_decrypt()
* delegate directly to the portable 64-block bitslice path instead.
*
* Requires rectangle.h to already be included (reuses RECT_ROUNDS,
* RECT_BLOCK_SIZE, RECT_BS_BLOCKS, RECT_KEY_SIZE, plane_t, _rect_key_words,
* _rect_key_schedule, words_to_planes, planes_to_words,
* rectangle_bitslice_encrypt, rectangle_bitslice_decrypt).
*
* Build: add -mavx2 to your compiler flags.
*/

#include <immintrin.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#define RECT_BS_GROUPS 4
#define RECT_BS_BLOCKS_AVX2 (RECT_BS_GROUPS * RECT_BS_BLOCKS) /* 256 */

static inline int rectangle_avx2_available(void) {
    __builtin_cpu_init();
    return __builtin_cpu_supports("avx2");
}

/*
* words_to_planes_avx2_fast() - drop-in accelerated replacement for
* rectangle.h's words_to_planes(), bit-for-bit identical output.
*
* Processes 16 words at a time (one __m256i load, each word in its own
* 16-bit lane). For each of the 16 output bit-planes b:
*   1. Broadcast (1<<b) to every lane, AND with the loaded words, compare
*      for equality against the same broadcast value -> each lane becomes
*      0xFFFF (bit b was set) or 0x0000 (bit b was clear).
*   2. _mm256_movemask_epi8 reads the MSB of each of the 32 bytes in that
*      result into a 32-bit mask. Since each 16-bit lane is 2 identical
*      bytes (0xFF,0xFF or 0x00,0x00), the resulting 32-bit mask has each
*      real bit duplicated at positions (2k, 2k+1) for lane k.
*   3. The standard "compress every other bit" sequence below (masking
*      with the alternating constant 0x55555555 and successively merging
*      halves) throws away the duplicate and packs the 16 real bits
*      together, LSB = lane 0 = the first word in this chunk. This is a
*      well-known, independently checkable bit-twiddling algorithm, not
*      something derived ad hoc for this file.
*   4. That compacted 16-bit value is exactly 16 bits of plane[b] - one
*      bit per word in this chunk - and gets OR'd into the accumulating
*      64-bit plane at the correct chunk offset.
*
* A tail of fewer than 16 leftover words (n % 16 != 0) is handled with the
* exact original scalar loop, to avoid needing a masked/partial vector
* load for a case that's cheap to just do the plain way.
*/
static inline void words_to_planes_avx2_fast(const uint16_t *words, size_t n, plane_t p[16]) {
    for (int b = 0; b < 16; b++) p[b] = 0;

    size_t full_chunks = n / 16;

    for (size_t c = 0; c < full_chunks; c++) {
        __m256i w = _mm256_loadu_si256((const __m256i *)(words + c * 16));

        for (int b = 0; b < 16; b++) {
            __m256i mask = _mm256_set1_epi16((short)(1 << b));
            __m256i test = _mm256_and_si256(w, mask);
            __m256i cmp = _mm256_cmpeq_epi16(test, mask);
            uint32_t mm = (uint32_t)_mm256_movemask_epi8(cmp);

            uint32_t x = mm & 0x55555555u;
            x = (x | (x >> 1)) & 0x33333333u;
            x = (x | (x >> 2)) & 0x0F0F0F0Fu;
            x = (x | (x >> 4)) & 0x00FF00FFu;
            x = (x | (x >> 8)) & 0x0000FFFFu;

            p[b] |= ((plane_t)x) << (c * 16);
        }
    }

    /* Tail: identical to rectangle.h's words_to_planes() scalar loop. */
    for (size_t i = full_chunks * 16; i < n; i++) {
        uint16_t wv = words[i];
        for (int b = 0; b < 16; b++)
            if ((wv >> b) & 1) p[b] |= ((plane_t)1 << i);
    }
}

static inline __m256i _rect_avx2_not(__m256i x) {
    return _mm256_xor_si256(x, _mm256_set1_epi32(-1));
}

#define A3(a,b,c) _mm256_and_si256(_mm256_and_si256(a,b),c)
#define A4(a,b,c,d) _mm256_and_si256(A3(a,b,c),d)
#define OR2(a,b) _mm256_or_si256(a,b)
#define OR3(a,b,c) OR2(OR2(a,b),c)
#define OR4(a,b,c,d) OR2(OR3(a,b,c),d)
#define OR5(a,b,c,d,e) OR2(OR4(a,b,c,d),e)
#define OR6(a,b,c,d,e,f) OR2(OR5(a,b,c,d,e),f)

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
 * encrypt and decrypt via the `encrypt` flag. Unchanged from the previous
 * revision - this part was already genuinely vectorized. */
static inline void _rect_avx2_crypt_planes(__m256i P0[16], __m256i P1[16], __m256i P2[16], __m256i P3[16],
                                            uint16_t rks[RECT_ROUNDS + 1][4], int encrypt) {
    __m256i tmp[16];
    if (encrypt) {
        for (int r = 0; r < RECT_ROUNDS; r++) {
            _xor_roundkey_avx2(P0, rks[r][0]); _xor_roundkey_avx2(P1, rks[r][1]);
            _xor_roundkey_avx2(P2, rks[r][2]); _xor_roundkey_avx2(P3, rks[r][3]);

            _rect_sbox_planes_avx2(P0); _rect_sbox_planes_avx2(P1);
            _rect_sbox_planes_avx2(P2); _rect_sbox_planes_avx2(P3);

            _rotl_planes_avx2(tmp, P1, 1); memcpy(P1, tmp, sizeof(tmp));
            _rotl_planes_avx2(tmp, P2, 12); memcpy(P2, tmp, sizeof(tmp));
            _rotl_planes_avx2(tmp, P3, 13); memcpy(P3, tmp, sizeof(tmp));
        }
        _xor_roundkey_avx2(P0, rks[RECT_ROUNDS][0]); _xor_roundkey_avx2(P1, rks[RECT_ROUNDS][1]);
        _xor_roundkey_avx2(P2, rks[RECT_ROUNDS][2]); _xor_roundkey_avx2(P3, rks[RECT_ROUNDS][3]);
    } else {
        _xor_roundkey_avx2(P0, rks[RECT_ROUNDS][0]); _xor_roundkey_avx2(P1, rks[RECT_ROUNDS][1]);
        _xor_roundkey_avx2(P2, rks[RECT_ROUNDS][2]); _xor_roundkey_avx2(P3, rks[RECT_ROUNDS][3]);

        for (int r = RECT_ROUNDS - 1; r >= 0; r--) {
            _rotr_planes_avx2(tmp, P1, 1); memcpy(P1, tmp, sizeof(tmp));
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
 * (4 groups of <=64) into planes using the accelerated
 * words_to_planes_avx2_fast(), packs 4 groups' scalar planes into one
 * __m256i per (word, bit) pair, runs the round schedule, then unpacks
 * with the (still scalar) planes_to_words() and transposes back. `buf`
 * already holds either padded plaintext or raw ciphertext of length
 * n_blocks * RECT_BLOCK_SIZE.
 *
 * `lanes` is 32-byte aligned so the pack/unpack steps can use the aligned
 * _mm256_load_si256/_mm256_store_si256 intrinsics instead of the
 * unaligned loadu/storeu variants. */
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
                words_to_planes_avx2_fast(words, n, scalar_planes[w][g]);
            }
        }

        __m256i P0[16], P1[16], P2[16], P3[16];
        __m256i *Pw[4] = { P0, P1, P2, P3 };
        for (int w = 0; w < 4; w++) {
            for (int i = 0; i < 16; i++) {
                __attribute__((aligned(32))) uint64_t lanes[4] = {
                    scalar_planes[w][0][i], scalar_planes[w][1][i],
                    scalar_planes[w][2][i], scalar_planes[w][3][i]
                };
                Pw[w][i] = _mm256_load_si256((const __m256i *)lanes);
            }
        }

        _rect_avx2_crypt_planes(P0, P1, P2, P3, rks, encrypt);

        for (int w = 0; w < 4; w++) {
            for (int i = 0; i < 16; i++) {
                __attribute__((aligned(32))) uint64_t lanes[4];
                _mm256_store_si256((__m256i *)lanes, Pw[w][i]);
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
    /* Small-input fallback: below one full 256-block batch, delegate to
     * the portable path rather than pay the AVX2 scratch-buffer setup
     * cost while computing on mostly-empty (zero-padded) lanes. */
    size_t worst_case_blocks = (plain_len / RECT_BLOCK_SIZE) + 1;
    if (worst_case_blocks < RECT_BS_BLOCKS_AVX2) {
        return rectangle_bitslice_encrypt(key, plain, plain_len, out_len);
    }

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
    size_t n_blocks = ct_len / RECT_BLOCK_SIZE;
    if (n_blocks < RECT_BS_BLOCKS_AVX2) {
        return rectangle_bitslice_decrypt(key, ct, ct_len, out_len);
    }

    uint32_t k0, k1, k2, k3;
    _rect_key_words(key, &k0, &k1, &k2, &k3);
    uint16_t rks[RECT_ROUNDS + 1][4];
    _rect_key_schedule(k0, k1, k2, k3, rks);

    uint8_t *buf = (uint8_t *)malloc(ct_len);
    if (!buf) return NULL;
    memcpy(buf, ct, ct_len);

    _rectangle_avx2_process(buf, n_blocks, rks, 0);

    *out_len = pkcs7_unpad_len(buf, ct_len);
    return buf;
}

#endif
