/*
* test_rectangle_avx2.c - Correctness test for rectangle_avx2.h
*
* Three layers of checks, weakest assumption to strongest, run in order:
*
*   1. words_to_planes_avx2_fast() vs. rectangle.h's words_to_planes(),
*      IN ISOLATION, on many random inputs of every size from 0 to 200
*      words (covering: empty, 1-15 word tail-only, exactly 16, 17
*      (one full chunk + 1 tail), multiple full chunks, multiple full
*      chunks + tail). This is the critical check: if the accelerated
*      transpose doesn't produce bit-identical plane arrays to the
*      trusted scalar version, nothing downstream can be trusted, no
*      matter what a full round-trip test appears to show.
*
*   2. rectangle_avx2_encrypt() ciphertext vs. rectangle_bitslice_encrypt()
*      ciphertext, byte-for-byte, same key/plaintext, at sizes that
*      exercise: the small-input fallback path (below 256 blocks), right
*      at the fallback boundary, and multiple sizes above it (so the
*      AVX2 path with the new transpose actually runs and gets compared).
*      This is the real end-to-end proof that the new transpose composes
*      correctly with the (unchanged, already-correct) round function.
*
*   3. rectangle_avx2_encrypt() -> rectangle_avx2_decrypt() round-trip
*      recovers the original plaintext exactly, at the same set of sizes.
*      Included for completeness, but note this check ALONE would not
*      have caught a bug where encrypt and decrypt are internally
*      consistent with each other but disagree with the reference
*      implementation - that's exactly why check #2 exists.
*
* Build:
*   gcc -O2 -mavx2 -o test_rectangle_avx2 test_rectangle_avx2.c -lm
* Run:
*   ./test_rectangle_avx2
* Exit code 0 = all checks passed. Non-zero = at least one failure, with
* details printed to stderr.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "rectangle.h"
#include "rectangle_avx2.h"

static int g_failures = 0;

static void fail(const char *check, const char *detail) {
    fprintf(stderr, "[FAIL] %s: %s\n", check, detail);
    g_failures++;
}

static void ok(const char *check) {
    printf("[ OK ] %s\n", check);
}

static void fill_random(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)(rand() & 0xFF);
}

static void fill_random_words(uint16_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++) buf[i] = (uint16_t)(rand() & 0xFFFF);
}

/* ---- Check 1: words_to_planes_avx2_fast() vs. words_to_planes() ---- */

static void check_transpose_isolated(void) {
    /* Sizes chosen to hit every structurally distinct code path in
     * words_to_planes_avx2_fast(): 0 (no chunks, no tail), 1-15 (tail
     * only, no full chunks), 16 (exactly one full chunk, no tail), 17
     * (one full chunk + 1-word tail), 32/48/64 (multiple full chunks,
     * no tail), 33/50/70 (multiple full chunks + tail), and RECT_BS_BLOCKS
     * itself (64) plus a couple of values near it since that's the real
     * n used inside _rectangle_avx2_process(). */
    size_t sizes[] = { 0, 1, 5, 15, 16, 17, 31, 32, 33, 48, 50, 63, 64, 70, 100, 127, 128, 129, 200 };
    size_t n_sizes = sizeof(sizes) / sizeof(sizes[0]);

    int all_matched = 1;

    for (size_t s = 0; s < n_sizes; s++) {
        size_t n = sizes[s];
        for (int trial = 0; trial < 20; trial++) {
            uint16_t words[256];
            fill_random_words(words, n);

            plane_t p_scalar[16], p_fast[16];
            words_to_planes(words, n, p_scalar);
            words_to_planes_avx2_fast(words, n, p_fast);

            for (int b = 0; b < 16; b++) {
                if (p_scalar[b] != p_fast[b]) {
                    fprintf(stderr,
                            "  mismatch at n=%zu trial=%d plane[%d]: scalar=0x%016llx fast=0x%016llx\n",
                            n, trial, b,
                            (unsigned long long)p_scalar[b], (unsigned long long)p_fast[b]);
                    all_matched = 0;
                }
            }
        }
    }

    if (all_matched) ok("words_to_planes_avx2_fast matches scalar words_to_planes (all sizes/trials)");
    else fail("words_to_planes_avx2_fast", "output diverged from scalar reference - see mismatches above");
}

/* ---- Check 2: rectangle_avx2_encrypt() vs. rectangle_bitslice_encrypt() ---- */

static int buffers_equal(const uint8_t *a, const uint8_t *b, size_t len) {
    return memcmp(a, b, len) == 0;
}

static void check_ciphertext_matches_reference(void) {
    /* RECT_BLOCK_SIZE = 8 bytes/block. RECT_BS_BLOCKS_AVX2 = 256 blocks
     * = 2048 bytes is the small-input fallback boundary. Sizes below
     * cover: well below the boundary (fallback path), just below it,
     * just above it (first size that should hit the real AVX2 path),
     * and comfortably above it (multiple full 256-block batches, plus a
     * partial trailing batch). */
    size_t sizes[] = {
        1, 100, 1024,                          /* below boundary -> fallback */
        2040, 2047, 2048,                      /* at/just below/at boundary  */
        2049, 2056, 3000,                      /* just above -> AVX2 path    */
        2048 * 2, 2048 * 2 + 500,               /* 2 full batches, +partial  */
        2048 * 5 + 37                          /* 5 full batches, +partial  */
    };
    size_t n_sizes = sizeof(sizes) / sizeof(sizes[0]);

    int all_matched = 1;
    uint8_t key[RECT_KEY_SIZE];

    for (size_t s = 0; s < n_sizes; s++) {
        size_t len = sizes[s];
        fill_random(key, sizeof(key));

        uint8_t *plain = (uint8_t *)malloc(len ? len : 1);
        fill_random(plain, len);

        size_t ref_len = 0, avx_len = 0;
        uint8_t *ref_ct = rectangle_bitslice_encrypt(key, plain, len, &ref_len);
        uint8_t *avx_ct = rectangle_avx2_encrypt(key, plain, len, &avx_len);

        if (!ref_ct || !avx_ct) {
            fprintf(stderr, "  size=%zu: encrypt returned NULL (ref=%p avx=%p)\n",
                    len, (void *)ref_ct, (void *)avx_ct);
            all_matched = 0;
        } else if (ref_len != avx_len) {
            fprintf(stderr, "  size=%zu: output length mismatch (ref=%zu avx=%zu)\n",
                    len, ref_len, avx_len);
            all_matched = 0;
        } else if (!buffers_equal(ref_ct, avx_ct, ref_len)) {
            fprintf(stderr, "  size=%zu: ciphertext MISMATCH vs. reference implementation\n", len);
            all_matched = 0;
        }

        free(plain);
        free(ref_ct);
        free(avx_ct);
    }

    if (all_matched) ok("rectangle_avx2_encrypt matches rectangle_bitslice_encrypt (all sizes)");
    else fail("rectangle_avx2_encrypt", "ciphertext diverged from reference - see mismatches above");
}

/* ---- Check 3: encrypt -> decrypt round-trip ---- */

static void check_round_trip(void) {
    size_t sizes[] = {
        1, 100, 1024, 2040, 2048, 2049, 3000,
        2048 * 2, 2048 * 2 + 500, 2048 * 5 + 37
    };
    size_t n_sizes = sizeof(sizes) / sizeof(sizes[0]);

    int all_matched = 1;
    uint8_t key[RECT_KEY_SIZE];

    for (size_t s = 0; s < n_sizes; s++) {
        size_t len = sizes[s];
        fill_random(key, sizeof(key));

        uint8_t *plain = (uint8_t *)malloc(len ? len : 1);
        fill_random(plain, len);

        size_t ct_len = 0, pt_len = 0;
        uint8_t *ct = rectangle_avx2_encrypt(key, plain, len, &ct_len);
        uint8_t *pt = ct ? rectangle_avx2_decrypt(key, ct, ct_len, &pt_len) : NULL;

        if (!ct || !pt) {
            fprintf(stderr, "  size=%zu: encrypt/decrypt returned NULL\n", len);
            all_matched = 0;
        } else if (pt_len != len) {
            fprintf(stderr, "  size=%zu: decrypted length mismatch (got %zu)\n", len, pt_len);
            all_matched = 0;
        } else if (len > 0 && !buffers_equal(plain, pt, len)) {
            fprintf(stderr, "  size=%zu: decrypted plaintext does not match original\n", len);
            all_matched = 0;
        }

        free(plain);
        free(ct);
        free(pt);
    }

    if (all_matched) ok("rectangle_avx2_encrypt -> rectangle_avx2_decrypt round-trip (all sizes)");
    else fail("rectangle_avx2 round-trip", "decrypted plaintext diverged from original - see mismatches above");
}

int main(void) {
    srand((unsigned)time(NULL));

    if (!rectangle_avx2_available()) {
        fprintf(stderr,
                "This CPU/build does not support AVX2 - these tests exercise "
                "rectangle_avx2_encrypt/decrypt and cannot run without it.\n");
        return 1;
    }

    printf("=== Check 1: transpose isolation ===\n");
    check_transpose_isolated();

    printf("\n=== Check 2: ciphertext vs. reference implementation ===\n");
    check_ciphertext_matches_reference();

    printf("\n=== Check 3: encrypt/decrypt round-trip ===\n");
    check_round_trip();

    printf("\n");
    if (g_failures == 0) {
        printf("All checks passed.\n");
        return 0;
    } else {
        printf("%d check(s) FAILED. Do not trust rectangle_avx2.h until these pass.\n", g_failures);
        return 1;
    }
}
