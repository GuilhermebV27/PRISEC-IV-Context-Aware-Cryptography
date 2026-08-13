/*
* benchmark8.c - PRISEC-IV Phase 8 Benchmark (AES-256+ChaCha20+AES-128
* triple cascade, with and without ECC handshake, with per-layer hardware
* acceleration toggle)
*
* Entries (2 cascades x 4 hardware states = 8 rows per size):
*   AES-256+ChaCha20+AES-128
*   ECC+AES-256+ChaCha20+AES-128
*
* Hardware states (see ecc.h's get_shared_key(): NID_X9_62_prime256v1 P-256
* keygen+ECDH via OpenSSL's ecp_nistz256, plus a SHA-256 hash - both of
* which have their own hardware-accelerated code paths, gated by BMI2/ADX/
* AVX2 bits that live in the SAME OPENSSL_ia32cap word as ChaCha20's SIMD
* acceleration, but NOT in the same word as AES-NI):
*
*   - HW_ON:           native capabilities, nothing disabled.
*                       aes_ha=1, chacha_ha=1, ecc_ha=1 (accelerated).
*   - BOTH_OFF:         AES-NI + ChaCha20 SIMD both disabled (word1 zeroed).
*                       aes_ha=0, chacha_ha=0, ecc_ha=0 (word1 zeroing also
*                       kills BMI2/ADX, so ECC is collaterally slowed here).
*   - AES_ONLY_OFF:     ONLY AES-NI (word0 bit 57) cleared; word1 left
*                       completely untouched/autodetected.
*                       aes_ha=0, chacha_ha=1, ecc_ha=1 - ECC is NOT
*                       affected, because AES-NI has nothing to do with the
*                       BMI2/ADX/AVX2 bits P-256's ecp_nistz256 path uses.
*   - CHACHA_ONLY_OFF:  word0 SSSE3+AVX cleared, word1 zeroed (kills
*                       AVX2/AVX-512 ChaCha20 paths); AES-NI untouched.
*                       aes_ha=1, chacha_ha=0, ecc_ha=0 - ECC IS affected
*                       here too, since word1 zeroing removes BMI2/ADX
*                       regardless of why it was zeroed. This is expected
*                       and left as-is (see conversation): only the
*                       AES-only toggle is required to leave ECC untouched.
*
* ecc_ha is NA for the non-ECC cascade row (no handshake to accelerate).
*
* Layer semantics (mirrors benchmark3.c/benchmark4.c):
*   - Non-ECC entry: layer1/2/3 keys are fresh random bytes, regenerated
*     every outer repeat (benchmark3/5-style).
*   - ECC entry: each layer's key comes from its own independent ECDH
*     handshake via get_shared_key() (benchmark2/4-style); ecc_ms sums all
*     three handshakes.
*   - Encryption order: L1(AES-256) -> L2(ChaCha20) -> L3(AES-128).
*     Decryption order: L3 -> L2 -> L1.
*
* Because OpenSSL resolves ia32cap-gated capabilities in a library-load
* constructor that runs before main(), a plain fork() can't change them
* after the fact - each stage below is a genuine execv() into a fresh
* process image, chained via the PRISEC_PHASE8_STAGE env var:
*   (unset) -> HW_ON -> BOTH_OFF -> AES_ONLY_OFF -> CHACHA_ONLY_OFF -> done
*
* Build:
*   gcc -O2 -fno-stack-protector -o benchmark8 benchmark8.c -lcrypto -lm \
*       -Wl,--wrap=malloc,--wrap=free,--wrap=realloc,--wrap=calloc
* Run:
*   ./benchmark8
*/

#define _POSIX_C_SOURCE 199309L
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>
#include <math.h>
#include <malloc.h>

#include "aes.h"
#include "chacha20.h"
#include "ecc.h"
#include "utils.h"
#include "memtrack.h"

static inline double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

#define STACK_PROBE_SIZE (64 * 1024)
#define CANARY_BYTE 0xAA

__attribute__((noinline))
static void stack_paint(void) {
    volatile uint8_t probe[STACK_PROBE_SIZE];
    memset((void *)probe, CANARY_BYTE, STACK_PROBE_SIZE);
    __asm__ volatile("" ::: "memory");
}

__attribute__((noinline))
static size_t stack_measure(void) {
    volatile uint8_t probe[STACK_PROBE_SIZE];
    size_t touched = 0;
    for (size_t i = 0; i < STACK_PROBE_SIZE; i++) {
        if (probe[i] != CANARY_BYTE) touched++;
    }
    return touched;
}

static inline int get_inner_loops(size_t size_n) {
    if (size_n <= 1 * 1024) return 10000;
    else if (size_n <= 5 * 1024) return 5000;
    else if (size_n <= 10 * 1024) return 2000;
    else if (size_n <= 50 * 1024) return 200;
    else if (size_n <= 100 * 1024) return 100;
    else if (size_n <= 1 * 1024 * 1024) return 50;
    else if (size_n <= 5 * 1024 * 1024) return 10;
    else if (size_n <= 10 * 1024 * 1024) return 5;
    else return 1;
}

static inline int get_outer_repeats(size_t size_n) {
    if (size_n <= 10 * 1024) return 300;
    else if (size_n <= 1 * 1024 * 1024) return 100;
    else return 50;
}

static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a, db = *(const double *)b;
    return (da > db) - (da < db);
}

static double median(double *arr, int n) {
    qsort(arr, n, sizeof(double), cmp_double);
    if (n % 2 == 1) return arr[n / 2];
    return (arr[n / 2 - 1] + arr[n / 2]) / 2.0;
}

typedef int (*enc_fn)(const uint8_t *key, int key_len,
                       const uint8_t *in, size_t in_len,
                       uint8_t **out, size_t *out_len);
typedef int (*dec_fn)(const uint8_t *key, int key_len,
                       const uint8_t *in, size_t in_len,
                       uint8_t **out, size_t *out_len);

static int wrap_aes_enc(const uint8_t *key, int key_len,
                         const uint8_t *in, size_t in_len,
                         uint8_t **out, size_t *out_len) {
    size_t cap = in_len + AES_OVERHEAD;
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf) return 0;
    if (!aes_encrypt(key, key_len, in, in_len, buf, out_len)) { free(buf); return 0; }
    *out = buf;
    return 1;
}

static int wrap_aes_dec(const uint8_t *key, int key_len,
                         const uint8_t *in, size_t in_len,
                         uint8_t **out, size_t *out_len) {
    uint8_t *buf = (uint8_t *)malloc(in_len);
    if (!buf) return 0;
    if (!aes_decrypt(key, key_len, in, in_len, buf, out_len)) { free(buf); return 0; }
    *out = buf;
    return 1;
}

static int wrap_chacha_enc(const uint8_t *key, int key_len,
                            const uint8_t *in, size_t in_len,
                            uint8_t **out, size_t *out_len) {
    size_t cap = in_len + CC20_OVERHEAD;
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf) return 0;
    if (!chacha20_encrypt(key, key_len, in, in_len, buf, out_len)) { free(buf); return 0; }
    *out = buf;
    return 1;
}

static int wrap_chacha_dec(const uint8_t *key, int key_len,
                            const uint8_t *in, size_t in_len,
                            uint8_t **out, size_t *out_len) {
    uint8_t *buf = (uint8_t *)malloc(in_len);
    if (!buf) return 0;
    if (!chacha20_decrypt(key, key_len, in, in_len, buf, out_len)) { free(buf); return 0; }
    *out = buf;
    return 1;
}

typedef struct {
    const char *name;
    int key_len_bytes;
    int is_block_cipher;
    int block_size;
    enc_fn enc;
    dec_fn dec;
} algo_t;

static algo_t AES256 = { "AES-256", 32, 1, 16, wrap_aes_enc, wrap_aes_dec };
static algo_t CHACHA20 = { "ChaCha20", 32, 0, 0, wrap_chacha_enc, wrap_chacha_dec };
static algo_t AES128 = { "AES-128", 16, 1, 16, wrap_aes_enc, wrap_aes_dec };

/* Three-layer cascade: L1 -> L2 -> L3 on encrypt, L3 -> L2 -> L1 on decrypt. */
typedef struct {
    const char *pair_name;
    algo_t *layer1;
    algo_t *layer2;
    algo_t *layer3;
    int use_ecc; /* 1 = derive each layer's key via ECDH, 0 = random keys */
} cascade3_t;

static cascade3_t CASCADES[] = {
    { "AES-256+ChaCha20+AES-128",     &AES256, &CHACHA20, &AES128, 0 },
    { "ECC+AES-256+ChaCha20+AES-128", &AES256, &CHACHA20, &AES128, 1 },
};
#define N_CASCADES (int)(sizeof(CASCADES)/sizeof(CASCADES[0]))

typedef struct { const char *label; size_t bytes; } size_entry_t;

static size_entry_t SIZES[] = {
    { "1KB", 1UL * 1024 },
    { "5KB", 5UL * 1024 },
    { "10KB", 10UL * 1024 },
    { "50KB", 50UL * 1024 },
    { "100KB", 100UL * 1024 },
    { "1MB", 1UL * 1024 * 1024 },
    { "5MB", 5UL * 1024 * 1024 },
    { "10MB", 10UL * 1024 * 1024 },
    { "50MB", 50UL * 1024 * 1024 },
};
#define N_SIZES (int)(sizeof(SIZES)/sizeof(SIZES[0]))

static void fill_random(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)(rand() & 0xFF);
}

typedef struct {
    int valid;
    double ecc_ms;
    double enc_ms, dec_ms;
    double thr_enc_mbps, thr_dec_mbps;
    double latency_us;
    double mem_enc_peak_kb, mem_dec_peak_kb;
    double mem_enc_overhead_kb, mem_dec_overhead_kb;
} result_t;

static void measure_cascade3_memory(algo_t *L1, algo_t *L2, algo_t *L3,
                                     const uint8_t *key1, const uint8_t *key2, const uint8_t *key3,
                                     const uint8_t *plaintext, size_t data_size,
                                     double *mem_enc_peak_kb, double *mem_enc_overhead_kb,
                                     double *mem_dec_peak_kb, double *mem_dec_overhead_kb) {
    uint8_t *ct1 = NULL; size_t ct1_len = 0;
    uint8_t *ct2 = NULL; size_t ct2_len = 0;
    uint8_t *ct3 = NULL; size_t ct3_len = 0;

    size_t base_enc = mt_mark();
    stack_paint();
    L1->enc(key1, L1->key_len_bytes, plaintext, data_size, &ct1, &ct1_len);
    L2->enc(key2, L2->key_len_bytes, ct1, ct1_len, &ct2, &ct2_len);
    L3->enc(key3, L3->key_len_bytes, ct2, ct2_len, &ct3, &ct3_len);
    size_t stack_enc = stack_measure();
    size_t heap_peak_enc = mt_peak_delta(base_enc);

    size_t ct3_buf_bytes = ct3 ? malloc_usable_size(ct3) : 0;
    double total_enc = (double)heap_peak_enc + (double)stack_enc;
    *mem_enc_peak_kb = total_enc / 1024.0;
    double ovh_enc = total_enc - (double)ct3_buf_bytes;
    *mem_enc_overhead_kb = (ovh_enc > 0 ? ovh_enc : 0) / 1024.0;

    free(ct1); ct1 = NULL;
    free(ct2); ct2 = NULL;

    uint8_t *dt2 = NULL; size_t dt2_len = 0;
    uint8_t *dt1 = NULL; size_t dt1_len = 0;
    uint8_t *dt0 = NULL; size_t dt0_len = 0;

    size_t base_dec = mt_mark();
    stack_paint();
    L3->dec(key3, L3->key_len_bytes, ct3, ct3_len, &dt2, &dt2_len);
    L2->dec(key2, L2->key_len_bytes, dt2, dt2_len, &dt1, &dt1_len);
    L1->dec(key1, L1->key_len_bytes, dt1, dt1_len, &dt0, &dt0_len);
    size_t stack_dec = stack_measure();
    size_t heap_peak_dec = mt_peak_delta(base_dec);

    size_t dt0_buf_bytes = dt0 ? malloc_usable_size(dt0) : 0;
    double total_dec = (double)heap_peak_dec + (double)stack_dec;
    *mem_dec_peak_kb = total_dec / 1024.0;
    double ovh_dec = total_dec - (double)dt0_buf_bytes;
    *mem_dec_overhead_kb = (ovh_dec > 0 ? ovh_dec : 0) / 1024.0;

    free(ct3);
    free(dt2);
    free(dt1);
    free(dt0);
}

static result_t run_combo(cascade3_t *casc, size_entry_t *sz) {
    result_t res; memset(&res, 0, sizeof(res));

    size_t data_size = sz->bytes;
    int outer_repeats = get_outer_repeats(data_size);
    int inner_loops = get_inner_loops(data_size);

    algo_t *L1 = casc->layer1;
    algo_t *L2 = casc->layer2;
    algo_t *L3 = casc->layer3;

    uint8_t *plaintext = (uint8_t *)malloc(data_size);
    fill_random(plaintext, data_size);

    double *ecc_means = (double *)malloc(sizeof(double) * outer_repeats);
    double *enc_means = (double *)malloc(sizeof(double) * outer_repeats);
    double *dec_means = (double *)malloc(sizeof(double) * outer_repeats);
    double *thr_enc_means = (double *)malloc(sizeof(double) * outer_repeats);
    double *thr_dec_means = (double *)malloc(sizeof(double) * outer_repeats);
    double *lat_means = (double *)malloc(sizeof(double) * outer_repeats);
    double *mem_enc_peaks = (double *)malloc(sizeof(double) * outer_repeats);
    double *mem_dec_peaks = (double *)malloc(sizeof(double) * outer_repeats);
    double *mem_enc_ovhs = (double *)malloc(sizeof(double) * outer_repeats);
    double *mem_dec_ovhs = (double *)malloc(sizeof(double) * outer_repeats);

    uint8_t (*keys1)[32] = malloc(sizeof(uint8_t[32]) * outer_repeats);
    uint8_t (*keys2)[32] = malloc(sizeof(uint8_t[32]) * outer_repeats);
    uint8_t (*keys3)[32] = malloc(sizeof(uint8_t[32]) * outer_repeats);
    int *handshake_ok = (int *)calloc(outer_repeats, sizeof(int));

    printf("[pid %d] [%s | %s] starting: %d outer repeats x %d inner loops (use_ecc=%d)\n",
           getpid(), casc->pair_name, sz->label, outer_repeats, inner_loops, casc->use_ecc);
    fflush(stdout);

    for (int r = 0; r < outer_repeats; r++) {
        if (casc->use_ecc) {
            double t0 = now_ms();
            int ok1 = get_shared_key(keys1[r], L1->key_len_bytes);
            double t1 = now_ms();
            int ok2 = get_shared_key(keys2[r], L2->key_len_bytes);
            double t2 = now_ms();
            int ok3 = get_shared_key(keys3[r], L3->key_len_bytes);
            double t3 = now_ms();
            ecc_means[r] = (t1 - t0) + (t2 - t1) + (t3 - t2);
            handshake_ok[r] = (ok1 && ok2 && ok3);
            if (!handshake_ok[r]) {
                fprintf(stderr, "[pid %d] [%s | %s] repeat %d: ECC handshake failed\n",
                        getpid(), casc->pair_name, sz->label, r + 1);
            }
        } else {
            fill_random(keys1[r], L1->key_len_bytes);
            fill_random(keys2[r], L2->key_len_bytes);
            fill_random(keys3[r], L3->key_len_bytes);
            ecc_means[r] = 0.0;
            handshake_ok[r] = 1;
        }
    }

    int warm_idx = 0;
    while (warm_idx < outer_repeats && !handshake_ok[warm_idx]) warm_idx++;
    if (warm_idx < outer_repeats) {
        uint8_t *w1 = NULL; size_t w1l = 0;
        uint8_t *w2 = NULL; size_t w2l = 0;
        uint8_t *w3 = NULL; size_t w3l = 0;
        uint8_t *wd2 = NULL; size_t wd2l = 0;
        uint8_t *wd1 = NULL; size_t wd1l = 0;
        uint8_t *wd0 = NULL; size_t wd0l = 0;

        L1->enc(keys1[warm_idx], L1->key_len_bytes, plaintext, data_size, &w1, &w1l);
        if (w1) L2->enc(keys2[warm_idx], L2->key_len_bytes, w1, w1l, &w2, &w2l);
        if (w2) L3->enc(keys3[warm_idx], L3->key_len_bytes, w2, w2l, &w3, &w3l);
        if (w3) L3->dec(keys3[warm_idx], L3->key_len_bytes, w3, w3l, &wd2, &wd2l);
        if (wd2) L2->dec(keys2[warm_idx], L2->key_len_bytes, wd2, wd2l, &wd1, &wd1l);
        if (wd1) L1->dec(keys1[warm_idx], L1->key_len_bytes, wd1, wd1l, &wd0, &wd0l);

        free(w1); free(w2); free(w3); free(wd2); free(wd1); free(wd0);
    }

    for (int r = 0; r < outer_repeats; r++) {
        if (!handshake_ok[r]) {
            enc_means[r] = NAN; dec_means[r] = NAN;
            thr_enc_means[r] = NAN; thr_dec_means[r] = NAN;
            lat_means[r] = NAN;
            mem_enc_peaks[r] = NAN; mem_dec_peaks[r] = NAN;
            mem_enc_ovhs[r] = NAN; mem_dec_ovhs[r] = NAN;
            continue;
        }

        double sum_enc_ms = 0.0, sum_dec_ms = 0.0;

        for (int i = 0; i < inner_loops; i++) {
            uint8_t *ct1 = NULL; size_t ct1_len = 0;
            uint8_t *ct2 = NULL; size_t ct2_len = 0;
            uint8_t *ct3 = NULL; size_t ct3_len = 0;

            double t0 = now_ms();
            L1->enc(keys1[r], L1->key_len_bytes, plaintext, data_size, &ct1, &ct1_len);
            L2->enc(keys2[r], L2->key_len_bytes, ct1, ct1_len, &ct2, &ct2_len);
            L3->enc(keys3[r], L3->key_len_bytes, ct2, ct2_len, &ct3, &ct3_len);
            double t1 = now_ms();
            sum_enc_ms += (t1 - t0);

            uint8_t *dt2 = NULL; size_t dt2_len = 0;
            uint8_t *dt1 = NULL; size_t dt1_len = 0;
            uint8_t *dt0 = NULL; size_t dt0_len = 0;

            double t2 = now_ms();
            L3->dec(keys3[r], L3->key_len_bytes, ct3, ct3_len, &dt2, &dt2_len);
            L2->dec(keys2[r], L2->key_len_bytes, dt2, dt2_len, &dt1, &dt1_len);
            L1->dec(keys1[r], L1->key_len_bytes, dt1, dt1_len, &dt0, &dt0_len);
            double t3 = now_ms();
            sum_dec_ms += (t3 - t2);

            free(ct1); free(ct2); free(ct3);
            free(dt2); free(dt1); free(dt0);
        }

        double mean_enc_ms = sum_enc_ms / inner_loops;
        double mean_dec_ms = sum_dec_ms / inner_loops;

        double mem_enc_peak = 0.0, mem_enc_ovh = 0.0;
        double mem_dec_peak = 0.0, mem_dec_ovh = 0.0;
        measure_cascade3_memory(L1, L2, L3, keys1[r], keys2[r], keys3[r], plaintext, data_size,
                                 &mem_enc_peak, &mem_enc_ovh, &mem_dec_peak, &mem_dec_ovh);

        double data_mbits = (double)data_size * 8.0 / 1e6;
        double thr_enc_mbps = (mean_enc_ms > 0) ? (data_mbits / (mean_enc_ms / 1000.0)) : 0.0;
        double thr_dec_mbps = (mean_dec_ms > 0) ? (data_mbits / (mean_dec_ms / 1000.0)) : 0.0;

        int has_block_layer = L1->is_block_cipher || L2->is_block_cipher || L3->is_block_cipher;
        double latency_us = 0.0;
        if (has_block_layer) {
            int block_size = L1->is_block_cipher ? L1->block_size :
                              (L2->is_block_cipher ? L2->block_size : L3->block_size);
            size_t n_blocks = (data_size + block_size - 1) / block_size;
            latency_us = (mean_enc_ms * 1000.0) / (double)n_blocks;
        }

        enc_means[r] = mean_enc_ms;
        dec_means[r] = mean_dec_ms;
        thr_enc_means[r] = thr_enc_mbps;
        thr_dec_means[r] = thr_dec_mbps;
        lat_means[r] = latency_us;
        mem_enc_peaks[r] = mem_enc_peak;
        mem_dec_peaks[r] = mem_dec_peak;
        mem_enc_ovhs[r] = mem_enc_ovh;
        mem_dec_ovhs[r] = mem_dec_ovh;

        printf("[pid %d] [%s | %s] repeat %d/%d - ecc=%.4fms enc=%.4fms dec=%.4fms "
               "mem_enc_peak=%.4fKB (ovh=%.4fKB) mem_dec_peak=%.4fKB (ovh=%.4fKB)\n",
               getpid(), casc->pair_name, sz->label, r + 1, outer_repeats,
               ecc_means[r], mean_enc_ms, mean_dec_ms,
               mem_enc_peak, mem_enc_ovh, mem_dec_peak, mem_dec_ovh);
        fflush(stdout);
    }

    int valid_count = 0;
    for (int r = 0; r < outer_repeats; r++) if (handshake_ok[r]) valid_count++;

    if (valid_count > 0) {
        double *tmp = (double *)malloc(sizeof(double) * valid_count);
        int idx;

        idx = 0; for (int r = 0; r < outer_repeats; r++) if (handshake_ok[r]) tmp[idx++] = ecc_means[r];
        res.ecc_ms = median(tmp, valid_count);

        idx = 0; for (int r = 0; r < outer_repeats; r++) if (handshake_ok[r]) tmp[idx++] = enc_means[r];
        res.enc_ms = median(tmp, valid_count);

        idx = 0; for (int r = 0; r < outer_repeats; r++) if (handshake_ok[r]) tmp[idx++] = dec_means[r];
        res.dec_ms = median(tmp, valid_count);

        idx = 0; for (int r = 0; r < outer_repeats; r++) if (handshake_ok[r]) tmp[idx++] = thr_enc_means[r];
        res.thr_enc_mbps = median(tmp, valid_count);

        idx = 0; for (int r = 0; r < outer_repeats; r++) if (handshake_ok[r]) tmp[idx++] = thr_dec_means[r];
        res.thr_dec_mbps = median(tmp, valid_count);

        idx = 0; for (int r = 0; r < outer_repeats; r++) if (handshake_ok[r]) tmp[idx++] = lat_means[r];
        res.latency_us = median(tmp, valid_count);

        idx = 0; for (int r = 0; r < outer_repeats; r++) if (handshake_ok[r]) tmp[idx++] = mem_enc_peaks[r];
        res.mem_enc_peak_kb = median(tmp, valid_count);

        idx = 0; for (int r = 0; r < outer_repeats; r++) if (handshake_ok[r]) tmp[idx++] = mem_dec_peaks[r];
        res.mem_dec_peak_kb = median(tmp, valid_count);

        idx = 0; for (int r = 0; r < outer_repeats; r++) if (handshake_ok[r]) tmp[idx++] = mem_enc_ovhs[r];
        res.mem_enc_overhead_kb = median(tmp, valid_count);

        idx = 0; for (int r = 0; r < outer_repeats; r++) if (handshake_ok[r]) tmp[idx++] = mem_dec_ovhs[r];
        res.mem_dec_overhead_kb = median(tmp, valid_count);

        free(tmp);
        res.valid = 1;
    } else {
        res.valid = 0;
    }

    free(plaintext);
    free(keys1); free(keys2); free(keys3);
    free(handshake_ok);
    free(ecc_means);
    free(enc_means); free(dec_means);
    free(thr_enc_means); free(thr_dec_means);
    free(lat_means);
    free(mem_enc_peaks); free(mem_dec_peaks);
    free(mem_enc_ovhs); free(mem_dec_ovhs);

    return res;
}

/* pass_aes_hw/pass_chacha_hw/pass_ecc_hw describe THIS process's actual
 * capability state (this stage's OPENSSL_ia32cap). ecc_ha is only printed
 * for the ECC cascade - the non-ECC row has no handshake to accelerate. */
static void write_row(FILE *csv, cascade3_t *casc, const char *size_label,
                       result_t *res, int pass_aes_hw, int pass_chacha_hw, int pass_ecc_hw) {
    char ecc_field[4];
    if (casc->use_ecc) snprintf(ecc_field, sizeof(ecc_field), "%d", pass_ecc_hw);
    else snprintf(ecc_field, sizeof(ecc_field), "NA");

    if (casc->use_ecc) {
        fprintf(csv, "%s,%s,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%d,%d,%s\n",
                casc->pair_name, size_label,
                res->ecc_ms, res->enc_ms, res->dec_ms,
                res->thr_enc_mbps, res->thr_dec_mbps,
                res->latency_us,
                res->mem_enc_peak_kb, res->mem_enc_overhead_kb,
                res->mem_dec_peak_kb, res->mem_dec_overhead_kb,
                pass_aes_hw, pass_chacha_hw, ecc_field);
    } else {
        fprintf(csv, "%s,%s,NA,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%d,%d,%s\n",
                casc->pair_name, size_label,
                res->enc_ms, res->dec_ms,
                res->thr_enc_mbps, res->thr_dec_mbps,
                res->latency_us,
                res->mem_enc_peak_kb, res->mem_enc_overhead_kb,
                res->mem_dec_peak_kb, res->mem_dec_overhead_kb,
                pass_aes_hw, pass_chacha_hw, ecc_field);
    }
}

static void run_all_combos(FILE *csv, int pass_aes_hw, int pass_chacha_hw, int pass_ecc_hw) {
    for (int c = 0; c < N_CASCADES; c++) {
        for (int s = 0; s < N_SIZES; s++) {
            int pipefd[2];
            if (pipe(pipefd) != 0) {
                fprintf(stderr, "pipe() failed for %s %s\n", CASCADES[c].pair_name, SIZES[s].label);
                continue;
            }

            pid_t pid = fork();
            if (pid < 0) {
                fprintf(stderr, "fork() failed for %s %s\n", CASCADES[c].pair_name, SIZES[s].label);
                close(pipefd[0]); close(pipefd[1]);
                continue;
            }

            if (pid == 0) {
                close(pipefd[0]);
                srand((unsigned)time(NULL) ^ (unsigned)getpid());
                result_t res = run_combo(&CASCADES[c], &SIZES[s]);
                ssize_t written = write(pipefd[1], &res, sizeof(res));
                (void)written;
                close(pipefd[1]);
                _exit(0);
            }

            close(pipefd[1]);
            result_t res; memset(&res, 0, sizeof(res));
            ssize_t n = read(pipefd[0], &res, sizeof(res));
            close(pipefd[0]);
            int status;
            waitpid(pid, &status, 0);

            if (n != (ssize_t)sizeof(res) || !res.valid) {
                fprintf(stderr, "Child failed or returned no data for %s %s\n",
                        CASCADES[c].pair_name, SIZES[s].label);
                continue;
            }

            write_row(csv, &CASCADES[c], SIZES[s].label, &res, pass_aes_hw, pass_chacha_hw, pass_ecc_hw);
            fflush(csv);

            printf("[parent] [%s | %s | aes_ha=%d chacha_ha=%d ecc_ha=%d] finished -> "
                   "enc_ms=%.4f dec_ms=%.4f mem_enc_peak_kb=%.4f mem_dec_peak_kb=%.4f\n\n",
                   CASCADES[c].pair_name, SIZES[s].label, pass_aes_hw, pass_chacha_hw, pass_ecc_hw,
                   res.enc_ms, res.dec_ms, res.mem_enc_peak_kb, res.mem_dec_peak_kb);
            fflush(stdout);
        }
    }
}

int main(int argc, char **argv) {
    const char *stage = getenv("PRISEC_PHASE8_STAGE");

    /* Stage chain: unset -> HW_ON -> BOTH_OFF -> AES_ONLY_OFF ->
     * CHACHA_ONLY_OFF -> done. Each transition sets OPENSSL_ia32cap for
     * the NEXT stage and execv()s, since capability detection is a
     * load-time constructor and can't be changed by a plain fork(). */
    if (!stage) {
        setenv("PRISEC_PHASE8_STAGE", "HW_ON", 1);
        execv(argv[0], argv);
        perror("execv failed to start HW_ON stage");
        return 1;
    }

    if (!mt_install_openssl()) {
        fprintf(stderr, "CRYPTO_set_mem_functions failed; OpenSSL memory would not be tracked\n");
        return 1;
    }

    if (!getenv("PRISEC_TCACHE_DISABLED")) {
        setenv("GLIBC_TUNABLES", "glibc.malloc.tcache_count=0", 1);
        setenv("PRISEC_TCACHE_DISABLED", "1", 1);
        execv("/proc/self/exe", argv);
        perror("execv failed to disable tcache; memory results would be unreliable");
        return 1;
    }

    mallopt(M_MMAP_THRESHOLD, 128 * 1024 * 1024);
    mallopt(M_MMAP_MAX, 0);
    mallopt(M_TRIM_THRESHOLD, -1);

    if (strcmp(stage, "HW_ON") == 0) {
        FILE *csv = fopen("phase8_results.csv", "w");
        if (!csv) {
            fprintf(stderr, "Failed to open phase8_results.csv for writing\n");
            return 1;
        }
        fprintf(csv,
                "cascade,data_size,ecc_ms,enc_ms,dec_ms,"
                "throughput_enc_mbps,throughput_dec_mbps,"
                "latency_us,memory_enc_peak_kb,memory_enc_overhead_kb,"
                "memory_dec_peak_kb,memory_dec_overhead_kb,aes_ha,chacha_ha,ecc_ha\n");

        printf("=== Phase 8, stage 1/4: HW_ON (native, everything accelerated) ===\n");
        fflush(stdout);
        run_all_combos(csv, 1, 1, 1);
        fclose(csv);

        setenv("OPENSSL_ia32cap", "~0x1200020200000000:0", 1); /* BOTH_OFF mask */
        setenv("PRISEC_PHASE8_STAGE", "BOTH_OFF", 1);
        execv(argv[0], argv);
        perror("execv failed to move to BOTH_OFF stage");
        return 1;

    } else if (strcmp(stage, "BOTH_OFF") == 0) {
        FILE *csv = fopen("phase8_results.csv", "a");
        if (!csv) {
            fprintf(stderr, "Failed to open phase8_results.csv for appending\n");
            return 1;
        }

        printf("=== Phase 8, stage 2/4: BOTH_OFF (AES-NI + ChaCha20 SIMD both off; "
               "ECC collaterally unaccelerated too - word1 zeroed) ===\n");
        fflush(stdout);
        run_all_combos(csv, 0, 0, 0);
        fclose(csv);

        setenv("OPENSSL_ia32cap", "~0x0200000000000000", 1); /* AES-NI only, word1 untouched */
        setenv("PRISEC_PHASE8_STAGE", "AES_ONLY_OFF", 1);
        execv(argv[0], argv);
        perror("execv failed to move to AES_ONLY_OFF stage");
        return 1;

    } else if (strcmp(stage, "AES_ONLY_OFF") == 0) {
        FILE *csv = fopen("phase8_results.csv", "a");
        if (!csv) {
            fprintf(stderr, "Failed to open phase8_results.csv for appending\n");
            return 1;
        }

        printf("=== Phase 8, stage 3/4: AES_ONLY_OFF (AES-NI off, ChaCha20 SIMD on; "
               "word1 untouched so ECC's BMI2/ADX stay accelerated) ===\n");
        fflush(stdout);
        run_all_combos(csv, 0, 1, 1);
        fclose(csv);

        setenv("OPENSSL_ia32cap", "~0x1000020000000000:0", 1); /* ChaCha SIMD only */
        setenv("PRISEC_PHASE8_STAGE", "CHACHA_ONLY_OFF", 1);
        execv(argv[0], argv);
        perror("execv failed to move to CHACHA_ONLY_OFF stage");
        return 1;

    } else if (strcmp(stage, "CHACHA_ONLY_OFF") == 0) {
        FILE *csv = fopen("phase8_results.csv", "a");
        if (!csv) {
            fprintf(stderr, "Failed to open phase8_results.csv for appending\n");
            return 1;
        }

        printf("=== Phase 8, stage 4/4: CHACHA_ONLY_OFF (ChaCha20 SIMD off, AES-NI on; "
               "word1 zeroed so ECC is collaterally unaccelerated here too) ===\n");
        fflush(stdout);
        run_all_combos(csv, 1, 0, 0);
        fclose(csv);

        printf("Done. Results written to phase8_results.csv "
               "(2 cascades x 4 hardware states x %d sizes)\n", N_SIZES);
        return 0;
    }

    fprintf(stderr, "Unknown PRISEC_PHASE8_STAGE value: %s\n", stage);
    return 1;
}
