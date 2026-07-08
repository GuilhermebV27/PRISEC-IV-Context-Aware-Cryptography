#define _POSIX_C_SOURCE 199309L
/*
 * benchmark1.c - PRISEC-IV Phase 1 Benchmark
 *
 * Benchmarks: AES-128, AES-192, AES-256, ChaCha20, SPECK, RECTANGLE, HIGHT
 * Data sizes: 1KB,5KB,10KB,50KB,100KB,1MB,5MB,10MB,50MB
 * Metrics: encryption time (ms), decryption time (ms), throughput (Mbps) enc/dec,
 *          latency (ms/block) for block ciphers, RAM usage (KB, via getrusage ru_maxrss delta)
 *
 * Repeat structure:
 *   outer repeats: 300 (<=10KB), 100 (<=1MB), 50 (>1MB)
 *   inner loops per outer repeat: per get_inner_loops()
 *   -> mean of each metric across inner loops = one sample per outer repeat
 *   -> median of the outer-repeat means = value written to CSV
 *
 * Build (Ubuntu):
 *   gcc -O2 -o benchmark1 benchmark1.c -lcrypto -lm
 *
 * Run:
 *   ./benchmark1 > phase1_results.csv
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/resource.h>
#include <math.h>

#include "aes.h"
#include "chacha20.h"
#include "speck.h"
#include "rectangle.h"
#include "hight.h"
#include "ecc.h"
#include "utils.h"

/* ---------------- Utility: high resolution timer ---------------- */
static inline double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

/* Peak resident set size in KB (Linux getrusage reports KB already) */
static inline long get_peak_rss_kb(void) {
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    return ru.ru_maxrss;
}

/* ---------------- Inner loop count rule (BUG-FIXED) ---------------- */
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

/* Outer repeat count rule, per Guilherme's Phase 1 spec */
static inline int get_outer_repeats(size_t size_n) {
    if (size_n <= 10 * 1024) return 300;
    else if (size_n <= 1 * 1024 * 1024) return 100;
    else return 50;
}

/* ---------------- Median helper ---------------- */
static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a, db = *(const double *)b;
    return (da > db) - (da < db);
}

static double median(double *arr, int n) {
    qsort(arr, n, sizeof(double), cmp_double);
    if (n % 2 == 1) return arr[n / 2];
    return (arr[n / 2 - 1] + arr[n / 2]) / 2.0;
}

/* ---------------- Unified wrapper signatures ----------------
 * All algorithms are normalized to this signature so the benchmark
 * loop can be table-driven regardless of the underlying header's API.
 * Returns 1 on success, 0 on failure. *out is heap-allocated; caller frees.
 */
typedef int (*enc_fn)(const uint8_t *key, int key_len,
                       const uint8_t *in, size_t in_len,
                       uint8_t **out, size_t *out_len);
typedef int (*dec_fn)(const uint8_t *key, int key_len,
                       const uint8_t *in, size_t in_len,
                       uint8_t **out, size_t *out_len);

/* ---- AES (AEAD/CCM, variable key length selects 128/192/256) ---- */
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

/* ---- ChaCha20-Poly1305 (stream, key_len ignored - always 32 bytes) ---- */
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

/* ---- SPECK (block, malloc'd-buffer API) ---- */
static int wrap_speck_enc(const uint8_t *key, int key_len,
                           const uint8_t *in, size_t in_len,
                           uint8_t **out, size_t *out_len) {
    (void)key_len;
    uint8_t *buf = speck_encrypt(key, in, in_len, out_len);
    if (!buf) return 0;
    *out = buf;
    return 1;
}
static int wrap_speck_dec(const uint8_t *key, int key_len,
                           const uint8_t *in, size_t in_len,
                           uint8_t **out, size_t *out_len) {
    (void)key_len;
    uint8_t *buf = speck_decrypt(key, in, in_len, out_len);
    if (!buf) return 0;
    *out = buf;
    return 1;
}

/* ---- RECTANGLE (block, malloc'd-buffer API) ---- */
static int wrap_rect_enc(const uint8_t *key, int key_len,
                          const uint8_t *in, size_t in_len,
                          uint8_t **out, size_t *out_len) {
    (void)key_len;
    uint8_t *buf = rectangle_encrypt(key, in, in_len, out_len);
    if (!buf) return 0;
    *out = buf;
    return 1;
}
static int wrap_rect_dec(const uint8_t *key, int key_len,
                          const uint8_t *in, size_t in_len,
                          uint8_t **out, size_t *out_len) {
    (void)key_len;
    uint8_t *buf = rectangle_decrypt(key, in, in_len, out_len);
    if (!buf) return 0;
    *out = buf;
    return 1;
}

/* ---- HIGHT (block, void-return encrypt with out-param, malloc'd decrypt) ---- */
static int wrap_hight_enc(const uint8_t *key, int key_len,
                           const uint8_t *in, size_t in_len,
                           uint8_t **out, size_t *out_len) {
    (void)key_len;
    hight_encrypt(key, in, in_len, out, out_len);
    return (*out != NULL);
}
static int wrap_hight_dec(const uint8_t *key, int key_len,
                           const uint8_t *in, size_t in_len,
                           uint8_t **out, size_t *out_len) {
    (void)key_len;
    uint8_t *buf = hight_decrypt(key, in, in_len, out_len);
    if (!buf) return 0;
    *out = buf;
    return 1;
}

/* ---------------- Algorithm registry ---------------- */
typedef struct {
    const char *name;
    int key_len_bytes;      /* key length to generate/pass */
    int is_block_cipher;    /* 1 = block cipher (latency applies), 0 = stream */
    int block_size;         /* used for latency = time / n_blocks */
    enc_fn enc;
    dec_fn dec;
} algo_t;

static algo_t ALGOS[] = {
    { "AES-128",    16, 1, 16, wrap_aes_enc,    wrap_aes_dec    },
    { "AES-192",    24, 1, 16, wrap_aes_enc,    wrap_aes_dec    },
    { "AES-256",    32, 1, 16, wrap_aes_enc,    wrap_aes_dec    },
    { "ChaCha20",   32, 0,  0, wrap_chacha_enc, wrap_chacha_dec },
    { "SPECK",      16, 1, 16, wrap_speck_enc,  wrap_speck_dec  },
    { "RECTANGLE",  16, 1,  8, wrap_rect_enc,   wrap_rect_dec   },
    { "HIGHT",      16, 1,  8, wrap_hight_enc,  wrap_hight_dec  },
};
#define N_ALGOS (int)(sizeof(ALGOS)/sizeof(ALGOS[0]))

/* ---------------- Data size registry ---------------- */
typedef struct { const char *label; size_t bytes; } size_entry_t;

static size_entry_t SIZES[] = {
    { "1KB",   1UL * 1024 },
    { "5KB",   5UL * 1024 },
    { "10KB",  10UL * 1024 },
    { "50KB",  50UL * 1024 },
    { "100KB", 100UL * 1024 },
    { "1MB",   1UL * 1024 * 1024 },
    { "5MB",   5UL * 1024 * 1024 },
    { "10MB",  10UL * 1024 * 1024 },
    { "50MB",  50UL * 1024 * 1024 },
};
#define N_SIZES (int)(sizeof(SIZES)/sizeof(SIZES[0]))

/* ---------------- Random buffer / key generation ---------------- */
static void fill_random(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)(rand() & 0xFF);
}

int main(void) {
    srand((unsigned)time(NULL));

    printf("algorithm,key_size_bits,data_size_label,data_size_bytes,"
           "outer_repeats,inner_loops,"
           "enc_time_ms_median,dec_time_ms_median,"
           "throughput_enc_mbps_median,throughput_dec_mbps_median,"
           "latency_ms_median,ram_kb_median\n");

    for (int a = 0; a < N_ALGOS; a++) {
        algo_t *algo = &ALGOS[a];
        uint8_t *key = (uint8_t *)malloc(algo->key_len_bytes);
        fill_random(key, algo->key_len_bytes);

        for (int s = 0; s < N_SIZES; s++) {
            size_t data_size = SIZES[s].bytes;
            int outer_repeats = get_outer_repeats(data_size);
            int inner_loops = get_inner_loops(data_size);

            uint8_t *plaintext = (uint8_t *)malloc(data_size);
            fill_random(plaintext, data_size);

            double *enc_means = (double *)malloc(sizeof(double) * outer_repeats);
            double *dec_means = (double *)malloc(sizeof(double) * outer_repeats);
            double *thr_enc_means = (double *)malloc(sizeof(double) * outer_repeats);
            double *thr_dec_means = (double *)malloc(sizeof(double) * outer_repeats);
            double *lat_means = (double *)malloc(sizeof(double) * outer_repeats);
            double *ram_means = (double *)malloc(sizeof(double) * outer_repeats);

            for (int r = 0; r < outer_repeats; r++) {
                double sum_enc_ms = 0.0, sum_dec_ms = 0.0;
                long ram_before = get_peak_rss_kb();

                for (int i = 0; i < inner_loops; i++) {
                    uint8_t *ct = NULL; size_t ct_len = 0;
                    double t0 = now_ms();
                    if (!algo->enc(key, algo->key_len_bytes, plaintext, data_size, &ct, &ct_len)) {
                        fprintf(stderr, "Encrypt failed: %s size=%s\n", algo->name, SIZES[s].label);
                        exit(1);
                    }
                    double t1 = now_ms();
                    sum_enc_ms += (t1 - t0);

                    uint8_t *pt = NULL; size_t pt_len = 0;
                    double t2 = now_ms();
                    if (!algo->dec(key, algo->key_len_bytes, ct, ct_len, &pt, &pt_len)) {
                        fprintf(stderr, "Decrypt failed: %s size=%s\n", algo->name, SIZES[s].label);
                        exit(1);
                    }
                    double t3 = now_ms();
                    sum_dec_ms += (t3 - t2);

                    free(ct);
                    free(pt);
                }

                long ram_after = get_peak_rss_kb();

                double mean_enc_ms = sum_enc_ms / inner_loops;
                double mean_dec_ms = sum_dec_ms / inner_loops;

                double data_mbits = (double)data_size * 8.0 / 1e6;
                double thr_enc_mbps = (mean_enc_ms > 0) ? (data_mbits / (mean_enc_ms / 1000.0)) : 0.0;
                double thr_dec_mbps = (mean_dec_ms > 0) ? (data_mbits / (mean_dec_ms / 1000.0)) : 0.0;

                double latency_ms = 0.0;
                if (algo->is_block_cipher) {
                    size_t n_blocks = (data_size + algo->block_size - 1) / algo->block_size;
                    latency_ms = mean_enc_ms / (double)n_blocks;
                }

                double ram_delta_kb = (double)(ram_after - ram_before);
                if (ram_delta_kb < 0) ram_delta_kb = 0; /* rss is non-decreasing high-water mark */

                enc_means[r] = mean_enc_ms;
                dec_means[r] = mean_dec_ms;
                thr_enc_means[r] = thr_enc_mbps;
                thr_dec_means[r] = thr_dec_mbps;
                lat_means[r] = latency_ms;
                ram_means[r] = ram_delta_kb;
            }

            double enc_med = median(enc_means, outer_repeats);
            double dec_med = median(dec_means, outer_repeats);
            double thr_enc_med = median(thr_enc_means, outer_repeats);
            double thr_dec_med = median(thr_dec_means, outer_repeats);
            double lat_med = algo->is_block_cipher ? median(lat_means, outer_repeats) : NAN;
            double ram_med = median(ram_means, outer_repeats);

            if (algo->is_block_cipher) {
                printf("%s,%d,%s,%zu,%d,%d,%.6f,%.6f,%.6f,%.6f,%.6f,%.2f\n",
                       algo->name, algo->key_len_bytes * 8, SIZES[s].label, data_size,
                       outer_repeats, inner_loops,
                       enc_med, dec_med, thr_enc_med, thr_dec_med, lat_med, ram_med);
            } else {
                printf("%s,%d,%s,%zu,%d,%d,%.6f,%.6f,%.6f,%.6f,NA,%.2f\n",
                       algo->name, algo->key_len_bytes * 8, SIZES[s].label, data_size,
                       outer_repeats, inner_loops,
                       enc_med, dec_med, thr_enc_med, thr_dec_med, ram_med);
            }

            fflush(stdout);

            free(plaintext);
            free(enc_means); free(dec_means);
            free(thr_enc_means); free(thr_dec_means);
            free(lat_means); free(ram_means);
        }

        free(key);
    }

    return 0;
}
