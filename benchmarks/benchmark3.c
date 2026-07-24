/*
 * benchmark3.c - PRISEC-IV Phase 3 Benchmark (cascade / dual-layer encryption)
 *
 * Cascade pairs (layer1 -> layer2):
 *   AES-128   -> AES-256
 *   AES-128   -> HIGHT
 *   AES-128   -> SPECK
 *   ChaCha20  -> AES-256
 *   ChaCha20  -> SPECK
 *   SPECK     -> HIGHT
 *   HIGHT     -> RECTANGLE
 *
 * Build:
 *   gcc -O2 -fno-stack-protector -o benchmark3 benchmark3.c -lcrypto -lm \
 *       -Wl,--wrap=malloc,--wrap=free,--wrap=realloc,--wrap=calloc
 * Run:
 *   ./benchmark3
 */

#define _POSIX_C_SOURCE 199309L
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <malloc.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "aes.h"
#include "chacha20.h"
#include "speck.h"
#include "rectangle.h"
#include "hight.h"
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

typedef struct {
    const char *name;
    int key_len_bytes;
    int is_block_cipher;
    int block_size;
    enc_fn enc;
    dec_fn dec;
} algo_t;

static algo_t AES128    = { "AES-128",   16, 1, 16, wrap_aes_enc,    wrap_aes_dec    };
static algo_t AES256    = { "AES-256",   32, 1, 16, wrap_aes_enc,    wrap_aes_dec    };
static algo_t CHACHA20  = { "ChaCha20",  32, 0,  0, wrap_chacha_enc, wrap_chacha_dec };
static algo_t SPECK_    = { "SPECK",     16, 1, 16, wrap_speck_enc,  wrap_speck_dec  };
static algo_t RECTANGLE_= { "RECTANGLE", 16, 1,  8, wrap_rect_enc,   wrap_rect_dec   };
static algo_t HIGHT_    = { "HIGHT",     16, 1,  8, wrap_hight_enc,  wrap_hight_dec  };

typedef struct {
    const char *pair_name;
    algo_t *layer1;
    algo_t *layer2;
} cascade_t;

static cascade_t CASCADES[] = {
    { "AES-128+AES-256",   &AES128,   &AES256     },
    { "AES-128+HIGHT",     &AES128,   &HIGHT_     },
    { "AES-128+SPECK",     &AES128,   &SPECK_     },
    { "ChaCha20+AES-256",  &CHACHA20, &AES256     },
    { "ChaCha20+SPECK",    &CHACHA20, &SPECK_     },
    { "SPECK+HIGHT",       &SPECK_,   &HIGHT_     },
    { "HIGHT+RECTANGLE",   &HIGHT_,   &RECTANGLE_ },
};
#define N_CASCADES (int)(sizeof(CASCADES)/sizeof(CASCADES[0]))

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

static void fill_random(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)(rand() & 0xFF);
}

typedef struct {
    int valid;
    double enc_ms, dec_ms;
    double thr_enc_mbps, thr_dec_mbps;
    double latency_us;
    double mem_enc_peak_kb, mem_dec_peak_kb;
    double mem_enc_overhead_kb, mem_dec_overhead_kb;
} result_t;

/*
 * Measures the full two-layer cascade as one region, so the peak correctly
 * includes the intermediate ciphertext that stays alive while layer 2 runs.
 *
 * Peak memory  = peak heap growth during the cascade (intermediate buffer,
 *                final output buffer, every transient allocation such as
 *                OpenSSL's EVP context) + peak stack usage.
 * Overhead     = peak memory minus the final output buffer, i.e. everything
 *                the cascade needs beyond what a single-shot API must return.
 *                The intermediate ciphertext counts as overhead: it is a real
 *                cost of cascading that a single cipher does not pay.
 */
static void measure_cascade_memory(algo_t *L1, algo_t *L2,
                                    const uint8_t *key1, const uint8_t *key2,
                                    const uint8_t *plaintext, size_t data_size,
                                    double *mem_enc_peak_kb, double *mem_enc_overhead_kb,
                                    double *mem_dec_peak_kb, double *mem_dec_overhead_kb) {
    uint8_t *ct1 = NULL; size_t ct1_len = 0;
    uint8_t *ct2 = NULL; size_t ct2_len = 0;

    size_t base_enc = mt_mark();
    stack_paint();
    L1->enc(key1, L1->key_len_bytes, plaintext, data_size, &ct1, &ct1_len);
    L2->enc(key2, L2->key_len_bytes, ct1, ct1_len, &ct2, &ct2_len);
    size_t stack_enc = stack_measure();
    size_t heap_peak_enc = mt_peak_delta(base_enc);

    size_t ct2_buf_bytes = ct2 ? malloc_usable_size(ct2) : 0;
    double total_enc = (double)heap_peak_enc + (double)stack_enc;
    *mem_enc_peak_kb = total_enc / 1024.0;
    double ovh_enc = total_enc - (double)ct2_buf_bytes;
    *mem_enc_overhead_kb = (ovh_enc > 0 ? ovh_enc : 0) / 1024.0;

    free(ct1); ct1 = NULL;

    uint8_t *dt1 = NULL; size_t dt1_len = 0;
    uint8_t *dt0 = NULL; size_t dt0_len = 0;

    size_t base_dec = mt_mark();
    stack_paint();
    L2->dec(key2, L2->key_len_bytes, ct2, ct2_len, &dt1, &dt1_len);
    L1->dec(key1, L1->key_len_bytes, dt1, dt1_len, &dt0, &dt0_len);
    size_t stack_dec = stack_measure();
    size_t heap_peak_dec = mt_peak_delta(base_dec);

    size_t dt0_buf_bytes = dt0 ? malloc_usable_size(dt0) : 0;
    double total_dec = (double)heap_peak_dec + (double)stack_dec;
    *mem_dec_peak_kb = total_dec / 1024.0;
    double ovh_dec = total_dec - (double)dt0_buf_bytes;
    *mem_dec_overhead_kb = (ovh_dec > 0 ? ovh_dec : 0) / 1024.0;

    free(ct2);
    free(dt1);
    free(dt0);
}

static result_t run_combo(cascade_t *casc, size_entry_t *sz) {
    result_t res; memset(&res, 0, sizeof(res));

    size_t data_size = sz->bytes;
    int outer_repeats = get_outer_repeats(data_size);
    int inner_loops = get_inner_loops(data_size);

    algo_t *L1 = casc->layer1;
    algo_t *L2 = casc->layer2;

    uint8_t *key1 = (uint8_t *)malloc(L1->key_len_bytes);
    uint8_t *key2 = (uint8_t *)malloc(L2->key_len_bytes);
    uint8_t *plaintext = (uint8_t *)malloc(data_size);
    fill_random(plaintext, data_size);

    double *enc_means      = (double *)malloc(sizeof(double) * outer_repeats);
    double *dec_means      = (double *)malloc(sizeof(double) * outer_repeats);
    double *thr_enc_means  = (double *)malloc(sizeof(double) * outer_repeats);
    double *thr_dec_means  = (double *)malloc(sizeof(double) * outer_repeats);
    double *lat_means      = (double *)malloc(sizeof(double) * outer_repeats);
    double *mem_enc_peaks  = (double *)malloc(sizeof(double) * outer_repeats);
    double *mem_dec_peaks  = (double *)malloc(sizeof(double) * outer_repeats);
    double *mem_enc_ovhs   = (double *)malloc(sizeof(double) * outer_repeats);
    double *mem_dec_ovhs   = (double *)malloc(sizeof(double) * outer_repeats);

    printf("[pid %d] [%s | %s] starting: %d outer repeats x %d inner loops (independent keys per layer)\n",
           getpid(), casc->pair_name, sz->label, outer_repeats, inner_loops);
    fflush(stdout);

    for (int r = 0; r < outer_repeats; r++) {
        fill_random(key1, L1->key_len_bytes);
        fill_random(key2, L2->key_len_bytes);

        double sum_enc_ms = 0.0, sum_dec_ms = 0.0;

        for (int i = 0; i < inner_loops; i++) {
            uint8_t *ct1 = NULL; size_t ct1_len = 0;
            uint8_t *ct2 = NULL; size_t ct2_len = 0;

            double t0 = now_ms();
            L1->enc(key1, L1->key_len_bytes, plaintext, data_size, &ct1, &ct1_len);
            double t1 = now_ms();
            L2->enc(key2, L2->key_len_bytes, ct1, ct1_len, &ct2, &ct2_len);
            double t2 = now_ms();
            sum_enc_ms += (t2 - t0);

            uint8_t *dt1 = NULL; size_t dt1_len = 0;
            uint8_t *dt0 = NULL; size_t dt0_len = 0;

            double t3 = now_ms();
            L2->dec(key2, L2->key_len_bytes, ct2, ct2_len, &dt1, &dt1_len);
            double t4 = now_ms();
            L1->dec(key1, L1->key_len_bytes, dt1, dt1_len, &dt0, &dt0_len);
            double t5 = now_ms();
            sum_dec_ms += (t5 - t3);

            free(ct1); free(ct2);
            free(dt1); free(dt0);
        }

        double mean_enc_ms = sum_enc_ms / inner_loops;
        double mean_dec_ms = sum_dec_ms / inner_loops;

        double mem_enc_peak = 0.0, mem_enc_ovh = 0.0;
        double mem_dec_peak = 0.0, mem_dec_ovh = 0.0;
        measure_cascade_memory(L1, L2, key1, key2, plaintext, data_size,
                               &mem_enc_peak, &mem_enc_ovh,
                               &mem_dec_peak, &mem_dec_ovh);

        double data_mbits = (double)data_size * 8.0 / 1e6;
        double thr_enc_mbps = (mean_enc_ms > 0) ? (data_mbits / (mean_enc_ms / 1000.0)) : 0.0;
        double thr_dec_mbps = (mean_dec_ms > 0) ? (data_mbits / (mean_dec_ms / 1000.0)) : 0.0;

        double latency_us = 0.0;
        int has_block_layer = L1->is_block_cipher || L2->is_block_cipher;
        if (has_block_layer) {
            int block_size = L1->is_block_cipher ? L1->block_size : L2->block_size;
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
        mem_enc_ovhs[r]  = mem_enc_ovh;
        mem_dec_ovhs[r]  = mem_dec_ovh;

        printf("[pid %d] [%s | %s] repeat %d/%d - enc=%.4fms dec=%.4fms mem_enc_peak=%.4fKB (ovh=%.4fKB) mem_dec_peak=%.4fKB (ovh=%.4fKB)\n",
               getpid(), casc->pair_name, sz->label, r + 1, outer_repeats,
               mean_enc_ms, mean_dec_ms, mem_enc_peak, mem_enc_ovh, mem_dec_peak, mem_dec_ovh);
        fflush(stdout);
    }

    res.enc_ms = median(enc_means, outer_repeats);
    res.dec_ms = median(dec_means, outer_repeats);
    res.thr_enc_mbps = median(thr_enc_means, outer_repeats);
    res.thr_dec_mbps = median(thr_dec_means, outer_repeats);
    res.latency_us = (L1->is_block_cipher || L2->is_block_cipher) ? median(lat_means, outer_repeats) : NAN;
    res.mem_enc_peak_kb = median(mem_enc_peaks, outer_repeats);
    res.mem_dec_peak_kb = median(mem_dec_peaks, outer_repeats);
    res.mem_enc_overhead_kb = median(mem_enc_ovhs, outer_repeats);
    res.mem_dec_overhead_kb = median(mem_dec_ovhs, outer_repeats);
    res.valid = 1;

    free(key1); free(key2); free(plaintext);
    free(enc_means); free(dec_means);
    free(thr_enc_means); free(thr_dec_means);
    free(lat_means);
    free(mem_enc_peaks); free(mem_dec_peaks);
    free(mem_enc_ovhs); free(mem_dec_ovhs);

    return res;
}

int main(int argc, char **argv) {
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

    FILE *csv = fopen("phase3_results.csv", "w");
    if (!csv) {
        fprintf(stderr, "Failed to open phase3_results.csv for writing\n");
        return 1;
    }

    fprintf(csv,
        "cascade,data_size,enc_ms,dec_ms,"
        "throughput_enc_mbps,throughput_dec_mbps,"
        "latency_us,memory_enc_peak_kb,memory_enc_overhead_kb,"
        "memory_dec_peak_kb,memory_dec_overhead_kb\n");

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
            result_t res;
            memset(&res, 0, sizeof(res));
            ssize_t n = read(pipefd[0], &res, sizeof(res));
            close(pipefd[0]);

            int status;
            waitpid(pid, &status, 0);

            if (n != (ssize_t)sizeof(res) || !res.valid) {
                fprintf(stderr, "Child failed or returned no data for %s %s\n",
                        CASCADES[c].pair_name, SIZES[s].label);
                continue;
            }

            int has_block_layer = CASCADES[c].layer1->is_block_cipher || CASCADES[c].layer2->is_block_cipher;

            if (has_block_layer) {
                fprintf(csv, "%s,%s,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f\n",
                        CASCADES[c].pair_name, SIZES[s].label,
                        res.enc_ms, res.dec_ms,
                        res.thr_enc_mbps, res.thr_dec_mbps,
                        res.latency_us,
                        res.mem_enc_peak_kb, res.mem_enc_overhead_kb,
                        res.mem_dec_peak_kb, res.mem_dec_overhead_kb);
            } else {
                fprintf(csv, "%s,%s,%.4f,%.4f,%.4f,%.4f,NA,%.4f,%.4f,%.4f,%.4f\n",
                        CASCADES[c].pair_name, SIZES[s].label,
                        res.enc_ms, res.dec_ms,
                        res.thr_enc_mbps, res.thr_dec_mbps,
                        res.mem_enc_peak_kb, res.mem_enc_overhead_kb,
                        res.mem_dec_peak_kb, res.mem_dec_overhead_kb);
            }
            fflush(csv);

            printf("[parent] [%s | %s] finished -> enc_ms=%.4f dec_ms=%.4f mem_enc_peak_kb=%.4f (ovh=%.4f) mem_dec_peak_kb=%.4f (ovh=%.4f)\n\n",
                   CASCADES[c].pair_name, SIZES[s].label, res.enc_ms, res.dec_ms,
                   res.mem_enc_peak_kb, res.mem_enc_overhead_kb,
                   res.mem_dec_peak_kb, res.mem_dec_overhead_kb);
            fflush(stdout);
        }
    }

    fclose(csv);
    return 0;
}