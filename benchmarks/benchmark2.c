/*
 * benchmark2.c - PRISEC-IV Phase 2 Benchmark (ECC handshake + Cipher)
 *
 *   ECC + AES-128
 *   ECC + AES-256
 *   ECC + ChaCha20
 *   ECC + SPECK
 *   ECC + RECTANGLE
 *   ECC + HIGHT
 * 
 *
 * Build:
 *   gcc -O2 -fno-stack-protector -o benchmark2 benchmark2.c -lcrypto -lm \
 *       -Wl,--wrap=malloc,--wrap=free,--wrap=realloc,--wrap=calloc
 * Run:
 *   ./benchmark2
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
#include <malloc.h>
#include <math.h>

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

static algo_t ALGOS[] = {
    { "ECC+AES-128",    16, 1, 16, wrap_aes_enc,    wrap_aes_dec },
    { "ECC+AES-256",    32, 1, 16, wrap_aes_enc,    wrap_aes_dec },
    { "ECC+ChaCha20",   32, 0, 0,  wrap_chacha_enc, wrap_chacha_dec },
    { "ECC+SPECK",      16, 1, 16, wrap_speck_enc,  wrap_speck_dec },
    { "ECC+RECTANGLE",  16, 1, 8,  wrap_rect_enc,   wrap_rect_dec },
    { "ECC+HIGHT",      16, 1, 8,  wrap_hight_enc,  wrap_hight_dec },
};
#define N_ALGOS (int)(sizeof(ALGOS)/sizeof(ALGOS[0]))

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
    double ecc_ms;
    double enc_ms, dec_ms;
    double thr_enc_mbps, thr_dec_mbps;
    double latency_us;
    double mem_enc_peak_kb, mem_dec_peak_kb;
    double mem_enc_overhead_kb, mem_dec_overhead_kb;
} result_t;

/*
 * Peak memory  = peak heap growth during the call (includes the output buffer
 *                and every transient allocation, e.g. OpenSSL's EVP context)
 *              + peak stack usage.
 * Overhead     = peak memory minus the output buffer that any implementation
 *                would need, i.e. the algorithm's own working memory.
 */
static void measure_memory_isolated(algo_t *algo, const uint8_t *key,
                                     const uint8_t *plaintext, size_t data_size,
                                     double *mem_enc_peak_kb, double *mem_enc_overhead_kb,
                                     double *mem_dec_peak_kb, double *mem_dec_overhead_kb) {
    uint8_t *ct = NULL; size_t ct_len = 0;

    size_t base_enc = mt_mark();
    stack_paint();
    algo->enc(key, algo->key_len_bytes, plaintext, data_size, &ct, &ct_len);
    size_t stack_enc = stack_measure();
    size_t heap_peak_enc = mt_peak_delta(base_enc);

    size_t ct_buf_bytes = ct ? malloc_usable_size(ct) : 0;
    double total_enc = (double)heap_peak_enc + (double)stack_enc;
    *mem_enc_peak_kb = total_enc / 1024.0;
    double ovh_enc = total_enc - (double)ct_buf_bytes;
    *mem_enc_overhead_kb = (ovh_enc > 0 ? ovh_enc : 0) / 1024.0;

    uint8_t *pt = NULL; size_t pt_len = 0;

    size_t base_dec = mt_mark();
    stack_paint();
    algo->dec(key, algo->key_len_bytes, ct, ct_len, &pt, &pt_len);
    size_t stack_dec = stack_measure();
    size_t heap_peak_dec = mt_peak_delta(base_dec);

    size_t pt_buf_bytes = pt ? malloc_usable_size(pt) : 0;
    double total_dec = (double)heap_peak_dec + (double)stack_dec;
    *mem_dec_peak_kb = total_dec / 1024.0;
    double ovh_dec = total_dec - (double)pt_buf_bytes;
    *mem_dec_overhead_kb = (ovh_dec > 0 ? ovh_dec : 0) / 1024.0;

    free(ct);
    free(pt);
}

static result_t run_combo(algo_t *algo, size_entry_t *sz) {
    result_t res; memset(&res, 0, sizeof(res));

    size_t data_size = sz->bytes;
    int outer_repeats = get_outer_repeats(data_size);
    int inner_loops = get_inner_loops(data_size);

    uint8_t *plaintext = (uint8_t *)malloc(data_size);
    fill_random(plaintext, data_size);

    double *ecc_means     = (double *)malloc(sizeof(double) * outer_repeats);
    double *enc_means     = (double *)malloc(sizeof(double) * outer_repeats);
    double *dec_means     = (double *)malloc(sizeof(double) * outer_repeats);
    double *thr_enc_means = (double *)malloc(sizeof(double) * outer_repeats);
    double *thr_dec_means = (double *)malloc(sizeof(double) * outer_repeats);
    double *lat_means     = (double *)malloc(sizeof(double) * outer_repeats);
    double *mem_enc_peaks = (double *)malloc(sizeof(double) * outer_repeats);
    double *mem_dec_peaks = (double *)malloc(sizeof(double) * outer_repeats);
    double *mem_enc_ovhs  = (double *)malloc(sizeof(double) * outer_repeats);
    double *mem_dec_ovhs  = (double *)malloc(sizeof(double) * outer_repeats);

    uint8_t (*keys)[32] = malloc(sizeof(uint8_t[32]) * outer_repeats);
    int *handshake_ok = (int *)calloc(outer_repeats, sizeof(int));

    printf("[pid %d] [%s | %s] starting: %d outer repeats x %d inner loops "
           "(Phase A: %d ECC handshakes, then warmup, then Phase B: symmetric timing)\n",
           getpid(), algo->name, sz->label, outer_repeats, inner_loops, outer_repeats);
    fflush(stdout);

    for (int r = 0; r < outer_repeats; r++) {
        double ecc_t0 = now_ms();
        int ecc_ok = get_shared_key(keys[r], algo->key_len_bytes);
        double ecc_t1 = now_ms();
        double ecc_ms = ecc_t1 - ecc_t0;

        handshake_ok[r] = ecc_ok;
        ecc_means[r] = ecc_ms;

        if (!ecc_ok) {
            fprintf(stderr, "[pid %d] [%s | %s] repeat %d: ECC handshake failed\n",
                    getpid(), algo->name, sz->label, r + 1);
        }
    }

    {
        int warm_idx = 0;
        while (warm_idx < outer_repeats && !handshake_ok[warm_idx]) warm_idx++;
        if (warm_idx < outer_repeats) {
            uint8_t *wct = NULL; size_t wct_len = 0;
            uint8_t *wpt = NULL; size_t wpt_len = 0;
            algo->enc(keys[warm_idx], algo->key_len_bytes, plaintext, data_size, &wct, &wct_len);
            if (wct) algo->dec(keys[warm_idx], algo->key_len_bytes, wct, wct_len, &wpt, &wpt_len);
            free(wct);
            free(wpt);
        }
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
            uint8_t *ct = NULL; size_t ct_len = 0;

            double t0 = now_ms();
            algo->enc(keys[r], algo->key_len_bytes, plaintext, data_size, &ct, &ct_len);
            double t1 = now_ms();
            sum_enc_ms += (t1 - t0);

            uint8_t *pt = NULL; size_t pt_len = 0;
            double t2 = now_ms();
            algo->dec(keys[r], algo->key_len_bytes, ct, ct_len, &pt, &pt_len);
            double t3 = now_ms();
            sum_dec_ms += (t3 - t2);

            free(ct);
            free(pt);
        }

        double mean_enc_ms = sum_enc_ms / inner_loops;
        double mean_dec_ms = sum_dec_ms / inner_loops;

        double mem_enc_peak = 0.0, mem_enc_ovh = 0.0;
        double mem_dec_peak = 0.0, mem_dec_ovh = 0.0;
        measure_memory_isolated(algo, keys[r], plaintext, data_size,
                                &mem_enc_peak, &mem_enc_ovh,
                                &mem_dec_peak, &mem_dec_ovh);

        double data_mbits = (double)data_size * 8.0 / 1e6;
        double thr_enc_mbps = (mean_enc_ms > 0) ? (data_mbits / (mean_enc_ms / 1000.0)) : 0.0;
        double thr_dec_mbps = (mean_dec_ms > 0) ? (data_mbits / (mean_dec_ms / 1000.0)) : 0.0;

        double latency_us = 0.0;
        if (algo->is_block_cipher) {
            size_t n_blocks = (data_size + algo->block_size - 1) / algo->block_size;
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

        printf("[pid %d] [%s | %s] repeat %d/%d - ecc=%.4fms enc=%.4fms dec=%.4fms mem_enc_peak=%.4fKB (ovh=%.4fKB) mem_dec_peak=%.4fKB (ovh=%.4fKB)\n",
               getpid(), algo->name, sz->label, r + 1, outer_repeats,
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

        if (algo->is_block_cipher) {
            idx = 0; for (int r = 0; r < outer_repeats; r++) if (handshake_ok[r]) tmp[idx++] = lat_means[r];
            res.latency_us = median(tmp, valid_count);
        } else {
            res.latency_us = NAN;
        }

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
    free(keys);
    free(handshake_ok);
    free(ecc_means);
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

    FILE *csv = fopen("phase2_results.csv", "w");
    if (!csv) {
        fprintf(stderr, "Failed to open phase2_results.csv for writing\n");
        return 1;
    }

    fprintf(csv,
        "algorithm,data_size,ecc_ms,enc_ms,dec_ms,"
        "throughput_enc_mbps,throughput_dec_mbps,"
        "latency_us,memory_enc_peak_kb,memory_enc_overhead_kb,"
        "memory_dec_peak_kb,memory_dec_overhead_kb\n");

    for (int a = 0; a < N_ALGOS; a++) {
        for (int s = 0; s < N_SIZES; s++) {
            int pipefd[2];
            if (pipe(pipefd) != 0) {
                fprintf(stderr, "pipe() failed for %s %s\n", ALGOS[a].name, SIZES[s].label);
                continue;
            }

            pid_t pid = fork();
            if (pid < 0) {
                fprintf(stderr, "fork() failed for %s %s\n", ALGOS[a].name, SIZES[s].label);
                close(pipefd[0]); close(pipefd[1]);
                continue;
            }

            if (pid == 0) {
                close(pipefd[0]);
                srand((unsigned)time(NULL) ^ (unsigned)getpid());

                result_t res = run_combo(&ALGOS[a], &SIZES[s]);

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
                        ALGOS[a].name, SIZES[s].label);
                continue;
            }

            if (ALGOS[a].is_block_cipher) {
                fprintf(csv, "%s,%s,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f\n",
                    ALGOS[a].name, SIZES[s].label,
                    res.ecc_ms, res.enc_ms, res.dec_ms,
                    res.thr_enc_mbps, res.thr_dec_mbps,
                    res.latency_us,
                    res.mem_enc_peak_kb, res.mem_enc_overhead_kb,
                    res.mem_dec_peak_kb, res.mem_dec_overhead_kb);
            } else {
                fprintf(csv, "%s,%s,%.4f,%.4f,%.4f,%.4f,%.4f,NA,%.4f,%.4f,%.4f,%.4f\n",
                    ALGOS[a].name, SIZES[s].label,
                    res.ecc_ms, res.enc_ms, res.dec_ms,
                    res.thr_enc_mbps, res.thr_dec_mbps,
                    res.mem_enc_peak_kb, res.mem_enc_overhead_kb,
                    res.mem_dec_peak_kb, res.mem_dec_overhead_kb);
            }
            fflush(csv);

            printf("[parent] [%s | %s] finished -> ecc_ms=%.4f enc_ms=%.4f dec_ms=%.4f mem_enc_peak_kb=%.4f (ovh=%.4f) mem_dec_peak_kb=%.4f (ovh=%.4f)\n\n",
                ALGOS[a].name, SIZES[s].label, res.ecc_ms, res.enc_ms, res.dec_ms,
                res.mem_enc_peak_kb, res.mem_enc_overhead_kb,
                res.mem_dec_peak_kb, res.mem_dec_overhead_kb);
            fflush(stdout);
        }
    }

    fclose(csv);
    return 0;
}