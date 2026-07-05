#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "utils.h"
#include "aes.h"
#include "chacha20.h"
#include "speck.h"
#include "rectangle.h"
#include "hight.h"

typedef struct { const char *label; size_t size; } DataSize;

static const DataSize DATA_SIZES[] = {
    { "64 B",    64 },
    { "256 B",   256 },
    { "1 KB",    1 * 1024 },
    { "5 KB",    5 * 1024 },
    { "10 KB",   10 * 1024 },
    { "50 KB",   50 * 1024 },
    { "100 KB",  100 * 1024 },
    { "1 MB",    1 * 1024 * 1024 },
    { "5 MB",    5 * 1024 * 1024 },
    { "10 MB",   10 * 1024 * 1024 },
    { "50 MB",   50 * 1024 * 1024 },
};
#define N_SIZES (sizeof(DATA_SIZES) / sizeof(DATA_SIZES[0]))

static inline int get_repeats(size_t size_n) {
    if (size_n <= 10 * 1024) return 100;
    else if (size_n <= 1024 * 1024) return 30;
    else return 10;
}

static inline double now_s(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec * 1e-9;
}

static int _cmp_double(const void *a, const void *b) {
    double da = *(const double *)a, db = *(const double *)b;
    return (da > db) - (da < db);
}

static inline double _median(double *arr, int n) {
    qsort(arr, n, sizeof(double), _cmp_double);
    return (n % 2 == 0)
        ? (arr[n / 2 - 1] + arr[n / 2]) / 2.0
        : arr[n / 2];
}

typedef int (*enc_aead_fn)(const uint8_t*, int, const uint8_t*, size_t, uint8_t*, size_t*);
typedef int (*dec_aead_fn)(const uint8_t*, int, const uint8_t*, size_t, uint8_t*, size_t*);

static void bench_aead(FILE *csv,
                       const char *algo, const char *size_label,
                       size_t size_n, int repeats,
                       const uint8_t *key, int key_len,
                       int is_stream,
                       enc_aead_fn enc_fn,
                       dec_aead_fn dec_fn) {
    uint8_t *plain = (uint8_t *)malloc(size_n);
    for (size_t i = 0; i < size_n; i++) plain[i] = (uint8_t)(i & 0xFF);

    size_t max_ct = size_n + 64;
    uint8_t *ct = (uint8_t *)malloc(max_ct);
    uint8_t *rec = (uint8_t *)malloc(size_n);

    double *enc_times = (double *)malloc(repeats * sizeof(double));
    double *dec_times = (double *)malloc(repeats * sizeof(double));

    size_t ct_len = 0, rec_len = 0;
    enc_fn(key, key_len, plain, size_n, ct, &ct_len);

    for (int r = 0; r < repeats; r++) {
        double t0 = now_s();
        enc_fn(key, key_len, plain, size_n, ct, &ct_len);
        double t1 = now_s();
        enc_times[r] = t1 - t0;
    }

    for (int r = 0; r < repeats; r++) {
        double t0 = now_s();
        dec_fn(key, key_len, ct, ct_len, rec, &rec_len);
        double t1 = now_s();
        dec_times[r] = t1 - t0;
    }

    double enc_med = _median(enc_times, repeats);
    double dec_med = _median(dec_times, repeats);

    size_t mem_bytes = size_n + (size_t)(key_len > 0 ? key_len : 0) + 64;
    double mem_kb = mem_bytes / 1024.0;
    double mb = size_n / (1024.0 * 1024.0);
    double enc_mbps = mb / enc_med;
    double dec_mbps = mb / dec_med;

    if (is_stream) {
        fprintf(csv, "%s,%s,%.4f,%.4f,%.4f,%.4f,N/A,%.2f\n",
            algo, size_label,
            enc_med * 1e3,
            dec_med * 1e3,
            enc_mbps, dec_mbps,
            mem_kb);
    } else {
        double lat_us = (enc_med / ((double)size_n / 16.0)) * 1e6;
        fprintf(csv, "%s,%s,%.4f,%.4f,%.4f,%.4f,%.6f,%.2f\n",
            algo, size_label,
            enc_med * 1e3,
            dec_med * 1e3,
            enc_mbps, dec_mbps,
            lat_us, mem_kb);
    }

    free(plain); free(ct); free(rec);
    free(enc_times); free(dec_times);
}

static void bench_blk_alloc(FILE *csv,
                            const char *algo, const char *size_label,
                            size_t size_n, int repeats,
                            const uint8_t *key, size_t block_bytes,
                            uint8_t *(*enc_fn)(const uint8_t*, const uint8_t*, size_t, size_t*),
                            uint8_t *(*dec_fn)(const uint8_t*, const uint8_t*, size_t, size_t*)) {
    uint8_t *plain = (uint8_t *)malloc(size_n);
    for (size_t i = 0; i < size_n; i++) plain[i] = (uint8_t)(i & 0xFF);

    double *enc_t = (double*)malloc(repeats * sizeof(double));
    double *dec_t = (double*)malloc(repeats * sizeof(double));

    size_t ct_len, pt_len;

    for (int r = 0; r < repeats; r++) {
        double t0 = now_s();
        uint8_t *c = enc_fn(key, plain, size_n, &ct_len);
        double t1 = now_s();
        enc_t[r] = t1 - t0;
        free(c);
    }

    uint8_t *last_ct = enc_fn(key, plain, size_n, &ct_len);

    for (int r = 0; r < repeats; r++) {
        double t0 = now_s();
        uint8_t *p = dec_fn(key, last_ct, ct_len, &pt_len);
        double t1 = now_s();
        dec_t[r] = t1 - t0;
        free(p);
    }

    uint8_t *rec = dec_fn(key, last_ct, ct_len, &pt_len);
    free(last_ct); free(rec);

    double enc_med = _median(enc_t, repeats);
    double dec_med = _median(dec_t, repeats);
    double mb = size_n / (1024.0 * 1024.0);
    double lat_us = (enc_med / ((double)size_n / (double)block_bytes)) * 1e6;

    size_t mem_bytes = size_n + 128;
    double mem_kb = mem_bytes / 1024.0;

    fprintf(csv, "%s,%s,%.4f,%.4f,%.4f,%.4f,%.6f,%.2f\n",
        algo, size_label,
        enc_med * 1e3,
        dec_med * 1e3,
        mb / enc_med, mb / dec_med,
        lat_us, mem_kb);

    free(plain); free(enc_t); free(dec_t);
}

static void bench_hight(FILE *csv,
                        const char *algo, const char *size_label,
                        size_t size_n, int repeats,
                        const uint8_t *key) {
    uint8_t *plain = (uint8_t *)malloc(size_n);
    for (size_t i = 0; i < size_n; i++) plain[i] = (uint8_t)(i & 0xFF);

    double *enc_t = (double*)malloc(repeats * sizeof(double));
    double *dec_t = (double*)malloc(repeats * sizeof(double));

    size_t ct_len, pt_len;

    for (int r = 0; r < repeats; r++) {
        uint8_t *hct;
        double t0 = now_s();
        hight_encrypt(key, plain, size_n, &hct, &ct_len);
        double t1 = now_s();
        enc_t[r] = t1 - t0;
        free(hct);
    }

    uint8_t *last_hct;
    hight_encrypt(key, plain, size_n, &last_hct, &ct_len);

    for (int r = 0; r < repeats; r++) {
        double t0 = now_s();
        uint8_t *p = hight_decrypt(key, last_hct, ct_len, &pt_len);
        double t1 = now_s();
        dec_t[r] = t1 - t0;
        free(p);
    }

    uint8_t *rec = hight_decrypt(key, last_hct, ct_len, &pt_len);
    free(last_hct); free(rec);

    double enc_med = _median(enc_t, repeats);
    double dec_med = _median(dec_t, repeats);
    double mb = size_n / (1024.0 * 1024.0);
    double lat_us = (enc_med / ((double)size_n / HIGHT_BLOCK_SIZE)) * 1e6;

    size_t mem_bytes = size_n + 128;
    double mem_kb = mem_bytes / 1024.0;

    fprintf(csv, "%s,%s,%.4f,%.4f,%.4f,%.4f,%.6f,%.2f\n",
        algo, size_label,
        enc_med * 1e3,
        dec_med * 1e3,
        mb / enc_med, mb / dec_med,
        lat_us, mem_kb);

    free(plain); free(enc_t); free(dec_t);
}

int main(void) {
    FILE *csv = fopen("results_fase1.csv", "w");
    if (!csv) { perror("fopen"); return 1; }

    fprintf(csv, "algorithm,data_size,enc_ms,dec_ms,enc_mbps,dec_mbps,lat_us,mem_kb\n");

    uint8_t key16[16], key24[24], key32[32];
    for (int i = 0; i < 16; i++) key16[i] = (uint8_t)i;
    for (int i = 0; i < 24; i++) key24[i] = (uint8_t)i;
    for (int i = 0; i < 32; i++) key32[i] = (uint8_t)i;

    printf("Warm-up...\n");
    {
        uint8_t wd[64]; memset(wd, 0xAB, 64);
        uint8_t tmp[128]; size_t tmp_len = 0;

        aes_encrypt(key16, 16, wd, 64, tmp, &tmp_len);
        aes_decrypt(key16, 16, tmp, tmp_len, wd, &tmp_len);

        chacha20_encrypt(key32, 32, wd, 64, tmp, &tmp_len);
        chacha20_decrypt(key32, 32, tmp, tmp_len, wd, &tmp_len);

        size_t out_len;
        uint8_t *ct, *pt, *hct;

        ct = speck_encrypt(key16, wd, 64, &out_len);
        pt = speck_decrypt(key16, ct, out_len, &out_len);
        free(ct); free(pt);

        ct = rectangle_encrypt(key16, wd, 64, &out_len);
        pt = rectangle_decrypt(key16, ct, out_len, &out_len);
        free(ct); free(pt);

        hight_encrypt(key16, wd, 64, &hct, &out_len);
        pt = hight_decrypt(key16, hct, out_len, &out_len);
        free(hct); free(pt);
    }

    for (size_t s = 0; s < N_SIZES; s++) {
        int reps = get_repeats(DATA_SIZES[s].size);
        printf("AES-128   %s  (repeats=%d)\n", DATA_SIZES[s].label, reps);
        bench_aead(csv, "AES-128", DATA_SIZES[s].label, DATA_SIZES[s].size,
                   reps, key16, 16, 0,
                   (enc_aead_fn)aes_encrypt, (dec_aead_fn)aes_decrypt);
    }
    for (size_t s = 0; s < N_SIZES; s++) {
        int reps = get_repeats(DATA_SIZES[s].size);
        printf("AES-192   %s  (repeats=%d)\n", DATA_SIZES[s].label, reps);
        bench_aead(csv, "AES-192", DATA_SIZES[s].label, DATA_SIZES[s].size,
                   reps, key24, 24, 0,
                   (enc_aead_fn)aes_encrypt, (dec_aead_fn)aes_decrypt);
    }
    for (size_t s = 0; s < N_SIZES; s++) {
        int reps = get_repeats(DATA_SIZES[s].size);
        printf("AES-256   %s  (repeats=%d)\n", DATA_SIZES[s].label, reps);
        bench_aead(csv, "AES-256", DATA_SIZES[s].label, DATA_SIZES[s].size,
                   reps, key32, 32, 0,
                   (enc_aead_fn)aes_encrypt, (dec_aead_fn)aes_decrypt);
    }
    for (size_t s = 0; s < N_SIZES; s++) {
        int reps = get_repeats(DATA_SIZES[s].size);
        printf("ChaCha20  %s  (repeats=%d)\n", DATA_SIZES[s].label, reps);
        fflush(stdout);
        bench_aead(csv, "ChaCha20", DATA_SIZES[s].label, DATA_SIZES[s].size,
                   reps, key32, 32, 1,
                   (enc_aead_fn)chacha20_encrypt, (dec_aead_fn)chacha20_decrypt);
    }
    for (size_t s = 0; s < N_SIZES; s++) {
        int reps = get_repeats(DATA_SIZES[s].size);
        printf("SPECK     %s  (repeats=%d)\n", DATA_SIZES[s].label, reps);
        bench_blk_alloc(csv, "SPECK", DATA_SIZES[s].label, DATA_SIZES[s].size,
                        reps, key16, SPECK_BLOCK_SIZE,
                        speck_encrypt, speck_decrypt);
    }
    for (size_t s = 0; s < N_SIZES; s++) {
        int reps = get_repeats(DATA_SIZES[s].size);
        printf("RECTANGLE %s  (repeats=%d)\n", DATA_SIZES[s].label, reps);
        bench_blk_alloc(csv, "RECTANGLE", DATA_SIZES[s].label, DATA_SIZES[s].size,
                        reps, key16, RECT_BLOCK_SIZE,
                        rectangle_encrypt, rectangle_decrypt);
    }
    for (size_t s = 0; s < N_SIZES; s++) {
        int reps = get_repeats(DATA_SIZES[s].size);
        printf("HIGHT     %s  (repeats=%d)\n", DATA_SIZES[s].label, reps);
        bench_hight(csv, "HIGHT", DATA_SIZES[s].label, DATA_SIZES[s].size,
                    reps, key16);
    }

    fclose(csv);
    printf("\nResultados escritos em results_fase1.csv\n");
    return 0;
}