#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sched.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/resource.h>

#include "utils.h"
#include "aes.h"
#include "chacha20.h"
#include "speck.h"
#include "rectangle.h"
#include "hight.h"

typedef struct { const char *label; size_t size; } DataSize;

static const DataSize DATA_SIZES[] = {
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

typedef struct {
    double enc_ms;
    double dec_ms;
    double enc_mbps;
    double dec_mbps;
    double lat_us;
    int latency_na;
} BenchMetrics;

typedef int (*enc_aead_fn)(const uint8_t*, int, const uint8_t*, size_t, uint8_t*, size_t*);
typedef int (*dec_aead_fn)(const uint8_t*, int, const uint8_t*, size_t, uint8_t*, size_t*);

static inline int get_repeats(size_t size_n) {
    if (size_n <= 10 * 1024) return 300;
    else if (size_n <= 1024 * 1024) return 120;
    else return 40;
}

static inline int get_inner_loops(size_t size_n) {
    if (size_n <= 1 * 1024) return 10000;
    else if (size_n <= 5 * 1024) return 5000;
    else if (size_n <= 10 * 1024) return 2000;
    else if (size_n <= 50 * 1024) return 200;
    else if (size_n <= 100 * 1024) return 100;
    else return 1;
}

static inline double now_s(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec * 1e-9;
}

static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    return (da > db) - (da < db);
}

static double median(double *arr, int n) {
    qsort(arr, n, sizeof(double), cmp_double);
    if (n % 2 == 0) return (arr[n/2 - 1] + arr[n/2]) / 2.0;
    return arr[n/2];
}

static void pin_to_cpu0_if_possible(void) {
#ifdef __linux__
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        fprintf(stderr, "warning: sched_setaffinity failed: %s\n", strerror(errno));
    }
#endif
}

static BenchMetrics run_bench_aead(size_t size_n, int repeats, int inner_loops,
                                   const uint8_t *key, int key_len,
                                   int is_stream,
                                   enc_aead_fn enc_fn,
                                   dec_aead_fn dec_fn) {
    BenchMetrics m = {0};

    uint8_t *plain = (uint8_t *)malloc(size_n);
    size_t max_ct = size_n + 64;
    uint8_t *ct = (uint8_t *)malloc(max_ct);
    uint8_t *rec = (uint8_t *)malloc(size_n);
    double *enc_times = (double *)malloc(repeats * sizeof(double));
    double *dec_times = (double *)malloc(repeats * sizeof(double));

    if (!plain || !ct || !rec || !enc_times || !dec_times) {
        perror("malloc");
        exit(1);
    }

    for (size_t i = 0; i < size_n; i++) plain[i] = (uint8_t)(i & 0xFF);

    size_t ct_len = 0, rec_len = 0;

    enc_fn(key, key_len, plain, size_n, ct, &ct_len);
    dec_fn(key, key_len, ct, ct_len, rec, &rec_len);

    for (int r = 0; r < repeats; r++) {
        double t0 = now_s();
        for (int k = 0; k < inner_loops; k++) {
            enc_fn(key, key_len, plain, size_n, ct, &ct_len);
        }
        double t1 = now_s();
        enc_times[r] = (t1 - t0) / (double)inner_loops;
    }

    enc_fn(key, key_len, plain, size_n, ct, &ct_len);

    for (int r = 0; r < repeats; r++) {
        double t0 = now_s();
        for (int k = 0; k < inner_loops; k++) {
            dec_fn(key, key_len, ct, ct_len, rec, &rec_len);
        }
        double t1 = now_s();
        dec_times[r] = (t1 - t0) / (double)inner_loops;
    }

    double enc_med = median(enc_times, repeats);
    double dec_med = median(dec_times, repeats);
    double mb = size_n / (1024.0 * 1024.0);

    m.enc_ms = enc_med * 1e3;
    m.dec_ms = dec_med * 1e3;
    m.enc_mbps = mb / enc_med;
    m.dec_mbps = mb / dec_med;

    if (is_stream) {
        m.latency_na = 1;
        m.lat_us = 0.0;
    } else {
        m.latency_na = 0;
        m.lat_us = (enc_med / ((double)size_n / 16.0)) * 1e6;
    }

    free(plain);
    free(ct);
    free(rec);
    free(enc_times);
    free(dec_times);
    return m;
}

static BenchMetrics run_bench_blk_alloc(size_t size_n, int repeats, int inner_loops,
                                        const uint8_t *key, size_t block_bytes,
                                        uint8_t *(*enc_fn)(const uint8_t*, const uint8_t*, size_t, size_t*),
                                        uint8_t *(*dec_fn)(const uint8_t*, const uint8_t*, size_t, size_t*)) {
    BenchMetrics m = {0};

    uint8_t *plain = (uint8_t *)malloc(size_n);
    double *enc_t = (double *)malloc(repeats * sizeof(double));
    double *dec_t = (double *)malloc(repeats * sizeof(double));

    if (!plain || !enc_t || !dec_t) {
        perror("malloc");
        exit(1);
    }

    for (size_t i = 0; i < size_n; i++) plain[i] = (uint8_t)(i & 0xFF);

    size_t ct_len = 0, pt_len = 0;

    uint8_t *warm_ct = enc_fn(key, plain, size_n, &ct_len);
    uint8_t *warm_pt = dec_fn(key, warm_ct, ct_len, &pt_len);
    free(warm_ct);
    free(warm_pt);

    for (int r = 0; r < repeats; r++) {
        double t0 = now_s();
        for (int k = 0; k < inner_loops; k++) {
            uint8_t *c = enc_fn(key, plain, size_n, &ct_len);
            free(c);
        }
        double t1 = now_s();
        enc_t[r] = (t1 - t0) / (double)inner_loops;
    }

    uint8_t *last_ct = enc_fn(key, plain, size_n, &ct_len);
    if (!last_ct) {
        fprintf(stderr, "encryption failed\n");
        exit(1);
    }

    for (int r = 0; r < repeats; r++) {
        double t0 = now_s();
        for (int k = 0; k < inner_loops; k++) {
            uint8_t *p = dec_fn(key, last_ct, ct_len, &pt_len);
            free(p);
        }
        double t1 = now_s();
        dec_t[r] = (t1 - t0) / (double)inner_loops;
    }

    uint8_t *rec = dec_fn(key, last_ct, ct_len, &pt_len);
    free(last_ct);
    free(rec);

    double enc_med = median(enc_t, repeats);
    double dec_med = median(dec_t, repeats);
    double mb = size_n / (1024.0 * 1024.0);

    m.enc_ms = enc_med * 1e3;
    m.dec_ms = dec_med * 1e3;
    m.enc_mbps = mb / enc_med;
    m.dec_mbps = mb / dec_med;
    m.latency_na = 0;
    m.lat_us = (enc_med / ((double)size_n / (double)block_bytes)) * 1e6;

    free(plain);
    free(enc_t);
    free(dec_t);
    return m;
}

static BenchMetrics run_bench_hight(size_t size_n, int repeats, int inner_loops, const uint8_t *key) {
    BenchMetrics m = {0};

    uint8_t *plain = (uint8_t *)malloc(size_n);
    double *enc_t = (double *)malloc(repeats * sizeof(double));
    double *dec_t = (double *)malloc(repeats * sizeof(double));

    if (!plain || !enc_t || !dec_t) {
        perror("malloc");
        exit(1);
    }

    for (size_t i = 0; i < size_n; i++) plain[i] = (uint8_t)(i & 0xFF);

    size_t ct_len = 0, pt_len = 0;

    uint8_t *warm_ct = NULL;
    hight_encrypt(key, plain, size_n, &warm_ct, &ct_len);
    uint8_t *warm_pt = hight_decrypt(key, warm_ct, ct_len, &pt_len);
    free(warm_ct);
    free(warm_pt);

    for (int r = 0; r < repeats; r++) {
        double t0 = now_s();
        for (int k = 0; k < inner_loops; k++) {
            uint8_t *hct = NULL;
            hight_encrypt(key, plain, size_n, &hct, &ct_len);
            free(hct);
        }
        double t1 = now_s();
        enc_t[r] = (t1 - t0) / (double)inner_loops;
    }

    uint8_t *last_hct = NULL;
    hight_encrypt(key, plain, size_n, &last_hct, &ct_len);

    for (int r = 0; r < repeats; r++) {
        double t0 = now_s();
        for (int k = 0; k < inner_loops; k++) {
            uint8_t *p = hight_decrypt(key, last_hct, ct_len, &pt_len);
            free(p);
        }
        double t1 = now_s();
        dec_t[r] = (t1 - t0) / (double)inner_loops;
    }

    uint8_t *rec = hight_decrypt(key, last_hct, ct_len, &pt_len);
    free(last_hct);
    free(rec);

    double enc_med = median(enc_t, repeats);
    double dec_med = median(dec_t, repeats);
    double mb = size_n / (1024.0 * 1024.0);

    m.enc_ms = enc_med * 1e3;
    m.dec_ms = dec_med * 1e3;
    m.enc_mbps = mb / enc_med;
    m.dec_mbps = mb / dec_med;
    m.latency_na = 0;
    m.lat_us = (enc_med / ((double)size_n / HIGHT_BLOCK_SIZE)) * 1e6;

    free(plain);
    free(enc_t);
    free(dec_t);
    return m;
}

static void write_result_line(FILE *csv,
                              const char *algo, const char *size_label,
                              const BenchMetrics *m,
                              double peak_mem_kb, double cpu_pct) {
    if (m->latency_na) {
        fprintf(csv, "%s,%s,%.4f,%.4f,%.4f,%.4f,N/A,%.2f,%.2f\n",
                algo, size_label,
                m->enc_ms, m->dec_ms,
                m->enc_mbps, m->dec_mbps,
                peak_mem_kb, cpu_pct);
    } else {
        fprintf(csv, "%s,%s,%.4f,%.4f,%.4f,%.4f,%.6f,%.2f,%.2f\n",
                algo, size_label,
                m->enc_ms, m->dec_ms,
                m->enc_mbps, m->dec_mbps,
                m->lat_us,
                peak_mem_kb, cpu_pct);
    }
}

static void run_case_child_write_pipe(int fd,
                                      size_t size_n, int repeats, int inner_loops,
                                      const uint8_t *key, int key_len,
                                      int kind) {
    pin_to_cpu0_if_possible();

    BenchMetrics m;

    if (kind == 0) {
        m = run_bench_aead(size_n, repeats, inner_loops, key, key_len, 0,
                           (enc_aead_fn)aes_encrypt, (dec_aead_fn)aes_decrypt);
    } else if (kind == 1) {
        m = run_bench_aead(size_n, repeats, inner_loops, key, key_len, 1,
                           (enc_aead_fn)chacha20_encrypt, (dec_aead_fn)chacha20_decrypt);
    } else if (kind == 2) {
        m = run_bench_blk_alloc(size_n, repeats, inner_loops, key, SPECK_BLOCK_SIZE,
                                speck_encrypt, speck_decrypt);
    } else if (kind == 3) {
        m = run_bench_blk_alloc(size_n, repeats, inner_loops, key, RECT_BLOCK_SIZE,
                                rectangle_encrypt, rectangle_decrypt);
    } else {
        m = run_bench_hight(size_n, repeats, inner_loops, key);
    }

    if (write(fd, &m, sizeof(m)) != sizeof(m)) {
        perror("write");
    }
    close(fd);
    _exit(0);
}

static void run_case_parent(FILE *csv,
                            const char *algo, const char *size_label,
                            size_t size_n, int repeats, int inner_loops,
                            const uint8_t *key, int key_len,
                            int kind) {
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        perror("pipe");
        exit(1);
    }

    double wall_start = now_s();

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(1);
    }

    if (pid == 0) {
        close(pipefd[0]);
        run_case_child_write_pipe(pipefd[1], size_n, repeats, inner_loops, key, key_len, kind);
    }

    close(pipefd[1]);

    BenchMetrics m;
    memset(&m, 0, sizeof(m));

    ssize_t rd = read(pipefd[0], &m, sizeof(m));
    close(pipefd[0]);

    if (rd != sizeof(m)) {
        fprintf(stderr, "failed to read child metrics for %s %s\n", algo, size_label);
        exit(1);
    }

    int status = 0;
    struct rusage ru;
    memset(&ru, 0, sizeof(ru));

    if (wait4(pid, &status, 0, &ru) < 0) {
        perror("wait4");
        exit(1);
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "child failed for %s %s\n", algo, size_label);
        exit(1);
    }

    double wall_end = now_s();
    double wall_delta = wall_end - wall_start;

    double cpu_s =
        (double)ru.ru_utime.tv_sec + (double)ru.ru_utime.tv_usec * 1e-6 +
        (double)ru.ru_stime.tv_sec + (double)ru.ru_stime.tv_usec * 1e-6;

    double cpu_pct = (wall_delta > 0.0) ? (100.0 * cpu_s / wall_delta) : 0.0;
    double peak_mem_kb = (double)ru.ru_maxrss;

    write_result_line(csv, algo, size_label, &m, peak_mem_kb, cpu_pct);
    fflush(csv);
}

int main(void) {
    FILE *csv = fopen("results_fase1.csv", "w");
    if (!csv) {
        perror("fopen");
        return 1;
    }

    fprintf(csv, "algorithm,data_size,enc_ms,dec_ms,enc_mbps,dec_mbps,lat_us,peak_mem_kb,cpu_pct\n");

    uint8_t key16[16], key24[24], key32[32];
    for (int i = 0; i < 16; i++) key16[i] = (uint8_t)i;
    for (int i = 0; i < 24; i++) key24[i] = (uint8_t)i;
    for (int i = 0; i < 32; i++) key32[i] = (uint8_t)i;

    printf("Warm-up...\n");
    {
        uint8_t wd[1024];
        memset(wd, 0xAB, sizeof(wd));
        uint8_t tmp[2048];
        size_t tmp_len = 0;

        aes_encrypt(key16, 16, wd, sizeof(wd), tmp, &tmp_len);
        aes_decrypt(key16, 16, tmp, tmp_len, wd, &tmp_len);

        chacha20_encrypt(key32, 32, wd, sizeof(wd), tmp, &tmp_len);
        chacha20_decrypt(key32, 32, tmp, tmp_len, wd, &tmp_len);

        size_t out_len = 0;
        uint8_t *ct = speck_encrypt(key16, wd, sizeof(wd), &out_len);
        uint8_t *pt = speck_decrypt(key16, ct, out_len, &out_len);
        free(ct);
        free(pt);

        ct = rectangle_encrypt(key16, wd, sizeof(wd), &out_len);
        pt = rectangle_decrypt(key16, ct, out_len, &out_len);
        free(ct);
        free(pt);

        uint8_t *hct = NULL;
        hight_encrypt(key16, wd, sizeof(wd), &hct, &out_len);
        pt = hight_decrypt(key16, hct, out_len, &out_len);
        free(hct);
        free(pt);
    }

    for (size_t s = 0; s < N_SIZES; s++) {
        int reps = get_repeats(DATA_SIZES[s].size);
        int inner = get_inner_loops(DATA_SIZES[s].size);
        printf("AES-128   %s  (repeats=%d, inner=%d)\n", DATA_SIZES[s].label, reps, inner);
        run_case_parent(csv, "AES-128", DATA_SIZES[s].label, DATA_SIZES[s].size, reps, inner, key16, 16, 0);
    }

    for (size_t s = 0; s < N_SIZES; s++) {
        int reps = get_repeats(DATA_SIZES[s].size);
        int inner = get_inner_loops(DATA_SIZES[s].size);
        printf("AES-192   %s  (repeats=%d, inner=%d)\n", DATA_SIZES[s].label, reps, inner);
        run_case_parent(csv, "AES-192", DATA_SIZES[s].label, DATA_SIZES[s].size, reps, inner, key24, 24, 0);
    }

    for (size_t s = 0; s < N_SIZES; s++) {
        int reps = get_repeats(DATA_SIZES[s].size);
        int inner = get_inner_loops(DATA_SIZES[s].size);
        printf("AES-256   %s  (repeats=%d, inner=%d)\n", DATA_SIZES[s].label, reps, inner);
        run_case_parent(csv, "AES-256", DATA_SIZES[s].label, DATA_SIZES[s].size, reps, inner, key32, 32, 0);
    }

    for (size_t s = 0; s < N_SIZES; s++) {
        int reps = get_repeats(DATA_SIZES[s].size);
        int inner = get_inner_loops(DATA_SIZES[s].size);
        printf("ChaCha20  %s  (repeats=%d, inner=%d)\n", DATA_SIZES[s].label, reps, inner);
        run_case_parent(csv, "ChaCha20", DATA_SIZES[s].label, DATA_SIZES[s].size, reps, inner, key32, 32, 1);
    }

    for (size_t s = 0; s < N_SIZES; s++) {
        int reps = get_repeats(DATA_SIZES[s].size);
        int inner = get_inner_loops(DATA_SIZES[s].size);
        printf("SPECK     %s  (repeats=%d, inner=%d)\n", DATA_SIZES[s].label, reps, inner);
        run_case_parent(csv, "SPECK", DATA_SIZES[s].label, DATA_SIZES[s].size, reps, inner, key16, 16, 2);
    }

    for (size_t s = 0; s < N_SIZES; s++) {
        int reps = get_repeats(DATA_SIZES[s].size);
        int inner = get_inner_loops(DATA_SIZES[s].size);
        printf("RECTANGLE %s  (repeats=%d, inner=%d)\n", DATA_SIZES[s].label, reps, inner);
        run_case_parent(csv, "RECTANGLE", DATA_SIZES[s].label, DATA_SIZES[s].size, reps, inner, key16, 16, 3);
    }

    for (size_t s = 0; s < N_SIZES; s++) {
        int reps = get_repeats(DATA_SIZES[s].size);
        int inner = get_inner_loops(DATA_SIZES[s].size);
        printf("HIGHT     %s  (repeats=%d, inner=%d)\n", DATA_SIZES[s].label, reps, inner);
        run_case_parent(csv, "HIGHT", DATA_SIZES[s].label, DATA_SIZES[s].size, reps, inner, key16, 16, 4);
    }

    fclose(csv);
    printf("\nResultados escritos em results_fase1.csv\n");
    return 0;
}