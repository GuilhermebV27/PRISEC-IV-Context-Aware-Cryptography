/*
 * benchmark5.c - PRISEC-IV Phase 5 Benchmark (cipher/cascade setup cost +
 * ECC key-exchange cost)
 *
 * Measures pure "setup time" - key schedule / cipher-context initialization,
 * with no encryption or decryption involved - for every single cipher and
 * every non-ECC cascade already used in benchmark1.c/benchmark2.c, plus the
 * three-layer cascade from benchmark3.c, PLUS the ECC-prefixed variants
 * (single cipher, two-layer cascade, three-layer cascade), whose setup cost
 * is the matching ECC key-exchange cost added to the cipher(s)' own setup
 * cost.
 *
 * ECC key-exchange cost is now derived via get_shared_keys_hkdf(): ONE
 * ECDH exchange (EC P-256 keygen x2 + derive), then n_keys HKDF-Expand
 * calls (one per cascade layer) instead of n independent full ECDH
 * exchanges. The elliptic-curve cost is paid once regardless of cascade
 * length; only cheap HKDF-Expand calls scale with the number of layers.
 *
 * Single ciphers:
 * AES-128, AES-192, AES-256, ChaCha20, SPECK, RECTANGLE, HIGHT
 *
 * Two-layer cascades (Stronger+Weaker naming, matching benchmark2/4/8.c):
 * AES-256+AES-128, AES-128+HIGHT, AES-128+SPECK, AES-256+ChaCha20,
 * ChaCha20+SPECK, SPECK+HIGHT, RECTANGLE+HIGHT
 *
 * Three-layer cascade:
 * AES-256+ChaCha20+AES-128
 *
 * ECC key-exchange cost (raw, in isolation - N_ECC_RUNS iterations each,
 * fresh derivation per iteration, median reported):
 * ECC-handshake-x1 (1 key derived: one ECDH + 1 HKDF-Expand)
 * ECC-handshake-x2 (2 keys derived: one ECDH + 2 HKDF-Expand)
 * ECC-handshake-x3 (3 keys derived: one ECDH + 3 HKDF-Expand)
 *
 * ECC + single cipher (setup = ECC-handshake-x1 + the cipher's own setup):
 * ECC+AES-128, ECC+AES-256, ECC+ChaCha20, ECC+SPECK, ECC+RECTANGLE,
 * ECC+HIGHT
 *
 * ECC + two-layer cascade (setup = ECC-handshake-x2 + the cascade's own
 * combined setup):
 * ECC+AES-256+AES-128, ECC+AES-256+ChaCha20, ECC+AES-128+SPECK,
 * ECC+ChaCha20+SPECK, ECC+SPECK+HIGHT
 *
 * ECC + three-layer cascade (setup = ECC-handshake-x3 + the three layers'
 * combined setup):
 * ECC+AES-256+ChaCha20+AES-128
 *
 * For each setup-cost entry, the value is measured N_RUNS (1000) times with
 * a fresh random key per iteration, and the median is reported. The three
 * ECC handshake entries use N_ECC_RUNS (100000) iterations instead.
 * Output: cipher/cascade name + setup_us.
 *
 * Build:
 * gcc -O2 -o benchmark5 benchmark5.c -lcrypto -lm
 * Run:
 * ./benchmark5
 */

#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>

#include "aes.h"
#include "chacha20.h"
#include "speck.h"
#include "rectangle.h"
#include "hight.h"
#include "ecc.h"

#define N_RUNS 1000
#define N_ECC_RUNS 100000

static inline double now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec / 1e3;
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

static void fill_random(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)(rand() & 0xFF);
}

/* Forces the compiler to actually perform pure, side-effect-free key
 * schedules (SPECK/HIGHT/RECTANGLE) instead of discarding them as dead
 * code, without adding any measurable extra cost worth mentioning. */
static volatile uint8_t g_sink = 0;

typedef void (*setup_fn)(const uint8_t *key, int key_len);

static void setup_aes(const uint8_t *key, int key_len) {
    const EVP_CIPHER *cipher;
    switch (key_len) {
        case 16: cipher = EVP_aes_128_ccm(); break;
        case 24: cipher = EVP_aes_192_ccm(); break;
        case 32: cipher = EVP_aes_256_ccm(); break;
        default: return;
    }

    uint8_t nonce[AES_NONCE_SIZE] = {0};

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return;

    EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, AES_NONCE_SIZE, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);

    g_sink ^= (uint8_t)(uintptr_t)ctx;
    EVP_CIPHER_CTX_free(ctx);
}

static void setup_chacha20(const uint8_t *key, int key_len) {
    (void)key_len;
    uint8_t nonce[CC20_NONCE_SIZE] = {0};

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return;

    EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);

    g_sink ^= (uint8_t)(uintptr_t)ctx;
    EVP_CIPHER_CTX_free(ctx);
}

static void setup_speck(const uint8_t *key, int key_len) {
    (void)key_len;
    uint64_t A, B;
    _key_words(key, &A, &B);
    uint64_t rks[SPECK_ROUNDS];
    _key_schedule(A, B, rks);
    g_sink ^= (uint8_t)(rks[SPECK_ROUNDS - 1] & 0xFF);
}

static void setup_hight(const uint8_t *key, int key_len) {
    (void)key_len;
    uint8_t wk[8], sk[128];
    _hight_key_schedule(key, wk, sk);
    g_sink ^= sk[127];
}

static void setup_rectangle(const uint8_t *key, int key_len) {
    (void)key_len;
    uint32_t k0, k1, k2, k3;
    _rect_key_words(key, &k0, &k1, &k2, &k3);
    uint16_t rks[RECT_ROUNDS + 1][4];
    _rect_key_schedule(k0, k1, k2, k3, rks);
    g_sink ^= (uint8_t)(rks[RECT_ROUNDS][0] & 0xFF);
}

typedef struct {
    const char *name;
    int key_len_bytes;
    setup_fn setup;
} algo_t;

static algo_t AES128 = { "AES-128", 16, setup_aes };
static algo_t AES192 = { "AES-192", 24, setup_aes };
static algo_t AES256 = { "AES-256", 32, setup_aes };
static algo_t CHACHA20 = { "ChaCha20", 32, setup_chacha20 };
static algo_t SPECK_ = { "SPECK", 16, setup_speck };
static algo_t RECTANGLE_ = { "RECTANGLE", 16, setup_rectangle };
static algo_t HIGHT_ = { "HIGHT", 16, setup_hight };

static algo_t *SINGLE_ALGOS[] = { &AES128, &AES192, &AES256, &CHACHA20, &SPECK_, &RECTANGLE_, &HIGHT_ };
#define N_SINGLE (int)(sizeof(SINGLE_ALGOS)/sizeof(SINGLE_ALGOS[0]))

typedef struct {
    const char *pair_name;
    algo_t *layer1;
    algo_t *layer2;
} cascade_t;

static cascade_t CASCADES[] = {
    { "AES-256+AES-128", &AES256, &AES128 },
    { "AES-128+HIGHT", &AES128, &HIGHT_ },
    { "AES-128+SPECK", &AES128, &SPECK_ },
    { "AES-256+ChaCha20", &AES256, &CHACHA20 },
    { "ChaCha20+SPECK", &CHACHA20, &SPECK_ },
    { "SPECK+HIGHT", &SPECK_, &HIGHT_ },
    { "RECTANGLE+HIGHT", &RECTANGLE_, &HIGHT_ },
};
#define N_CASCADES (int)(sizeof(CASCADES)/sizeof(CASCADES[0]))

typedef struct {
    const char *triple_name;
    algo_t *layer1;
    algo_t *layer2;
    algo_t *layer3;
} cascade3_t;

static cascade3_t CASCADES3[] = {
    { "AES-256+ChaCha20+AES-128", &AES256, &CHACHA20, &AES128 },
};
#define N_CASCADES3 (int)(sizeof(CASCADES3)/sizeof(CASCADES3[0]))

static algo_t *ECC_SINGLE_ALGOS[] = { &AES128, &AES256, &CHACHA20, &SPECK_, &RECTANGLE_, &HIGHT_ };
#define N_ECC_SINGLE (int)(sizeof(ECC_SINGLE_ALGOS)/sizeof(ECC_SINGLE_ALGOS[0]))

static cascade_t ECC_CASCADES[] = {
    { "ECC+AES-256+AES-128", &AES256, &AES128 },
    { "ECC+AES-256+ChaCha20", &AES256, &CHACHA20 },
    { "ECC+AES-128+SPECK", &AES128, &SPECK_ },
    { "ECC+ChaCha20+SPECK", &CHACHA20, &SPECK_ },
    { "ECC+SPECK+HIGHT", &SPECK_, &HIGHT_ },
};
#define N_ECC_CASCADES (int)(sizeof(ECC_CASCADES)/sizeof(ECC_CASCADES[0]))

static cascade3_t ECC_CASCADES3[] = {
    { "ECC+AES-256+ChaCha20+AES-128", &AES256, &CHACHA20, &AES128 },
};
#define N_ECC_CASCADES3 (int)(sizeof(ECC_CASCADES3)/sizeof(ECC_CASCADES3[0]))

static double run_single_setup(algo_t *algo) {
    double times[N_RUNS];
    uint8_t key[32];

    for (int i = 0; i < N_RUNS; i++) {
        fill_random(key, algo->key_len_bytes);

        double t0 = now_us();
        algo->setup(key, algo->key_len_bytes);
        double t1 = now_us();

        times[i] = t1 - t0;
    }
    return median(times, N_RUNS);
}

static double run_cascade_setup(cascade_t *casc) {
    double times[N_RUNS];
    uint8_t key1[32], key2[32];
    algo_t *L1 = casc->layer1;
    algo_t *L2 = casc->layer2;

    for (int i = 0; i < N_RUNS; i++) {
        fill_random(key1, L1->key_len_bytes);
        fill_random(key2, L2->key_len_bytes);

        double t0 = now_us();
        L1->setup(key1, L1->key_len_bytes);
        L2->setup(key2, L2->key_len_bytes);
        double t1 = now_us();

        times[i] = t1 - t0;
    }
    return median(times, N_RUNS);
}

static double run_cascade3_setup(cascade3_t *casc) {
    double times[N_RUNS];
    uint8_t key1[32], key2[32], key3[32];
    algo_t *L1 = casc->layer1;
    algo_t *L2 = casc->layer2;
    algo_t *L3 = casc->layer3;

    for (int i = 0; i < N_RUNS; i++) {
        fill_random(key1, L1->key_len_bytes);
        fill_random(key2, L2->key_len_bytes);
        fill_random(key3, L3->key_len_bytes);

        double t0 = now_us();
        L1->setup(key1, L1->key_len_bytes);
        L2->setup(key2, L2->key_len_bytes);
        L3->setup(key3, L3->key_len_bytes);
        double t1 = now_us();

        times[i] = t1 - t0;
    }
    return median(times, N_RUNS);
}

/* ECC handshake cost, in isolation - n_keys derived per iteration via
 * ONE ECDH exchange + n_keys HKDF-Expand calls, timed as one span,
 * median of N_ECC_RUNS iterations. n_keys=1/2/3 covers ECC+single,
 * ECC+two-layer-cascade, and ECC+three-layer-cascade respectively. */
static double run_ecc_handshake(int n_keys) {
    double *times = (double *)malloc(sizeof(double) * N_ECC_RUNS);
    uint8_t buf1[32], buf2[32], buf3[32];
    uint8_t *out_keys[3] = { buf1, buf2, buf3 };
    int key_sizes[3] = { 32, 32, 32 };

    for (int i = 0; i < N_ECC_RUNS; i++) {
        double t0 = now_us();
        if (!get_shared_keys_hkdf(out_keys, key_sizes, n_keys)) {
            fprintf(stderr, "[ECC x%d] derivation failed on run %d\n", n_keys, i + 1);
        }
        double t1 = now_us();
        times[i] = t1 - t0;

        if ((i + 1) % 10000 == 0) {
            printf("[ECC x%d] %d/%d runs done\n", n_keys, i + 1, N_ECC_RUNS);
            fflush(stdout);
        }
    }

    double result = median(times, N_ECC_RUNS);
    free(times);
    return result;
}

int main(void) {
    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    FILE *csv = fopen("phase5_results.csv", "w");
    if (!csv) {
        fprintf(stderr, "Failed to open phase5_results.csv for writing\n");
        return 1;
    }

    fprintf(csv, "cipher,setup_us\n");

    for (int a = 0; a < N_SINGLE; a++) {
        double setup_us = run_single_setup(SINGLE_ALGOS[a]);
        fprintf(csv, "%s,%.4f\n", SINGLE_ALGOS[a]->name, setup_us);
        fflush(csv);
        printf("[%s] setup (median of %d runs) = %.4f us\n",
               SINGLE_ALGOS[a]->name, N_RUNS, setup_us);
        fflush(stdout);
    }

    for (int c = 0; c < N_CASCADES; c++) {
        double setup_us = run_cascade_setup(&CASCADES[c]);
        fprintf(csv, "%s,%.4f\n", CASCADES[c].pair_name, setup_us);
        fflush(csv);
        printf("[%s] setup (median of %d runs) = %.4f us\n",
               CASCADES[c].pair_name, N_RUNS, setup_us);
        fflush(stdout);
    }

    for (int c = 0; c < N_CASCADES3; c++) {
        double setup_us = run_cascade3_setup(&CASCADES3[c]);
        fprintf(csv, "%s,%.4f\n", CASCADES3[c].triple_name, setup_us);
        fflush(csv);
        printf("[%s] setup (median of %d runs) = %.4f us\n",
               CASCADES3[c].triple_name, N_RUNS, setup_us);
        fflush(stdout);
    }

    printf("=== ECC handshake cost (median of %d runs each) ===\n", N_ECC_RUNS);
    fflush(stdout);

    double ecc_x1 = run_ecc_handshake(1);
    fprintf(csv, "ECC-handshake-x1,%.4f\n", ecc_x1);
    fflush(csv);
    printf("[ECC-handshake-x1] = %.4f us\n", ecc_x1);
    fflush(stdout);

    double ecc_x2 = run_ecc_handshake(2);
    fprintf(csv, "ECC-handshake-x2,%.4f\n", ecc_x2);
    fflush(csv);
    printf("[ECC-handshake-x2] = %.4f us\n", ecc_x2);
    fflush(stdout);

    double ecc_x3 = run_ecc_handshake(3);
    fprintf(csv, "ECC-handshake-x3,%.4f\n", ecc_x3);
    fflush(csv);
    printf("[ECC-handshake-x3] = %.4f us\n", ecc_x3);
    fflush(stdout);

    /* ECC + single cipher: ECC-handshake-x1 + the cipher's own setup. */
    for (int a = 0; a < N_ECC_SINGLE; a++) {
        double cipher_setup_us = run_single_setup(ECC_SINGLE_ALGOS[a]);
        double combined_us = ecc_x1 + cipher_setup_us;
        char name[64];
        snprintf(name, sizeof(name), "ECC+%s", ECC_SINGLE_ALGOS[a]->name);
        fprintf(csv, "%s,%.4f\n", name, combined_us);
        fflush(csv);
        printf("[%s] setup = %.4f us (ecc_x1=%.4f + cipher=%.4f)\n",
               name, combined_us, ecc_x1, cipher_setup_us);
        fflush(stdout);
    }

    /* ECC + two-layer cascade: ECC-handshake-x2 + the cascade's own
     * combined (layer1+layer2) setup span. */
    for (int c = 0; c < N_ECC_CASCADES; c++) {
        double cascade_setup_us = run_cascade_setup(&ECC_CASCADES[c]);
        double combined_us = ecc_x2 + cascade_setup_us;
        fprintf(csv, "%s,%.4f\n", ECC_CASCADES[c].pair_name, combined_us);
        fflush(csv);
        printf("[%s] setup = %.4f us (ecc_x2=%.4f + cascade=%.4f)\n",
               ECC_CASCADES[c].pair_name, combined_us, ecc_x2, cascade_setup_us);
        fflush(stdout);
    }

    /* ECC + three-layer cascade: ECC-handshake-x3 + the three layers'
     * combined setup span. */
    for (int c = 0; c < N_ECC_CASCADES3; c++) {
        double cascade_setup_us = run_cascade3_setup(&ECC_CASCADES3[c]);
        double combined_us = ecc_x3 + cascade_setup_us;
        fprintf(csv, "%s,%.4f\n", ECC_CASCADES3[c].triple_name, combined_us);
        fflush(csv);
        printf("[%s] setup = %.4f us (ecc_x3=%.4f + cascade=%.4f)\n",
               ECC_CASCADES3[c].triple_name, combined_us, ecc_x3, cascade_setup_us);
        fflush(stdout);
    }

    fclose(csv);
    printf("Done. Results written to phase5_results.csv\n");
    return 0;
}
