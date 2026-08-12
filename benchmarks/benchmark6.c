/*
* benchmark6.c - PRISEC-IV Phase 6 Benchmark (cipher/cascade setup cost)
*
* Measures pure "setup time" — key schedule / cipher-context initialization,
* with no encryption or decryption involved — for every single cipher and
* every non-ECC cascade already used in benchmark1.c / benchmark3.c:
*
*   Single ciphers:
*     AES-128, AES-192, AES-256, ChaCha20, SPECK, RECTANGLE, HIGHT
*
*   Cascades (layer1 -> layer2):
*     AES-128+AES-256, AES-128+HIGHT, AES-128+SPECK, ChaCha20+AES-256,
*     ChaCha20+SPECK, SPECK+HIGHT, HIGHT+RECTANGLE
*
* "Setup" is defined per algorithm as the work needed before the first byte
* can be encrypted:
*   - AES / ChaCha20 (OpenSSL EVP)  -> EVP_CIPHER_CTX_new() + the two
*                                      EVP_*Init_ex() calls that load the key
*                                      (IV-length/tag ctrl included for AES).
*                                      EVP_CIPHER_CTX_free() runs *after* the
*                                      timer stops — teardown isn't setup.
*   - SPECK / HIGHT / RECTANGLE     -> their key-schedule expansion routine
*                                      (software round-key derivation).
*   - Cascades                      -> layer1's setup immediately followed
*                                      by layer2's setup, timed as one span
*                                      (mirrors how benchmark3.c times a
*                                      cascade's enc/dec as a single region).
*
* For each entry, setup is measured 1000 times with a fresh random key per
* iteration (so the compiler can't hoist/cache the key schedule), and the
* median is reported. Output: cipher/cascade name + setup_us.
*
* Build:
*   gcc -O2 -o benchmark6 benchmark6.c -lcrypto -lm
* Run:
*   ./benchmark6
*/

#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#include "aes.h"
#include "chacha20.h"
#include "speck.h"
#include "rectangle.h"
#include "hight.h"

#define N_RUNS 1000

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

static algo_t AES128     = { "AES-128",   16, setup_aes };
static algo_t AES192     = { "AES-192",   24, setup_aes };
static algo_t AES256     = { "AES-256",   32, setup_aes };
static algo_t CHACHA20   = { "ChaCha20",  32, setup_chacha20 };
static algo_t SPECK_     = { "SPECK",     16, setup_speck };
static algo_t RECTANGLE_ = { "RECTANGLE", 16, setup_rectangle };
static algo_t HIGHT_     = { "HIGHT",     16, setup_hight };

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

int main(void) {
    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    FILE *csv = fopen("phase6_results.csv", "w");
    if (!csv) {
        fprintf(stderr, "Failed to open phase6_results.csv for writing\n");
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

    fclose(csv);
    printf("Done. Results written to phase6_results.csv\n");
    return 0;
}
