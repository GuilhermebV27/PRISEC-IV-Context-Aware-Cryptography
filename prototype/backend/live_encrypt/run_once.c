/*
 * Build:
 *   gcc -O2 -mavx2 -fno-stack-protector -o run_once run_once.c -lcrypto -lm \
 *       -Wl,--wrap=malloc,--wrap=free,--wrap=realloc,--wrap=calloc
 */

#define _POSIX_C_SOURCE 199309L
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#ifndef _WIN32
#include <unistd.h>
#endif
#include <malloc.h>
#ifdef _WIN32
#include <process.h>
#define getpid _getpid
#endif

#include "aes.h"
#include "chacha20.h"
#include "speck.h"
#include "rectangle.h"
#include "rectangle_avx2.h"
#include "hight.h"
#include "ecc.h"
#include "utils.h"
#include "memtrack.h"

static inline double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}
static inline double now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec / 1e3;
}

#define STACK_PROBE_SIZE (64 * 1024)
#define CANARY_BYTE 0xAA

__attribute__((noinline)) static void stack_paint(void) {
    volatile uint8_t probe[STACK_PROBE_SIZE];
    memset((void *)probe, CANARY_BYTE, STACK_PROBE_SIZE);
    __asm__ volatile("" ::: "memory");
}
__attribute__((noinline)) static size_t stack_measure(void) {
    volatile uint8_t probe[STACK_PROBE_SIZE];
    size_t touched = 0;
    for (size_t i = 0; i < STACK_PROBE_SIZE; i++) if (probe[i] != CANARY_BYTE) touched++;
    return touched;
}

typedef int (*enc_fn)(const uint8_t *key, int key_len, const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len);
typedef int (*dec_fn)(const uint8_t *key, int key_len, const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len);
typedef void (*setup_fn)(const uint8_t *key, int key_len);

static int wrap_aes_enc(const uint8_t *key, int key_len, const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len) {
    size_t cap = in_len + AES_OVERHEAD;
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf) return 0;
    if (!aes_encrypt(key, key_len, in, in_len, buf, out_len)) { free(buf); return 0; }
    *out = buf;
    return 1;
}
static int wrap_aes_dec(const uint8_t *key, int key_len, const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len) {
    uint8_t *buf = (uint8_t *)malloc(in_len);
    if (!buf) return 0;
    if (!aes_decrypt(key, key_len, in, in_len, buf, out_len)) { free(buf); return 0; }
    *out = buf;
    return 1;
}
static int wrap_chacha_enc(const uint8_t *key, int key_len, const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len) {
    size_t cap = in_len + CC20_OVERHEAD;
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf) return 0;
    if (!chacha20_encrypt(key, key_len, in, in_len, buf, out_len)) { free(buf); return 0; }
    *out = buf;
    return 1;
}
static int wrap_chacha_dec(const uint8_t *key, int key_len, const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len) {
    uint8_t *buf = (uint8_t *)malloc(in_len);
    if (!buf) return 0;
    if (!chacha20_decrypt(key, key_len, in, in_len, buf, out_len)) { free(buf); return 0; }
    *out = buf;
    return 1;
}
static int wrap_speck_enc(const uint8_t *key, int key_len, const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len) {
    (void)key_len;
    uint8_t *buf = speck_encrypt(key, in, in_len, out_len);
    if (!buf) return 0;
    *out = buf;
    return 1;
}
static int wrap_speck_dec(const uint8_t *key, int key_len, const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len) {
    (void)key_len;
    uint8_t *buf = speck_decrypt(key, in, in_len, out_len);
    if (!buf) return 0;
    *out = buf;
    return 1;
}

static int g_rect_used_avx2 = 0;

static int wrap_rect_enc(const uint8_t *key, int key_len, const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len) {
    (void)key_len;
    uint8_t *buf = rectangle_avx2_available()
        ? rectangle_avx2_encrypt(key, in, in_len, out_len)
        : rectangle_bitslice_encrypt(key, in, in_len, out_len);
    if (!buf) return 0;
    *out = buf;
    return 1;
}
static int wrap_rect_dec(const uint8_t *key, int key_len, const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len) {
    (void)key_len;
    uint8_t *buf = rectangle_avx2_available()
        ? rectangle_avx2_decrypt(key, in, in_len, out_len)
        : rectangle_bitslice_decrypt(key, in, in_len, out_len);
    if (!buf) return 0;
    *out = buf;
    return 1;
}
static int wrap_hight_enc(const uint8_t *key, int key_len, const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len) {
    (void)key_len;
    hight_encrypt(key, in, in_len, out, out_len);
    return (*out != NULL);
}
static int wrap_hight_dec(const uint8_t *key, int key_len, const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len) {
    (void)key_len;
    uint8_t *buf = hight_decrypt(key, in, in_len, out_len);
    if (!buf) return 0;
    *out = buf;
    return 1;
}

static volatile uint8_t g_sink = 0;

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
    enc_fn enc;
    dec_fn dec;
    setup_fn setup;
} algo_t;

static algo_t AES128     = { "AES-128",   16, wrap_aes_enc,    wrap_aes_dec,    setup_aes };
static algo_t AES192     = { "AES-192",   24, wrap_aes_enc,    wrap_aes_dec,    setup_aes };
static algo_t AES256     = { "AES-256",   32, wrap_aes_enc,    wrap_aes_dec,    setup_aes };
static algo_t CHACHA20   = { "ChaCha20",  32, wrap_chacha_enc, wrap_chacha_dec, setup_chacha20 };
static algo_t SPECK_     = { "SPECK",     16, wrap_speck_enc,  wrap_speck_dec,  setup_speck };
static algo_t RECTANGLE_ = { "RECTANGLE", RECT_KEY_SIZE, wrap_rect_enc, wrap_rect_dec, setup_rectangle };
static algo_t HIGHT_     = { "HIGHT",     16, wrap_hight_enc,  wrap_hight_dec,  setup_hight };

static algo_t *ALL_ALGOS[] = { &AES128, &AES192, &AES256, &CHACHA20, &SPECK_, &RECTANGLE_, &HIGHT_ };
#define N_ALL_ALGOS (int)(sizeof(ALL_ALGOS)/sizeof(ALL_ALGOS[0]))

static algo_t *find_algo(const char *name) {
    for (int i = 0; i < N_ALL_ALGOS; i++) {
        if (strcmp(ALL_ALGOS[i]->name, name) == 0) return ALL_ALGOS[i];
    }
    return NULL;
}

static void fill_random(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)(rand() & 0xFF);
}

#define MAX_LAYERS 3

typedef struct {
    int use_ecc;
    int n_layers;
    algo_t *layers[MAX_LAYERS];
} spec_t;

static int parse_spec(const char *spec_in, spec_t *out) {
    char buf[256];
    strncpy(buf, spec_in, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    out->use_ecc = 0;
    out->n_layers = 0;

    char *saveptr = NULL;
    char *token = strtok_r(buf, "+", &saveptr);
    int first = 1;
    while (token) {
        if (first && strcmp(token, "ECC") == 0) {
            out->use_ecc = 1;
        } else {
            if (out->n_layers >= MAX_LAYERS) {
                fprintf(stderr, "Too many layers (max %d)\n", MAX_LAYERS);
                return 0;
            }
            algo_t *a = find_algo(token);
            if (!a) {
                fprintf(stderr, "Unknown cipher layer: '%s'\n", token);
                return 0;
            }
            out->layers[out->n_layers++] = a;
        }
        first = 0;
        token = strtok_r(NULL, "+", &saveptr);
    }

    if (out->n_layers == 0) {
        fprintf(stderr, "No cipher layers found in spec\n");
        return 0;
    }
    return 1;
}

/* latency_us is per-BLOCK, not per-byte - matches the Python decision
 * model's latency_block_size_bytes_for() exactly. ECC is a prefix (already
 * stripped from spec.layers, see parse_spec), so for a cascade this always
 * uses the LAST layer's block size, spec->layers[spec->n_layers - 1]. */
static int block_size_bytes_for(spec_t *s) {
    algo_t *last = s->layers[s->n_layers - 1];
    if (last == &AES128 || last == &AES192 || last == &AES256) return 16; /* 128 bits */
    if (last == &SPECK_) return 16;                                        /* 128 bits */
    if (last == &RECTANGLE_) return 8;                                     /* 64 bits */
    if (last == &HIGHT_) return 8;                                         /* 64 bits */
    /* ChaCha20 is a stream cipher: unlike a true block cipher, it doesn't
     * need to finish an entire 512-bit internal chunk before ANY output is
     * usable - it delivers keystream continuously. 32 bits (its ARX word
     * size) reflects that, matching the Python model's same choice. */
    if (last == &CHACHA20) return 4; /* 32 bits */
    return 1; /* unreachable given the fixed ALL_ALGOS set, but never silently wrong */
}

static int cascade_encrypt(spec_t *s, uint8_t *keys[MAX_LAYERS],
                            const uint8_t *plain, size_t plain_len,
                            uint8_t **out, size_t *out_len) {
    uint8_t *cur = (uint8_t *)plain;
    size_t cur_len = plain_len;
    uint8_t *prev_alloc = NULL;

    for (int i = 0; i < s->n_layers; i++) {
        uint8_t *next = NULL;
        size_t next_len = 0;
        algo_t *L = s->layers[i];
        if (!L->enc(keys[i], L->key_len_bytes, cur, cur_len, &next, &next_len)) {
            if (prev_alloc) free(prev_alloc);
            return 0;
        }
        if (prev_alloc) free(prev_alloc);
        prev_alloc = next;
        cur = next;
        cur_len = next_len;
    }
    *out = cur;
    *out_len = cur_len;
    return 1;
}

static int cascade_decrypt(spec_t *s, uint8_t *keys[MAX_LAYERS],
                            const uint8_t *ct, size_t ct_len,
                            uint8_t **out, size_t *out_len) {
    uint8_t *cur = (uint8_t *)ct;
    size_t cur_len = ct_len;
    uint8_t *prev_alloc = NULL;

    for (int i = s->n_layers - 1; i >= 0; i--) {
        uint8_t *next = NULL;
        size_t next_len = 0;
        algo_t *L = s->layers[i];
        if (!L->dec(keys[i], L->key_len_bytes, cur, cur_len, &next, &next_len)) {
            if (prev_alloc) free(prev_alloc);
            return 0;
        }
        if (prev_alloc) free(prev_alloc);
        prev_alloc = next;
        cur = next;
        cur_len = next_len;
    }
    *out = cur;
    *out_len = cur_len;
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <cipher_spec> <packet_size_bytes> [warmup_runs]\n", argv[0]);
        return 1;
    }

    const char *cipher_spec = argv[1];
    size_t packet_size = (size_t)strtoull(argv[2], NULL, 10);
    int warmup_runs = (argc >= 4) ? atoi(argv[3]) : 5;
    if (warmup_runs < 0) warmup_runs = 0;
    if (packet_size == 0) {
        fprintf(stderr, "packet_size_bytes must be > 0\n");
        return 1;
    }

    spec_t spec;
    if (!parse_spec(cipher_spec, &spec)) return 1;

    for (int i = 0; i < spec.n_layers; i++) {
        if (spec.layers[i] == &RECTANGLE_) {
            g_rect_used_avx2 = rectangle_avx2_available();
        }
    }

    if (!mt_install_openssl()) {
        fprintf(stderr, "CRYPTO_set_mem_functions failed; memory would not be tracked\n");
        return 1;
    }

    /* Cold-start mitigation, Linux/glibc only: re-exec once with tcache
     * disabled, and tune mmap/trim thresholds - both fix glibc ptmalloc2-
     * specific first-call behavior that doesn't apply to Windows's heap
     * manager at all, so there's no equivalent needed there. The
     * warmup_runs mechanism above is platform-independent and already does
     * the real work of avoiding cold-start skew on both platforms - this
     * block is an extra refinement on top of that, specific to Linux. */
#ifndef _WIN32
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
#endif

    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    uint8_t *keys[MAX_LAYERS] = { NULL, NULL, NULL };
    for (int i = 0; i < spec.n_layers; i++) {
        keys[i] = (uint8_t *)malloc(spec.layers[i]->key_len_bytes);
    }

    uint8_t *plaintext = (uint8_t *)malloc(packet_size);
    if (!plaintext) {
        fprintf(stderr, "Failed to allocate %zu-byte plaintext buffer\n", packet_size);
        return 1;
    }
    fill_random(plaintext, packet_size);

    for (int w = 0; w < warmup_runs; w++) {
        for (int i = 0; i < spec.n_layers; i++) fill_random(keys[i], spec.layers[i]->key_len_bytes);
        if (spec.use_ecc) {
            uint8_t *out_keys[MAX_LAYERS];
            int key_sizes[MAX_LAYERS];
            for (int i = 0; i < spec.n_layers; i++) { out_keys[i] = keys[i]; key_sizes[i] = spec.layers[i]->key_len_bytes; }
            get_shared_keys_hkdf(out_keys, key_sizes, spec.n_layers);
        }
        uint8_t *wct = NULL; size_t wct_len = 0;
        if (cascade_encrypt(&spec, keys, plaintext, packet_size, &wct, &wct_len)) {
            uint8_t *wpt = NULL; size_t wpt_len = 0;
            if (cascade_decrypt(&spec, keys, wct, wct_len, &wpt, &wpt_len)) free(wpt);
            free(wct);
        }
    }

    for (int i = 0; i < spec.n_layers; i++) fill_random(keys[i], spec.layers[i]->key_len_bytes);

    double ecc_handshake_us = 0.0;
    if (spec.use_ecc) {
        uint8_t *out_keys[MAX_LAYERS];
        int key_sizes[MAX_LAYERS];
        for (int i = 0; i < spec.n_layers; i++) { out_keys[i] = keys[i]; key_sizes[i] = spec.layers[i]->key_len_bytes; }
        double t0 = now_us();
        if (!get_shared_keys_hkdf(out_keys, key_sizes, spec.n_layers)) {
            fprintf(stderr, "ECC key derivation failed\n");
            return 1;
        }
        double t1 = now_us();
        ecc_handshake_us = t1 - t0;
    }

    double t_setup0 = now_us();
    for (int i = 0; i < spec.n_layers; i++) {
        spec.layers[i]->setup(keys[i], spec.layers[i]->key_len_bytes);
    }
    double t_setup1 = now_us();
    double cipher_setup_us = t_setup1 - t_setup0;
    double total_setup_us = ecc_handshake_us + cipher_setup_us;

    uint8_t *ct = NULL; size_t ct_len = 0;
    double t_enc0 = now_ms();
    if (!cascade_encrypt(&spec, keys, plaintext, packet_size, &ct, &ct_len)) {
        fprintf(stderr, "Encryption failed\n");
        return 1;
    }
    double t_enc1 = now_ms();
    double enc_ms = t_enc1 - t_enc0;

    uint8_t *pt = NULL; size_t pt_len = 0;
    double t_dec0 = now_ms();
    int dec_ok = cascade_decrypt(&spec, keys, ct, ct_len, &pt, &pt_len);
    double t_dec1 = now_ms();
    double dec_ms = t_dec1 - t_dec0;

    int roundtrip_ok = dec_ok && (pt_len == packet_size) && (memcmp(pt, plaintext, packet_size) == 0);

    for (int i = 0; i < spec.n_layers; i++) fill_random(keys[i], spec.layers[i]->key_len_bytes);
    if (spec.use_ecc) {
        uint8_t *out_keys[MAX_LAYERS];
        int key_sizes[MAX_LAYERS];
        for (int i = 0; i < spec.n_layers; i++) { out_keys[i] = keys[i]; key_sizes[i] = spec.layers[i]->key_len_bytes; }
        get_shared_keys_hkdf(out_keys, key_sizes, spec.n_layers);
    }

    uint8_t *mem_ct = NULL; size_t mem_ct_len = 0;
    size_t base_enc = mt_mark();
    stack_paint();
    cascade_encrypt(&spec, keys, plaintext, packet_size, &mem_ct, &mem_ct_len);
    size_t stack_enc = stack_measure();
    size_t heap_peak_enc = mt_peak_delta(base_enc);
    size_t final_buf_bytes = mem_ct ? PORTABLE_USABLE_SIZE(mem_ct) : 0;
    double total_mem_enc = (double)heap_peak_enc + (double)stack_enc;
    double mem_enc_peak_kb = total_mem_enc / 1024.0;
    double ovh_enc = total_mem_enc - (double)final_buf_bytes;
    double mem_enc_overhead_kb = (ovh_enc > 0 ? ovh_enc : 0) / 1024.0;

    uint8_t *mem_pt = NULL; size_t mem_pt_len = 0;
    size_t base_dec = mt_mark();
    stack_paint();
    cascade_decrypt(&spec, keys, mem_ct, mem_ct_len, &mem_pt, &mem_pt_len);
    size_t stack_dec = stack_measure();
    size_t heap_peak_dec = mt_peak_delta(base_dec);
    size_t pt_buf_bytes = mem_pt ? PORTABLE_USABLE_SIZE(mem_pt) : 0;
    double total_mem_dec = (double)heap_peak_dec + (double)stack_dec;
    double mem_dec_peak_kb = total_mem_dec / 1024.0;
    double ovh_dec = total_mem_dec - (double)pt_buf_bytes;
    double mem_dec_overhead_kb = (ovh_dec > 0 ? ovh_dec : 0) / 1024.0;

    free(mem_ct);
    free(mem_pt);

    double data_mbits = (double)packet_size * 8.0 / 1e6;
    double throughput_enc_mbps = (enc_ms > 0) ? (data_mbits / (enc_ms / 1000.0)) : 0.0;
    double throughput_dec_mbps = (dec_ms > 0) ? (data_mbits / (dec_ms / 1000.0)) : 0.0;
    double latency_us_per_byte = (enc_ms * 1000.0) / (double)packet_size;
    double latency_us_per_block = latency_us_per_byte * (double)block_size_bytes_for(&spec);

    printf("{"
           "\"cipher\":\"%s\","
           "\"packet_size_bytes\":%zu,"
           "\"warmup_runs\":%d,"
           "\"roundtrip_ok\":%s,"
           "\"rectangle_used_avx2\":%s,"
           "\"setup_us\":%.4f,"
           "\"ecc_handshake_us\":%.4f,"
           "\"cipher_setup_us\":%.4f,"
           "\"enc_ms\":%.4f,"
           "\"dec_ms\":%.4f,"
           "\"throughput_enc_mbps\":%.4f,"
           "\"throughput_dec_mbps\":%.4f,"
           "\"latency_us\":%.8f,"
           "\"memory_enc_peak_kb\":%.4f,"
           "\"memory_enc_overhead_kb\":%.4f,"
           "\"memory_dec_peak_kb\":%.4f,"
           "\"memory_dec_overhead_kb\":%.4f"
           "}\n",
           cipher_spec, packet_size, warmup_runs, roundtrip_ok ? "true" : "false",
           g_rect_used_avx2 ? "true" : "false",
           total_setup_us, ecc_handshake_us, cipher_setup_us,
           enc_ms, dec_ms, throughput_enc_mbps, throughput_dec_mbps, latency_us_per_block,
           mem_enc_peak_kb, mem_enc_overhead_kb, mem_dec_peak_kb, mem_dec_overhead_kb);

    free(ct);
    free(pt);
    for (int i = 0; i < spec.n_layers; i++) free(keys[i]);
    free(plaintext);

    return roundtrip_ok ? 0 : 2;
}