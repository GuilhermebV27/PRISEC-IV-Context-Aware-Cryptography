#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
#endif

#if defined(__AVR__)
#include <avr/io.h>
#endif

#define SAMPLES 100000UL
#define WARMUP 1000UL

static uint32_t load32_le(const uint8_t *p) {
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void store32_le(uint8_t *p, uint32_t x) {
    p[0] = (uint8_t)x;
    p[1] = (uint8_t)(x >> 8);
    p[2] = (uint8_t)(x >> 16);
    p[3] = (uint8_t)(x >> 24);
}

static uint32_t rotl32(uint32_t x, unsigned n) {
    return (x << n) | (x >> (32U - n));
}

#define QR(a, b, c, d) do { \
    (a) += (b); (d) ^= (a); (d) = rotl32((d), 16); \
    (c) += (d); (b) ^= (c); (b) = rotl32((b), 12); \
    (a) += (b); (d) ^= (a); (d) = rotl32((d), 8);  \
    (c) += (d); (b) ^= (c); (b) = rotl32((b), 7);  \
} while (0)

static void chacha20_block(const uint8_t key[32], uint32_t counter,
                           const uint8_t nonce[12], uint8_t out[64]) {
    static const uint32_t constants[4] = {
        0x61707865U, 0x3320646eU, 0x79622d32U, 0x6b206574U
    };
    uint32_t x[16];
    uint32_t initial[16];
    unsigned i;

    x[0] = constants[0];
    x[1] = constants[1];
    x[2] = constants[2];
    x[3] = constants[3];

    for (i = 0; i < 8; ++i)
        x[4 + i] = load32_le(key + 4U * i);

    x[12] = counter;
    x[13] = load32_le(nonce + 0);
    x[14] = load32_le(nonce + 4);
    x[15] = load32_le(nonce + 8);

    memcpy(initial, x, sizeof(x));

    for (i = 0; i < 10; ++i) {
        QR(x[0], x[4], x[8],  x[12]);
        QR(x[1], x[5], x[9],  x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);

        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8],  x[13]);
        QR(x[3], x[4], x[9],  x[14]);
    }

    for (i = 0; i < 16; ++i)
        store32_le(out + 4U * i, x[i] + initial[i]);
}

#if defined(__x86_64__) || defined(__i386__)
static uint64_t read_ticks(void) {
    unsigned aux;
    return __rdtscp(&aux);
}
#elif defined(__AVR__)
static uint16_t read_ticks(void) {
    return TCNT1;
}
#else
#include <time.h>
static uint64_t read_ticks(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL +
           (uint64_t)ts.tv_nsec;
}
#endif

static int check_rfc8439_vector(void) {
    static const uint8_t key[32] = {0};
    static const uint8_t nonce[12] = {0};
    static const uint8_t expected[64] = {
        0x76,0xb8,0xe0,0xad,0xa0,0xf1,0x3d,0x90,
        0x40,0x5d,0x6a,0xe5,0x53,0x86,0xbd,0x28,
        0xbd,0xd2,0x19,0xb8,0xa0,0x8d,0xed,0x1a,
        0xa8,0x36,0xef,0xcc,0x8b,0x77,0x0d,0xc7,
        0xda,0x41,0x59,0x7c,0x51,0x57,0x48,0x8d,
        0x77,0x24,0xe0,0x3f,0xb8,0xd8,0x4a,0x37,
        0x6a,0x43,0xb8,0xf4,0x15,0x18,0xa1,0x1c,
        0xc3,0x87,0xb6,0x69,0xb2,0xee,0x65,0x86
    };
    uint8_t output[64];

    chacha20_block(key, 0, nonce, output);
    return memcmp(output, expected, sizeof(expected)) == 0;
}
static int compare_uint64(const void *a, const void *b);

int main(void) {
    static const uint8_t key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    static const uint8_t nonce[12] = {
        0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,
        0xa6,0xa7,0xa8,0xa9,0xaa,0xab
    };
    static uint8_t output[64];
    uint64_t *timings;
    uint64_t start, end;
    uint64_t median, p10, p90;
    uint32_t i;
    uint8_t sink = 0;

#if defined(__AVR__)
    TCCR1A = 0;
    TCCR1B = _BV(CS10);
    TCNT1 = 0;
#endif

    if (!check_rfc8439_vector()) {
        fprintf(stderr, "ChaCha20 RFC 8439 block test failed\n");
        return EXIT_FAILURE;
    }

    for (i = 0; i < WARMUP; ++i)
        chacha20_block(key, i, nonce, output);

    timings = (uint64_t *)malloc(sizeof(uint64_t) * SAMPLES);
    if (timings == NULL) {
        fprintf(stderr, "Unable to allocate timing buffer\n");
        return EXIT_FAILURE;
    }

    for (i = 0; i < SAMPLES; ++i) {
        start = read_ticks();
        chacha20_block(key, i + WARMUP, nonce, output);
        end = read_ticks();
        sink ^= output[i & 63U];
        timings[i] = end - start;
    }

    /* Simple insertion sort is intentionally avoided here; qsort is portable. */
    qsort(timings, SAMPLES, sizeof(uint64_t), compare_uint64);

    median = timings[SAMPLES / 2U];
    p10 = timings[SAMPLES / 10U];
    p90 = timings[(SAMPLES * 9U) / 10U];

    printf("ChaCha20 block-function benchmark\n");
    printf("RFC 8439 test vector: PASS\n");
    printf("Samples: %lu\n", (unsigned long)SAMPLES);
    printf("Output size: 64 bytes\n");
    printf("Median ticks/block: %llu\n", (unsigned long long)median);
    printf("Median ticks/byte: %.6f\n", (double)median / 64.0);
    printf("P10 ticks/block: %llu\n", (unsigned long long)p10);
    printf("P90 ticks/block: %llu\n", (unsigned long long)p90);
    printf("Sink: %u\n", (unsigned)sink);

#if defined(__AVR__)
    printf("AVR Timer1 is configured with no prescaler.\n");
#else
    printf("On x86, ticks are CPU cycles; on other hosts, fallback ticks are nanoseconds.\n");
#endif

    free(timings);
    return 0;
}

static int compare_uint64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}
