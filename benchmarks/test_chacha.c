#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "utils.h"
#include "chacha20.h"

int main(void) {
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;

    size_t size_n = 64;
    int repeats = 5;

    uint8_t *plain = (uint8_t *)malloc(size_n);
    for (size_t i = 0; i < size_n; i++) plain[i] = (uint8_t)(i & 0xFF);

    size_t max_ct = size_n + 64;
    uint8_t *ct  = (uint8_t *)malloc(max_ct);
    uint8_t *rec = (uint8_t *)malloc(size_n);

    size_t ct_len = 0, rec_len = 0;

    printf("warm-up encrypt\n"); fflush(stdout);
    int r = chacha20_encrypt(key, plain, size_n, ct, &ct_len);
    printf("warm-up ok: r=%d ct_len=%zu\n", r, ct_len); fflush(stdout);

    for (int rep = 0; rep < repeats; rep++) {
        printf("enc rep %d\n", rep); fflush(stdout);
        r = chacha20_encrypt(key, plain, size_n, ct, &ct_len);
        printf("enc rep %d done: r=%d\n", rep, r); fflush(stdout);
    }

    printf("inicio decrypt loop\n"); fflush(stdout);
    for (int rep = 0; rep < repeats; rep++) {
        printf("dec rep %d\n", rep); fflush(stdout);
        r = chacha20_decrypt(key, ct, ct_len, rec, &rec_len);
        printf("dec rep %d done: r=%d rec_len=%zu\n", rep, r, rec_len); fflush(stdout);
    }

    int ok = (rec_len == size_n && memcmp(rec, plain, size_n) == 0);
    printf("integrity: %s\n", ok ? "PASS" : "FAIL"); fflush(stdout);

    free(plain); free(ct); free(rec);
    return 0;
}