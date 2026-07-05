#ifndef UTILS_H
#define UTILS_H

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static inline uint8_t *pkcs7_pad(const uint8_t *data, size_t len,
                                 size_t block_size, size_t *out_len) {
    size_t pad_len = block_size - (len % block_size);
    *out_len = len + pad_len;
    uint8_t *buf = (uint8_t *)malloc(*out_len);
    memcpy(buf, data, len);
    memset(buf + len, (uint8_t)pad_len, pad_len);
    return buf;
}

static inline size_t pkcs7_unpad_len(const uint8_t *data, size_t len) {
    if (len == 0) return 0;
    uint8_t pad_len = data[len - 1];
    if (pad_len == 0 || pad_len > len) {
        fprintf(stderr, "Invalid PKCS#7 padding\n");
        return 0;
    }
    return len - pad_len;
}

#endif