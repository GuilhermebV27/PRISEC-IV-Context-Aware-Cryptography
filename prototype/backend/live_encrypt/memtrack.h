#ifndef MEMTRACK_H
#define MEMTRACK_H
/*
 * memtrack.h - byte-accurate live/peak heap tracking for the PRISEC benchmarks.
 *
 * Counts every allocation made by the benchmark itself (via linker wrapping)
 * and by OpenSSL (via CRYPTO_set_mem_functions), so transient allocations
 * such as EVP_CIPHER_CTX are captured at their peak, not just what is still
 * allocated when the call returns.
 *
 * Requires these extra link flags:
 *   -Wl,--wrap=malloc,--wrap=free,--wrap=realloc,--wrap=calloc
 *
 * mt_install_openssl() must run before any other OpenSSL call.
 */

#include <stddef.h>
#include <malloc.h>
#include <openssl/crypto.h>

/* Portable "how many bytes is this allocation actually usable for" query -
 * glibc's malloc_usable_size() doesn't exist on Windows; the MSVC/MinGW CRT
 * calls the same thing _msize(). This is the one place this copy of
 * memtrack.h intentionally diverges from the canonical benchmark-suite
 * version: live_encrypt runs directly inside the prototype's own backend
 * process, which may be Windows, unlike the offline Linux-only benchmark
 * suite this header was originally written for. */
#ifdef _WIN32
  #define PORTABLE_USABLE_SIZE(p) _msize(p)
#else
  #define PORTABLE_USABLE_SIZE(p) malloc_usable_size(p)
#endif

static size_t mt_live_bytes = 0;
static size_t mt_peak_bytes = 0;

static inline void mt_count_add(size_t n) {
    mt_live_bytes += n;
    if (mt_live_bytes > mt_peak_bytes) mt_peak_bytes = mt_live_bytes;
}
static inline void mt_count_sub(size_t n) {
    mt_live_bytes = (n > mt_live_bytes) ? 0 : mt_live_bytes - n;
}

void *__real_malloc(size_t n);
void  __real_free(void *p);
void *__real_realloc(void *p, size_t n);
void *__real_calloc(size_t nmemb, size_t sz);

void *__wrap_malloc(size_t n) {
    void *p = __real_malloc(n);
    if (p) mt_count_add(PORTABLE_USABLE_SIZE(p));
    return p;
}
void __wrap_free(void *p) {
    if (p) mt_count_sub(PORTABLE_USABLE_SIZE(p));
    __real_free(p);
}
void *__wrap_realloc(void *p, size_t n) {
    if (p) mt_count_sub(PORTABLE_USABLE_SIZE(p));
    void *q = __real_realloc(p, n);
    if (q) mt_count_add(PORTABLE_USABLE_SIZE(q));
    return q;
}
void *__wrap_calloc(size_t nmemb, size_t sz) {
    void *p = __real_calloc(nmemb, sz);
    if (p) mt_count_add(PORTABLE_USABLE_SIZE(p));
    return p;
}

static void *mt_ossl_malloc(size_t n, const char *file, int line) {
    (void)file; (void)line;
    return __wrap_malloc(n);
}
static void *mt_ossl_realloc(void *p, size_t n, const char *file, int line) {
    (void)file; (void)line;
    return __wrap_realloc(p, n);
}
static void mt_ossl_free(void *p, const char *file, int line) {
    (void)file; (void)line;
    __wrap_free(p);
}

/* Must be the first OpenSSL call in the process, otherwise it fails. */
static inline int mt_install_openssl(void) {
    return CRYPTO_set_mem_functions(mt_ossl_malloc, mt_ossl_realloc, mt_ossl_free);
}

/*
 * Marks the start of a measured region: returns the current live byte count
 * and resets the peak to it. Pass the returned baseline to mt_peak_delta().
 */
static inline size_t mt_mark(void) {
    mt_peak_bytes = mt_live_bytes;
    return mt_live_bytes;
}

/* Peak heap growth (bytes) since the matching mt_mark(). */
static inline size_t mt_peak_delta(size_t baseline) {
    return (mt_peak_bytes > baseline) ? mt_peak_bytes - baseline : 0;
}

#endif