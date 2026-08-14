# PRISEC-IV Benchmark Suite — Reference

This document catalogs every cipher/cascade combination covered by the current
5-file benchmark suite (`benchmark1.c` – `benchmark5.c`), and explains what
each file measures and how.

> **Convention used throughout:** "RECTANGLE" on its own always means the
> AVX2 bit-sliced (hardware-accelerated) implementation. The portable,
> non-AVX2 bit-sliced implementation is only ever called the "software
> version" and only appears in §1.4 — it is never the default meaning of
> a bare "RECTANGLE" anywhere else in this document, the same way a bare
> "AES-256" or "ChaCha20" elsewhere always implies the accelerated OpenSSL
> EVP path without needing to say so each time.

---

## 1. Cipher and Cascade Catalog

### 1.1 Single ciphers

| Cipher | Hardware acceleration |
|---|---|
| AES-128 | accelerated (AES-NI) |
| AES-192 | accelerated (AES-NI) |
| AES-256 | accelerated (AES-NI) |
| ChaCha20 | accelerated (SIMD) |
| SPECK | none available |
| RECTANGLE | accelerated (AVX2 bit-sliced) |
| HIGHT | none available |

SPECK and HIGHT have no hardware-accelerated path at all — their software
implementation is the only implementation, so there is nothing to toggle
for them anywhere in this suite.

### 1.2 Two-layer cascades

| Cascade | Hardware acceleration |
|---|---|
| AES-256+AES-128 | accelerated (both layers) |
| AES-128+HIGHT | accelerated on AES only |
| AES-128+SPECK | accelerated on AES only |
| AES-256+ChaCha20 | accelerated on both |
| ChaCha20+SPECK | accelerated on ChaCha20 only |
| SPECK+HIGHT | none available (neither layer accelerates) |
| RECTANGLE+HIGHT | accelerated on RECTANGLE only |

### 1.3 Three-layer cascade

| Cascade | Hardware acceleration |
|---|---|
| AES-256+ChaCha20+AES-128 | accelerated (all three layers) |

### 1.4 Hardware acceleration OFF / reduced

None of the entries in this section ever run with **both** AES-NI and
ChaCha20 SIMD fully on at once — that combination only exists in §1.1–1.3.
Here, acceleration is either fully off, or (for the two mixed
AES+ChaCha20 entries) one half on and the other off. This is also the only
place the portable bit-sliced (software) RECTANGLE appears, alone and
paired with HIGHT.

| Entry | Hardware states measured |
|---|---|
| AES-128 | off |
| AES-192 | off |
| AES-256 | off |
| ChaCha20 | off |
| RECTANGLE (software version) | off (no accelerated state exists to toggle) |
| AES-256+AES-128 | off |
| AES-128+HIGHT | off (AES side only, since HIGHT never accelerates) |
| AES-128+SPECK | off (AES side only) |
| AES-256+ChaCha20 | three states: AES off/ChaCha on, AES on/ChaCha off, both off |
| ChaCha20+SPECK | off (ChaCha20 side only) |
| RECTANGLE+HIGHT (software version) | off (no accelerated state exists to toggle) |
| AES-256+ChaCha20+AES-128 | three states: AES off/ChaCha on, AES on/ChaCha off, both off |

SPECK+HIGHT does not appear here at all — neither layer ever accelerates,
so its §1.2 entry already is its only/complete measurement.

### 1.5 Setup-cost catalog

Every entry below is measured for pure key-schedule/handshake
initialization time only (no encryption/decryption) — see benchmark5.c in
§2.5.

| Category | Entries |
|---|---|
| Single ciphers | AES-128, AES-192, AES-256, ChaCha20, SPECK, RECTANGLE, HIGHT |
| Two-layer cascades | AES-256+AES-128, AES-128+HIGHT, AES-128+SPECK, AES-256+ChaCha20, ChaCha20+SPECK, SPECK+HIGHT, RECTANGLE+HIGHT |
| Three-layer cascade | AES-256+ChaCha20+AES-128 |
| Raw ECC handshake cost | ECC-handshake-x1, ECC-handshake-x2, ECC-handshake-x3 |
| ECC + single cipher | ECC+AES-128, ECC+AES-256, ECC+ChaCha20, ECC+SPECK, ECC+RECTANGLE, ECC+HIGHT |
| ECC + two-layer cascade | ECC+AES-256+AES-128, ECC+AES-256+ChaCha20, ECC+AES-128+SPECK, ECC+ChaCha20+SPECK, ECC+SPECK+HIGHT |
| ECC + three-layer cascade | ECC+AES-256+ChaCha20+AES-128 |

> ECC never gets a full per-size (throughput/latency/memory) benchmark
> elsewhere in this suite — an ECC-derived key is indistinguishable from a
> random one to the downstream cipher, so re-running the full 9-size sweep
> with ECC keys would just re-measure identical numbers with a constant
> handshake-cost offset added. Any `ECC+X` figure at any data size can be
> reconstructed exactly as `plain X's value + N× handshake cost` (N =
> number of cascade layers) using the raw handshake numbers above.

---

## 2. What Each Benchmark File Does

### 2.1 `benchmark1.c` — Single ciphers (hardware-accelerated)

**Covers:** §1.1 in full — 7 entries × 9 data sizes (1KB → 50MB) = 63 rows.

**Methodology:** for each entry, encrypts and decrypts data of a given size
across `outer_repeats` (50–300, size-dependent) × `inner_loops` (1–10,000,
size-dependent) iterations, reporting the median encryption time, decryption
time, throughput (Mbps), per-block latency (block ciphers only), and peak
heap+stack memory (with and without the output-buffer's own footprint) for
both the encrypt and decrypt paths. Each cipher/size combination runs in a
forked child process for isolation.

**Requirement:** RECTANGLE runs the AVX2 implementation; the binary checks
`rectangle_avx2_available()` at startup and refuses to run at all on
non-AVX2 hardware — there is no software fallback in this file.

**Output:** `phase1_results.csv`

**Build:** `gcc -O2 -mavx2 -fno-stack-protector -o benchmark1 benchmark1.c -lcrypto -lm -Wl,--wrap=malloc,--wrap=free,--wrap=realloc,--wrap=calloc`

---

### 2.2 `benchmark2.c` — Two-layer cascades (hardware-accelerated)

**Covers:** §1.2 in full — 7 cascades × 9 sizes = 63 rows.

**Methodology:** same repeat/loop structure as benchmark1.c, but each
"encrypt" timing spans both layers back-to-back (layer 1 encrypts, then
layer 2 encrypts the result; decryption reverses the order), and memory is
measured across the full two-layer region so the peak correctly captures
the intermediate ciphertext that stays alive while layer 2 runs. Each layer
gets an independent fresh random key per outer repeat.

**Requirement:** same AVX2 startup check as benchmark1.c (for the
RECTANGLE+HIGHT cascade's RECTANGLE layer).

**Output:** `phase2_results.csv`

**Build:** `gcc -O2 -mavx2 -fno-stack-protector -o benchmark2 benchmark2.c -lcrypto -lm -Wl,--wrap=malloc,--wrap=free,--wrap=realloc,--wrap=calloc`

---

### 2.3 `benchmark3.c` — Three-layer cascade (hardware-accelerated)

**Covers:** §1.3 in full — 1 cascade × 9 sizes = 9 rows.

**Methodology:** encrypts L1(AES-256)→L2(ChaCha20)→L3(AES-128), decrypts in
reverse; same timing/memory approach as benchmark2.c, extended to three
layers (two intermediate ciphertexts tracked instead of one). Keys are
fresh random bytes per layer per outer repeat — no ECC handshake, no
software/mixed-hardware variants (those live in benchmark4.c).

**Output:** `phase3_results.csv`

**Build:** `gcc -O2 -fno-stack-protector -o benchmark3 benchmark3.c -lcrypto -lm -Wl,--wrap=malloc,--wrap=free,--wrap=realloc,--wrap=calloc`

---

### 2.4 `benchmark4.c` — Hardware acceleration OFF / reduced states

**Covers:** §1.4 in full.

**Hardware states run, as a chained sequence of `execv()`-restarted process
images (`PRISEC_PHASE4_STAGE` env var), since OpenSSL resolves capability
bits in a library-load constructor that a plain `fork()` can't override:**

1. **BOTH_OFF** — every §1.4 entry, AES-NI and ChaCha20 SIMD both disabled
   (`OPENSSL_ia32cap="~0x1200020200000000:0"`).
2. **AES_ONLY_OFF** — AES-256+ChaCha20 and AES-256+ChaCha20+AES-128 only,
   AES-NI disabled, ChaCha20 SIMD left on (`~0x0200000000000000`).
3. **CHACHA_ONLY_OFF** — same two entries, ChaCha20 SIMD disabled, AES-NI
   left on (`~0x1000020000000000:0`).

AES-NI and ChaCha20 SIMD are independent OpenSSL capability bits, so a
mixed cascade like AES-256+ChaCha20(+AES-128) can have either half
disabled alone — stages 2 and 3 exist specifically to capture that split.
Every other entry only has one off state, since it either has no
accelerated path at all (SPECK, HIGHT, RECTANGLE's software version) or
only one accelerable component (the single-toggle cascades).

**Output:** `phase4_results.csv` (`aes_ha`/`chacha_ha` columns record the
hardware state per row; `NA` where that family isn't present in the entry)

**Build:** `gcc -O2 -fno-stack-protector -o benchmark4 benchmark4.c -lcrypto -lm -Wl,--wrap=malloc,--wrap=free,--wrap=realloc,--wrap=calloc`

---

### 2.5 `benchmark5.c` — Setup cost + ECC key-exchange cost

**Covers:** §1.5 in full.

**Methodology:** each entry's setup routine (EVP context init for
AES/ChaCha20; software key-schedule expansion for SPECK/HIGHT/RECTANGLE —
identical regardless of which RECTANGLE encryption implementation is used
elsewhere, since both share the same key schedule; `get_shared_key()` — two
P-256 keygens + ECDH derive + SHA-256 — for ECC) is timed 1,000 times
(100,000 for the raw ECC handshakes) with a fresh random key per iteration,
median reported in microseconds. Cascade setup times each layer's setup
back-to-back as one span. Every `ECC+X` row is computed as the matching raw
ECC handshake cost (x1/x2/x3, by layer count) plus that cipher/cascade's own
already-measured setup cost — no separate ECC+X measurement loop.

**Output:** `phase5_results.csv` (`cipher,setup_us`)

**Build:** `gcc -O2 -o benchmark5 benchmark5.c -lcrypto -lm` (no
`--wrap`/stack-protector flags needed — no memory or stack profiling here)

---

## 3. Coverage Summary

| Section | File |
|---|---|
| §1.1 Single ciphers, accelerated | benchmark1.c |
| §1.2 Two-layer cascades, accelerated | benchmark2.c |
| §1.3 Three-layer cascade, accelerated | benchmark3.c |
| §1.4 Hardware acceleration off/reduced (+ software RECTANGLE) | benchmark4.c |
| §1.5 Setup cost (all ciphers/cascades + ECC) | benchmark5.c |
