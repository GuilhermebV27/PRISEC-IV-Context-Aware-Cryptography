import os
import aes
import chacha20
import speck
import rectangle
import hight
from utils import measure

DATA_SIZES = {
    "64 B":   64,
    "256 B":  256,
    "1 KB":   1   * 1024,
    "5 KB":   5   * 1024,
    "10 KB":  10  * 1024,
    "50 KB":  50  * 1024,
    "100 KB": 100 * 1024,
    "1 MB":   1   * 1024 * 1024,
    "5 MB":   5   * 1024 * 1024,
    "10 MB":  10  * 1024 * 1024,
    "50 MB":  50  * 1024 * 1024,
}

ALGORITHMS = [
    (aes,       "AES-128",   16, 16),
    (aes,       "AES-192",   24, 16),
    (aes,       "AES-256",   32, 16),
    (chacha20,  "ChaCha20",  32, 64),
    (speck,     "SPECK",     16, 16),
    (rectangle, "RECTANGLE", 16,  8),
    (hight,     "HIGHT",     16,  8),
]

def get_repeats(size_n):
    if size_n <= 10 * 1024:     return 100
    elif size_n <= 1024 * 1024: return 30
    else:                       return 10

def run_benchmark():
    # warm-up
    _wd = os.urandom(64)
    for _mod in (aes, chacha20, speck, rectangle, hight):
        _k = os.urandom(32 if _mod is chacha20 else 16)
        _mod.decrypt(_k, _mod.encrypt(_k, _wd))

    results = []
    for mod, label, key_bytes, block_bytes in ALGORITHMS:
        key = os.urandom(key_bytes)
        for size_label, size_n in DATA_SIZES.items():
            plaintext = os.urandom(size_n)
            reps = get_repeats(size_n)

            enc_t, enc_std, enc_mem, ct  = measure(mod.encrypt, key, plaintext, repeats=reps)
            dec_t, dec_std, dec_mem, rec = measure(mod.decrypt, key, ct,        repeats=reps)

            assert rec == plaintext, f"{label} decrypt mismatch @ {size_label}"

            is_stream = (mod is chacha20)
            lat_us    = None if is_stream else (enc_t / (size_n / block_bytes)) * 1e6
            mem_kb    = max(enc_mem, dec_mem) / 1024

            results.append({
                "algorithm":    label,
                "data_size":    size_label,
                "enc_ms":       round(enc_t   * 1e3,  4),
                "enc_ms_stdev": round(enc_std * 1e3,  4),
                "dec_ms":       round(dec_t   * 1e3,  4),
                "dec_ms_stdev": round(dec_std * 1e3,  4),
                "enc_mbps":     round(size_n / enc_t / (1024 ** 2), 4),
                "dec_mbps":     round(size_n / dec_t / (1024 ** 2), 4),
                "lat_us":       round(lat_us, 6) if lat_us is not None else "N/A",
                "mem_kb":       round(mem_kb, 2),
            })

    return results