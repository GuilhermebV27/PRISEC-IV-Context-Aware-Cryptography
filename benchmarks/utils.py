import gc
import os
import time
import statistics
import tracemalloc
import psutil


def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len == 0 or pad_len > len(data):
        raise ValueError("Invalid PKCS#7 padding")
    return data[:-pad_len]


REPEATS = 100

_proc = psutil.Process(os.getpid())


def measure(fn, *args, repeats=REPEATS):
    times     = []
    mem_peaks = []
    result    = None

    for _ in range(repeats):
        gc.collect()
        tracemalloc.start()
        t0 = time.perf_counter()
        result = fn(*args)
        t1 = time.perf_counter()
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        times.append(t1 - t0)
        mem_peaks.append(peak)

    med_time = statistics.median(times)
    std_time = statistics.stdev(times) if len(times) > 1 else 0.0
    med_mem  = statistics.median(mem_peaks)

    return med_time, std_time, med_mem, result
