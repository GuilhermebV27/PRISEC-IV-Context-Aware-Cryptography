"""
live_execute.py - runs a real, single encryption/decryption on the actual
device (via live_encrypt/run_once.c)
"""

import json
import os
import subprocess

LIVE_ENCRYPT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "live_encrypt")
BINARY_PATH = os.path.join(LIVE_ENCRYPT_DIR, "run_once")
SOURCE_PATH = os.path.join(LIVE_ENCRYPT_DIR, "run_once.c")

DEFAULT_WARMUP_RUNS = 5
DEFAULT_TIMEOUT_S = 60.0


class LiveExecutionError(Exception):
    pass


def _ensure_binary_built() -> None:

    needs_build = not os.path.exists(BINARY_PATH) or (
        os.path.getmtime(SOURCE_PATH) > os.path.getmtime(BINARY_PATH)
    )
    if not needs_build:
        return

    cmd = [
        "gcc", "-O2", "-mavx2", "-fno-stack-protector",
        "-o", BINARY_PATH, SOURCE_PATH, "-lcrypto", "-lm",
        "-Wl,--wrap=malloc,--wrap=free,--wrap=realloc,--wrap=calloc",
    ]
    result = subprocess.run(cmd, cwd=LIVE_ENCRYPT_DIR, capture_output=True, text=True)
    if result.returncode != 0:
        raise LiveExecutionError(
            "Failed to build the live-execution binary on this device. "
            "This device needs gcc and libssl-dev (OpenSSL development headers) "
            "installed to run a real test.\n"
            f"Build error:\n{result.stderr.strip()}"
        )


def run_live_encryption(cipher_name: str, packet_size_bytes: int,
                         warmup_runs: int = DEFAULT_WARMUP_RUNS,
                         timeout_s: float = DEFAULT_TIMEOUT_S) -> dict:

    if packet_size_bytes <= 0:
        raise LiveExecutionError("packet_size_bytes must be greater than 0.")
    if warmup_runs < 0:
        raise LiveExecutionError("warmup_runs cannot be negative.")

    _ensure_binary_built()

    cmd = [BINARY_PATH, cipher_name, str(packet_size_bytes), str(warmup_runs)]
    try:
        result = subprocess.run(cmd, cwd=LIVE_ENCRYPT_DIR, capture_output=True,
                                 text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        raise LiveExecutionError(
            f"Live encryption run timed out after {timeout_s}s "
            f"(cipher={cipher_name}, size={packet_size_bytes} bytes)."
        )

    if result.returncode not in (0, 2):

        raise LiveExecutionError(
            f"Live encryption failed for '{cipher_name}': {result.stderr.strip() or 'unknown error'}"
        )

    try:
        data = json.loads(result.stdout.strip())
    except (json.JSONDecodeError, ValueError):
        raise LiveExecutionError(
            f"Live encryption produced unreadable output for '{cipher_name}': {result.stdout!r}"
        )

    if not data.get("roundtrip_ok", False):
        raise LiveExecutionError(
            f"Live encryption ran but decrypted output didn't match the original plaintext "
            f"for '{cipher_name}' - the result is not trustworthy and has been discarded."
        )

    return data