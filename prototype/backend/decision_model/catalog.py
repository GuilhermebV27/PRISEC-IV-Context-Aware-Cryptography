"""
catalog.py

Loads the 5-phase benchmark suite (phase1-5 CSVs) plus the security_strength
ranking, and exposes one thing: given a cipher name, a device's hardware
acceleration capabilities, and a packet size, return the correct real
measured numbers to use.

Key design point: which benchmark ROW gets used (phase1-3's accelerated
numbers vs phase4's unaccelerated ones) depends on the device's actual
hardware, per the finding that phase1-3 already assume acceleration is
present by default. This module picks the row; it does not apply any
synthetic discount/bonus factor.
"""

import csv
import os
from dataclasses import dataclass, field
from typing import Optional

_SIZE_MULTIPLIERS = {"KB": 1024, "MB": 1024 * 1024}


def parse_data_size(raw: str) -> int:
    raw = raw.strip()
    unit = raw[-2:]
    number = float(raw[:-2])
    return int(number * _SIZE_MULTIPLIERS[unit])


# ---------------------------------------------------------------------------
# Per-cipher static metadata (word size, acceleration requirements)
# ---------------------------------------------------------------------------
#
# cipher_operand_bits: the word size word_fit compares against the device's
# own word size. AES/ChaCha20 = 32-bit per their specs. HIGHT = 8-bit
# (byte-oriented by design). RECTANGLE adapts to whatever width is
# available (bit-sliced) and is handled as a special case (always 1.0,
# never computed via the ratio) rather than a fixed operand size.
CIPHER_OPERAND_BITS = {
    "AES-128": 32, "AES-192": 32, "AES-256": 32,
    "ChaCha20": 32,
    "HIGHT": 8,
    "SPECK": 64,   # 16-byte (128-bit) block -> word = block/2 = 64-bit (Speck128/* family)
}

# SPECK can shrink its effective word size to match a narrower device (same
# spirit as RECTANGLE's adaptability), stepping through REAL, actually-
# published Speck2n/mn variants: Speck128/* (word=64), Speck64/* (word=32),
# Speck32/64 (word=16, the smallest published variant - no smaller one
# exists). Floor is therefore 16-bit, not arbitrary. RECTANGLE has NO floor
# (fully adaptive); ciphers not listed here are fixed-width (no adaptation).
#
# KNOWN OPEN ITEM: the smallest variant (Speck32/64) has only a 32-bit
# block size, which carries a real birthday-bound collision risk around
# ~2^16 blocks (~256KB of data) - a genuine security weakness, not just a
# performance tradeoff. security_strength is currently a single fixed
# value per cipher regardless of which variant a given device ends up
# using; whether SPECK's security_strength should be reduced when a narrow
# device forces the smallest variant is an open design question, not yet
# decided.
CIPHER_WORD_ADAPT_FLOOR_BITS = {
    "SPECK": 16,
}

# Which acceleration family each base cipher can use. RECTANGLE needs AVX2
# specifically (hard requirement in the reference implementation - falls
# back to software, not a mismatch penalty, when AVX2 is absent).
CIPHER_ACCEL_FAMILY = {
    "AES-128": "aes_ni", "AES-192": "aes_ni", "AES-256": "aes_ni",
    "ChaCha20": "chacha_simd",
    "RECTANGLE": "avx2",
    "SPECK": None, "HIGHT": None,
}

# SIMD tiers (from hw_detect.py's best_simd_tier) that count as "has ChaCha
# SIMD acceleration" vs "has AVX2 specifically" (for RECTANGLE).
_CHACHA_SIMD_TIERS = {"ssse3", "avx2", "avx512", "neon", "sve"}
_AVX2_TIERS = {"avx2", "avx512"}


def cipher_components(name: str) -> list:
    """'AES-256+ChaCha20+AES-128' -> ['AES-256','ChaCha20','AES-128']. Strips a leading 'ECC+'."""
    n = name
    if n.startswith("ECC+"):
        n = n[len("ECC+"):]
    return n.split("+")


def component_word_fit(component: str, device_word_bits: int) -> float:
    """0-1 fit score for a single cascade component against a device's word
    size. RECTANGLE: fully adaptive, always 1.0. SPECK: adapts down to its
    floor (CIPHER_WORD_ADAPT_FLOOR_BITS), penalized only below that. Fixed
    ciphers (AES/ChaCha20/HIGHT): standard ratio, capped at 1.0."""
    if component == "RECTANGLE":
        return 1.0
    floor = CIPHER_WORD_ADAPT_FLOOR_BITS.get(component)
    if floor is not None:
        if device_word_bits >= floor:
            return 1.0
        return device_word_bits / floor
    bits = CIPHER_OPERAND_BITS.get(component)
    if bits is None:
        return 1.0
    return min(1.0, device_word_bits / bits)


def word_fit_for_cascade(name: str, device_word_bits: int) -> float:
    """Cascade's overall word_fit = the worst (minimum) per-component fit -
    a device narrower than any single stage's requirement is penalized for
    that stage, regardless of how well the others fit."""
    comps = cipher_components(name)
    return min(component_word_fit(c, device_word_bits) for c in comps)


def component_word_penalty(component: str, device_word_bits: int) -> float:
    """Time-multiplier version (>=1, never speeds things up) - the inverse
    shape of component_word_fit, for use in the application-side time
    scaling formula."""
    if component == "RECTANGLE":
        return 1.0
    floor = CIPHER_WORD_ADAPT_FLOOR_BITS.get(component)
    if floor is not None:
        if device_word_bits >= floor:
            return 1.0
        return floor / device_word_bits
    bits = CIPHER_OPERAND_BITS.get(component)
    if bits is None:
        return 1.0
    return max(1.0, bits / device_word_bits)


def word_penalty_for_cascade(name: str, device_word_bits: int) -> float:
    """Cascade's overall time penalty = the worst (maximum) per-component
    penalty, matching word_fit_for_cascade's use of the minimum fit."""
    comps = cipher_components(name)
    return max(component_word_penalty(c, device_word_bits) for c in comps)


def is_ecc(name: str) -> bool:
    return name.startswith("ECC+") or name.startswith("ECC-")


def uses_component(name: str, component: str) -> bool:
    return component in cipher_components(name)


# ---------------------------------------------------------------------------
# security_strength ranking (from security-needs-profile.md #7)
# ---------------------------------------------------------------------------

SECURITY_STRENGTH = {
    "ECC+AES-256+ChaCha20+AES-128": 1.00,
    "ECC+AES-256+ChaCha20": 0.97,
    "ECC+AES-256+AES-128": 0.96,
    "AES-256+ChaCha20+AES-128": 0.95,
    "ECC+AES-256": 0.92,
    "AES-256+ChaCha20": 0.92,
    "ECC+ChaCha20+SPECK": 0.92,
    "AES-256+AES-128": 0.91,
    "ECC+ChaCha20": 0.89,
    "AES-256": 0.87,
    "ChaCha20+SPECK": 0.87,
    "ChaCha20": 0.84,
    "ECC+AES-128+SPECK": 0.73,
    "AES-192": 0.71,
    "ECC+AES-128": 0.68,
    "AES-128+SPECK": 0.68,
    "AES-128+HIGHT": 0.66,
    "AES-128": 0.63,
    "ECC+SPECK+HIGHT": 0.51,
    "ECC+SPECK": 0.48,
    "SPECK+HIGHT": 0.46,
    "SPECK": 0.43,
    "ECC+RECTANGLE": 0.40,
    "RECTANGLE+HIGHT": 0.38,
    "RECTANGLE": 0.35,
    "ECC+HIGHT": 0.31,
    "HIGHT": 0.26,
}
# All 27 rows now map cleanly to catalog entries - the earlier ambiguous
# "ECC + RECTANGLE -> HIGHT" row is gone, replaced by "ECC + SPECK -> HIGHT"
# (= ECC+SPECK+HIGHT), which matches the actual catalog. No open mapping
# issue remains.


@dataclass
class BenchmarkRow:
    enc_ms: float
    memory_enc_peak_kb: float
    throughput_enc_mbps: float
    latency_us: Optional[float]
    energy_mah: Optional[float] = None

    @property
    def effective_latency_us(self) -> float:
        return self.latency_us if self.latency_us is not None else self.enc_ms * 1000.0


@dataclass
class CipherEntry:
    name: str
    security_strength: float
    is_ecc: bool
    setup_us: float
    # ALL measured acceleration variants: {(aes_flag, simd_flag): {size_bytes: BenchmarkRow}}
    # flags are strings matching the CSV exactly: "1"/"0"/"NA"
    variants: dict = field(default_factory=dict)

    def closest_size(self, benchmarks: dict, target_bytes: int) -> Optional[BenchmarkRow]:
        if not benchmarks:
            return None
        closest_key = min(benchmarks.keys(), key=lambda s: abs(s - target_bytes))
        return benchmarks[closest_key]

    def benchmark_for(self, device, target_bytes: int) -> BenchmarkRow:
        """Picks the EXACT variant this device qualifies for (accelerated,
        unaccelerated, or - for the mixed AES+ChaCha20 cascades - the correct
        partial-acceleration state), not just a fully-on/fully-off simplification."""
        desired = desired_accel_flags(self.name, device)
        by_size = self.variants.get(desired)
        if by_size:
            row = self.closest_size(by_size, target_bytes)
            if row is not None:
                return row
        # Fallback: desired combo not measured (shouldn't happen for the 27
        # catalog entries, verified against the full checklist) - use
        # whatever variant IS available, preferring the most-accelerated one.
        for combo in sorted(self.variants.keys(), key=lambda c: c.count("1"), reverse=True):
            row = self.closest_size(self.variants[combo], target_bytes)
            if row is not None:
                return row
        raise ValueError(f"No benchmark data at all for '{self.name}'")

    def estimate_memory_kb(self, device) -> "MemoryModel":
        """
        Derives a linear model (fixed_kb + slope * size_bytes) for this
        cipher's memory usage, from the two smallest REAL benchmarked points
        at the device's matching hardware variant. Verified against actual
        data: predicts every other real benchmarked size essentially
        exactly (not just small sizes) - single ciphers get slope~1
        (buffer ~= packet size), cascades get slope~N (N buffers, since
        the intermediate ciphertext from each stage scales with data too).

        This replaces closest_size() for memory specifically, since
        closest_size() uses a fixed-size row's memory value as-is even for
        a very different requested size - correct at the 9 benchmarked
        points, wrong everywhere between them (the bug this fixes: a 0.6MB
        request rounding to the 1MB row's ~1MB+ footprint and being
        wrongly excluded on a 1MB-RAM device).
        """
        desired = desired_accel_flags(self.name, device)
        by_size = self.variants.get(desired) or next(iter(self.variants.values()), {})
        sizes = sorted(by_size.keys())
        if len(sizes) < 2:
            only = by_size[sizes[0]] if sizes else None
            return MemoryModel(fixed_kb=only.memory_enc_peak_kb if only else 0.0, slope=0.0)

        s1, s2 = sizes[0], sizes[1]
        p1, p2 = by_size[s1].memory_enc_peak_kb, by_size[s2].memory_enc_peak_kb
        slope = (p2 - p1) / (s2 - s1)
        fixed_kb = p1 - slope * s1
        return MemoryModel(fixed_kb=fixed_kb, slope=slope)


@dataclass
class MemoryModel:
    fixed_kb: float
    slope: float  # kb of memory per byte of packet size

    def estimate(self, target_bytes: int) -> float:
        return self.fixed_kb + self.slope * target_bytes


def _load_consolidated(path: str) -> dict:
    """Returns {name: {(aes_flag, simd_flag): {size_bytes: BenchmarkRow}}}
    and {name: setup_us} - loaded together since they're in the same file.
    battery_usage_mah is read directly into each BenchmarkRow - no separate
    energy file/join needed, timing/memory/energy all live in one row now."""
    benchmarks = {}
    setup_by_name = {}
    if not os.path.exists(path):
        return benchmarks, setup_by_name
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            name = row["algorithm/cascade"]
            size = parse_data_size(row["data_size"])
            aes_flag = row["aes-ni_ha"]
            simd_flag = row["simd_ha"]
            setup_by_name[name] = float(row["setup_us"])  # same value every row for a given name

            lat = row.get("latency_us")
            latency_us = None if lat in (None, "NA") else float(lat)
            energy_raw = row.get("battery_usage_mah")
            energy_mah = None if energy_raw in (None, "NA") else float(energy_raw)
            benchmarks.setdefault(name, {}).setdefault((aes_flag, simd_flag), {})[size] = BenchmarkRow(
                enc_ms=float(row["enc_ms"]),
                memory_enc_peak_kb=float(row["memory_enc_peak_kb"]),
                throughput_enc_mbps=float(row["throughput_enc_mbps"]),
                latency_us=latency_us,
                energy_mah=energy_mah,
            )
    return benchmarks, setup_by_name


def desired_accel_flags(name: str, device) -> tuple:
    """What (aes-ni_ha, simd_ha) combo this device actually qualifies for,
    for this specific cipher/cascade's components."""
    comps = cipher_components(name)
    aes_flag, simd_flag = "NA", "NA"
    for c in comps:
        family = CIPHER_ACCEL_FAMILY.get(c)
        if family == "aes_ni":
            aes_flag = "1" if device.hw_accel_aes_ni else "0"
        elif family == "chacha_simd":
            simd_flag = "1" if device.hw_accel_simd_best_tier in _CHACHA_SIMD_TIERS else "0"
        elif family == "avx2":
            simd_flag = "1" if device.hw_accel_simd_best_tier in _AVX2_TIERS else "0"
    return (aes_flag, simd_flag)


def load_catalog(benchmarks_dir: Optional[str] = None) -> dict:
    benchmarks_dir = benchmarks_dir or os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(benchmarks_dir, "benchmarks_full.csv")

    all_benchmarks, all_setup = _load_consolidated(path)

    catalog = {}
    for name, strength in SECURITY_STRENGTH.items():
        setup_us = all_setup.get(name)
        if setup_us is None:
            import sys
            print(f"[catalog] WARNING: no setup_us found for '{name}' - setup_fit will be unavailable for it", file=sys.stderr)
            setup_us = float("inf")

        catalog[name] = CipherEntry(
            name=name,
            security_strength=strength,
            is_ecc=is_ecc(name),
            setup_us=setup_us,
            variants=all_benchmarks.get(name, {}),
        )
    return catalog