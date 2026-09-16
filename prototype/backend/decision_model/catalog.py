"""
Loads the 5-phase benchmark suite (phase1-5 CSVs) plus the security_strength
ranking, and exposes one thing: given a cipher name, a device's hardware
acceleration capabilities, and a packet size, return the correct real
measured numbers to use.
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

CIPHER_OPERAND_BITS = {
    "AES-128": 32, "AES-192": 32, "AES-256": 32,
    "ChaCha20": 32,
    "HIGHT": 8,
    "SPECK": 64,  
}

CIPHER_WORD_ADAPT_FLOOR_BITS = {
    "SPECK": 16,
}

CIPHER_ACCEL_FAMILY = {
    "AES-128": "aes_ni", "AES-192": "aes_ni", "AES-256": "aes_ni",
    "ChaCha20": "chacha_simd",
    "RECTANGLE": "avx2",
    "SPECK": None, "HIGHT": None,
}

_CHACHA_SIMD_TIERS = {"ssse3", "avx2", "avx512", "neon", "sve"}
_AVX2_TIERS = {"avx2", "avx512"}


def cipher_components(name: str) -> list:
    n = name
    if n.startswith("ECC+"):
        n = n[len("ECC+"):]
    return n.split("+")


AES_NI_NARROW_DEVICE_WORD_FIT = 0.9
AES_NI_NARROW_DEVICE_WORD_PENALTY = 1 / AES_NI_NARROW_DEVICE_WORD_FIT

def component_word_fit(component: str, device) -> float:
    if component == "RECTANGLE":
        return 1.0
    if component == "ChaCha20" and device.hw_accel_simd_best_tier in _CHACHA_SIMD_TIERS:
        return 1.0
    if component.startswith("AES") and device.hw_accel_aes_ni:
        if device.word_bits >= 32:
            return 1.0
        return AES_NI_NARROW_DEVICE_WORD_FIT
    floor = CIPHER_WORD_ADAPT_FLOOR_BITS.get(component)
    if floor is not None:
        if device.word_bits >= floor:
            return 1.0
        return device.word_bits / floor
    bits = CIPHER_OPERAND_BITS.get(component)
    if bits is None:
        return 1.0
    return min(1.0, device.word_bits / bits)


def word_fit_for_cascade(name: str, device) -> float:
    comps = cipher_components(name)
    return min(component_word_fit(c, device) for c in comps)


def component_word_penalty(component: str, device) -> float:
    if component == "RECTANGLE":
        return 1.0
    if component == "ChaCha20" and device.hw_accel_simd_best_tier in _CHACHA_SIMD_TIERS:
        return 1.0
    if component.startswith("AES") and device.hw_accel_aes_ni:
        if device.word_bits >= 32:
            return 1.0
        return AES_NI_NARROW_DEVICE_WORD_PENALTY
    floor = CIPHER_WORD_ADAPT_FLOOR_BITS.get(component)
    if floor is not None:
        if device.word_bits >= floor:
            return 1.0
        return floor / device.word_bits
    bits = CIPHER_OPERAND_BITS.get(component)
    if bits is None:
        return 1.0
    return max(1.0, bits / device.word_bits)


def word_penalty_for_cascade(name: str, device) -> float:
    comps = cipher_components(name)
    return max(component_word_penalty(c, device) for c in comps)


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
    variants: dict = field(default_factory=dict)
    _time_model_cache: dict = field(default_factory=dict, repr=False, compare=False)
    _memory_model_cache: dict = field(default_factory=dict, repr=False, compare=False)
    _energy_model_cache: dict = field(default_factory=dict, repr=False, compare=False)

    def closest_size(self, benchmarks: dict, target_bytes: int) -> Optional[BenchmarkRow]:
        if not benchmarks:
            return None
        closest_key = min(benchmarks.keys(), key=lambda s: abs(s - target_bytes))
        return benchmarks[closest_key]

    def benchmark_for(self, device, target_bytes: int) -> BenchmarkRow:
        desired = desired_accel_flags(self.name, device)
        by_size = self.variants.get(desired)
        if by_size:
            row = self.closest_size(by_size, target_bytes)
            if row is not None:
                return row

        import sys
        print(f"[catalog] WARNING: '{self.name}' has no benchmark data for accel state {desired} - "
              f"falling back to a different measured variant. This should not happen for the current "
              f"27-entry catalog; check CIPHER_ACCEL_FAMILY / benchmarks_full.csv for a gap.", file=sys.stderr)
        for combo in sorted(self.variants.keys(), key=lambda c: c.count("1"), reverse=True):
            row = self.closest_size(self.variants[combo], target_bytes)
            if row is not None:
                return row
        raise ValueError(f"No benchmark data at all for '{self.name}'")

    def estimate_time_ms(self, device) -> "TimeModel":
        desired = desired_accel_flags(self.name, device)
        if desired in self._time_model_cache:
            return self._time_model_cache[desired]

        by_size = self.variants.get(desired) or next(iter(self.variants.values()), {})
        sizes = sorted(by_size.keys())
        enc_ms_by_size = {s: by_size[s].enc_ms for s in sizes}

        if len(sizes) < 2:
            only = by_size[sizes[0]] if sizes else None
            model = TimeModel(fixed_ms=only.enc_ms if only else 0.0, slope=0.0,
                               sizes=sizes, enc_ms_by_size=enc_ms_by_size)
        else:
            s1, s2 = sizes[0], sizes[1]
            e1, e2 = enc_ms_by_size[s1], enc_ms_by_size[s2]
            slope = (e2 - e1) / (s2 - s1)
            fixed_ms = e1 - slope * s1
            model = TimeModel(fixed_ms=fixed_ms, slope=slope, sizes=sizes, enc_ms_by_size=enc_ms_by_size)

        self._time_model_cache[desired] = model
        return model

    def estimate_memory_kb(self, device) -> "MemoryModel":
        desired = desired_accel_flags(self.name, device)
        if desired in self._memory_model_cache:
            return self._memory_model_cache[desired]

        by_size = self.variants.get(desired) or next(iter(self.variants.values()), {})
        sizes = sorted(by_size.keys())
        if len(sizes) < 2:
            only = by_size[sizes[0]] if sizes else None
            model = MemoryModel(fixed_kb=only.memory_enc_peak_kb if only else 0.0, slope=0.0)
        else:
            s1, s2 = sizes[0], sizes[1]
            p1, p2 = by_size[s1].memory_enc_peak_kb, by_size[s2].memory_enc_peak_kb
            slope = (p2 - p1) / (s2 - s1)
            fixed_kb = p1 - slope * s1
            model = MemoryModel(fixed_kb=fixed_kb, slope=slope)

        self._memory_model_cache[desired] = model
        return model

    def estimate_energy_mah(self, device) -> "EnergyModel":
        desired = desired_accel_flags(self.name, device)
        if desired in self._energy_model_cache:
            return self._energy_model_cache[desired]

        by_size = self.variants.get(desired) or next(iter(self.variants.values()), {})
        sizes_with_energy = sorted(s for s, row in by_size.items() if row.energy_mah is not None)

        if not sizes_with_energy:
            self._energy_model_cache[desired] = None
            return None

        if len(sizes_with_energy) < 2:
            only_size = sizes_with_energy[0]
            model = EnergyModel(fixed_mah=by_size[only_size].energy_mah, slope=0.0)
        else:
            s1, s2 = sizes_with_energy[0], sizes_with_energy[1]
            m1, m2 = by_size[s1].energy_mah, by_size[s2].energy_mah
            slope = (m2 - m1) / (s2 - s1)
            fixed_mah = m1 - slope * s1
            model = EnergyModel(fixed_mah=fixed_mah, slope=slope)

        self._energy_model_cache[desired] = model
        return model


@dataclass
class MemoryModel:
    fixed_kb: float
    slope: float

    def estimate(self, target_bytes: int) -> float:
        return self.fixed_kb + self.slope * target_bytes


@dataclass
class EnergyModel:
    fixed_mah: float
    slope: float

    def estimate(self, target_bytes: int) -> float:
        return max(self.fixed_mah + self.slope * target_bytes, 0.0)


@dataclass
class TimeEstimate:
    enc_ms: float
    throughput_enc_mbps: float
    latency_us: float
    below_min_sample: bool
    interpolated: bool


@dataclass
class TimeModel:
    fixed_ms: float
    slope: float
    sizes: list
    enc_ms_by_size: dict

    def _enc_ms_for(self, target_bytes: int) -> tuple:
        """Returns (enc_ms, below_min_sample, interpolated)."""
        if not self.sizes:
            return max(self.fixed_ms + self.slope * target_bytes, 1e-12), False, False

        if target_bytes in self.enc_ms_by_size:
            return self.enc_ms_by_size[target_bytes], False, False

        if target_bytes < self.sizes[0]:
            return max(self.fixed_ms + self.slope * target_bytes, 1e-12), True, False

        if target_bytes > self.sizes[-1]:
            s_max = self.sizes[-1]
            e_max = self.enc_ms_by_size[s_max]
            return max(e_max * (target_bytes / s_max), 1e-12), False, False

        s_lo = max(s for s in self.sizes if s < target_bytes)
        s_hi = min(s for s in self.sizes if s > target_bytes)
        e_lo, e_hi = self.enc_ms_by_size[s_lo], self.enc_ms_by_size[s_hi]
        estimate_from_lo = e_lo * (target_bytes / s_lo)
        estimate_from_hi = e_hi * (target_bytes / s_hi)
        enc_ms = (estimate_from_lo + estimate_from_hi) / 2
        return max(enc_ms, 1e-12), False, True

    def estimate(self, target_bytes: int) -> TimeEstimate:
        enc_ms, below_min_sample, interpolated = self._enc_ms_for(target_bytes)
        throughput_mbps = (target_bytes * 8) / (enc_ms / 1000) / 1e6
        latency_us_per_byte = (enc_ms * 1000) / target_bytes if target_bytes > 0 else 0.0
        return TimeEstimate(
            enc_ms=enc_ms,
            throughput_enc_mbps=throughput_mbps,
            latency_us=latency_us_per_byte,
            below_min_sample=below_min_sample,
            interpolated=interpolated,
        )


def _load_consolidated(path: str) -> dict:

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
            setup_by_name[name] = float(row["setup_us"])

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