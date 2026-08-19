"""
device_fit.py

device_fit(cipher) = memory_fit + word_fit (+ energy_fit if battery-powered)

See device-fit.md for the full design rationale.
"""

import catalog
from typing import Optional

PENALTY_FACTOR = 0.75
MEM_THRESHOLD = 0.5

# device_fit weights, by duty_cycle - only used when battery_powered=True.
# When not battery-powered: fixed 0.5/0.5 mem/word (defined inline below).
BATTERY_WEIGHTS = {
    "Sporadic":   {"mem": 0.45, "word": 0.45, "energy": 0.10},
    "Periodic":   {"mem": 0.40, "word": 0.40, "energy": 0.20},
    "Continuous": {"mem": 0.35, "word": 0.35, "energy": 0.30},
}


def memory_feasible(cipher_entry, device, packet_size_bytes: int) -> bool:
    """Hard exclusion, not a score: if a cipher's peak memory genuinely
    exceeds the device's RAM, it cannot run without fragmenting the buffer
    into smaller chunks - an architectural change this model doesn't
    support, so such a cipher is excluded from candidates entirely rather
    than just scored very low.

    Uses the linear-fit memory estimate (catalog.CipherEntry.estimate_memory_kb),
    not the closest benchmarked row's raw value - a request between two
    benchmarked sizes (e.g. 0.6MB) would otherwise round to whichever real
    row is numerically closer (e.g. 1MB) and use THAT row's footprint,
    wrongly excluding a cipher that would actually fit at the real
    requested size."""
    device_ram_kb = device.ram_size_mb * 1024
    estimated_kb = cipher_entry.estimate_memory_kb(device).estimate(packet_size_bytes)
    return estimated_kb <= device_ram_kb


def memory_fit(cipher_memory_kb: float, device_ram_kb: float) -> float:
    utilization = cipher_memory_kb / device_ram_kb
    if utilization <= MEM_THRESHOLD:
        return 1 - utilization
    return (1 - utilization) * PENALTY_FACTOR


def word_fit(cipher_name: str, device) -> float:
    """Delegates to catalog.word_fit_for_cascade - handles per-component
    behavior (SPECK's adaptive floor, RECTANGLE's full adaptability, fixed
    ciphers, and AES's AES-NI-aware special case) uniformly, worst-component-wins for cascades."""
    return catalog.word_fit_for_cascade(cipher_name, device)


def energy_fit(cipher_entry, device, packet_size_bytes: int, full_catalog: dict) -> Optional[float]:
    """
    Normalized against the FULL catalog (not the candidate pool) at this
    device's actual hardware state and this packet size - lower energy ->
    higher fit. Returns None if energy data isn't available for this
    cipher/device/size combination (caller falls back to non-battery weighting).
    """
    catalog_values = {}
    for name, entry in full_catalog.items():
        row = entry.benchmark_for(device, packet_size_bytes)
        if row.energy_mah is not None:
            catalog_values[name] = row.energy_mah

    if cipher_entry.name not in catalog_values or not catalog_values:
        return None

    values = list(catalog_values.values())
    lo, hi = min(values), max(values)
    if hi == lo:
        return 0.5
    return 1 - (catalog_values[cipher_entry.name] - lo) / (hi - lo)


def device_fit(cipher_entry, device, packet_size_bytes: int, full_catalog: dict = None) -> dict:
    """
    Returns {"score": float, "breakdown": {...}} - breakdown included for
    auditability/debugging, same pattern as the rest of the model.
    full_catalog is needed for energy_fit's catalog-wide normalization -
    pass the same catalog dict decision_model.py already has loaded.
    """
    row = cipher_entry.benchmark_for(device, packet_size_bytes)
    device_ram_kb = device.ram_size_mb * 1024  # ram_size stored in MB per the profile schema

    estimated_memory_kb = cipher_entry.estimate_memory_kb(device).estimate(packet_size_bytes)
    mem_fit = memory_fit(estimated_memory_kb, device_ram_kb)
    wrd_fit = word_fit(cipher_entry.name, device)

    if not device.battery_powered:
        score = 0.5 * mem_fit + 0.5 * wrd_fit
        breakdown = {"memory_fit": mem_fit, "word_fit": wrd_fit, "energy_fit": None,
                     "weights": {"mem": 0.5, "word": 0.5, "energy": 0.0}}
        return {"score": score, "breakdown": breakdown}

    weights = BATTERY_WEIGHTS[device.duty_cycle]
    nrg_fit = energy_fit(cipher_entry, device, packet_size_bytes, full_catalog) if full_catalog else None

    if nrg_fit is None:
        # No energy data available for this cipher/device/size - fall back to
        # the non-battery weighting rather than guess. Flagged in the
        # breakdown so callers can see this happened.
        score = 0.5 * mem_fit + 0.5 * wrd_fit
        breakdown = {"memory_fit": mem_fit, "word_fit": wrd_fit, "energy_fit": None,
                     "weights": {"mem": 0.5, "word": 0.5, "energy": 0.0},
                     "note": "energy data unavailable - fell back to non-battery weighting"}
        return {"score": score, "breakdown": breakdown}

    score = weights["mem"] * mem_fit + weights["word"] * wrd_fit + weights["energy"] * nrg_fit
    breakdown = {"memory_fit": mem_fit, "word_fit": wrd_fit, "energy_fit": nrg_fit, "weights": weights}
    return {"score": score, "breakdown": breakdown}