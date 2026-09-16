"""device_fit(cipher) = memory_fit + word_fit (+ energy_fit if battery-powered)"""

from typing import Optional

import catalog

PENALTY_FACTOR = 0.75
MEM_THRESHOLD = 0.5

BATTERY_WEIGHTS = {
    "Sporadic":   {"mem": 0.45, "word": 0.45, "energy": 0.10},
    "Periodic":   {"mem": 0.40, "word": 0.40, "energy": 0.20},
    "Continuous": {"mem": 0.35, "word": 0.35, "energy": 0.30},
}


def memory_feasible(cipher_entry, device, packet_size_bytes: int) -> bool:
    device_ram_kb = device.ram_size_mb * 1024
    estimated_kb = cipher_entry.estimate_memory_kb(device).estimate(packet_size_bytes)
    return estimated_kb <= device_ram_kb


def memory_fit(cipher_memory_kb: float, device_ram_kb: float) -> float:
    utilization = cipher_memory_kb / device_ram_kb
    if utilization <= MEM_THRESHOLD:
        return 1 - utilization
    return (1 - utilization) * PENALTY_FACTOR


def word_fit(cipher_name: str, device) -> float:
    return catalog.word_fit_for_cascade(cipher_name, device)


def energy_fit(cipher_entry, device, packet_size_bytes: int, full_catalog: dict) -> Optional[float]:
    catalog_values = {}
    for name, entry in full_catalog.items():
        model = entry.estimate_energy_mah(device)
        if model is not None:
            catalog_values[name] = model.estimate(packet_size_bytes)

    if cipher_entry.name not in catalog_values or not catalog_values:
        return None

    values = list(catalog_values.values())
    lo, hi = min(values), max(values)
    if hi == lo:
        return 0.5
    return 1 - (catalog_values[cipher_entry.name] - lo) / (hi - lo)


def device_fit(cipher_entry, device, packet_size_bytes: int, full_catalog: dict = None) -> dict:
    device_ram_kb = device.ram_size_mb * 1024

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
        score = 0.5 * mem_fit + 0.5 * wrd_fit
        breakdown = {"memory_fit": mem_fit, "word_fit": wrd_fit, "energy_fit": None,
                     "weights": {"mem": 0.5, "word": 0.5, "energy": 0.0},
                     "note": "energy data unavailable - fell back to non-battery weighting"}
        return {"score": score, "breakdown": breakdown}

    score = weights["mem"] * mem_fit + weights["word"] * wrd_fit + weights["energy"] * nrg_fit
    breakdown = {"memory_fit": mem_fit, "word_fit": wrd_fit, "energy_fit": nrg_fit, "weights": weights}
    return {"score": score, "breakdown": breakdown}