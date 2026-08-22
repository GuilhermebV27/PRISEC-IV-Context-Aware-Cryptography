"""
decision_model.py

Single entry point: decide(profile, context, weights) -> ranked list of
ciphers with full score breakdowns.

final_score(cipher) = w_device*device_fit + w_security*security_fit + w_application*application_fit

Weights are user-configurable (must sum to exactly 1); default is equal
thirds. This module imports the three focused fit modules rather than
containing their logic itself.
"""

from dataclasses import dataclass
from typing import Optional

import application_fit
import device_fit
import security_fit
from catalog import load_catalog

DEFAULT_WEIGHTS = {"device": 1 / 3, "security": 1 / 3, "application": 1 / 3}
_CATALOG = None


def _get_catalog():
    global _CATALOG
    if _CATALOG is None:
        _CATALOG = load_catalog()
    return _CATALOG


@dataclass
class Device:
    ram_size_mb: float
    clock_speed_mhz: float
    word_bits: int
    battery_powered: bool
    hw_accel_aes_ni: bool
    hw_accel_simd_best_tier: Optional[str]  # None (no SIMD) / "ssse3"/"avx2"/"avx512"/"neon"/"sve"
    duty_cycle: str  # needed here too, since device_fit's energy_fit weighting depends on it


@dataclass
class Context:
    security_level: str
    data_confidentiality: str
    data_lifetime: str
    duty_cycle: str
    latency_tolerance: str
    throughput_required: str
    packet_size_bytes: int


def validate_weights(weights: dict):
    total = sum(weights.values())
    if abs(total - 1.0) > 1e-9:
        raise ValueError(f"Top-level weights must sum to exactly 1.0, got {total}")


MAX_SUPPORTED_PACKET_SIZE_BYTES = 100 * 1024 * 1024  # 100MB - largest benchmarked size is 50MB;
                                                        # beyond 100MB the closest-match approximation
                                                        # is too far from any real measurement to trust


def decide(device: Device, context: Context, weights: Optional[dict] = None) -> dict:
    weights = weights or DEFAULT_WEIGHTS
    validate_weights(weights)

    if context.packet_size_bytes > MAX_SUPPORTED_PACKET_SIZE_BYTES:
        return {
            "recommended_ciphers": [],
            "infeasible": True,
            "reason": f"Packet size ({context.packet_size_bytes} bytes) exceeds the maximum "
                      f"supported size ({MAX_SUPPORTED_PACKET_SIZE_BYTES} bytes / 100MB). The largest "
                      f"benchmarked packet size is 50MB - beyond 100MB, proportional extrapolation from "
                      f"the 50MB measurement is too far past any real data to trust.",
            "weights_used": weights,
        }

    catalog = _get_catalog()
    requirement = security_fit.compute_requirement(
        context.security_level, context.data_confidentiality, context.data_lifetime
    )

    # Hard feasibility filter: exclude any cipher whose peak memory genuinely
    # exceeds the device's RAM (would require buffer fragmentation, not
    # modeled). Done BEFORE scoring, and the surviving set is what
    # application_fit normalizes throughput/latency/setup against too.
    feasible = {
        name: entry for name, entry in catalog.items()
        if device_fit.memory_feasible(entry, device, context.packet_size_bytes)
    }

    if not feasible:
        return {
            "recommended_ciphers": [],
            "infeasible": True,
            "reason": "No cipher/cascade fits this device's RAM at this packet size. "
                      "Every candidate's peak memory footprint exceeds the device's total RAM - "
                      "would require fragmenting the payload into smaller chunks, which this "
                      "model does not support.",
            "requirement": requirement,
            "weights_used": weights,
        }

    results = {}
    for name, entry in feasible.items():
        dev = device_fit.device_fit(entry, device, context.packet_size_bytes, catalog)
        sec = security_fit.security_fit(entry, requirement)
        app = application_fit.application_fit(entry, device, context.packet_size_bytes, context, feasible)

        final = weights["device"] * dev["score"] + weights["security"] * sec["score"] + weights["application"] * app["score"]

        results[name] = {
            "final_score": final,
            "device_fit": dev, "security_fit": sec, "application_fit": app,
        }

    best_score = max(r["final_score"] for r in results.values())
    tied_winners = [name for name, r in results.items() if abs(r["final_score"] - best_score) < 1e-9]

    if len(tied_winners) > 1:
        # Exact ties are broken by security_strength (highest wins) rather
        # than returning every tied cipher - a deliberate, deterministic
        # tiebreaker, not an arbitrary pick. If security_strength ALSO ties
        # (rare - would need two ciphers with identical final_score AND
        # identical security_strength), the remaining tied set is returned
        # as-is, since there's no further rule to break it by.
        best_strength = max(feasible[name].security_strength for name in tied_winners)
        tied_winners = [name for name in tied_winners
                        if abs(feasible[name].security_strength - best_strength) < 1e-9]

    return {
        "recommended_ciphers": tied_winners,   # list - normally a single winner; may still
                                                 # contain more than one if security_strength
                                                 # also ties after the primary tiebreaker
        "infeasible": False,
        "excluded_for_memory": sorted(set(catalog) - set(feasible)),
        "requirement": requirement,
        "weights_used": weights,
        "all_scores": results,
    }