"""
application_fit.py

application_fit(cipher) = w_throughput_eff*throughput_fit + w_latency_eff*latency_fit
                         + w_setup_eff*setup_fit

See application-needs-profile.md for the full design rationale.
"""

import catalog

PENALTY_FACTOR = 0.75

REFERENCE_CLOCK_MHZ = 2500  # benchmark suite's reference machine (Xeon Platinum 8259CL)

LATENCY_TOLERANCE_SCORE = {"High": 0.4, "Medium": 0.7, "Low": 1.0}
THROUGHPUT_REQUIRED_SCORE = {"Low": 0.25, "Medium": 0.5, "High": 0.75, "Very High": 1.0}

DUTY_CYCLE_WEIGHTS = {
    "Sporadic":   {"setup": 0.33, "throughput": 0.33, "latency": 0.33},
    "Periodic":   {"setup": 0.2,  "throughput": 0.4,  "latency": 0.4},
    "Continuous": {"setup": 0.0,  "throughput": 0.5,  "latency": 0.5},
}


def word_penalty(cipher_name: str, device_word_bits: int) -> float:
    """Delegates to catalog.word_penalty_for_cascade - same per-component
    handling as device_fit.word_fit, worst-component-wins for cascades."""
    return catalog.word_penalty_for_cascade(cipher_name, device_word_bits)


def scale_time(benchmark_value_ms_or_us: float, device_clock_mhz: float, cipher_name: str, device_word_bits: int) -> float:
    """Applies clock-speed + word-size scaling. Unit-agnostic (works for both
    enc_ms and setup_us, caller keeps track of which unit is which)."""
    clock_ratio = REFERENCE_CLOCK_MHZ / device_clock_mhz
    return benchmark_value_ms_or_us * clock_ratio * word_penalty(cipher_name, device_word_bits)


def scale_throughput(benchmark_throughput_mbps: float, device_clock_mhz: float, cipher_name: str, device_word_bits: int) -> float:
    """Throughput is inversely related to time, so it scales by the INVERSE
    of scale_time()'s multiplier - a slower/narrower device gets LOWER
    throughput, not higher."""
    clock_ratio = REFERENCE_CLOCK_MHZ / device_clock_mhz
    multiplier = clock_ratio * word_penalty(cipher_name, device_word_bits)
    return benchmark_throughput_mbps / multiplier


def _capped_fit(offer: float, requirement: float) -> float:
    if offer >= requirement:
        return min(offer, requirement)
    return offer * PENALTY_FACTOR


def throughput_fit(cipher_entry, device, packet_size_bytes: int, throughput_required: str,
                    candidate_scaled_throughputs: dict) -> float:
    """
    candidate_scaled_throughputs: {cipher_name: scaled_throughput_mbps} for
    every candidate in THIS decision - used to normalize offer to 0-1 before
    the capped comparison (higher raw Mbps = better, so no inversion needed).
    """
    requirement = THROUGHPUT_REQUIRED_SCORE[throughput_required]
    values = list(candidate_scaled_throughputs.values())
    lo, hi = min(values), max(values)
    raw = candidate_scaled_throughputs[cipher_entry.name]
    normalized_offer = 0.5 if hi == lo else (raw - lo) / (hi - lo)
    return _capped_fit(normalized_offer, requirement)


def latency_fit(cipher_entry, device, packet_size_bytes: int, latency_tolerance: str,
                 candidate_scaled_latencies: dict) -> float:
    """candidate_scaled_latencies: {cipher_name: scaled_latency_us} - LOWER is
    better, so offer is inverted during normalization."""
    requirement = LATENCY_TOLERANCE_SCORE[latency_tolerance]
    values = list(candidate_scaled_latencies.values())
    lo, hi = min(values), max(values)
    raw = candidate_scaled_latencies[cipher_entry.name]
    normalized_offer = 0.5 if hi == lo else 1 - (raw - lo) / (hi - lo)
    return _capped_fit(normalized_offer, requirement)


def setup_fit(cipher_entry, candidate_scaled_setups: dict) -> float:
    """Uncapped - fastest (normalized) setup among candidates wins outright.
    candidate_scaled_setups: {cipher_name: scaled_setup_us}."""
    values = list(candidate_scaled_setups.values())
    lo, hi = min(values), max(values)
    raw = candidate_scaled_setups[cipher_entry.name]
    if hi == lo:
        return 0.5
    return 1 - (raw - lo) / (hi - lo)


def amortization_factor(cipher_entry, device, packet_size_bytes: int) -> float:
    """setup_time / (setup_time + encryption_time), both scaled for this
    device, at this packet size. This is the MEASURED share of total work
    that setup represents - not modeled/estimated."""
    row = cipher_entry.benchmark_for(device, packet_size_bytes)
    scaled_setup_us = scale_time(cipher_entry.setup_us, device.clock_speed_mhz, cipher_entry.name, device.word_bits)
    scaled_enc_us = scale_time(row.enc_ms * 1000, device.clock_speed_mhz, cipher_entry.name, device.word_bits)
    total = scaled_setup_us + scaled_enc_us
    if total == 0:
        return 0.0
    return scaled_setup_us / total


def application_fit(cipher_entry, device, packet_size_bytes: int, context,
                     candidate_entries: dict) -> dict:
    """
    context needs: .duty_cycle, .latency_tolerance, .throughput_required
    candidate_entries: {cipher_name: CipherEntry} - every candidate in this
    decision, needed to normalize throughput/latency/setup against each
    other before the capped comparison.
    """
    base_weights = DUTY_CYCLE_WEIGHTS[context.duty_cycle]

    # Build normalization pools across all candidates, scaled for this device
    scaled_throughputs, scaled_latencies, scaled_setups = {}, {}, {}
    for name, entry in candidate_entries.items():
        row = entry.benchmark_for(device, packet_size_bytes)
        scaled_throughputs[name] = scale_throughput(row.throughput_enc_mbps, device.clock_speed_mhz, entry.name, device.word_bits)
        scaled_latencies[name] = scale_time(row.effective_latency_us, device.clock_speed_mhz, entry.name, device.word_bits)
        scaled_setups[name] = scale_time(entry.setup_us, device.clock_speed_mhz, entry.name, device.word_bits)

    t_fit = throughput_fit(cipher_entry, device, packet_size_bytes, context.throughput_required, scaled_throughputs)
    l_fit = latency_fit(cipher_entry, device, packet_size_bytes, context.latency_tolerance, scaled_latencies)
    s_fit = setup_fit(cipher_entry, scaled_setups)

    amort = amortization_factor(cipher_entry, device, packet_size_bytes)
    w_setup_eff = base_weights["setup"] * amort
    freed = base_weights["setup"] - w_setup_eff
    w_throughput_eff = base_weights["throughput"] + freed / 2
    w_latency_eff = base_weights["latency"] + freed / 2

    score = w_throughput_eff * t_fit + w_latency_eff * l_fit + w_setup_eff * s_fit

    return {
        "score": score,
        "breakdown": {
            "throughput_fit": t_fit, "latency_fit": l_fit, "setup_fit": s_fit,
            "amortization_factor": amort,
            "weights_effective": {"throughput": w_throughput_eff, "latency": w_latency_eff, "setup": w_setup_eff},
        },
    }
