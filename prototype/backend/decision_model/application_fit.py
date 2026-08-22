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


def word_penalty(cipher_name: str, device) -> float:
    """Delegates to catalog.word_penalty_for_cascade - same per-component
    handling as device_fit.word_fit, worst-component-wins for cascades."""
    return catalog.word_penalty_for_cascade(cipher_name, device)


def scale_time(benchmark_value_ms_or_us: float, device_clock_mhz: float, cipher_name: str, device) -> float:
    """Applies clock-speed + word-size scaling. Unit-agnostic (works for both
    enc_ms and setup_us, caller keeps track of which unit is which)."""
    clock_ratio = REFERENCE_CLOCK_MHZ / device_clock_mhz
    return benchmark_value_ms_or_us * clock_ratio * word_penalty(cipher_name, device)


def scale_throughput(benchmark_throughput_mbps: float, device_clock_mhz: float, cipher_name: str, device) -> float:
    """Throughput is inversely related to time, so it scales by the INVERSE
    of scale_time()'s multiplier - a slower/narrower device gets LOWER
    throughput, not higher."""
    clock_ratio = REFERENCE_CLOCK_MHZ / device_clock_mhz
    multiplier = clock_ratio * word_penalty(cipher_name, device)
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


def setup_fit(amort: float) -> float:
    """Self-referential, NOT peer-relative (fixed from an earlier bug):
    setup_fit = 1 - amortization_factor, matching how w_setup_effective is
    already computed (also self-referential, via amortization_factor). The
    original peer-relative version (normalized against other candidates in
    the pool) let an expensive ECC cipher's setup_fit look decent just
    because OTHER slow-setup candidates were also in the pool, even while
    its own amortization_factor (and therefore its weight) correctly
    marked it as setup-dominated - producing a large weight on a
    not-actually-bad score, the opposite of what should happen. Using the
    same self-referential basis for both the weight and the score fixes
    this: a cipher whose setup genuinely dominates its own workload now
    gets penalized on setup_fit itself, not just weighted more without
    being scored worse."""
    return 1 - amort


def amortization_factor(cipher_entry, device, packet_size_bytes: int) -> float:
    """setup_time / (setup_time + encryption_time), both scaled for this
    device, at this packet size. encryption_time comes from the fitted
    TimeModel (estimate_time_ms), not a closest-match row - see
    CipherEntry.estimate_time_ms for why."""
    time_model = cipher_entry.estimate_time_ms(device)
    estimate = time_model.estimate(packet_size_bytes)
    scaled_setup_us = scale_time(cipher_entry.setup_us, device.clock_speed_mhz, cipher_entry.name, device)
    scaled_enc_us = scale_time(estimate.enc_ms * 1000, device.clock_speed_mhz, cipher_entry.name, device)
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
    # (throughput/latency stay peer-relative - only setup_fit changed to
    # self-referential, see setup_fit's docstring). Both now come from each
    # candidate's fitted TimeModel, not a closest-match benchmark row.
    scaled_throughputs, scaled_latencies = {}, {}
    for name, entry in candidate_entries.items():
        estimate = entry.estimate_time_ms(device).estimate(packet_size_bytes)
        scaled_throughputs[name] = scale_throughput(estimate.throughput_enc_mbps, device.clock_speed_mhz, entry.name, device)
        scaled_latencies[name] = scale_time(estimate.latency_us, device.clock_speed_mhz, entry.name, device)

    t_fit = throughput_fit(cipher_entry, device, packet_size_bytes, context.throughput_required, scaled_throughputs)
    l_fit = latency_fit(cipher_entry, device, packet_size_bytes, context.latency_tolerance, scaled_latencies)

    amort = amortization_factor(cipher_entry, device, packet_size_bytes)
    s_fit = setup_fit(amort)
    w_setup_eff = base_weights["setup"] * amort
    freed = base_weights["setup"] - w_setup_eff
    w_throughput_eff = base_weights["throughput"] + freed / 2
    w_latency_eff = base_weights["latency"] + freed / 2

    score = w_throughput_eff * t_fit + w_latency_eff * l_fit + w_setup_eff * s_fit

    time_estimate = cipher_entry.estimate_time_ms(device).estimate(packet_size_bytes)
    below_min_sample = time_estimate.below_min_sample
    interpolated = time_estimate.interpolated

    return {
        "score": score,
        "breakdown": {
            "throughput_fit": t_fit, "latency_fit": l_fit, "setup_fit": s_fit,
            "amortization_factor": amort,
            "weights_effective": {"throughput": w_throughput_eff, "latency": w_latency_eff, "setup": w_setup_eff},
            "below_min_sample": below_min_sample,  # True = packet size is below the smallest real
                                                     # benchmark (1KB) - lower confidence, extrapolated
            "interpolated": interpolated,  # True = packet size sits between two real benchmarked
                                             # sizes - bracket-averaged, not extrapolated
        },
    }