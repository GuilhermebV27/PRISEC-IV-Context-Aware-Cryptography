"""
decision_adapter.py

Translates between the FastAPI layer (a DB Profile row + a DecisionRequest
body) and decision_model's own Device/Context dataclasses. Keeps
decision_model.py itself free of any FastAPI/SQLAlchemy dependency, so it
stays independently testable/importable (e.g. from a notebook) the way it
already has been throughout development.
"""

from decision_model.decision_model import Context, Device
from decision_model.device_arch import word_bits_for


def build_device(profile, duty_cycle: str) -> Device:
    """
    profile: a models.Profile row (or anything with the same attributes).
    duty_cycle comes from the request context, not the profile - device_fit's
    energy weighting needs it, per the design (duty_cycle affects how much
    energy cost matters, alongside application_fit's own duty_cycle use).
    """
    return Device(
        ram_size_mb=profile.ram_size,
        clock_speed_mhz=profile.clock_speed,
        word_bits=word_bits_for(profile.cpu_architecture),
        battery_powered=bool(profile.battery_powered),
        hw_accel_aes_ni=bool(profile.hw_accel_aes_ni),
        hw_accel_simd_best_tier=profile.hw_accel_simd_best_tier or "scalar",
        duty_cycle=duty_cycle,
    )


def build_context(decision_context) -> Context:
    """decision_context: a schemas.DecisionContext (already validated by Pydantic)."""
    return Context(
        security_level=decision_context.security_level,
        data_confidentiality=decision_context.data_confidentiality,
        data_lifetime=decision_context.data_lifetime,
        duty_cycle=decision_context.duty_cycle,
        latency_tolerance=decision_context.latency_tolerance,
        throughput_required=decision_context.throughput_required,
        packet_size_bytes=decision_context.packet_size_bytes,
    )
