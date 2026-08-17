from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class ProfileCreate(BaseModel):
    name: str
    detection_method: str = "manual"
    cpu_architecture: str
    clock_speed: float | None = None
    core_count: int | None = None
    ram_size: int | None = None
    battery_powered: bool | None = None
    hw_accel_aes_ni: bool | None = None
    hw_accel_simd_presence: bool | None = None         # NEW
    hw_accel_simd_best_tier: str | None = None
    device_tier: int | None = None

class ProfileOut(ProfileCreate):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class ProfileUpdate(ProfileCreate):
    pass


class DecisionCreate(BaseModel):
    profile_id: int
    context_json: str          # or a nested model, see note below
    recommended_cipher: str
    decision_metadata: str | None = None

class DecisionOut(DecisionCreate):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True


# --- Decision engine request/response ---------------------------------

class DecisionContext(BaseModel):
    security_level: str          # Guest / Basic / Advanced / Admin
    data_confidentiality: str    # Low / Medium / High
    data_lifetime: str           # Short-term / Medium-term / Long-term
    duty_cycle: str              # Sporadic / Periodic / Continuous
    latency_tolerance: str       # High / Medium / Low
    throughput_required: str     # Low / Medium / High / Very High
    packet_size_bytes: int


class DecisionWeights(BaseModel):
    device: float = 1 / 3
    security: float = 1 / 3
    application: float = 1 / 3


class DecisionRequest(BaseModel):
    profile_id: int
    context: DecisionContext
    weights: DecisionWeights | None = None


class DecisionResponse(BaseModel):
    recommended_ciphers: list[str]
    infeasible: bool
    reason: str | None = None
    excluded_for_memory: list[str] | None = None
    requirement: float | None = None
    weights_used: dict
    scores: dict | None = None   # full per-cipher breakdown, for auditability