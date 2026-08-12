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
    decision_metadata: Optional[str] = None

class DecisionOut(DecisionCreate):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True