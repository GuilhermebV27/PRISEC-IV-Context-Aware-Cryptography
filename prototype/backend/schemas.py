from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class ProfileCreate(BaseModel):
    name: str
    detection_method: str = "manual"
    cpu_architecture: str
    clock_speed: Optional[float] = None
    core_count: Optional[int] = None
    ram_size: Optional[int] = None
    battery_powered: Optional[bool] = None
    hw_accel_aes_ni: Optional[bool] = None
    device_tier: Optional[int] = None

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