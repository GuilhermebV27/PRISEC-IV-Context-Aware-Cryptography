from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class ProfileCreate(BaseModel):
    cpu_architecture: str
    clock_speed: Optional[float] = None
    core_count: Optional[int] = None
    ram_size: Optional[int] = None
    battery_powered: Optional[bool] = None
    hw_accel_aes_ni: Optional[bool] = None

class ProfileOut(ProfileCreate):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


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