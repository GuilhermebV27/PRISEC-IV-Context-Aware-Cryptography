from database import Base
from sqlalchemy import (
    TIMESTAMP,
    Boolean,
    Column,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)


class Profile(Base):
    __tablename__ = "profiles"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False, default="Device Profile")
    detection_method = Column(String(10), nullable=False, default="manual")
    cpu_architecture = Column(String(50), nullable=False)
    clock_speed = Column(Float)
    core_count = Column(Integer)
    ram_size = Column(Integer)
    battery_powered = Column(Boolean)
    device_tier = Column(Integer)
    hw_accel_aes_ni = Column(Boolean)
    hw_accel_simd_presence = Column(Boolean)          # NEW
    hw_accel_simd_best_tier = Column(String(10))
    created_at = Column(TIMESTAMP, server_default=func.now())
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())

class Decision(Base):
    __tablename__ = "decisions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    profile_id = Column(Integer, ForeignKey("profiles.id"), nullable=False)
    context_json = Column(Text, nullable=False)
    recommended_cipher = Column(String(50), nullable=False)
    decision_metadata = Column(Text, nullable=True)
    created_at = Column(TIMESTAMP, server_default=func.now())
    
