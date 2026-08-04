import platform

import cpuinfo
import models
import psutil
import schemas
from database import Base, engine, get_db
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select
from sqlalchemy.orm import Session

Base.metadata.create_all(bind=engine)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/profiles", response_model=schemas.ProfileOut)
def create_profile(profile: schemas.ProfileCreate, db: Session = Depends(get_db)):
    db_profile = models.Profile(**profile.model_dump())
    db.add(db_profile)
    db.commit()
    db.refresh(db_profile)
    return db_profile

@app.put("/profiles/{profile_id}", response_model=schemas.ProfileOut)
def update_profile(profile_id: int, profile: schemas.ProfileUpdate, db: Session = Depends(get_db)):
    db_profile = db.get(models.Profile, profile_id)
    if not db_profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    for field, value in profile.model_dump().items():
        setattr(db_profile, field, value)

    db.commit()
    db.refresh(db_profile)
    return db_profile

@app.get("/profiles", response_model=list[schemas.ProfileOut])
def list_profiles(db: Session = Depends(get_db)):
    return db.scalars(select(models.Profile)).all()

@app.get("/profiles/{profile_id}", response_model=schemas.ProfileOut)
def get_profile(profile_id: int, db: Session = Depends(get_db)):
    profile = db.get(models.Profile, profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return profile

@app.delete("/profiles/{profile_id}")
def delete_profile(profile_id: int, db: Session = Depends(get_db)):
    profile = db.get(models.Profile, profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    db.delete(profile)
    db.commit()
    return {"deleted": True}

@app.get("/detect-specs")
def detect_specs():
    info = cpuinfo.get_cpu_info()
    flags = info.get("flags", [])

    return {
        "cpu_architecture": platform.machine(),  # e.g. 'x86_64', 'AMD64', 'aarch64'
        "clock_speed_mhz": info.get("hz_advertised", [None])[0] / 1_000_000 if info.get("hz_advertised") else None,
        "core_count": psutil.cpu_count(logical=True),
        "ram_size_mb": round(psutil.virtual_memory().total / (1024 * 1024)),
        "battery_powered": psutil.sensors_battery() is not None,
        "hw_accel_aes_ni": "aes" in flags,
    }