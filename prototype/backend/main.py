import platform

import models
import psutil
import schemas
from database import Base, engine, get_db
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from hw_detect import best_simd_tier, detect_hw_aes, detect_simd
from sqlalchemy import select
from sqlalchemy.orm import Session

from decision_adapter import build_context, build_device
from decision_model.decision_model import decide as run_decision
from decision_model.decision_model import validate_weights
import live_execute

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
    freq = psutil.cpu_freq()
    clock_speed_mhz = None
    if freq:
        clock_speed_mhz = freq.max if freq.max else freq.current

    simd = detect_simd()

    return {
        "cpu_architecture": platform.machine(),
        "clock_speed_mhz": clock_speed_mhz,
        "core_count": psutil.cpu_count(logical=True),
        "ram_size_mb": psutil.virtual_memory().total / (1024 * 1024),
        "battery_powered": psutil.sensors_battery() is not None,
        "hw_accel_aes_ni": detect_hw_aes(),
        "hw_accel_simd_presence": any(simd.values()),
        "hw_accel_simd_best_tier": best_simd_tier(simd),
    }

@app.post("/decision", response_model=schemas.DecisionResponse)
def create_decision(request: schemas.DecisionRequest, db: Session = Depends(get_db)):
    profile = db.get(models.Profile, request.profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    weights = request.weights.model_dump() if request.weights else None
    if weights:
        try:
            validate_weights(weights)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))

    device = build_device(profile, request.context.duty_cycle)
    context = build_context(request.context)

    result = run_decision(device, context, weights)

    if request.persist:
        winning_final_score = None
        if not result["infeasible"] and result["recommended_ciphers"]:
            winning_final_score = result["all_scores"][result["recommended_ciphers"][0]]["final_score"]

        import json
        db_decision = models.Decision(
            profile_id=request.profile_id,
            context_json=request.context.model_dump_json(),
            recommended_cipher=json.dumps(result["recommended_ciphers"]),
            decision_metadata=json.dumps({
                "infeasible": result["infeasible"],
                "reason": result.get("reason"),
                "weights_used": result["weights_used"],
                "final_score": winning_final_score,
            }),
        )
        db.add(db_decision)
        db.commit()

    return schemas.DecisionResponse(
        recommended_ciphers=result["recommended_ciphers"],
        infeasible=result["infeasible"],
        reason=result.get("reason"),
        excluded_for_memory=result.get("excluded_for_memory"),
        requirement=result.get("requirement"),
        weights_used=result["weights_used"],
        scores=result.get("all_scores"),
    )


@app.get("/decisions/latest", response_model=schemas.LatestDecisionResponse)
def get_latest_decision(db: Session = Depends(get_db)):
    latest = db.scalars(
        select(models.Decision).order_by(models.Decision.created_at.desc())
    ).first()
    if not latest:
        raise HTTPException(status_code=404, detail="No decisions have been made yet")

    profile = db.get(models.Profile, latest.profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="The profile for this decision no longer exists")

    import json
    context = json.loads(latest.context_json)
    ciphers = json.loads(latest.recommended_cipher) if latest.recommended_cipher else []
    metadata = json.loads(latest.decision_metadata) if latest.decision_metadata else {}

    return schemas.LatestDecisionResponse(
        profile=profile,
        context=schemas.DecisionContext(**context),
        recommended_ciphers=ciphers,
        infeasible=metadata.get("infeasible", False),
        reason=metadata.get("reason"),
        final_score=metadata.get("final_score"),
        created_at=latest.created_at,
    )


@app.post("/execute", response_model=schemas.ExecuteResponse)
def execute_live_encryption(request: schemas.ExecuteRequest, db: Session = Depends(get_db)):
    """
    Runs ONE real encryption of `request.cipher` at `request.packet_size_bytes`,
    on THIS actual machine (wherever this backend process happens to be
    running). Deliberately NOT compared against the model's own prediction -
    a single live run, under whatever load happens to be on the machine at
    that moment, is its own isolated measurement, not a fair like-for-like
    test of the model's benchmark-trained estimates.

    Only meaningful when the profile's specs genuinely describe the machine
    this backend is running on - the frontend gates the button on this
    (the "Does this profile match this device?" check) before ever calling
    this endpoint, since the backend itself has no way to verify that.
    """
    profile = db.get(models.Profile, request.profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    try:
        live_result = live_execute.run_live_encryption(
            request.cipher, request.packet_size_bytes, request.warmup_runs
        )
    except live_execute.LiveExecutionError as e:
        raise HTTPException(status_code=422, detail=str(e))

    return schemas.ExecuteResponse(
        cipher=request.cipher,
        packet_size_bytes=live_result["packet_size_bytes"],
        roundtrip_ok=live_result["roundtrip_ok"],
        time_ms=live_result["enc_ms"],
        throughput_mbps=live_result["throughput_enc_mbps"],
        latency_us=live_result["latency_us"],
        memory_overhead_kb=live_result["memory_enc_overhead_kb"],
    )