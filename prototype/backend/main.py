from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import select

import models, schemas
from database import Base, engine, get_db

Base.metadata.create_all(bind=engine)

app = FastAPI()

@app.post("/profiles", response_model=schemas.ProfileOut)
def create_profile(profile: schemas.ProfileCreate, db: Session = Depends(get_db)):
    db_profile = models.Profile(**profile.model_dump())
    db.add(db_profile)
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