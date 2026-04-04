"""
FastAPI application entry point.
Run: uvicorn backend.main:app --reload
"""
from __future__ import annotations

from datetime import timedelta

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.auth import (
    authenticate_user, create_access_token, ensure_default_admin,
    get_current_user, hash_password, ACCESS_TOKEN_EXPIRE_HOURS,
)
from backend.database import get_db, init_db
from backend import models
from backend.routers import assessments, machines, reports, users

app = FastAPI(
    title="Essential Eight Compliance Tool",
    description="Self-hosted ACSC Essential Eight assessment platform",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(assessments.router)
app.include_router(machines.router)
app.include_router(reports.router)
app.include_router(users.router)


@app.on_event("startup")
def on_startup():
    init_db()
    db = next(get_db())
    ensure_default_admin(db)
    db.close()


# ── Auth routes ───────────────────────────────────────────────────────────────

@app.post("/api/auth/token")
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS),
    )
    return {"access_token": token, "token_type": "bearer"}


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


@app.post("/api/auth/change-password")
def change_password(
    req: ChangePasswordRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    from backend.auth import verify_password
    if not verify_password(req.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    current_user.hashed_password = hash_password(req.new_password)
    db.commit()
    return {"detail": "Password changed successfully"}


@app.get("/api/auth/me")
def me(current_user: models.User = Depends(get_current_user)):
    return {"username": current_user.username, "id": current_user.id}


@app.get("/health")
def health():
    return {"status": "ok", "service": "Essential Eight Compliance Tool"}
