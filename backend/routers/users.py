"""User management endpoints."""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend import models
from backend.auth import get_current_user, hash_password, get_user
from backend.database import get_db

router = APIRouter(prefix="/api/users", tags=["users"])


class UserOut(BaseModel):
    id: int
    username: str
    created_at: datetime

    class Config:
        from_attributes = True


class CreateUserRequest(BaseModel):
    username: str
    password: str


@router.get("/", response_model=list[UserOut])
def list_users(
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
):
    return db.query(models.User).order_by(models.User.created_at.asc()).all()


@router.post("/", response_model=UserOut, status_code=201)
def create_user(
    req: CreateUserRequest,
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
):
    if not req.username.strip():
        raise HTTPException(status_code=400, detail="Username cannot be empty")
    if get_user(db, req.username):
        raise HTTPException(status_code=409, detail="Username already exists")
    user = models.User(
        username=req.username.strip(),
        hashed_password=hash_password(req.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.delete("/{user_id}", status_code=204)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()
