"""
Machine registry endpoints.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend import models
from backend.auth import get_current_user
from backend.database import get_db
from backend.routers.assessments import _machine_dict, _assessment_summary

router = APIRouter(prefix="/api/machines", tags=["machines"])


@router.get("/")
def list_machines(
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
):
    """List all known machines with their latest assessment summary."""
    machines = db.query(models.Machine).order_by(models.Machine.last_seen.desc()).all()
    result = []
    for m in machines:
        latest = (
            db.query(models.Assessment)
            .filter_by(machine_id=m.id)
            .order_by(models.Assessment.assessed_at.desc())
            .first()
        )
        entry = _machine_dict(m)
        entry["latest_assessment"] = _assessment_summary(latest) if latest else None
        result.append(entry)
    return result


@router.get("/{machine_uuid}")
def get_machine(
    machine_uuid: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
):
    """Get machine detail with all assessments."""
    m = db.query(models.Machine).filter_by(machine_id=machine_uuid).first()
    if not m:
        raise HTTPException(status_code=404, detail="Machine not found")

    assessments = (
        db.query(models.Assessment)
        .filter_by(machine_id=m.id)
        .order_by(models.Assessment.assessed_at.desc())
        .limit(20)
        .all()
    )
    return {
        **_machine_dict(m),
        "assessments": [_assessment_summary(a) for a in assessments],
    }


@router.delete("/{machine_uuid}", status_code=204)
def delete_machine(
    machine_uuid: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
):
    """Delete a machine and all its assessments."""
    m = db.query(models.Machine).filter_by(machine_id=machine_uuid).first()
    if not m:
        raise HTTPException(status_code=404, detail="Machine not found")
    db.delete(m)
    db.commit()
