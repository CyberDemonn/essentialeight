"""
Assessment ingestion and query endpoints.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend import models
from backend.auth import get_current_user
from backend.database import get_db

router = APIRouter(prefix="/api/assessments", tags=["assessments"])


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class MachineInfo(BaseModel):
    machine_id: str
    machine_label: str
    fqdn: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    os_release: Optional[str] = None


class SummarySchema(BaseModel):
    overall_maturity: int
    overall_label: str
    controls: dict
    gap_count: int
    high_priority_controls: List[str]
    fully_compliant: bool


class IngestPayload(BaseModel):
    schema_version: str = "1.0"
    assessed_at: str
    machine: MachineInfo
    target_level: int = 3
    summary: SummarySchema
    controls: List[dict]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _upsert_machine(db: Session, info: MachineInfo) -> models.Machine:
    machine = db.query(models.Machine).filter_by(machine_id=info.machine_id).first()
    now = datetime.now(timezone.utc)
    if machine is None:
        machine = models.Machine(
            machine_id=info.machine_id,
            machine_label=info.machine_label,
            fqdn=info.fqdn,
            os_name=info.os_name,
            os_version=info.os_version,
            os_release=info.os_release,
            first_seen=now,
            last_seen=now,
        )
        db.add(machine)
    else:
        machine.machine_label = info.machine_label
        machine.fqdn = info.fqdn
        machine.os_name = info.os_name
        machine.os_version = info.os_version
        machine.os_release = info.os_release
        machine.last_seen = now
    db.flush()
    return machine


def _store_assessment(db: Session, machine: models.Machine, payload: IngestPayload) -> models.Assessment:
    assessed_at = datetime.fromisoformat(payload.assessed_at.replace("Z", "+00:00"))
    summary = payload.summary

    assessment = models.Assessment(
        machine_id=machine.id,
        assessed_at=assessed_at,
        schema_version=payload.schema_version,
        target_level=payload.target_level,
        overall_maturity=summary.overall_maturity,
        overall_label=summary.overall_label,
        gap_count=summary.gap_count,
        fully_compliant=int(summary.fully_compliant),
        raw_payload=payload.dict(),
    )
    db.add(assessment)
    db.flush()

    for ctrl in payload.controls:
        cr = models.ControlResult(
            assessment_id=assessment.id,
            control_id=ctrl.get("control_id", ""),
            control_name=ctrl.get("control_name", ""),
            maturity_level=ctrl.get("maturity_level", 0),
            maturity_label=ctrl.get("maturity_label", ""),
            findings=ctrl.get("findings", []),
            gaps=ctrl.get("gaps", []),
            remediation=ctrl.get("remediation", []),
            error=ctrl.get("error"),
        )
        db.add(cr)

    db.commit()
    db.refresh(assessment)
    return assessment


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/ingest", status_code=status.HTTP_201_CREATED)
def ingest_assessment(
    payload: IngestPayload,
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
):
    """Accept a JSON assessment pushed by the agent."""
    machine = _upsert_machine(db, payload.machine)
    assessment = _store_assessment(db, machine, payload)
    return {"assessment_id": assessment.id, "machine_id": machine.machine_id}


@router.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_assessment(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
):
    """Upload a standalone JSON report file."""
    import json
    content = await file.read()
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {e}")

    try:
        payload = IngestPayload(**data)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Invalid report schema: {e}")

    machine = _upsert_machine(db, payload.machine)
    assessment = _store_assessment(db, machine, payload)
    return {"assessment_id": assessment.id, "machine_id": machine.machine_id}


@router.get("/")
def list_assessments(
    machine_id: Optional[str] = None,
    limit: int = 50,
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
):
    """List assessments, optionally filtered by machine UUID."""
    q = db.query(models.Assessment).join(models.Machine)
    if machine_id:
        q = q.filter(models.Machine.machine_id == machine_id)
    assessments = q.order_by(models.Assessment.assessed_at.desc()).limit(limit).all()
    return [_assessment_summary(a) for a in assessments]


@router.get("/{assessment_id}")
def get_assessment(
    assessment_id: int,
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
):
    """Get full assessment detail including all control results."""
    a = db.query(models.Assessment).filter_by(id=assessment_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return {
        **_assessment_summary(a),
        "controls": [_control_dict(cr) for cr in a.control_results],
        "raw_payload": a.raw_payload,
    }


@router.get("/history/{machine_uuid}")
def machine_history(
    machine_uuid: str,
    limit: int = 20,
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
):
    """Historical maturity trend for a specific machine."""
    machine = db.query(models.Machine).filter_by(machine_id=machine_uuid).first()
    if not machine:
        raise HTTPException(status_code=404, detail="Machine not found")

    assessments = (
        db.query(models.Assessment)
        .filter_by(machine_id=machine.id)
        .order_by(models.Assessment.assessed_at.asc())
        .limit(limit)
        .all()
    )
    return {
        "machine": _machine_dict(machine),
        "history": [_assessment_summary(a) for a in assessments],
    }


# ── Serialisers ───────────────────────────────────────────────────────────────

def _assessment_summary(a: models.Assessment) -> dict:
    return {
        "id": a.id,
        "machine_id": a.machine.machine_id,
        "machine_label": a.machine.machine_label,
        "assessed_at": a.assessed_at.isoformat(),
        "overall_maturity": a.overall_maturity,
        "overall_label": a.overall_label,
        "gap_count": a.gap_count,
        "fully_compliant": bool(a.fully_compliant),
        "target_level": a.target_level,
    }


def _control_dict(cr: models.ControlResult) -> dict:
    return {
        "control_id": cr.control_id,
        "control_name": cr.control_name,
        "maturity_level": cr.maturity_level,
        "maturity_label": cr.maturity_label,
        "findings": cr.findings or [],
        "gaps": cr.gaps or [],
        "remediation": cr.remediation or [],
        "error": cr.error,
    }


def _machine_dict(m: models.Machine) -> dict:
    return {
        "machine_id": m.machine_id,
        "machine_label": m.machine_label,
        "fqdn": m.fqdn,
        "os_name": m.os_name,
        "os_version": m.os_version,
        "os_release": m.os_release,
        "first_seen": m.first_seen.isoformat() if m.first_seen else None,
        "last_seen": m.last_seen.isoformat() if m.last_seen else None,
    }
