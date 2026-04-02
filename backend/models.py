"""
SQLAlchemy ORM models.
"""
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship

from backend.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    hashed_password = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class Machine(Base):
    __tablename__ = "machines"

    id = Column(Integer, primary_key=True, index=True)
    machine_id = Column(String(64), unique=True, index=True, nullable=False)  # UUID
    machine_label = Column(String(256), nullable=False)
    fqdn = Column(String(256))
    os_name = Column(String(64))
    os_version = Column(String(128))
    os_release = Column(String(64))
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    assessments = relationship("Assessment", back_populates="machine", cascade="all, delete-orphan")


class Assessment(Base):
    __tablename__ = "assessments"

    id = Column(Integer, primary_key=True, index=True)
    machine_id = Column(Integer, ForeignKey("machines.id"), nullable=False)
    assessed_at = Column(DateTime, nullable=False)
    schema_version = Column(String(16), default="1.0")
    target_level = Column(Integer, default=3)
    overall_maturity = Column(Integer, nullable=False)
    overall_label = Column(String(64))
    gap_count = Column(Integer, default=0)
    fully_compliant = Column(Integer, default=0)  # SQLite has no bool
    raw_payload = Column(JSON)  # Full agent payload for reference

    machine = relationship("Machine", back_populates="assessments")
    control_results = relationship("ControlResult", back_populates="assessment", cascade="all, delete-orphan")


class ControlResult(Base):
    __tablename__ = "control_results"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), nullable=False)
    control_id = Column(String(16), nullable=False)    # e.g. "E8-1"
    control_name = Column(String(128), nullable=False)
    maturity_level = Column(Integer, nullable=False)
    maturity_label = Column(String(64))
    findings = Column(JSON)   # List[str]
    gaps = Column(JSON)       # List[str]
    remediation = Column(JSON)  # List[RemediationStep dicts]
    error = Column(Text)

    assessment = relationship("Assessment", back_populates="control_results")
