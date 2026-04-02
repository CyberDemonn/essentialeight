"""
Base class for all Essential Eight check modules.
Every check must implement run(), which returns a CheckResult.
"""
from __future__ import annotations

import platform
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import IntEnum
from typing import List, Optional


class MaturityLevel(IntEnum):
    NOT_IMPLEMENTED = 0
    PARTIAL = 1
    MOSTLY_IMPLEMENTED = 2
    FULLY_IMPLEMENTED = 3

    def label(self) -> str:
        return {
            0: "ML0 – Not Implemented",
            1: "ML1 – Partially Implemented",
            2: "ML2 – Mostly Implemented",
            3: "ML3 – Fully Implemented",
        }[self.value]


@dataclass
class RemediationStep:
    description: str
    script: str                     # PowerShell / bash / zsh snippet
    script_type: str                # "powershell" | "bash" | "zsh"
    acsc_reference: str             # URL to ACSC guidance
    priority: str                   # "high" | "medium" | "low"
    target_level: MaturityLevel     # Which ML this step achieves


@dataclass
class CheckResult:
    control_id: str                 # e.g. "E8-1"
    control_name: str               # e.g. "Application Control"
    platform: str                   # "Windows" | "Linux" | "Darwin"
    maturity_level: MaturityLevel
    findings: List[str] = field(default_factory=list)      # What was found
    gaps: List[str] = field(default_factory=list)           # What is missing
    remediation: List[RemediationStep] = field(default_factory=list)
    raw_data: dict = field(default_factory=dict)            # Raw collected data
    error: Optional[str] = None                             # If check failed

    def to_dict(self) -> dict:
        return {
            "control_id": self.control_id,
            "control_name": self.control_name,
            "platform": self.platform,
            "maturity_level": int(self.maturity_level),
            "maturity_label": self.maturity_level.label(),
            "findings": self.findings,
            "gaps": self.gaps,
            "remediation": [
                {
                    "description": r.description,
                    "script": r.script,
                    "script_type": r.script_type,
                    "acsc_reference": r.acsc_reference,
                    "priority": r.priority,
                    "target_level": int(r.target_level),
                }
                for r in self.remediation
            ],
            "raw_data": self.raw_data,
            "error": self.error,
        }


class BaseCheck(ABC):
    """Abstract base for all E8 checks."""

    SUPPORTED_PLATFORMS: List[str] = ["Windows", "Linux", "Darwin"]

    @property
    @abstractmethod
    def control_id(self) -> str:
        """E8 control identifier, e.g. 'E8-1'."""

    @property
    @abstractmethod
    def control_name(self) -> str:
        """Human-readable control name."""

    def is_supported(self) -> bool:
        return platform.system() in self.SUPPORTED_PLATFORMS

    @abstractmethod
    def run(self) -> CheckResult:
        """Perform the check and return a CheckResult."""

    def _base_result(self) -> CheckResult:
        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            platform=platform.system(),
            maturity_level=MaturityLevel.NOT_IMPLEMENTED,
        )

    def _unsupported_result(self) -> CheckResult:
        r = self._base_result()
        r.error = f"Check not supported on {platform.system()}"
        r.findings.append(f"Platform {platform.system()} not assessed for this control.")
        return r
