"""
Scores the overall Essential Eight maturity level from individual check results.
Per ACSC methodology: overall maturity = min() across all 8 controls.
"""
from __future__ import annotations

from typing import List

from agent.checks.base import CheckResult, MaturityLevel


CONTROL_ORDER = [
    "E8-1",  # Application Control
    "E8-2",  # Patch Applications
    "E8-3",  # Configure Microsoft Office Macros
    "E8-4",  # User Application Hardening
    "E8-5",  # Restrict Administrative Privileges
    "E8-6",  # Patch Operating Systems
    "E8-7",  # Multi-Factor Authentication
    "E8-8",  # Regular Backups
]


def overall_maturity(results: List[CheckResult]) -> MaturityLevel:
    """Overall maturity is the minimum across all 8 controls (ACSC methodology)."""
    if not results:
        return MaturityLevel.NOT_IMPLEMENTED
    levels = [r.maturity_level for r in results if r.error is None]
    if not levels:
        return MaturityLevel.NOT_IMPLEMENTED
    return MaturityLevel(min(int(lvl) for lvl in levels))


def score_summary(results: List[CheckResult]) -> dict:
    """Return a structured summary for storage and display."""
    overall = overall_maturity(results)
    by_control = {r.control_id: int(r.maturity_level) for r in results}
    gaps = [r for r in results if int(r.maturity_level) < 3]
    high_priority = [
        r.control_id for r in gaps
        if any(step.priority == "high" for step in r.remediation)
    ]
    return {
        "overall_maturity": int(overall),
        "overall_label": overall.label(),
        "controls": by_control,
        "gap_count": len(gaps),
        "high_priority_controls": high_priority,
        "fully_compliant": overall == MaturityLevel.FULLY_IMPLEMENTED,
    }
