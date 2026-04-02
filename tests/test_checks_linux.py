"""
Integration tests for E8 agent checks on Linux (Ubuntu).

Run directly on the Ubuntu machine with:
    cd /opt/e8
    sudo python3 -m pytest tests/test_checks_linux.py -v

Requirements:
    sudo pip3 install pytest

Notes:
- Must run as root (sudo) — many checks read /etc/ssh/sshd_config, /etc/sudoers, PAM files.
- E8-2 and E8-6 run `apt-get update` which may take 30–60 seconds.
- Tests are structural (check output is valid and consistent), NOT asserting a specific ML
  score, since the actual score depends on the machine's security posture.
"""
import sys
import os

# Allow running from /opt/e8 without installing the package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import platform
import pytest

if platform.system() != "Linux":
    pytest.skip("These tests are Linux-only", allow_module_level=True)

from agent.checks.application_control import ApplicationControlCheck
from agent.checks.patch_applications import PatchApplicationsCheck
from agent.checks.office_macros import OfficeMacrosCheck
from agent.checks.user_app_hardening import UserAppHardeningCheck
from agent.checks.restrict_admin import RestrictAdminCheck
from agent.checks.patch_os import PatchOSCheck
from agent.checks.mfa import MFACheck
from agent.checks.backups import BackupsCheck
from agent.checks.base import MaturityLevel
from agent.core.scorer import overall_maturity, score_summary


# ── Shared assertion helper ───────────────────────────────────────────────────

def assert_valid_result(result, expected_control_id: str):
    """Assert a CheckResult is structurally valid and internally consistent."""
    assert result is not None
    assert result.error is None, f"{expected_control_id} check crashed: {result.error}"
    assert result.control_id == expected_control_id
    assert result.platform == "Linux"
    assert result.maturity_level in list(MaturityLevel), \
        f"maturity_level {result.maturity_level!r} is not a valid MaturityLevel"
    assert isinstance(result.findings, list), "findings must be a list"
    assert isinstance(result.gaps, list), "gaps must be a list"
    assert isinstance(result.raw_data, dict), "raw_data must be a dict"
    for f in result.findings:
        assert isinstance(f, str) and f.strip(), \
            f"{expected_control_id}: finding is empty or not a string: {f!r}"
    for g in result.gaps:
        assert isinstance(g, str) and g.strip(), \
            f"{expected_control_id}: gap is empty or not a string: {g!r}"
    # Gaps should only exist when maturity is below ML3
    if result.maturity_level == MaturityLevel.FULLY_IMPLEMENTED:
        assert len(result.gaps) == 0, \
            f"{expected_control_id}: ML3 result should have no gaps, found: {result.gaps}"


# ── Individual check tests ────────────────────────────────────────────────────

def test_e8_1_application_control():
    result = ApplicationControlCheck().run()
    assert_valid_result(result, "E8-1")
    assert len(result.findings) >= 1, "E8-1 must produce at least one finding"
    # Should mention AppArmor, SELinux, or absence of MAC
    all_text = " ".join(result.findings + result.gaps).lower()
    assert any(kw in all_text for kw in ("apparmor", "selinux", "mandatory", "access control")), \
        f"E8-1 findings should mention AppArmor or SELinux. Got: {result.findings}"


def test_e8_2_patch_applications():
    result = PatchApplicationsCheck().run()
    assert_valid_result(result, "E8-2")
    assert len(result.findings) >= 1
    all_text = " ".join(result.findings).lower()
    assert any(kw in all_text for kw in ("pending", "update", "patch", "automatic")), \
        f"E8-2 findings should report patch status. Got: {result.findings}"


def test_e8_3_office_macros():
    result = OfficeMacrosCheck().run()
    assert_valid_result(result, "E8-3")
    assert len(result.findings) >= 1
    all_text = " ".join(result.findings).lower()
    assert any(kw in all_text for kw in ("libreoffice", "macro", "office")), \
        f"E8-3 findings should mention LibreOffice or macros. Got: {result.findings}"


def test_e8_4_user_app_hardening():
    result = UserAppHardeningCheck().run()
    assert_valid_result(result, "E8-4")
    assert len(result.findings) + len(result.gaps) >= 1
    all_text = " ".join(result.findings + result.gaps).lower()
    assert any(kw in all_text for kw in ("java", "flash", "browser", "plugin", "policy")), \
        f"E8-4 should mention java, flash, or browser policies. Got: {result.findings}"


def test_e8_5_restrict_admin():
    result = RestrictAdminCheck().run()
    assert_valid_result(result, "E8-5")
    assert len(result.findings) >= 1
    all_text = " ".join(result.findings).lower()
    assert any(kw in all_text for kw in ("sudo", "admin", "root", "nopasswd", "ssh")), \
        f"E8-5 findings should report admin/sudo info. Got: {result.findings}"


def test_e8_6_patch_os():
    result = PatchOSCheck().run()
    assert_valid_result(result, "E8-6")
    assert len(result.findings) >= 1
    # Must report kernel version
    assert any("kernel" in f.lower() for f in result.findings), \
        f"E8-6 must report kernel version. Got: {result.findings}"


def test_e8_7_mfa():
    result = MFACheck().run()
    assert_valid_result(result, "E8-7")
    assert len(result.findings) >= 1
    all_text = " ".join(result.findings + result.gaps).lower()
    assert "ssh" in all_text, \
        f"E8-7 findings should mention SSH. Got: {result.findings}"


def test_e8_8_backups():
    result = BackupsCheck().run()
    assert_valid_result(result, "E8-8")
    assert len(result.findings) + len(result.gaps) >= 1
    all_text = " ".join(result.findings + result.gaps).lower()
    assert any(kw in all_text for kw in ("backup", "restic", "rsync", "cron", "duplicati", "borg")), \
        f"E8-8 should mention backup tools or status. Got: {result.findings + result.gaps}"


# ── Scorer tests ──────────────────────────────────────────────────────────────

def test_overall_maturity_is_minimum_of_all_controls():
    """Verify overall_maturity = min(all 8 control scores) per ACSC methodology."""
    checks = [
        ApplicationControlCheck(),
        PatchApplicationsCheck(),
        OfficeMacrosCheck(),
        UserAppHardeningCheck(),
        RestrictAdminCheck(),
        PatchOSCheck(),
        MFACheck(),
        BackupsCheck(),
    ]
    results = [c.run() for c in checks]

    # No check should crash
    for r in results:
        assert r.error is None, f"{r.control_id} crashed: {r.error}"

    overall = overall_maturity(results)
    expected_min = min(int(r.maturity_level) for r in results)
    assert int(overall) == expected_min, \
        f"overall_maturity should be {expected_min} (min of all controls), got {int(overall)}"


def test_score_summary_structure():
    """Verify score_summary returns the expected keys and types."""
    checks = [
        ApplicationControlCheck(),
        PatchApplicationsCheck(),
        OfficeMacrosCheck(),
        UserAppHardeningCheck(),
        RestrictAdminCheck(),
        PatchOSCheck(),
        MFACheck(),
        BackupsCheck(),
    ]
    results = [c.run() for c in checks]
    summary = score_summary(results)

    assert "overall_maturity" in summary
    assert "overall_label" in summary
    assert "controls" in summary
    assert "gap_count" in summary
    assert "high_priority_controls" in summary
    assert "fully_compliant" in summary

    assert isinstance(summary["overall_maturity"], int)
    assert summary["overall_maturity"] in range(4)
    assert isinstance(summary["overall_label"], str)
    assert isinstance(summary["controls"], dict)
    assert len(summary["controls"]) == 8
    assert isinstance(summary["gap_count"], int)
    assert 0 <= summary["gap_count"] <= 8
    assert isinstance(summary["fully_compliant"], bool)


def test_no_check_crashes():
    """Smoke test: all 8 checks must complete without raising an exception."""
    checks = [
        ApplicationControlCheck(),
        PatchApplicationsCheck(),
        OfficeMacrosCheck(),
        UserAppHardeningCheck(),
        RestrictAdminCheck(),
        PatchOSCheck(),
        MFACheck(),
        BackupsCheck(),
    ]
    for check in checks:
        try:
            result = check.run()
        except Exception as exc:
            pytest.fail(f"{check.control_id} raised an unhandled exception: {exc}")
        assert result is not None, f"{check.control_id} returned None"
        assert result.error is None, f"{check.control_id} set result.error: {result.error}"
