"""
E8-2: Patch Applications
Checks whether applications are kept up to date (within 2 weeks of patch release for ML1,
48 hours for internet-facing services at ML3).
"""
from __future__ import annotations

import platform
import subprocess
from datetime import datetime, timezone

from agent.checks.base import (
    BaseCheck, CheckResult, MaturityLevel, RemediationStep
)

ACSC_REF = "https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/patch-applications"


class PatchApplicationsCheck(BaseCheck):
    control_id = "E8-2"
    control_name = "Patch Applications"

    def run(self) -> CheckResult:
        os_name = platform.system()
        if os_name == "Windows":
            return self._check_windows()
        elif os_name == "Linux":
            return self._check_linux()
        elif os_name == "Darwin":
            return self._check_macos()
        return self._unsupported_result()

    # ── Windows ──────────────────────────────────────────────────────────────

    def _check_windows(self) -> CheckResult:
        result = self._base_result()
        raw: dict = {}

        pending = self._get_pending_windows_updates(raw)
        result.raw_data = raw

        if pending == 0:
            result.maturity_level = MaturityLevel.FULLY_IMPLEMENTED
            result.findings.append("No pending application updates detected via Windows Update.")
        elif pending <= 5:
            result.maturity_level = MaturityLevel.MOSTLY_IMPLEMENTED
            result.findings.append(f"{pending} pending update(s) detected.")
            result.gaps.append("Some application patches are outstanding.")
            result.remediation.append(self._windows_update_remediation())
        elif pending <= 20:
            result.maturity_level = MaturityLevel.PARTIAL
            result.findings.append(f"{pending} pending update(s) detected.")
            result.gaps.append("Significant backlog of application patches.")
            result.remediation.append(self._windows_update_remediation())
        else:
            result.maturity_level = MaturityLevel.NOT_IMPLEMENTED
            result.findings.append(f"{pending} pending update(s) detected — patching is not being maintained.")
            result.gaps.append("Application patching is severely neglected.")
            result.remediation.append(self._windows_update_remediation())

        return result

    def _get_pending_windows_updates(self, raw: dict) -> int:
        try:
            out = subprocess.run(
                ["powershell", "-NonInteractive", "-Command",
                 "$UpdateSession = New-Object -ComObject Microsoft.Update.Session; "
                 "$UpdateSearcher = $UpdateSession.CreateUpdateSearcher(); "
                 "$Updates = $UpdateSearcher.Search('IsInstalled=0 and Type=Software'); "
                 "$Updates.Updates.Count"],
                capture_output=True, text=True, timeout=60
            )
            count_str = out.stdout.strip()
            raw["pending_updates"] = count_str
            return int(count_str) if count_str.isdigit() else -1
        except Exception as e:
            raw["windows_update_error"] = str(e)
            return -1

    def _windows_update_remediation(self) -> RemediationStep:
        return RemediationStep(
            description="Install all pending Windows application updates immediately.",
            script=(
                "# Install all pending updates\n"
                "$UpdateSession = New-Object -ComObject Microsoft.Update.Session\n"
                "$UpdateSearcher = $UpdateSession.CreateUpdateSearcher()\n"
                "$Updates = $UpdateSearcher.Search('IsInstalled=0 and Type=Software')\n"
                "$Downloader = $UpdateSession.CreateUpdateDownloader()\n"
                "$Downloader.Updates = $Updates.Updates\n"
                "$Downloader.Download()\n"
                "$Installer = $UpdateSession.CreateUpdateInstaller()\n"
                "$Installer.Updates = $Updates.Updates\n"
                "$Installer.Install()\n\n"
                "# Or enable automatic updates via Group Policy:\n"
                "# Computer Configuration > Administrative Templates > Windows Components > Windows Update"
            ),
            script_type="powershell",
            acsc_reference=ACSC_REF,
            priority="high",
            target_level=MaturityLevel.FULLY_IMPLEMENTED,
        )

    # ── Linux ─────────────────────────────────────────────────────────────────

    def _check_linux(self) -> CheckResult:
        result = self._base_result()
        raw: dict = {}

        pending, pkg_mgr = self._get_pending_linux_updates(raw)
        auto_updates = self._check_unattended_upgrades(raw)
        result.raw_data = raw

        if pending == 0 and auto_updates:
            result.maturity_level = MaturityLevel.FULLY_IMPLEMENTED
            result.findings.append("No pending updates and automatic updates are configured.")
        elif pending == 0:
            result.maturity_level = MaturityLevel.MOSTLY_IMPLEMENTED
            result.findings.append("No pending updates, but automatic updates are not confirmed.")
            result.gaps.append("Unattended-upgrades or equivalent is not configured.")
            result.remediation.append(self._linux_auto_update_remediation(pkg_mgr))
        elif pending <= 10:
            result.maturity_level = MaturityLevel.PARTIAL
            result.findings.append(f"{pending} pending package update(s) via {pkg_mgr}.")
            result.gaps.append("Some package patches are outstanding.")
            result.remediation.append(self._linux_update_remediation(pkg_mgr))
        else:
            result.maturity_level = MaturityLevel.NOT_IMPLEMENTED
            result.findings.append(f"{pending} pending package update(s) — patching is not maintained.")
            result.gaps.append("Package patching is severely neglected.")
            result.remediation.append(self._linux_update_remediation(pkg_mgr))

        return result

    def _get_pending_linux_updates(self, raw: dict) -> tuple[int, str]:
        # Try apt
        try:
            subprocess.run(["apt-get", "update", "-qq"], capture_output=True, timeout=60)
            out = subprocess.run(
                ["apt-get", "--simulate", "upgrade"],
                capture_output=True, text=True, timeout=30
            )
            lines = [l for l in out.stdout.splitlines() if l.startswith("Inst ")]
            raw["apt_pending"] = len(lines)
            return len(lines), "apt"
        except FileNotFoundError:
            pass
        except Exception as e:
            raw["apt_error"] = str(e)

        # Try dnf/yum
        for cmd in [["dnf", "check-update", "-q"], ["yum", "check-update", "-q"]]:
            try:
                out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                lines = [l for l in out.stdout.splitlines() if l.strip() and not l.startswith("Last")]
                mgr = cmd[0]
                raw[f"{mgr}_pending"] = len(lines)
                return len(lines), mgr
            except FileNotFoundError:
                continue
            except Exception as e:
                raw[f"{cmd[0]}_error"] = str(e)

        return -1, "unknown"

    def _check_unattended_upgrades(self, raw: dict) -> bool:
        try:
            out = subprocess.run(
                ["systemctl", "is-active", "unattended-upgrades"],
                capture_output=True, text=True, timeout=5
            )
            active = out.stdout.strip() == "active"
            raw["unattended_upgrades"] = out.stdout.strip()
            return active
        except Exception as e:
            raw["unattended_upgrades_error"] = str(e)
            return False

    def _linux_update_remediation(self, pkg_mgr: str) -> RemediationStep:
        if pkg_mgr == "apt":
            script = "apt-get update && apt-get upgrade -y"
        else:
            script = f"{pkg_mgr} update -y"
        return RemediationStep(
            description="Apply all pending package updates.",
            script=script,
            script_type="bash",
            acsc_reference=ACSC_REF,
            priority="high",
            target_level=MaturityLevel.MOSTLY_IMPLEMENTED,
        )

    def _linux_auto_update_remediation(self, pkg_mgr: str) -> RemediationStep:
        return RemediationStep(
            description="Enable automatic security updates.",
            script=(
                "# For Debian/Ubuntu:\n"
                "apt-get install -y unattended-upgrades\n"
                "dpkg-reconfigure --priority=low unattended-upgrades\n"
                "systemctl enable unattended-upgrades\n\n"
                "# For RHEL/CentOS:\n"
                "dnf install -y dnf-automatic\n"
                "sed -i 's/apply_updates = no/apply_updates = yes/' /etc/dnf/automatic.conf\n"
                "systemctl enable --now dnf-automatic.timer"
            ),
            script_type="bash",
            acsc_reference=ACSC_REF,
            priority="medium",
            target_level=MaturityLevel.FULLY_IMPLEMENTED,
        )

    # ── macOS ─────────────────────────────────────────────────────────────────

    def _check_macos(self) -> CheckResult:
        result = self._base_result()
        raw: dict = {}

        pending = self._get_pending_macos_updates(raw)
        auto_updates = self._check_macos_auto_updates(raw)
        result.raw_data = raw

        if pending == 0 and auto_updates:
            result.maturity_level = MaturityLevel.FULLY_IMPLEMENTED
            result.findings.append("No pending macOS App Store updates and automatic updates are enabled.")
        elif pending == 0:
            result.maturity_level = MaturityLevel.MOSTLY_IMPLEMENTED
            result.findings.append("No pending updates found, but automatic updates are not confirmed active.")
            result.gaps.append("Enable automatic update checks and installation.")
            result.remediation.append(self._macos_auto_update_remediation())
        elif pending <= 5:
            result.maturity_level = MaturityLevel.PARTIAL
            result.findings.append(f"{pending} pending macOS software update(s).")
            result.gaps.append("Install outstanding updates.")
            result.remediation.append(self._macos_update_remediation())
        else:
            result.maturity_level = MaturityLevel.NOT_IMPLEMENTED
            result.findings.append(f"{pending} pending updates — patching not maintained.")
            result.gaps.append("Application patching is severely neglected.")
            result.remediation.append(self._macos_update_remediation())

        return result

    def _get_pending_macos_updates(self, raw: dict) -> int:
        try:
            out = subprocess.run(
                ["softwareupdate", "--list"],
                capture_output=True, text=True, timeout=60
            )
            combined = out.stdout + out.stderr
            raw["softwareupdate_output"] = combined[:500]
            lines = [l for l in combined.splitlines() if l.strip().startswith("*")]
            return len(lines)
        except Exception as e:
            raw["softwareupdate_error"] = str(e)
            return -1

    def _check_macos_auto_updates(self, raw: dict) -> bool:
        try:
            out = subprocess.run(
                ["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate",
                 "AutomaticCheckEnabled"],
                capture_output=True, text=True, timeout=5
            )
            val = out.stdout.strip()
            raw["macos_auto_check"] = val
            return val == "1"
        except Exception as e:
            raw["macos_auto_update_error"] = str(e)
            return False

    def _macos_update_remediation(self) -> RemediationStep:
        return RemediationStep(
            description="Install all pending macOS software updates.",
            script="sudo softwareupdate --install --all --restart",
            script_type="zsh",
            acsc_reference=ACSC_REF,
            priority="high",
            target_level=MaturityLevel.MOSTLY_IMPLEMENTED,
        )

    def _macos_auto_update_remediation(self) -> RemediationStep:
        return RemediationStep(
            description="Enable automatic macOS software updates.",
            script=(
                "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true\n"
                "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true\n"
                "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true\n"
                "sudo defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool true"
            ),
            script_type="zsh",
            acsc_reference=ACSC_REF,
            priority="medium",
            target_level=MaturityLevel.FULLY_IMPLEMENTED,
        )
