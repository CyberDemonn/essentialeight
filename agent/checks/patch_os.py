"""
E8-6: Patch Operating Systems
Checks OS version currency and pending OS-level updates.
"""
from __future__ import annotations

import platform
import subprocess

from agent.checks.base import (
    BaseCheck, CheckResult, MaturityLevel, RemediationStep
)

ACSC_REF = "https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/patch-operating-systems"

# Minimum acceptable Windows 10/11 builds (updated periodically)
MIN_WIN10_BUILD = 19045   # 22H2
MIN_WIN11_BUILD = 22631   # 23H2

# Minimum macOS major version
MIN_MACOS_MAJOR = 13  # Ventura


class PatchOSCheck(BaseCheck):
    control_id = "E8-6"
    control_name = "Patch Operating Systems"

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

        build = self._get_windows_build(raw)
        pending_os = self._get_pending_os_updates(raw)
        auto_update = self._check_windows_update_settings(raw)
        result.raw_data = raw

        issues = []

        if build:
            result.findings.append(f"Windows build: {build}")
            build_num = int(build.split(".")[-1]) if "." in build else int(build)
            if build_num < MIN_WIN10_BUILD and build_num < MIN_WIN11_BUILD:
                issues.append(f"OS build {build} is below minimum supported versions (Win10 {MIN_WIN10_BUILD} / Win11 {MIN_WIN11_BUILD}).")
                result.remediation.append(RemediationStep(
                    description="Upgrade Windows to a supported, fully-patched build.",
                    script=(
                        "# Check for Windows updates\n"
                        "Get-WindowsUpdate\n\n"
                        "# Or via Windows Update via Settings > Windows Update > Check for updates\n"
                        "Start-Process 'ms-settings:windowsupdate'"
                    ),
                    script_type="powershell",
                    acsc_reference=ACSC_REF,
                    priority="high",
                    target_level=MaturityLevel.PARTIAL,
                ))

        if pending_os is not None and pending_os > 0:
            issues.append(f"{pending_os} pending OS update(s).")
            result.remediation.append(RemediationStep(
                description="Install all pending Windows OS updates.",
                script=(
                    "# Install all OS updates\n"
                    "Install-Module PSWindowsUpdate -Force\n"
                    "Get-WindowsUpdate -Install -AcceptAll -AutoReboot"
                ),
                script_type="powershell",
                acsc_reference=ACSC_REF,
                priority="high",
                target_level=MaturityLevel.MOSTLY_IMPLEMENTED,
            ))
        elif pending_os == 0:
            result.findings.append("No pending OS updates.")

        if not auto_update:
            issues.append("Automatic OS updates are not configured.")
            result.remediation.append(RemediationStep(
                description="Enable automatic Windows OS updates via Group Policy.",
                script=(
                    "# Configure Windows Update via registry\n"
                    "$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU'\n"
                    "if (!(Test-Path $path)) { New-Item -Path $path -Force }\n"
                    "Set-ItemProperty -Path $path -Name 'NoAutoUpdate' -Value 0\n"
                    "Set-ItemProperty -Path $path -Name 'AUOptions' -Value 4  # Auto download+install"
                ),
                script_type="powershell",
                acsc_reference=ACSC_REF,
                priority="medium",
                target_level=MaturityLevel.FULLY_IMPLEMENTED,
            ))
        else:
            result.findings.append("Automatic Windows Update appears to be configured.")

        if not issues:
            result.maturity_level = MaturityLevel.FULLY_IMPLEMENTED
        elif len(issues) == 1:
            result.maturity_level = MaturityLevel.MOSTLY_IMPLEMENTED
            result.gaps.extend(issues)
        elif len(issues) == 2:
            result.maturity_level = MaturityLevel.PARTIAL
            result.gaps.extend(issues)
        else:
            result.maturity_level = MaturityLevel.NOT_IMPLEMENTED
            result.gaps.extend(issues)

        return result

    def _get_windows_build(self, raw: dict) -> str | None:
        try:
            out = subprocess.run(
                ["powershell", "-NonInteractive", "-Command",
                 "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').CurrentBuildNumber"],
                capture_output=True, text=True, timeout=10
            )
            build = out.stdout.strip()
            raw["windows_build"] = build
            return build
        except Exception as e:
            raw["build_error"] = str(e)
            return None

    def _get_pending_os_updates(self, raw: dict) -> int | None:
        try:
            out = subprocess.run(
                ["powershell", "-NonInteractive", "-Command",
                 "$s = New-Object -ComObject Microsoft.Update.Session; "
                 "$q = $s.CreateUpdateSearcher(); "
                 "($q.Search('IsInstalled=0 and Type=Software and CategoryIDs contains ''0FA1201D-4330-4FA8-8AE9-B877473B6441''')).Updates.Count"],
                capture_output=True, text=True, timeout=60
            )
            val = out.stdout.strip()
            raw["pending_os_updates"] = val
            return int(val) if val.isdigit() else None
        except Exception as e:
            raw["os_update_error"] = str(e)
            return None

    def _check_windows_update_settings(self, raw: dict) -> bool:
        try:
            out = subprocess.run(
                ["reg", "query",
                 r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
                 "/v", "NoAutoUpdate"],
                capture_output=True, text=True, timeout=5
            )
            raw["no_auto_update"] = out.stdout.strip()[:100]
            return "0x0" in out.stdout
        except Exception as e:
            raw["win_update_settings_error"] = str(e)
            return False

    # ── Linux ─────────────────────────────────────────────────────────────────

    def _check_linux(self) -> CheckResult:
        result = self._base_result()
        raw: dict = {}

        kernel = self._get_kernel_version(raw)
        pending_sec = self._get_pending_security_updates(raw)
        auto_updates = self._check_unattended_upgrades(raw)
        result.raw_data = raw

        result.findings.append(f"Kernel version: {kernel}")
        issues = []

        if pending_sec and pending_sec > 0:
            issues.append(f"{pending_sec} pending security update(s).")
            result.remediation.append(RemediationStep(
                description="Apply all pending security updates immediately.",
                script=(
                    "# Debian/Ubuntu\n"
                    "apt-get update && apt-get upgrade -y\n\n"
                    "# RHEL/CentOS\n"
                    "dnf update --security -y"
                ),
                script_type="bash",
                acsc_reference=ACSC_REF,
                priority="high",
                target_level=MaturityLevel.MOSTLY_IMPLEMENTED,
            ))
        elif pending_sec == 0:
            result.findings.append("No pending security updates.")

        if not auto_updates:
            issues.append("Automatic security updates (unattended-upgrades or equivalent) not active.")
            result.remediation.append(RemediationStep(
                description="Enable automatic security patching.",
                script=(
                    "# Debian/Ubuntu\n"
                    "apt-get install -y unattended-upgrades\n"
                    "dpkg-reconfigure --priority=low unattended-upgrades\n\n"
                    "# RHEL/CentOS\n"
                    "dnf install -y dnf-automatic\n"
                    "systemctl enable --now dnf-automatic.timer"
                ),
                script_type="bash",
                acsc_reference=ACSC_REF,
                priority="medium",
                target_level=MaturityLevel.FULLY_IMPLEMENTED,
            ))
        else:
            result.findings.append("Automatic security updates are active.")

        if not issues:
            result.maturity_level = MaturityLevel.FULLY_IMPLEMENTED
        elif len(issues) == 1:
            result.maturity_level = MaturityLevel.MOSTLY_IMPLEMENTED
            result.gaps.extend(issues)
        else:
            result.maturity_level = MaturityLevel.PARTIAL
            result.gaps.extend(issues)

        return result

    def _get_kernel_version(self, raw: dict) -> str:
        ver = platform.release()
        raw["kernel_version"] = ver
        return ver

    def _get_pending_security_updates(self, raw: dict) -> int | None:
        try:
            subprocess.run(["apt-get", "update", "-qq"], capture_output=True, timeout=60)
            out = subprocess.run(
                ["apt-get", "--simulate", "upgrade"],
                capture_output=True, text=True, timeout=30
            )
            security_lines = [l for l in out.stdout.splitlines()
                              if l.startswith("Inst") and "security" in l.lower()]
            raw["pending_security_updates"] = len(security_lines)
            return len(security_lines)
        except FileNotFoundError:
            pass
        except Exception as e:
            raw["apt_security_error"] = str(e)

        # Try dnf
        try:
            out = subprocess.run(
                ["dnf", "check-update", "--security", "-q"],
                capture_output=True, text=True, timeout=60
            )
            lines = [l for l in out.stdout.splitlines() if l.strip()]
            raw["dnf_security_pending"] = len(lines)
            return len(lines)
        except Exception as e:
            raw["dnf_security_error"] = str(e)

        return None

    def _check_unattended_upgrades(self, raw: dict) -> bool:
        try:
            out = subprocess.run(
                ["systemctl", "is-active", "unattended-upgrades"],
                capture_output=True, text=True, timeout=5
            )
            active = out.stdout.strip() == "active"
            raw["unattended_upgrades"] = out.stdout.strip()
            if active:
                return True
        except Exception:
            pass

        try:
            out = subprocess.run(
                ["systemctl", "is-active", "dnf-automatic.timer"],
                capture_output=True, text=True, timeout=5
            )
            active = out.stdout.strip() == "active"
            raw["dnf_automatic"] = out.stdout.strip()
            return active
        except Exception as e:
            raw["auto_update_error"] = str(e)
            return False

    # ── macOS ─────────────────────────────────────────────────────────────────

    def _check_macos(self) -> CheckResult:
        result = self._base_result()
        raw: dict = {}

        macos_version = platform.mac_ver()[0]
        raw["macos_version"] = macos_version
        result.findings.append(f"macOS version: {macos_version}")

        pending = self._get_pending_os_updates_macos(raw)
        auto_update = self._check_macos_auto_update(raw)
        result.raw_data = raw

        issues = []

        try:
            major = int(macos_version.split(".")[0])
            if major < MIN_MACOS_MAJOR:
                issues.append(f"macOS {macos_version} is below minimum supported version (macOS {MIN_MACOS_MAJOR}).")
                result.remediation.append(RemediationStep(
                    description="Upgrade to a supported macOS version.",
                    script=(
                        "# Open Software Update\n"
                        "open 'x-apple.systempreferences:com.apple.preferences.softwareupdate'"
                    ),
                    script_type="zsh",
                    acsc_reference=ACSC_REF,
                    priority="high",
                    target_level=MaturityLevel.PARTIAL,
                ))
        except (ValueError, IndexError):
            pass

        if pending and pending > 0:
            issues.append(f"{pending} pending macOS OS update(s).")
            result.remediation.append(RemediationStep(
                description="Install all pending macOS updates.",
                script="sudo softwareupdate --install --all --restart",
                script_type="zsh",
                acsc_reference=ACSC_REF,
                priority="high",
                target_level=MaturityLevel.MOSTLY_IMPLEMENTED,
            ))
        elif pending == 0:
            result.findings.append("No pending macOS updates.")

        if not auto_update:
            issues.append("Automatic macOS updates are not enabled.")
            result.remediation.append(RemediationStep(
                description="Enable automatic macOS updates.",
                script=(
                    "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true\n"
                    "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true\n"
                    "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true"
                ),
                script_type="zsh",
                acsc_reference=ACSC_REF,
                priority="medium",
                target_level=MaturityLevel.FULLY_IMPLEMENTED,
            ))
        else:
            result.findings.append("Automatic macOS updates are enabled.")

        if not issues:
            result.maturity_level = MaturityLevel.FULLY_IMPLEMENTED
        elif len(issues) == 1:
            result.maturity_level = MaturityLevel.MOSTLY_IMPLEMENTED
            result.gaps.extend(issues)
        else:
            result.maturity_level = MaturityLevel.PARTIAL
            result.gaps.extend(issues)

        return result

    def _get_pending_os_updates_macos(self, raw: dict) -> int | None:
        try:
            out = subprocess.run(
                ["softwareupdate", "--list"],
                capture_output=True, text=True, timeout=60
            )
            combined = out.stdout + out.stderr
            lines = [l for l in combined.splitlines() if l.strip().startswith("*")]
            raw["pending_os_updates"] = len(lines)
            return len(lines)
        except Exception as e:
            raw["softwareupdate_error"] = str(e)
            return None

    def _check_macos_auto_update(self, raw: dict) -> bool:
        try:
            out = subprocess.run(
                ["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate",
                 "AutomaticallyInstallMacOSUpdates"],
                capture_output=True, text=True, timeout=5
            )
            val = out.stdout.strip()
            raw["auto_install_updates"] = val
            return val == "1"
        except Exception as e:
            raw["auto_update_error"] = str(e)
            return False
