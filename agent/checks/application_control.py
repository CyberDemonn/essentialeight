"""
E8-1: Application Control
Windows : WDAC policies, AppLocker rules, Software Restriction Policies
Linux   : AppArmor / SELinux enforcement status
macOS   : Gatekeeper + notarization enforcement
"""
from __future__ import annotations

import platform
import subprocess

from agent.checks.base import (
    BaseCheck, CheckResult, MaturityLevel, RemediationStep
)

ACSC_REF = "https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/application-control"


class ApplicationControlCheck(BaseCheck):
    control_id = "E8-1"
    control_name = "Application Control"

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

        wdac_enabled = self._check_wdac(raw)
        applocker_configured = self._check_applocker(raw)
        srp_configured = self._check_srp(raw)

        result.raw_data = raw

        if wdac_enabled:
            result.maturity_level = MaturityLevel.FULLY_IMPLEMENTED
            result.findings.append("Windows Defender Application Control (WDAC) policy is active.")
        elif applocker_configured:
            result.maturity_level = MaturityLevel.MOSTLY_IMPLEMENTED
            result.findings.append("AppLocker rules are configured.")
            result.gaps.append("WDAC is not enabled — AppLocker can be bypassed by local admins.")
            result.remediation.append(RemediationStep(
                description="Enable WDAC to replace or supplement AppLocker for ML3 compliance.",
                script=(
                    "# Deploy a WDAC policy (example: default allow Microsoft)\n"
                    "New-CIPolicy -Level Publisher -FilePath C:\\WDAC\\policy.xml -UserPEs\n"
                    "ConvertFrom-CIPolicy -XmlFilePath C:\\WDAC\\policy.xml -BinaryFilePath C:\\WDAC\\policy.bin\n"
                    "Copy-Item C:\\WDAC\\policy.bin -Destination C:\\Windows\\System32\\CodeIntegrity\\SiPolicy.p7b\n"
                    "Restart-Computer"
                ),
                script_type="powershell",
                acsc_reference=ACSC_REF,
                priority="medium",
                target_level=MaturityLevel.FULLY_IMPLEMENTED,
            ))
        elif srp_configured:
            result.maturity_level = MaturityLevel.PARTIAL
            result.findings.append("Software Restriction Policies (SRP) are configured.")
            result.gaps.append("SRP is weak; AppLocker or WDAC should replace it.")
        else:
            result.maturity_level = MaturityLevel.NOT_IMPLEMENTED
            result.findings.append("No application control mechanism detected (WDAC, AppLocker, SRP).")
            result.gaps.append("No application whitelisting is in place.")
            result.remediation.append(RemediationStep(
                description="Configure AppLocker as a baseline application control mechanism.",
                script=(
                    "# Enable AppLocker and create default rules\n"
                    "Set-Service -Name AppIDSvc -StartupType Automatic\n"
                    "Start-Service AppIDSvc\n"
                    "# Then configure rules via Group Policy or:\n"
                    "Get-AppLockerPolicy -Effective | Set-AppLockerPolicy"
                ),
                script_type="powershell",
                acsc_reference=ACSC_REF,
                priority="high",
                target_level=MaturityLevel.PARTIAL,
            ))

        return result

    def _check_wdac(self, raw: dict) -> bool:
        try:
            out = subprocess.run(
                ["powershell", "-NonInteractive", "-Command",
                 "Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard | Select-Object -ExpandProperty CodeIntegrityPolicyEnforcementStatus"],
                capture_output=True, text=True, timeout=15
            )
            status = out.stdout.strip()
            raw["wdac_status"] = status
            return status in ("2", "Enforced")
        except Exception as e:
            raw["wdac_error"] = str(e)
            return False

    def _check_applocker(self, raw: dict) -> bool:
        try:
            out = subprocess.run(
                ["powershell", "-NonInteractive", "-Command",
                 "(Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue).RuleCollections.Count"],
                capture_output=True, text=True, timeout=15
            )
            count_str = out.stdout.strip()
            raw["applocker_rule_count"] = count_str
            return count_str.isdigit() and int(count_str) > 0
        except Exception as e:
            raw["applocker_error"] = str(e)
            return False

    def _check_srp(self, raw: dict) -> bool:
        try:
            out = subprocess.run(
                ["powershell", "-NonInteractive", "-Command",
                 "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DefaultLevel"],
                capture_output=True, text=True, timeout=10
            )
            val = out.stdout.strip()
            raw["srp_default_level"] = val
            return val == "0"  # 0 = Disallowed (most restrictive)
        except Exception as e:
            raw["srp_error"] = str(e)
            return False

    # ── Linux ─────────────────────────────────────────────────────────────────

    def _check_linux(self) -> CheckResult:
        result = self._base_result()
        raw: dict = {}

        apparmor = self._check_apparmor(raw)
        selinux = self._check_selinux(raw)
        result.raw_data = raw

        if apparmor == "enforcing" or selinux == "Enforcing":
            result.maturity_level = MaturityLevel.FULLY_IMPLEMENTED
            mechanism = "AppArmor" if apparmor == "enforcing" else "SELinux"
            result.findings.append(f"{mechanism} is in enforcing mode.")
        elif apparmor == "loaded_no_root":
            result.maturity_level = MaturityLevel.PARTIAL
            result.findings.append("AppArmor module is loaded but enforcement mode cannot be determined — agent requires root (sudo) for full check.")
            result.gaps.append("Re-run as root (sudo) to verify AppArmor is in enforcing mode.")
            result.remediation.append(RemediationStep(
                description="Re-run the agent with sudo to determine AppArmor enforcement mode.",
                script="sudo python3 -m agent.e8_agent --output /tmp/e8_report.json",
                script_type="bash",
                acsc_reference=ACSC_REF,
                priority="high",
                target_level=MaturityLevel.FULLY_IMPLEMENTED,
            ))
        elif apparmor == "complaining" or selinux == "Permissive":
            result.maturity_level = MaturityLevel.PARTIAL
            mechanism = "AppArmor" if apparmor == "complaining" else "SELinux"
            result.findings.append(f"{mechanism} is in permissive/complaining mode — not enforcing.")
            result.gaps.append("MAC is not enforcing — switch to enforcing mode.")
            result.remediation.append(RemediationStep(
                description="Set AppArmor/SELinux to enforcing mode.",
                script=(
                    "# AppArmor: enforce all loaded profiles\n"
                    "aa-enforce /etc/apparmor.d/*\n\n"
                    "# Or for SELinux:\n"
                    "setenforce 1\n"
                    "sed -i 's/^SELINUX=permissive/SELINUX=enforcing/' /etc/selinux/config"
                ),
                script_type="bash",
                acsc_reference=ACSC_REF,
                priority="high",
                target_level=MaturityLevel.FULLY_IMPLEMENTED,
            ))
        else:
            result.maturity_level = MaturityLevel.NOT_IMPLEMENTED
            result.findings.append("Neither AppArmor nor SELinux is active.")
            result.gaps.append("No mandatory access control mechanism is enforcing application control.")
            result.remediation.append(RemediationStep(
                description="Install and enable AppArmor in enforcing mode.",
                script=(
                    "apt-get install -y apparmor apparmor-utils apparmor-profiles\n"
                    "systemctl enable apparmor && systemctl start apparmor\n"
                    "aa-enforce /etc/apparmor.d/*"
                ),
                script_type="bash",
                acsc_reference=ACSC_REF,
                priority="high",
                target_level=MaturityLevel.FULLY_IMPLEMENTED,
            ))

        return result

    def _check_apparmor(self, raw: dict) -> str:
        try:
            out = subprocess.run(["aa-status", "--json"], capture_output=True, text=True, timeout=10)
            if out.returncode == 0:
                raw["apparmor_output"] = out.stdout[:500]
                return "enforcing"
            # rc=4 means permission denied but AppArmor is loaded — agent not running as root
            if out.returncode == 4:
                raw["apparmor"] = "loaded_no_root"
                return "loaded_no_root"
            out2 = subprocess.run(["apparmor_status"], capture_output=True, text=True, timeout=10)
            status = out2.stdout.lower()
            raw["apparmor_status"] = status[:200]
            if "complain" in status:
                return "complaining"
            if "enforce" in status:
                return "enforcing"
            if "module is loaded" in status:
                raw["apparmor"] = "loaded_no_root"
                return "loaded_no_root"
        except FileNotFoundError:
            raw["apparmor"] = "not installed"
        except Exception as e:
            raw["apparmor_error"] = str(e)
        return "disabled"

    def _check_selinux(self, raw: dict) -> str:
        try:
            out = subprocess.run(["getenforce"], capture_output=True, text=True, timeout=5)
            status = out.stdout.strip()
            raw["selinux_status"] = status
            return status
        except FileNotFoundError:
            raw["selinux"] = "not installed"
        except Exception as e:
            raw["selinux_error"] = str(e)
        return "Disabled"

    # ── macOS ─────────────────────────────────────────────────────────────────

    def _check_macos(self) -> CheckResult:
        result = self._base_result()
        raw: dict = {}

        gatekeeper = self._check_gatekeeper(raw)
        result.raw_data = raw

        if gatekeeper == "enabled":
            result.maturity_level = MaturityLevel.MOSTLY_IMPLEMENTED
            result.findings.append("Gatekeeper is enabled — only notarized apps allowed from internet.")
            result.gaps.append("Gatekeeper can be bypassed; MDM-enforced application control provides ML3.")
            result.remediation.append(RemediationStep(
                description="Enforce Gatekeeper via MDM and restrict to App Store only for highest assurance.",
                script=(
                    "# Verify Gatekeeper is on\n"
                    "spctl --status\n\n"
                    "# Restrict to App Store + notarized apps (requires MDM profile for enforcement)\n"
                    "sudo spctl --master-enable\n"
                    "sudo defaults write /Library/Preferences/com.apple.security GKAutoRearm -bool YES"
                ),
                script_type="zsh",
                acsc_reference=ACSC_REF,
                priority="medium",
                target_level=MaturityLevel.FULLY_IMPLEMENTED,
            ))
        else:
            result.maturity_level = MaturityLevel.NOT_IMPLEMENTED
            result.findings.append("Gatekeeper is disabled — unsigned apps can run freely.")
            result.gaps.append("Gatekeeper must be enabled.")
            result.remediation.append(RemediationStep(
                description="Enable Gatekeeper immediately.",
                script="sudo spctl --master-enable",
                script_type="zsh",
                acsc_reference=ACSC_REF,
                priority="high",
                target_level=MaturityLevel.PARTIAL,
            ))

        return result

    def _check_gatekeeper(self, raw: dict) -> str:
        try:
            out = subprocess.run(
                ["spctl", "--status"], capture_output=True, text=True, timeout=10
            )
            combined = (out.stdout + out.stderr).lower()
            raw["gatekeeper_output"] = combined.strip()
            if "assessments enabled" in combined:
                return "enabled"
            return "disabled"
        except Exception as e:
            raw["gatekeeper_error"] = str(e)
            return "unknown"
