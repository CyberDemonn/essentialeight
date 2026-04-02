"""
E8-5: Restrict Administrative Privileges
Checks admin group membership, privilege tiering, and least-privilege enforcement.
"""
from __future__ import annotations

import platform
import subprocess

from agent.checks.base import (
    BaseCheck, CheckResult, MaturityLevel, RemediationStep
)

ACSC_REF = "https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/restrict-administrative-privileges"

# Threshold: more than this many local admins is suspicious
MAX_ACCEPTABLE_ADMINS = 3


class RestrictAdminCheck(BaseCheck):
    control_id = "E8-5"
    control_name = "Restrict Administrative Privileges"

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

        admins = self._get_local_admins(raw)
        laps_enabled = self._check_laps(raw)
        uac_level = self._check_uac(raw)
        admin_shares_restricted = self._check_admin_shares(raw)
        result.raw_data = raw

        issues = []

        if admins is not None:
            result.findings.append(f"Local Administrators group has {len(admins)} member(s): {', '.join(admins)}")
            if len(admins) > MAX_ACCEPTABLE_ADMINS:
                issues.append(f"Excessive local admins ({len(admins)}) — should be minimised to ≤{MAX_ACCEPTABLE_ADMINS}.")
        else:
            issues.append("Could not enumerate local Administrators group.")

        if laps_enabled:
            result.findings.append("Local Administrator Password Solution (LAPS) appears to be configured.")
        else:
            issues.append("LAPS is not configured — shared local admin passwords are a lateral movement risk.")
            result.remediation.append(RemediationStep(
                description="Deploy Windows LAPS to manage unique local admin passwords.",
                script=(
                    "# Install LAPS (Windows Server 2022+ has it built-in; for older use MSI)\n"
                    "# Enable LAPS via Group Policy:\n"
                    "# Computer Config > Admin Templates > LAPS > Enable local admin password management\n\n"
                    "# For Windows LAPS (built-in, 2022/Win11):\n"
                    "Update-LapsADSchema\n"
                    "Set-LapsADAuditing -Identity 'DC=contoso,DC=com' -AuditedPrincipals 'Everyone'\n"
                    "Set-LapsADComputerSelfPermission -Identity 'OU=Workstations,DC=contoso,DC=com'"
                ),
                script_type="powershell",
                acsc_reference=ACSC_REF,
                priority="high",
                target_level=MaturityLevel.MOSTLY_IMPLEMENTED,
            ))

        if uac_level and uac_level >= 2:
            result.findings.append(f"UAC is enabled (ConsentPromptBehaviorAdmin={uac_level}).")
        else:
            issues.append("UAC is disabled or set to lowest level — this allows privilege escalation.")
            result.remediation.append(RemediationStep(
                description="Enable UAC at the highest level.",
                script=(
                    "# Set UAC to prompt for credentials (not just consent)\n"
                    "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
                    "-Name 'ConsentPromptBehaviorAdmin' -Value 2\n"
                    "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
                    "-Name 'EnableLUA' -Value 1"
                ),
                script_type="powershell",
                acsc_reference=ACSC_REF,
                priority="high",
                target_level=MaturityLevel.PARTIAL,
            ))

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

    def _get_local_admins(self, raw: dict):
        try:
            out = subprocess.run(
                ["powershell", "-NonInteractive", "-Command",
                 "Get-LocalGroupMember -Group 'Administrators' | Select-Object -ExpandProperty Name"],
                capture_output=True, text=True, timeout=15
            )
            members = [m.strip() for m in out.stdout.splitlines() if m.strip()]
            raw["local_admins"] = members
            return members
        except Exception as e:
            raw["local_admins_error"] = str(e)
            return None

    def _check_laps(self, raw: dict) -> bool:
        try:
            out = subprocess.run(
                ["powershell", "-NonInteractive", "-Command",
                 "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\GPExtensions\\{D76B9641-3288-4f75-942D-087DE603E3EA}' "
                 "-ErrorAction SilentlyContinue | Select-Object -ExpandProperty DllName"],
                capture_output=True, text=True, timeout=10
            )
            has_laps = "laps" in out.stdout.lower() or "admpwd" in out.stdout.lower()
            raw["laps_gp_extension"] = out.stdout.strip()[:100]
            # Also check for Windows LAPS
            out2 = subprocess.run(
                ["powershell", "-NonInteractive", "-Command",
                 "Get-Command Get-LapsADPassword -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name"],
                capture_output=True, text=True, timeout=10
            )
            has_win_laps = "Get-LapsADPassword" in out2.stdout
            raw["windows_laps"] = has_win_laps
            return has_laps or has_win_laps
        except Exception as e:
            raw["laps_error"] = str(e)
            return False

    def _check_uac(self, raw: dict):
        try:
            out = subprocess.run(
                ["reg", "query",
                 r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                 "/v", "ConsentPromptBehaviorAdmin"],
                capture_output=True, text=True, timeout=5
            )
            for line in out.stdout.splitlines():
                if "ConsentPromptBehaviorAdmin" in line:
                    val = line.strip().split()[-1]
                    level = int(val, 16)
                    raw["uac_level"] = level
                    return level
        except Exception as e:
            raw["uac_error"] = str(e)
        return None

    def _check_admin_shares(self, raw: dict) -> bool:
        try:
            out = subprocess.run(
                ["reg", "query",
                 r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                 "/v", "AutoShareWks"],
                capture_output=True, text=True, timeout=5
            )
            raw["admin_shares"] = out.stdout.strip()[:100]
            return "0x0" in out.stdout
        except Exception as e:
            raw["admin_shares_error"] = str(e)
            return False

    # ── Linux ─────────────────────────────────────────────────────────────────

    def _check_linux(self) -> CheckResult:
        result = self._base_result()
        raw: dict = {}

        sudo_users = self._get_sudo_users(raw)
        root_ssh = self._check_root_ssh(raw)
        sudo_nopasswd = self._check_sudo_nopasswd(raw)
        result.raw_data = raw

        issues = []

        if sudo_users is not None:
            result.findings.append(f"Users with sudo access: {', '.join(sudo_users) or 'none found'}")
            if len(sudo_users) > MAX_ACCEPTABLE_ADMINS:
                issues.append(f"Excessive sudo users ({len(sudo_users)}) — review and minimise.")

        if root_ssh:
            issues.append("Root SSH login is permitted — this should be disabled.")
            result.remediation.append(RemediationStep(
                description="Disable root SSH login.",
                script=(
                    "sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config\n"
                    "sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config\n"
                    "systemctl restart sshd"
                ),
                script_type="bash",
                acsc_reference=ACSC_REF,
                priority="high",
                target_level=MaturityLevel.PARTIAL,
            ))
        else:
            result.findings.append("Root SSH login is disabled.")

        if sudo_nopasswd:
            issues.append("NOPASSWD sudo rules found — admin actions should require password authentication.")
            result.remediation.append(RemediationStep(
                description="Remove NOPASSWD sudo rules.",
                script=(
                    "# Review and edit sudoers\n"
                    "grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d/\n"
                    "# Edit with: visudo /etc/sudoers\n"
                    "# Remove or restrict any NOPASSWD entries"
                ),
                script_type="bash",
                acsc_reference=ACSC_REF,
                priority="high",
                target_level=MaturityLevel.MOSTLY_IMPLEMENTED,
            ))
        else:
            result.findings.append("No NOPASSWD sudo rules found.")

        if not issues:
            result.maturity_level = MaturityLevel.FULLY_IMPLEMENTED
        elif len(issues) == 1:
            result.maturity_level = MaturityLevel.MOSTLY_IMPLEMENTED
            result.gaps.extend(issues)
        else:
            result.maturity_level = MaturityLevel.PARTIAL
            result.gaps.extend(issues)

        return result

    def _get_sudo_users(self, raw: dict):
        try:
            users = []
            # Check /etc/sudoers and /etc/sudoers.d
            out = subprocess.run(
                ["grep", "-r", "ALL=(ALL", "/etc/sudoers", "/etc/sudoers.d/"],
                capture_output=True, text=True, timeout=5
            )
            for line in out.stdout.splitlines():
                if not line.startswith("#"):
                    parts = line.split()
                    if parts:
                        users.append(parts[0])

            # Also check wheel/sudo group members
            for group in ["sudo", "wheel", "admin"]:
                out2 = subprocess.run(
                    ["getent", "group", group], capture_output=True, text=True, timeout=5
                )
                if out2.returncode == 0 and ":" in out2.stdout:
                    members = out2.stdout.strip().split(":")[-1].split(",")
                    users.extend([m for m in members if m])

            users = list(set(users))
            raw["sudo_users"] = users
            return users
        except Exception as e:
            raw["sudo_error"] = str(e)
            return None

    def _check_root_ssh(self, raw: dict) -> bool:
        try:
            out = subprocess.run(
                ["grep", "-i", "PermitRootLogin", "/etc/ssh/sshd_config"],
                capture_output=True, text=True, timeout=5
            )
            config = out.stdout.lower()
            raw["sshd_root_login"] = out.stdout.strip()[:100]
            # If PermitRootLogin yes → dangerous
            return "permitrootlogin yes" in config
        except Exception as e:
            raw["ssh_root_error"] = str(e)
            return False

    def _check_sudo_nopasswd(self, raw: dict) -> bool:
        try:
            out = subprocess.run(
                ["grep", "-r", "NOPASSWD", "/etc/sudoers", "/etc/sudoers.d/"],
                capture_output=True, text=True, timeout=5
            )
            found = bool(out.stdout.strip())
            raw["sudo_nopasswd_entries"] = out.stdout.strip()[:200]
            return found
        except Exception as e:
            raw["sudo_nopasswd_error"] = str(e)
            return False

    # ── macOS ─────────────────────────────────────────────────────────────────

    def _check_macos(self) -> CheckResult:
        result = self._base_result()
        raw: dict = {}

        admin_users = self._get_macos_admins(raw)
        root_enabled = self._check_root_account(raw)
        sudo_nopasswd = self._check_sudo_nopasswd(raw)
        result.raw_data = raw

        issues = []

        if admin_users is not None:
            result.findings.append(f"Admin users: {', '.join(admin_users)}")
            if len(admin_users) > MAX_ACCEPTABLE_ADMINS:
                issues.append(f"Excessive admin users ({len(admin_users)}) — minimise local admins.")

        if root_enabled:
            issues.append("Root account is enabled — it should be disabled on macOS.")
            result.remediation.append(RemediationStep(
                description="Disable the root account on macOS.",
                script="dscl . -passwd /Users/root '*'  # Lock root account",
                script_type="zsh",
                acsc_reference=ACSC_REF,
                priority="high",
                target_level=MaturityLevel.PARTIAL,
            ))
        else:
            result.findings.append("Root account is disabled.")

        if sudo_nopasswd:
            issues.append("NOPASSWD sudo rules found.")
        else:
            result.findings.append("No NOPASSWD sudo rules found.")

        if not issues:
            result.maturity_level = MaturityLevel.FULLY_IMPLEMENTED
        elif len(issues) == 1:
            result.maturity_level = MaturityLevel.MOSTLY_IMPLEMENTED
            result.gaps.extend(issues)
        else:
            result.maturity_level = MaturityLevel.PARTIAL
            result.gaps.extend(issues)

        return result

    def _get_macos_admins(self, raw: dict):
        try:
            out = subprocess.run(
                ["dscl", ".", "-read", "/Groups/admin", "GroupMembership"],
                capture_output=True, text=True, timeout=10
            )
            if out.returncode == 0:
                members = out.stdout.replace("GroupMembership:", "").split()
                raw["admin_group"] = members
                return members
        except Exception as e:
            raw["macos_admin_error"] = str(e)
        return None

    def _check_root_account(self, raw: dict) -> bool:
        try:
            out = subprocess.run(
                ["dscl", ".", "-read", "/Users/root", "Password"],
                capture_output=True, text=True, timeout=5
            )
            # Root is disabled if password is '*'
            disabled = "*" in out.stdout
            raw["root_account"] = "disabled" if disabled else "enabled"
            return not disabled
        except Exception as e:
            raw["root_check_error"] = str(e)
            return False
