"""
E8-7: Multi-Factor Authentication
Checks MFA enforcement for remote access (RDP/SSH/VPN) and privileged accounts.
"""
from __future__ import annotations

import os
import platform
import subprocess

from agent.checks.base import (
    BaseCheck, CheckResult, MaturityLevel, RemediationStep
)

ACSC_REF = "https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/multi-factor-authentication"


class MFACheck(BaseCheck):
    control_id = "E8-7"
    control_name = "Multi-Factor Authentication"

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

        nla_enabled = self._check_rdp_nla(raw)
        rdp_enabled = self._check_rdp_enabled(raw)
        smart_card_required = self._check_smartcard(raw)
        result.raw_data = raw

        issues = []

        if rdp_enabled:
            result.findings.append("Remote Desktop (RDP) is enabled on this machine.")
            if nla_enabled:
                result.findings.append("Network Level Authentication (NLA) is required for RDP.")
            else:
                issues.append("RDP is enabled but NLA is NOT enforced — pre-authentication MFA is absent.")
                result.remediation.append(RemediationStep(
                    description="Enable Network Level Authentication for RDP.",
                    script=(
                        "# Enable NLA for RDP\n"
                        "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
                        "-Name 'UserAuthentication' -Value 1\n"
                        "# Also configure via Group Policy: Computer Config > Admin Templates > "
                        "Windows Components > Remote Desktop Services > RDS Host > Security"
                    ),
                    script_type="powershell",
                    acsc_reference=ACSC_REF,
                    priority="high",
                    target_level=MaturityLevel.PARTIAL,
                ))
        else:
            result.findings.append("RDP is not enabled on this machine.")

        if smart_card_required:
            result.findings.append("Smart card is required for interactive logon.")
        else:
            issues.append("Smart card / hardware MFA not required for interactive logon.")
            result.remediation.append(RemediationStep(
                description="Require smart card or Windows Hello for Business for privileged accounts.",
                script=(
                    "# Require smart card for all users via Group Policy:\n"
                    "# Computer Config > Windows Settings > Security Settings > Local Policies > Security Options\n"
                    "# 'Interactive logon: Require smart card' = Enabled\n\n"
                    "# Or enforce Windows Hello for Business:\n"
                    "# Deploy via Intune/Endpoint Manager or Group Policy"
                ),
                script_type="powershell",
                acsc_reference=ACSC_REF,
                priority="high",
                target_level=MaturityLevel.FULLY_IMPLEMENTED,
            ))

        if not issues:
            result.maturity_level = MaturityLevel.FULLY_IMPLEMENTED
        elif len(issues) == 1:
            result.maturity_level = MaturityLevel.MOSTLY_IMPLEMENTED
            result.gaps.extend(issues)
        else:
            result.maturity_level = MaturityLevel.PARTIAL
            result.gaps.extend(issues)

        return result

    def _check_rdp_enabled(self, raw: dict) -> bool:
        try:
            out = subprocess.run(
                ["reg", "query",
                 r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
                 "/v", "fDenyTSConnections"],
                capture_output=True, text=True, timeout=5
            )
            raw["rdp_deny"] = out.stdout.strip()[:100]
            return "0x0" in out.stdout  # 0 = RDP allowed
        except Exception as e:
            raw["rdp_error"] = str(e)
            return False

    def _check_rdp_nla(self, raw: dict) -> bool:
        try:
            out = subprocess.run(
                ["reg", "query",
                 r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                 "/v", "UserAuthentication"],
                capture_output=True, text=True, timeout=5
            )
            raw["rdp_nla"] = out.stdout.strip()[:100]
            return "0x1" in out.stdout
        except Exception as e:
            raw["nla_error"] = str(e)
            return False

    def _check_smartcard(self, raw: dict) -> bool:
        try:
            out = subprocess.run(
                ["reg", "query",
                 r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                 "/v", "ScForceOption"],
                capture_output=True, text=True, timeout=5
            )
            raw["smartcard_required"] = out.stdout.strip()[:100]
            return "0x1" in out.stdout
        except Exception as e:
            raw["smartcard_error"] = str(e)
            return False

    # ── Linux ─────────────────────────────────────────────────────────────────

    def _check_linux(self) -> CheckResult:
        result = self._base_result()
        raw: dict = {}

        ssh_key_only = self._check_ssh_key_auth(raw)
        pam_mfa = self._check_pam_mfa(raw)
        ssh_enabled = self._check_ssh_service(raw)
        result.raw_data = raw

        issues = []

        if ssh_enabled:
            result.findings.append("SSH service is running.")
            if ssh_key_only:
                result.findings.append("SSH password authentication is disabled (key-only) — good.")
            else:
                issues.append("SSH allows password authentication without MFA — key-only or MFA must be enforced.")
                result.remediation.append(RemediationStep(
                    description="Disable SSH password authentication and require key-based auth.",
                    script=(
                        "# Disable password auth in SSH\n"
                        "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config\n"
                        "sed -i 's/^#*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config\n"
                        "systemctl restart sshd\n\n"
                        "# Verify:\n"
                        "grep PasswordAuthentication /etc/ssh/sshd_config"
                    ),
                    script_type="bash",
                    acsc_reference=ACSC_REF,
                    priority="high",
                    target_level=MaturityLevel.MOSTLY_IMPLEMENTED,
                ))
        else:
            result.findings.append("SSH service is not running.")

        if pam_mfa:
            result.findings.append("PAM MFA module (TOTP/FIDO2) appears configured.")
        else:
            issues.append("No PAM-based MFA (Google Authenticator / FIDO2 / etc.) detected for local login.")
            result.remediation.append(RemediationStep(
                description="Configure PAM Google Authenticator for TOTP-based MFA.",
                script=(
                    "# Install Google Authenticator PAM module\n"
                    "apt-get install -y libpam-google-authenticator\n\n"
                    "# Add to /etc/pam.d/sshd:\n"
                    "echo 'auth required pam_google_authenticator.so' >> /etc/pam.d/sshd\n\n"
                    "# Enable ChallengeResponseAuthentication in sshd_config:\n"
                    "sed -i 's/^ChallengeResponseAuthentication no/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config\n"
                    "echo 'AuthenticationMethods publickey,keyboard-interactive' >> /etc/ssh/sshd_config\n"
                    "systemctl restart sshd\n\n"
                    "# Each user then runs: google-authenticator"
                ),
                script_type="bash",
                acsc_reference=ACSC_REF,
                priority="high",
                target_level=MaturityLevel.FULLY_IMPLEMENTED,
            ))

        if not issues:
            result.maturity_level = MaturityLevel.FULLY_IMPLEMENTED
        elif len(issues) == 1:
            result.maturity_level = MaturityLevel.MOSTLY_IMPLEMENTED
            result.gaps.extend(issues)
        else:
            result.maturity_level = MaturityLevel.PARTIAL
            result.gaps.extend(issues)

        return result

    def _check_ssh_service(self, raw: dict) -> bool:
        # Ubuntu uses "ssh"; RHEL/other distros use "sshd"
        for service in ["sshd", "ssh"]:
            try:
                out = subprocess.run(
                    ["systemctl", "is-active", service],
                    capture_output=True, text=True, timeout=5
                )
                if out.stdout.strip() == "active":
                    raw["sshd_active"] = "active"
                    raw["sshd_service_name"] = service
                    return True
            except Exception as e:
                raw["sshd_error"] = str(e)
        raw["sshd_active"] = "inactive"
        return False

    def _check_ssh_key_auth(self, raw: dict) -> bool:
        try:
            out = subprocess.run(
                ["grep", "-i", "PasswordAuthentication", "/etc/ssh/sshd_config"],
                capture_output=True, text=True, timeout=5
            )
            config = out.stdout.lower()
            raw["ssh_password_auth"] = out.stdout.strip()[:100]
            return "passwordauthentication no" in config
        except Exception as e:
            raw["ssh_key_error"] = str(e)
            return False

    def _check_pam_mfa(self, raw: dict) -> bool:
        pam_files = ["/etc/pam.d/sshd", "/etc/pam.d/login", "/etc/pam.d/common-auth"]
        mfa_indicators = ["pam_google_authenticator", "pam_u2f", "pam_fido2", "pam_oath"]
        for pam_file in pam_files:
            try:
                if os.path.exists(pam_file):
                    with open(pam_file, "r") as f:
                        content = f.read().lower()
                    for indicator in mfa_indicators:
                        if indicator in content:
                            raw["pam_mfa_found"] = f"{indicator} in {pam_file}"
                            return True
            except Exception as e:
                raw["pam_error"] = str(e)
        raw["pam_mfa_found"] = False
        return False

    # ── macOS ─────────────────────────────────────────────────────────────────

    def _check_macos(self) -> CheckResult:
        result = self._base_result()
        raw: dict = {}

        ssh_key_only = self._check_ssh_key_auth(raw)
        ssh_enabled = self._check_macos_ssh(raw)
        secure_token = self._check_secure_token(raw)
        screensaver_pwd = self._check_screensaver_password(raw)
        result.raw_data = raw

        issues = []

        if ssh_enabled:
            result.findings.append("Remote Login (SSH) is enabled.")
            if ssh_key_only:
                result.findings.append("SSH password authentication is disabled.")
            else:
                issues.append("SSH allows password authentication — disable it.")
                result.remediation.append(RemediationStep(
                    description="Disable SSH password authentication on macOS.",
                    script=(
                        "sudo sed -i '' 's/#*PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config\n"
                        "sudo launchctl stop com.openssh.sshd && sudo launchctl start com.openssh.sshd"
                    ),
                    script_type="zsh",
                    acsc_reference=ACSC_REF,
                    priority="high",
                    target_level=MaturityLevel.MOSTLY_IMPLEMENTED,
                ))
        else:
            result.findings.append("Remote Login (SSH) is disabled.")

        if secure_token:
            result.findings.append("Secure Token is enabled for user accounts (supports FileVault + MFA).")
        else:
            issues.append("Secure Token may not be configured — required for full disk encryption and MFA.")

        if screensaver_pwd:
            result.findings.append("Password required immediately on screensaver/sleep.")
        else:
            issues.append("Screen lock does not require password immediately — configure lock screen.")
            result.remediation.append(RemediationStep(
                description="Require password immediately when screensaver starts.",
                script=(
                    "# Require password immediately\n"
                    "sudo defaults write /Library/Preferences/com.apple.screensaver askForPassword -int 1\n"
                    "sudo defaults write /Library/Preferences/com.apple.screensaver askForPasswordDelay -int 0"
                ),
                script_type="zsh",
                acsc_reference=ACSC_REF,
                priority="medium",
                target_level=MaturityLevel.MOSTLY_IMPLEMENTED,
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

    def _check_macos_ssh(self, raw: dict) -> bool:
        try:
            out = subprocess.run(
                ["systemsetup", "-getremotelogin"],
                capture_output=True, text=True, timeout=5
            )
            enabled = "on" in out.stdout.lower()
            raw["remote_login"] = out.stdout.strip()
            return enabled
        except Exception as e:
            raw["ssh_macos_error"] = str(e)
            return False

    def _check_secure_token(self, raw: dict) -> bool:
        try:
            import getpass
            user = getpass.getuser()
            out = subprocess.run(
                ["sysadminctl", "-secureTokenStatus", user],
                capture_output=True, text=True, timeout=5
            )
            status = out.stdout + out.stderr
            enabled = "ENABLED" in status.upper()
            raw["secure_token"] = status.strip()[:100]
            return enabled
        except Exception as e:
            raw["secure_token_error"] = str(e)
            return False

    def _check_screensaver_password(self, raw: dict) -> bool:
        try:
            out = subprocess.run(
                ["defaults", "read", "com.apple.screensaver", "askForPassword"],
                capture_output=True, text=True, timeout=5
            )
            val = out.stdout.strip()
            raw["screensaver_password"] = val
            if val != "1":
                return False
            # Check delay
            out2 = subprocess.run(
                ["defaults", "read", "com.apple.screensaver", "askForPasswordDelay"],
                capture_output=True, text=True, timeout=5
            )
            delay = out2.stdout.strip()
            raw["screensaver_delay"] = delay
            return delay == "0"
        except Exception as e:
            raw["screensaver_error"] = str(e)
            return False
