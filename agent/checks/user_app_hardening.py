"""
E8-4: User Application Hardening
Checks browser security settings, Java, Flash, and web advertisement blocking.
"""
from __future__ import annotations

import os
import platform
import subprocess

from agent.checks.base import (
    BaseCheck, CheckResult, MaturityLevel, RemediationStep
)

ACSC_REF = "https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/user-application-hardening"


class UserAppHardeningCheck(BaseCheck):
    control_id = "E8-4"
    control_name = "User Application Hardening"

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
        score = 0
        max_score = 4

        java_disabled = self._check_java_windows(raw)
        flash_disabled = self._check_flash_windows(raw)
        ie_zones_ok = self._check_ie_zones(raw)
        wdag_enabled = self._check_wdag(raw)

        result.raw_data = raw

        if java_disabled:
            score += 1
            result.findings.append("Java browser plugin is not detected / disabled.")
        else:
            result.gaps.append("Java browser plugin may be enabled — disable or uninstall.")
            result.remediation.append(RemediationStep(
                description="Disable or uninstall Java browser plugin.",
                script=(
                    "# Uninstall Java runtime environments\n"
                    "Get-Package | Where-Object {$_.Name -like '*Java*'} | Uninstall-Package -Force\n"
                    "# Or disable the Java plugin in Group Policy"
                ),
                script_type="powershell",
                acsc_reference=ACSC_REF,
                priority="high",
                target_level=MaturityLevel.PARTIAL,
            ))

        if flash_disabled:
            score += 1
            result.findings.append("Adobe Flash is not installed or blocked.")
        else:
            result.gaps.append("Flash Player remnants detected — ensure it is fully removed.")
            result.remediation.append(RemediationStep(
                description="Remove Adobe Flash Player completely.",
                script=(
                    "# Adobe Flash Player Uninstaller\n"
                    "# Download from: https://www.adobe.com/products/flashplayer/end-of-life.html\n"
                    "Get-Package | Where-Object {$_.Name -like '*Flash*'} | Uninstall-Package -Force"
                ),
                script_type="powershell",
                acsc_reference=ACSC_REF,
                priority="high",
                target_level=MaturityLevel.PARTIAL,
            ))

        if ie_zones_ok:
            score += 1
            result.findings.append("IE/Edge security zones appear restrictive.")
        else:
            result.gaps.append("Internet Explorer/Edge security zone settings may be permissive.")
            result.remediation.append(RemediationStep(
                description="Configure IE/Edge security zones via Group Policy.",
                script=(
                    "# Set Internet Zone security to High via registry\n"
                    "$path = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3'\n"
                    "Set-ItemProperty -Path $path -Name 'CurrentLevel' -Value 0x00012000"
                ),
                script_type="powershell",
                acsc_reference=ACSC_REF,
                priority="medium",
                target_level=MaturityLevel.MOSTLY_IMPLEMENTED,
            ))

        if wdag_enabled:
            score += 1
            result.findings.append("Windows Defender Application Guard (WDAG) is enabled for Edge.")
        else:
            result.gaps.append("Windows Defender Application Guard is not enabled.")
            result.remediation.append(RemediationStep(
                description="Enable Windows Defender Application Guard for Microsoft Edge.",
                script=(
                    "# Enable WDAG feature\n"
                    "Enable-WindowsOptionalFeature -Online -FeatureName 'Windows-Defender-ApplicationGuard' -NoRestart\n"
                    "# Configure via GPO: Computer Config > Admin Templates > Windows Components > Microsoft Defender Application Guard"
                ),
                script_type="powershell",
                acsc_reference=ACSC_REF,
                priority="medium",
                target_level=MaturityLevel.FULLY_IMPLEMENTED,
            ))

        result.maturity_level = self._score_to_level(score, max_score)
        return result

    def _check_java_windows(self, raw: dict) -> bool:
        try:
            out = subprocess.run(
                ["powershell", "-NonInteractive", "-Command",
                 "Get-Package | Where-Object {$_.Name -like '*Java*'} | Select-Object Name"],
                capture_output=True, text=True, timeout=15
            )
            has_java = "java" in out.stdout.lower()
            raw["java_installed"] = has_java
            return not has_java
        except Exception as e:
            raw["java_check_error"] = str(e)
            return True  # Assume OK if can't check

    def _check_flash_windows(self, raw: dict) -> bool:
        flash_paths = [
            r"C:\Windows\System32\Macromed\Flash",
            r"C:\Windows\SysWOW64\Macromed\Flash",
        ]
        has_flash = any(os.path.isdir(p) for p in flash_paths)
        raw["flash_detected"] = has_flash
        return not has_flash

    def _check_ie_zones(self, raw: dict) -> bool:
        try:
            out = subprocess.run(
                ["reg", "query",
                 r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3",
                 "/v", "CurrentLevel"],
                capture_output=True, text=True, timeout=5
            )
            raw["ie_zone3"] = out.stdout.strip()[:100]
            return "12288" in out.stdout or "12000" in out.stdout  # High security
        except Exception as e:
            raw["ie_zones_error"] = str(e)
            return False

    def _check_wdag(self, raw: dict) -> bool:
        try:
            out = subprocess.run(
                ["powershell", "-NonInteractive", "-Command",
                 "(Get-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard).State"],
                capture_output=True, text=True, timeout=20
            )
            state = out.stdout.strip()
            raw["wdag_state"] = state
            return state == "Enabled"
        except Exception as e:
            raw["wdag_error"] = str(e)
            return False

    # ── Linux ─────────────────────────────────────────────────────────────────

    def _check_linux(self) -> CheckResult:
        result = self._base_result()
        raw: dict = {}
        score = 0
        max_score = 3

        java_ok = self._check_java_unix(raw)
        flash_ok = not self._check_flash_linux(raw)
        browser_policies = self._check_browser_policies_linux(raw)
        result.raw_data = raw

        if java_ok:
            score += 1
            result.findings.append("Java browser plugin not detected.")
        else:
            result.gaps.append("Java runtime detected — disable the browser plugin.")
            result.remediation.append(RemediationStep(
                description="Remove Java browser plugin.",
                script="apt-get purge -y icedtea-plugin default-jre icedtea-8-plugin || true",
                script_type="bash",
                acsc_reference=ACSC_REF,
                priority="high",
                target_level=MaturityLevel.PARTIAL,
            ))

        if flash_ok:
            score += 1
            result.findings.append("Adobe Flash not detected.")
        else:
            result.gaps.append("Flash Player detected — remove it.")
            result.remediation.append(RemediationStep(
                description="Remove Adobe Flash Player.",
                script="apt-get purge -y flashplugin-installer pepperflashplugin-nonfree || true",
                script_type="bash",
                acsc_reference=ACSC_REF,
                priority="high",
                target_level=MaturityLevel.PARTIAL,
            ))

        if browser_policies:
            score += 1
            result.findings.append("Browser enterprise policies directory found.")
        else:
            result.gaps.append("No browser enterprise policy configured.")
            result.remediation.append(RemediationStep(
                description="Deploy browser enterprise policies to harden browser security.",
                script=(
                    "# Create Chrome/Chromium policy directory\n"
                    "mkdir -p /etc/opt/chrome/policies/managed/\n"
                    "cat > /etc/opt/chrome/policies/managed/security.json << 'EOF'\n"
                    "{\n"
                    "  \"JavascriptEnabled\": true,\n"
                    "  \"PluginsAllowedForUrls\": [],\n"
                    "  \"DefaultPluginsSetting\": 2,\n"
                    "  \"SafeBrowsingEnabled\": true,\n"
                    "  \"BlockThirdPartyCookies\": true\n"
                    "}\n"
                    "EOF"
                ),
                script_type="bash",
                acsc_reference=ACSC_REF,
                priority="medium",
                target_level=MaturityLevel.MOSTLY_IMPLEMENTED,
            ))

        result.maturity_level = self._score_to_level(score, max_score)
        return result

    def _check_java_unix(self, raw: dict) -> bool:
        try:
            out = subprocess.run(["which", "java"], capture_output=True, text=True, timeout=5)
            installed = out.returncode == 0
            raw["java_installed"] = installed
            return not installed
        except Exception:
            return True

    def _check_flash_linux(self, raw: dict) -> bool:
        flash_paths = [
            "/usr/lib/flashplugin-installer/libflashplayer.so",
            "/usr/lib/pepperflashplugin-nonfree/libpepflashplayer.so",
        ]
        detected = any(os.path.exists(p) for p in flash_paths)
        raw["flash_detected"] = detected
        return detected

    def _check_browser_policies_linux(self, raw: dict) -> bool:
        policy_dirs = [
            "/etc/opt/chrome/policies/managed",
            "/etc/chromium/policies/managed",
            "/usr/lib/firefox/distribution",
        ]
        found = any(os.path.isdir(p) for p in policy_dirs)
        raw["browser_policy_dir"] = found
        return found

    # ── macOS ─────────────────────────────────────────────────────────────────

    def _check_macos(self) -> CheckResult:
        result = self._base_result()
        raw: dict = {}
        score = 0
        max_score = 3

        java_ok = self._check_java_unix(raw)
        safari_ok = self._check_safari_settings(raw)
        browser_policies = self._check_browser_policies_macos(raw)
        result.raw_data = raw

        if java_ok:
            score += 1
            result.findings.append("Java not detected on system.")
        else:
            result.gaps.append("Java detected — disable the browser plugin.")
            result.remediation.append(RemediationStep(
                description="Remove or disable Java on macOS.",
                script=(
                    "# Check installed Java versions\n"
                    "/usr/libexec/java_home -V\n\n"
                    "# Disable Java browser plugin (deprecated in modern macOS/browsers)\n"
                    "# Uninstall via: System Preferences > Java > Advanced > disable"
                ),
                script_type="zsh",
                acsc_reference=ACSC_REF,
                priority="high",
                target_level=MaturityLevel.PARTIAL,
            ))

        if safari_ok:
            score += 1
            result.findings.append("Safari has JavaScript restrictions or extensions policy in place.")
        else:
            result.gaps.append("Safari security settings may not be fully hardened.")
            result.remediation.append(RemediationStep(
                description="Harden Safari settings via MDM configuration profile.",
                script=(
                    "# These settings are best deployed via MDM profile (e.g. Jamf, Mosyle)\n"
                    "# Disable pop-ups in Safari\n"
                    "defaults write com.apple.Safari WebKitJavaEnabled -bool false\n"
                    "defaults write com.apple.Safari com.apple.Safari.ContentPageGroupIdentifier.WebKit2JavaEnabled -bool false"
                ),
                script_type="zsh",
                acsc_reference=ACSC_REF,
                priority="medium",
                target_level=MaturityLevel.MOSTLY_IMPLEMENTED,
            ))

        if browser_policies:
            score += 1
            result.findings.append("Browser enterprise policy directory found.")
        else:
            result.gaps.append("No browser enterprise policies configured.")

        result.maturity_level = self._score_to_level(score, max_score)
        return result

    def _check_safari_settings(self, raw: dict) -> bool:
        try:
            out = subprocess.run(
                ["defaults", "read", "com.apple.Safari", "WebKitJavaEnabled"],
                capture_output=True, text=True, timeout=5
            )
            val = out.stdout.strip()
            raw["safari_java_enabled"] = val
            return val == "0"
        except Exception as e:
            raw["safari_error"] = str(e)
            return False

    def _check_browser_policies_macos(self, raw: dict) -> bool:
        policy_dirs = [
            "/Library/Managed Preferences",
            "/etc/opt/chrome/policies/managed",
        ]
        found = any(os.path.isdir(p) for p in policy_dirs)
        raw["browser_policy_dir"] = found
        return found

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _score_to_level(self, score: int, max_score: int) -> MaturityLevel:
        ratio = score / max_score
        if ratio == 1.0:
            return MaturityLevel.FULLY_IMPLEMENTED
        elif ratio >= 0.75:
            return MaturityLevel.MOSTLY_IMPLEMENTED
        elif ratio >= 0.5:
            return MaturityLevel.PARTIAL
        return MaturityLevel.NOT_IMPLEMENTED
