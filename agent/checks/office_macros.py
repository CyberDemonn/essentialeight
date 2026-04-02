"""
E8-3: Configure Microsoft Office Macro Settings
Checks macro execution policy in Office (Windows registry/GPO) and LibreOffice (Linux/macOS).
"""
from __future__ import annotations

import platform
import subprocess

from agent.checks.base import (
    BaseCheck, CheckResult, MaturityLevel, RemediationStep
)

ACSC_REF = "https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/configure-microsoft-office-macro-settings"


class OfficeMacrosCheck(BaseCheck):
    control_id = "E8-3"
    control_name = "Configure Microsoft Office Macro Settings"

    def run(self) -> CheckResult:
        os_name = platform.system()
        if os_name == "Windows":
            return self._check_windows()
        elif os_name in ("Linux", "Darwin"):
            return self._check_libreoffice(os_name)
        return self._unsupported_result()

    # ── Windows ──────────────────────────────────────────────────────────────

    def _check_windows(self) -> CheckResult:
        result = self._base_result()
        raw: dict = {}

        # Office apps to check
        office_apps = {
            "Word": r"HKCU\Software\Policies\Microsoft\Office\16.0\Word\Security",
            "Excel": r"HKCU\Software\Policies\Microsoft\Office\16.0\Excel\Security",
            "PowerPoint": r"HKCU\Software\Policies\Microsoft\Office\16.0\PowerPoint\Security",
            "Access": r"HKCU\Software\Policies\Microsoft\Office\16.0\Access\Security",
        }

        # VBAWarnings values: 1=all enabled, 2=signed only, 3=disable all+notify, 4=disable all silently
        macro_settings: dict[str, int] = {}
        for app, reg_path in office_apps.items():
            val = self._read_reg_dword(reg_path, "VBAWarnings", raw, f"{app.lower()}_vba")
            macro_settings[app] = val

        vba_block = self._read_reg_dword(
            r"HKCU\Software\Policies\Microsoft\Office\16.0\Excel\Security",
            "BlockContentExecutionFromInternet", raw, "block_content_internet"
        )

        result.raw_data = raw
        configured = {app: v for app, v in macro_settings.items() if v is not None}
        disabled_apps = [app for app, v in configured.items() if v == 4]
        signed_only_apps = [app for app, v in configured.items() if v == 2]
        enabled_apps = [app for app, v in configured.items() if v == 1]

        if enabled_apps:
            result.maturity_level = MaturityLevel.NOT_IMPLEMENTED
            result.findings.append(f"Macros are ENABLED (unrestricted) in: {', '.join(enabled_apps)}.")
            result.gaps.append("Macros must not be enabled for all documents.")
            result.remediation.append(self._disable_macros_remediation())
        elif disabled_apps and not configured.keys() - set(disabled_apps):
            result.maturity_level = MaturityLevel.FULLY_IMPLEMENTED
            result.findings.append("Macros are disabled (silently) in all Office applications via Group Policy.")
        elif signed_only_apps:
            result.maturity_level = MaturityLevel.MOSTLY_IMPLEMENTED
            result.findings.append(f"Macros restricted to signed content in: {', '.join(signed_only_apps)}.")
            result.gaps.append("Not all Office apps are configured; consider blocking all macros.")
            result.remediation.append(self._disable_macros_remediation())
        elif configured:
            result.maturity_level = MaturityLevel.PARTIAL
            result.findings.append("Some Office macro settings are configured but not uniformly restrictive.")
            result.gaps.append("Enforce consistent macro restriction across all Office apps.")
            result.remediation.append(self._disable_macros_remediation())
        else:
            result.maturity_level = MaturityLevel.NOT_IMPLEMENTED
            result.findings.append("No Group Policy macro restrictions found for Microsoft Office.")
            result.gaps.append("Office macro restrictions are not configured via Group Policy.")
            result.remediation.append(self._disable_macros_remediation())

        return result

    def _read_reg_dword(self, path: str, name: str, raw: dict, key: str):
        try:
            out = subprocess.run(
                ["reg", "query", path, "/v", name],
                capture_output=True, text=True, timeout=5
            )
            for line in out.stdout.splitlines():
                if name in line and "REG_DWORD" in line:
                    val = line.strip().split()[-1]
                    raw[key] = val
                    return int(val, 16)
        except Exception as e:
            raw[f"{key}_error"] = str(e)
        return None

    def _disable_macros_remediation(self) -> RemediationStep:
        return RemediationStep(
            description="Disable all macros without notification via Group Policy for all Office apps.",
            script=(
                "# Set via Group Policy (recommended) or Registry\n"
                "# VBAWarnings = 4 means 'Disable all macros without notification'\n"
                "$apps = @('Word','Excel','PowerPoint','Access','Outlook','Project','Publisher','Visio')\n"
                "foreach ($app in $apps) {\n"
                "  $path = \"HKCU:\\Software\\Policies\\Microsoft\\Office\\16.0\\$app\\Security\"\n"
                "  if (!(Test-Path $path)) { New-Item -Path $path -Force | Out-Null }\n"
                "  Set-ItemProperty -Path $path -Name 'VBAWarnings' -Value 4 -Type DWord\n"
                "}\n"
                "Write-Host 'Macro restrictions applied. Verify via Group Policy Management Console.'"
            ),
            script_type="powershell",
            acsc_reference=ACSC_REF,
            priority="high",
            target_level=MaturityLevel.FULLY_IMPLEMENTED,
        )

    # ── Linux / macOS (LibreOffice) ───────────────────────────────────────────

    def _check_libreoffice(self, os_name: str) -> CheckResult:
        result = self._base_result()
        raw: dict = {}

        installed = self._is_libreoffice_installed(raw)
        if not installed:
            result.maturity_level = MaturityLevel.FULLY_IMPLEMENTED
            result.findings.append("LibreOffice is not installed — macro risk does not apply.")
            result.raw_data = raw
            return result

        macro_security = self._get_lo_macro_security(raw)
        result.raw_data = raw

        # LibreOffice macro security levels: 3=Very High, 2=High, 1=Medium, 0=Low
        if macro_security == 3:
            result.maturity_level = MaturityLevel.FULLY_IMPLEMENTED
            result.findings.append("LibreOffice macro security is set to 'Very High' (only signed macros from trusted locations).")
        elif macro_security == 2:
            result.maturity_level = MaturityLevel.MOSTLY_IMPLEMENTED
            result.findings.append("LibreOffice macro security is 'High' — prompts before enabling unsigned macros.")
            result.gaps.append("Set to 'Very High' to prevent unsigned macro execution.")
            result.remediation.append(self._lo_macro_remediation(os_name))
        elif macro_security == 1:
            result.maturity_level = MaturityLevel.PARTIAL
            result.findings.append("LibreOffice macro security is 'Medium' — user prompted but can allow macros.")
            result.gaps.append("Increase macro security level to High or Very High.")
            result.remediation.append(self._lo_macro_remediation(os_name))
        else:
            result.maturity_level = MaturityLevel.NOT_IMPLEMENTED
            result.findings.append("LibreOffice macro security is LOW or unknown — macros can run freely.")
            result.gaps.append("Macro security must be set to High or Very High.")
            result.remediation.append(self._lo_macro_remediation(os_name))

        return result

    def _is_libreoffice_installed(self, raw: dict) -> bool:
        try:
            out = subprocess.run(["which", "libreoffice"], capture_output=True, text=True, timeout=5)
            installed = out.returncode == 0
            raw["libreoffice_installed"] = installed
            return installed
        except Exception:
            return False

    def _get_lo_macro_security(self, raw: dict) -> int:
        import os
        # LibreOffice stores settings in registrymodifications.xcu
        possible_paths = [
            os.path.expanduser("~/.config/libreoffice/4/user/registrymodifications.xcu"),
            os.path.expanduser("~/Library/Application Support/LibreOffice/4/user/registrymodifications.xcu"),
        ]
        for path in possible_paths:
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    if "MacroSecurityLevel" in content:
                        for line in content.splitlines():
                            if "MacroSecurityLevel" in line and "value=" in line:
                                val = line.split('value="')[1].split('"')[0]
                                raw["lo_macro_security"] = val
                                return int(val)
                except Exception as e:
                    raw["lo_config_error"] = str(e)
        raw["lo_macro_security"] = "not_found"
        return -1

    def _lo_macro_remediation(self, os_name: str) -> RemediationStep:
        return RemediationStep(
            description="Set LibreOffice macro security to 'Very High' via configuration.",
            script=(
                "# LibreOffice macro security via command line\n"
                "# Set security level to 3 (Very High) in user profile\n"
                "python3 -c \"\n"
                "import os, re\n"
                "path = os.path.expanduser('~/.config/libreoffice/4/user/registrymodifications.xcu')\n"
                "# Alternatively configure via Tools > Macros > Security in LibreOffice GUI\n"
                "print('Please set macro security to Very High in LibreOffice: Tools > Macros > Organize Macros > Security')\n"
                "\"\n\n"
                "# For enterprise deployment, use a lock file:\n"
                "# /etc/libreoffice/sofficerc or install a policy via your MDM"
            ),
            script_type="bash",
            acsc_reference=ACSC_REF,
            priority="high",
            target_level=MaturityLevel.FULLY_IMPLEMENTED,
        )
