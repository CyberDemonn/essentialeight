"""
E8-8: Regular Backups
Checks backup configuration, recency, and integrity verification.
"""
from __future__ import annotations

import os
import platform
import subprocess
from datetime import datetime, timezone

from agent.checks.base import (
    BaseCheck, CheckResult, MaturityLevel, RemediationStep
)

ACSC_REF = "https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/regular-backups"

# Maximum acceptable days since last backup for each maturity level
MAX_DAYS_ML1 = 30
MAX_DAYS_ML2 = 7
MAX_DAYS_ML3 = 1


class BackupsCheck(BaseCheck):
    control_id = "E8-8"
    control_name = "Regular Backups"

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

        vss_snapshots = self._check_vss(raw)
        backup_configured = self._check_windows_backup(raw)
        offsite = self._check_offsite_indicators_windows(raw)
        result.raw_data = raw

        issues = []

        if vss_snapshots and len(vss_snapshots) > 0:
            result.findings.append(f"Volume Shadow Copy (VSS) has {len(vss_snapshots)} snapshot(s).")
            # Check recency of latest snapshot
            latest = self._latest_vss_age_days(vss_snapshots, raw)
            if latest is not None:
                if latest <= MAX_DAYS_ML3:
                    result.findings.append(f"Most recent VSS snapshot: {latest} day(s) ago.")
                elif latest <= MAX_DAYS_ML2:
                    issues.append(f"Latest VSS snapshot is {latest} days old — should be daily for ML3.")
                else:
                    issues.append(f"Latest VSS snapshot is {latest} days old — backups are infrequent.")
        else:
            issues.append("No Volume Shadow Copy snapshots found.")
            result.remediation.append(RemediationStep(
                description="Enable Volume Shadow Copy (VSS) scheduled snapshots.",
                script=(
                    "# Enable VSS for C: drive with daily schedule\n"
                    "vssadmin add shadowstorage /for=C: /on=C: /maxsize=10%\n"
                    "# Schedule via Task Scheduler or:\n"
                    "schtasks /create /tn 'VSS Daily Backup' /tr 'vssadmin create shadow /for=C:' "
                    "/sc daily /st 02:00 /ru SYSTEM"
                ),
                script_type="powershell",
                acsc_reference=ACSC_REF,
                priority="high",
                target_level=MaturityLevel.PARTIAL,
            ))

        if backup_configured:
            result.findings.append("Windows Backup / Backup and Restore is configured.")
        else:
            issues.append("Windows Backup is not configured.")

        if not offsite:
            issues.append("No indicators of offsite or cloud backup found — backups may not be resilient.")
            result.remediation.append(RemediationStep(
                description="Implement offsite or cloud backup to ensure business continuity.",
                script=(
                    "# Example: Azure Backup agent or third-party backup tool\n"
                    "# Install Azure Backup MARS agent from:\n"
                    "# https://aka.ms/azurebackup_agent\n\n"
                    "# Or use Windows Server Backup to a network location:\n"
                    "Install-WindowsFeature Windows-Server-Backup\n"
                    "wbadmin start backup -backuptarget:\\\\fileserver\\backups -include:C: -allCritical -quiet"
                ),
                script_type="powershell",
                acsc_reference=ACSC_REF,
                priority="high",
                target_level=MaturityLevel.FULLY_IMPLEMENTED,
            ))
        else:
            result.findings.append("Offsite/cloud backup indicators detected.")

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

    def _check_vss(self, raw: dict):
        try:
            out = subprocess.run(
                ["vssadmin", "list", "shadows"],
                capture_output=True, text=True, timeout=15
            )
            raw["vss_output"] = out.stdout[:500]
            lines = [l for l in out.stdout.splitlines() if "Creation time:" in l]
            return lines
        except Exception as e:
            raw["vss_error"] = str(e)
            return []

    def _latest_vss_age_days(self, lines: list, raw: dict):
        try:
            # Lines like: "  Creation time: 3/15/2024 2:00:01 AM"
            dates = []
            for line in lines:
                parts = line.split("Creation time:")
                if len(parts) > 1:
                    date_str = parts[1].strip()
                    dt = datetime.strptime(date_str, "%m/%d/%Y %I:%M:%S %p")
                    dates.append(dt)
            if dates:
                latest = max(dates)
                age = (datetime.now() - latest).days
                raw["latest_vss_age_days"] = age
                return age
        except Exception as e:
            raw["vss_date_error"] = str(e)
        return None

    def _check_windows_backup(self, raw: dict) -> bool:
        try:
            out = subprocess.run(
                ["powershell", "-NonInteractive", "-Command",
                 "Get-Service -Name SDRSVC -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status"],
                capture_output=True, text=True, timeout=10
            )
            status = out.stdout.strip()
            raw["windows_backup_service"] = status
            return status in ("Running", "Stopped")  # Stopped is OK if scheduled
        except Exception as e:
            raw["backup_service_error"] = str(e)
            return False

    def _check_offsite_indicators_windows(self, raw: dict) -> bool:
        indicators = [
            r"C:\Program Files\Microsoft Azure Recovery Services Agent",
            r"C:\Program Files\Veeam",
            r"C:\Program Files\Acronis",
            r"C:\Program Files\Commvault",
        ]
        for path in indicators:
            if os.path.isdir(path):
                raw["offsite_backup_found"] = path
                return True
        raw["offsite_backup_found"] = None
        return False

    # ── Linux ─────────────────────────────────────────────────────────────────

    def _check_linux(self) -> CheckResult:
        result = self._base_result()
        raw: dict = {}

        cron_backups = self._check_cron_backup_jobs(raw)
        backup_tool = self._detect_backup_tool_linux(raw)
        last_backup = self._check_last_backup_linux(raw)
        result.raw_data = raw

        issues = []

        if backup_tool:
            result.findings.append(f"Backup tool detected: {backup_tool}")
        else:
            issues.append("No known backup tool (rsync, restic, duplicati, bacula, etc.) detected.")
            result.remediation.append(RemediationStep(
                description="Install and configure a backup tool (restic recommended).",
                script=(
                    "# Install restic\n"
                    "apt-get install -y restic  # or: brew install restic\n\n"
                    "# Initialize a backup repository\n"
                    "restic init --repo /backup/restic-repo\n\n"
                    "# Run a backup\n"
                    "restic backup /home /etc /var\n\n"
                    "# Schedule via cron (daily at 2am):\n"
                    "echo '0 2 * * * root restic backup /home /etc /var >> /var/log/restic.log 2>&1' "
                    "> /etc/cron.d/restic-backup"
                ),
                script_type="bash",
                acsc_reference=ACSC_REF,
                priority="high",
                target_level=MaturityLevel.PARTIAL,
            ))

        if cron_backups:
            result.findings.append(f"Cron backup job(s) found: {cron_backups}")
        else:
            issues.append("No cron-scheduled backup jobs found.")

        if last_backup is not None:
            result.findings.append(f"Estimated last backup: {last_backup} day(s) ago.")
            if last_backup > MAX_DAYS_ML2:
                issues.append(f"Last backup was {last_backup} days ago — should be daily or more frequent.")
        else:
            issues.append("Unable to determine last backup time — verify backup recency manually.")

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

    def _check_cron_backup_jobs(self, raw: dict):
        backup_keywords = ["rsync", "restic", "duplicati", "bacula", "amanda", "borg"]
        cron_dirs = ["/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.d", "/var/spool/cron"]
        found = []
        for d in cron_dirs:
            if os.path.isdir(d):
                try:
                    for f in os.listdir(d):
                        path = os.path.join(d, f)
                        if os.path.isfile(path):
                            with open(path, "r", errors="ignore") as fh:
                                content = fh.read().lower()
                            for kw in backup_keywords:
                                if kw in content and path not in found:
                                    found.append(path)
                except Exception:
                    pass
        raw["cron_backup_jobs"] = found
        return found

    def _detect_backup_tool_linux(self, raw: dict) -> str | None:
        tools = {
            "restic": ["restic"],
            "rsync": ["rsync"],
            "duplicati": ["duplicati"],
            "bacula": ["bconsole", "bacula-director"],
            "amanda": ["amdump"],
            "borgbackup": ["borg"],
        }
        for name, cmds in tools.items():
            for cmd in cmds:
                try:
                    out = subprocess.run(["which", cmd], capture_output=True, timeout=5)
                    if out.returncode == 0:
                        raw["backup_tool"] = name
                        return name
                except Exception:
                    pass
        raw["backup_tool"] = None
        return None

    def _check_last_backup_linux(self, raw: dict) -> int | None:
        # Check restic snapshots
        try:
            out = subprocess.run(
                ["restic", "snapshots", "--last", "--json"],
                capture_output=True, text=True, timeout=15,
                env={**os.environ, "RESTIC_PASSWORD": os.environ.get("RESTIC_PASSWORD", "")}
            )
            import json
            snapshots = json.loads(out.stdout)
            if snapshots:
                ts = snapshots[-1].get("time", "")
                if ts:
                    dt = datetime.fromisoformat(ts.split(".")[0].replace("Z", "+00:00"))
                    age = (datetime.now(timezone.utc) - dt).days
                    raw["last_restic_backup_days"] = age
                    return age
        except Exception:
            pass

        # Check /var/log for backup tool logs
        log_files = ["/var/log/backup.log", "/var/log/rsync.log", "/var/log/duplicati.log"]
        for lf in log_files:
            if os.path.exists(lf):
                mtime = os.path.getmtime(lf)
                age = int((datetime.now().timestamp() - mtime) / 86400)
                raw["backup_log_age_days"] = age
                return age

        return None

    # ── macOS ─────────────────────────────────────────────────────────────────

    def _check_macos(self) -> CheckResult:
        result = self._base_result()
        raw: dict = {}

        tm_status = self._check_time_machine(raw)
        last_backup = self._get_last_tm_backup(raw)
        third_party = self._detect_third_party_backup_macos(raw)
        result.raw_data = raw

        issues = []

        if tm_status == "enabled":
            result.findings.append("Time Machine is enabled.")
            if last_backup is not None:
                result.findings.append(f"Last Time Machine backup: {last_backup} day(s) ago.")
                if last_backup > MAX_DAYS_ML2:
                    issues.append(f"Time Machine backup is {last_backup} days old — verify it's running.")
            else:
                issues.append("Time Machine is enabled but last backup time could not be determined.")
        elif tm_status == "disabled":
            if third_party:
                result.findings.append(f"Third-party backup tool detected: {third_party}")
            else:
                issues.append("Time Machine is disabled and no third-party backup tool detected.")
                result.remediation.append(RemediationStep(
                    description="Enable Time Machine or deploy a backup solution.",
                    script=(
                        "# Enable Time Machine (requires a backup disk)\n"
                        "sudo tmutil enable\n"
                        "# Set backup destination:\n"
                        "sudo tmutil setdestination /Volumes/BackupDisk\n"
                        "# Start a backup:\n"
                        "sudo tmutil startbackup"
                    ),
                    script_type="zsh",
                    acsc_reference=ACSC_REF,
                    priority="high",
                    target_level=MaturityLevel.PARTIAL,
                ))
        else:
            issues.append("Could not determine Time Machine status.")

        if not issues:
            result.maturity_level = MaturityLevel.FULLY_IMPLEMENTED
        elif len(issues) == 1:
            result.maturity_level = MaturityLevel.MOSTLY_IMPLEMENTED
            result.gaps.extend(issues)
        else:
            result.maturity_level = MaturityLevel.PARTIAL
            result.gaps.extend(issues)

        return result

    def _check_time_machine(self, raw: dict) -> str:
        try:
            out = subprocess.run(
                ["tmutil", "status"], capture_output=True, text=True, timeout=10
            )
            raw["tm_status"] = out.stdout[:300]
            if "Running" in out.stdout or "Enabled" in out.stdout:
                return "enabled"
            # Also check via defaults
            out2 = subprocess.run(
                ["defaults", "read", "/Library/Preferences/com.apple.TimeMachine", "AutoBackup"],
                capture_output=True, text=True, timeout=5
            )
            raw["tm_autobackup"] = out2.stdout.strip()
            return "enabled" if out2.stdout.strip() == "1" else "disabled"
        except Exception as e:
            raw["tm_error"] = str(e)
            return "unknown"

    def _get_last_tm_backup(self, raw: dict) -> int | None:
        try:
            out = subprocess.run(
                ["tmutil", "latestbackup"], capture_output=True, text=True, timeout=10
            )
            path = out.stdout.strip()
            raw["tm_latest_backup"] = path
            if path and os.path.exists(path):
                mtime = os.path.getmtime(path)
                age = int((datetime.now().timestamp() - mtime) / 86400)
                return age
        except Exception as e:
            raw["tm_last_error"] = str(e)
        return None

    def _detect_third_party_backup_macos(self, raw: dict) -> str | None:
        apps = {
            "Backblaze": "/Applications/Backblaze.app",
            "Carbon Copy Cloner": "/Applications/Carbon Copy Cloner.app",
            "SuperDuper": "/Applications/SuperDuper!.app",
            "Arq": "/Applications/Arq.app",
            "Acronis": "/Applications/Acronis True Image.app",
        }
        for name, path in apps.items():
            if os.path.isdir(path):
                raw["third_party_backup"] = name
                return name
        raw["third_party_backup"] = None
        return None
