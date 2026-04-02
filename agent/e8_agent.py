#!/usr/bin/env python3
"""
Essential Eight Compliance Agent
Usage:
  python e8_agent.py [--server URL] [--api-key KEY] [--output FILE] [--target-level 1-3]

Modes:
  Push mode     : --server https://my-e8-server
  Standalone    : --output report.json
  Print to stdout (default, no args)
"""
from __future__ import annotations

import argparse
import ctypes
import os
import platform
import sys

# Allow running from project root without installing as a package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.core.config import AgentConfig
from agent.core.reporter import deliver
from agent.checks.application_control import ApplicationControlCheck
from agent.checks.patch_applications import PatchApplicationsCheck
from agent.checks.office_macros import OfficeMacrosCheck
from agent.checks.user_app_hardening import UserAppHardeningCheck
from agent.checks.restrict_admin import RestrictAdminCheck
from agent.checks.patch_os import PatchOSCheck
from agent.checks.mfa import MFACheck
from agent.checks.backups import BackupsCheck


ALL_CHECKS = [
    ApplicationControlCheck,
    PatchApplicationsCheck,
    OfficeMacrosCheck,
    UserAppHardeningCheck,
    RestrictAdminCheck,
    PatchOSCheck,
    MFACheck,
    BackupsCheck,
]


def is_elevated() -> bool:
    """Return True if running as Administrator (Windows) or root (Unix)."""
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Essential Eight Compliance Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Print JSON to stdout (quick audit)
  python e8_agent.py

  # Save JSON + HTML report to disk
  python e8_agent.py --output /tmp/e8_report.json

  # Push to central dashboard
  python e8_agent.py --server https://e8.myorg.internal --api-key sk-...

  # Assess against ML2 only
  python e8_agent.py --target-level 2 --output report.json
""",
    )
    parser.add_argument("--server", metavar="URL", help="Backend API URL to push results to")
    parser.add_argument("--api-key", metavar="KEY", help="API key for backend authentication")
    parser.add_argument("--output", metavar="FILE", help="Save report to this JSON file (also creates .html)")
    parser.add_argument("--target-level", metavar="N", type=int, choices=[1, 2, 3], default=3,
                        help="Target maturity level to assess against (default: 3)")
    parser.add_argument("--machine-label", metavar="LABEL", help="Override machine display name")
    parser.add_argument("--no-elevation-warning", action="store_true",
                        help="Suppress the elevation warning")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    # Elevation check
    if not is_elevated() and not args.no_elevation_warning:
        print(
            "[WARNING] Agent is not running with elevated privileges (Administrator/root).\n"
            "          Some checks will be incomplete or inaccurate.\n"
            "          Re-run as Administrator (Windows) or with sudo (Linux/macOS).\n",
            file=sys.stderr
        )

    config = AgentConfig(
        server_url=args.server,
        api_key=args.api_key,
        output_path=args.output,
        target_level=args.target_level,
        machine_label=args.machine_label,
    )

    print(f"[E8 Agent] Assessing {config.machine_label} ({config.os_name} {config.os_release})")
    print(f"[E8 Agent] Target maturity level: ML{config.target_level}")
    print(f"[E8 Agent] Running {len(ALL_CHECKS)} checks...\n")

    results = []
    for CheckClass in ALL_CHECKS:
        check = CheckClass()
        print(f"  [{check.control_id}] {check.control_name} ... ", end="", flush=True)
        try:
            result = check.run()
            results.append(result)
            ml = int(result.maturity_level)
            indicator = ["✗", "!", "~", "✓"][ml]
            print(f"ML{ml} {indicator}")
        except Exception as exc:
            print(f"ERROR: {exc}")
            # Still add a placeholder result so report is complete
            from agent.checks.base import CheckResult, MaturityLevel
            r = CheckResult(
                control_id=check.control_id,
                control_name=check.control_name,
                platform=platform.system(),
                maturity_level=MaturityLevel.NOT_IMPLEMENTED,
                error=str(exc),
            )
            results.append(r)

    from agent.core.scorer import overall_maturity
    overall = overall_maturity(results)
    print(f"\n[E8 Agent] Overall maturity: ML{int(overall)} — {overall.label()}")

    deliver(config, results)
    return 0


if __name__ == "__main__":
    sys.exit(main())
