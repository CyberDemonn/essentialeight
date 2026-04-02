"""
Formats assessment results and delivers them:
  - PUSH mode: POST JSON to the backend API
  - STANDALONE mode: Write JSON (and optionally HTML) to disk
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import List

from agent.checks.base import CheckResult
from agent.core.config import AgentConfig
from agent.core.scorer import overall_maturity, score_summary


def build_payload(config: AgentConfig, results: List[CheckResult]) -> dict:
    return {
        "schema_version": "1.0",
        "assessed_at": datetime.now(timezone.utc).isoformat(),
        "machine": config.machine_info(),
        "target_level": config.target_level,
        "summary": score_summary(results),
        "controls": [r.to_dict() for r in results],
    }


def push_to_server(config: AgentConfig, payload: dict) -> bool:
    try:
        import requests  # type: ignore
    except ImportError:
        print("[ERROR] 'requests' library not installed. Run: pip install requests", file=sys.stderr)
        return False

    headers = {"Content-Type": "application/json"}
    if config.api_key:
        headers["Authorization"] = f"Bearer {config.api_key}"

    url = config.server_url.rstrip("/") + "/api/assessments/ingest"
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=30)
        resp.raise_for_status()
        print(f"[OK] Assessment pushed to {url} (status {resp.status_code})")
        return True
    except Exception as exc:
        print(f"[ERROR] Failed to push assessment: {exc}", file=sys.stderr)
        return False


def save_to_file(config: AgentConfig, payload: dict) -> bool:
    path = config.output_path
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        print(f"[OK] Assessment saved to {path}")

        # Also write a simple HTML report alongside the JSON
        html_path = os.path.splitext(path)[0] + ".html"
        _write_html_report(html_path, payload)
        print(f"[OK] HTML report saved to {html_path}")
        return True
    except Exception as exc:
        print(f"[ERROR] Failed to save assessment: {exc}", file=sys.stderr)
        return False


def _write_html_report(path: str, payload: dict) -> None:
    summary = payload["summary"]
    machine = payload["machine"]
    controls = payload["controls"]
    assessed_at = payload["assessed_at"]

    ml_colors = {0: "#dc2626", 1: "#f97316", 2: "#eab308", 3: "#16a34a"}
    overall = summary["overall_maturity"]
    color = ml_colors.get(overall, "#6b7280")

    rows = ""
    for ctrl in controls:
        ml = ctrl["maturity_level"]
        c = ml_colors.get(ml, "#6b7280")
        gaps = "<br>".join(ctrl["gaps"]) or "None"
        rows += (
            f"<tr>"
            f"<td><b>{ctrl['control_id']}</b></td>"
            f"<td>{ctrl['control_name']}</td>"
            f"<td style='color:{c};font-weight:bold'>{ctrl['maturity_label']}</td>"
            f"<td>{gaps}</td>"
            f"</tr>"
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Essential Eight Assessment — {machine['machine_label']}</title>
  <style>
    body {{ font-family: sans-serif; margin: 2rem; background: #f9fafb; color: #111; }}
    h1 {{ color: #1e3a5f; }}
    .badge {{ display:inline-block; padding:.4rem 1rem; border-radius:6px;
              background:{color}; color:#fff; font-size:1.2rem; font-weight:bold; }}
    table {{ border-collapse:collapse; width:100%; margin-top:1.5rem; background:#fff; }}
    th, td {{ border:1px solid #e5e7eb; padding:.6rem 1rem; text-align:left; }}
    th {{ background:#1e3a5f; color:#fff; }}
    tr:nth-child(even) {{ background:#f3f4f6; }}
    .meta {{ color:#6b7280; font-size:.9rem; margin-bottom:1rem; }}
  </style>
</head>
<body>
  <h1>Essential Eight Compliance Assessment</h1>
  <div class="meta">
    Machine: <b>{machine['machine_label']}</b> ({machine['fqdn']}) &nbsp;|&nbsp;
    OS: {machine['os_name']} {machine['os_release']} &nbsp;|&nbsp;
    Assessed: {assessed_at}
  </div>
  <div>Overall Maturity: <span class="badge">{summary['overall_label']}</span></div>
  <table>
    <thead><tr><th>ID</th><th>Control</th><th>Maturity</th><th>Gaps</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)


def deliver(config: AgentConfig, results: List[CheckResult]) -> None:
    payload = build_payload(config, results)

    if config.push_mode():
        push_to_server(config, payload)

    if config.standalone_mode():
        save_to_file(config, payload)

    if not config.push_mode() and not config.standalone_mode():
        # Default: print JSON to stdout
        print(json.dumps(payload, indent=2))
