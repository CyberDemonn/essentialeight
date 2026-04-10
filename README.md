# Essential Eight Compliance Tool

A self-hosted assessment platform for the [ACSC Essential Eight](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight) cybersecurity framework. The tool automatically discovers your environment, assesses all eight controls across maturity levels 0–3, and provides prioritised remediation guidance with ready-to-run scripts.

---

## Overview

The Essential Eight is the Australian Cyber Security Centre's baseline set of mitigation strategies. This tool automates the full compliance lifecycle:

1. **Discover** — the agent detects the OS and collects system state (read-only, elevated)
2. **Assess** — all 8 controls are evaluated against maturity levels 0–3 per ACSC methodology
3. **Report** — findings, gaps, and remediation scripts are surfaced in a web dashboard or as a local HTML/JSON report

**Supported platforms:** Windows, Linux, macOS

---

## Architecture

```
┌──────────────────────────────────────────┐
│         React Web Dashboard              │
│  Compliance scores, maturity radar,      │
│  historical trends, remediation scripts  │
└────────────────┬─────────────────────────┘
                 │ REST API (JWT auth)
┌────────────────▼─────────────────────────┐
│         FastAPI Backend                  │
│  Assessment ingestion, SQLite storage,   │
│  machine registry, report generation     │
└──────────────────────────────────────────┘

┌──────────────────────────────────────────┐
│         Agent (e8_agent.py)              │
│  Runs elevated on each target machine    │
│  PUSH → POST JSON to API                 │
│  STANDALONE → saves JSON + HTML locally  │
└──────────────────────────────────────────┘
```

---

## Project Structure

```
e8-tool/
├── agent/
│   ├── e8_agent.py              # Agent CLI entry point
│   ├── core/
│   │   ├── config.py            # Runtime configuration and OS detection
│   │   ├── scorer.py            # Maturity level scoring logic
│   │   └── reporter.py          # Report formatting and delivery (push/standalone)
│   └── checks/
│       ├── base.py              # BaseCheck abstract class and data types
│       ├── application_control.py
│       ├── patch_applications.py
│       ├── office_macros.py
│       ├── user_app_hardening.py
│       ├── restrict_admin.py
│       ├── patch_os.py
│       ├── mfa.py
│       └── backups.py
├── backend/
│   ├── main.py                  # FastAPI application, auth routes, startup
│   ├── auth.py                  # JWT tokens, password hashing
│   ├── database.py              # SQLite setup via SQLAlchemy
│   ├── models.py                # ORM models: User, Machine, Assessment, ControlResult
│   └── routers/
│       ├── assessments.py       # Ingest, upload, list, history endpoints
│       ├── machines.py          # Machine registry endpoints
│       └── reports.py           # JSON/HTML report endpoints, dashboard summary
├── frontend/
│   ├── src/
│   │   ├── App.tsx              # Router and auth guard
│   │   ├── api.ts               # Axios API client with JWT handling
│   │   ├── pages/
│   │   │   ├── Login.tsx        # Login page
│   │   │   ├── Dashboard.tsx    # Overview: radar chart, stat cards, recent assessments
│   │   │   ├── Machines.tsx     # Fleet table with latest maturity per machine
│   │   │   ├── AssessmentDetail.tsx  # Per-control findings, gaps, trend chart
│   │   │   └── Remediation.tsx  # Prioritised fix steps with copy-paste scripts
│   │   └── components/
│   │       ├── Layout.tsx       # Sidebar navigation and report upload
│   │       ├── MaturityBadge.tsx # Colour-coded ML0–ML3 badge
│   │       ├── ComplianceRadar.tsx # Recharts radar of per-control maturity
│   │       └── TrendChart.tsx   # Historical maturity trend line chart
│   └── package.json
└── requirements.txt             # Python backend dependencies
```

---

## The Eight Controls

Each control is assessed independently across all three supported platforms. The **overall maturity** is the minimum across all 8 controls, per ACSC methodology.

| ID | Control | What is checked |
|----|---------|-----------------|
| E8-1 | Application Control | WDAC / AppLocker (Windows), AppArmor / SELinux (Linux), Gatekeeper (macOS) |
| E8-2 | Patch Applications | Pending application updates via WUA / apt / dnf / softwareupdate |
| E8-3 | Configure Microsoft Office Macro Settings | Registry VBAWarnings policy (Windows), LibreOffice macro security level (Linux/macOS) |
| E8-4 | User Application Hardening | Java, Flash, browser enterprise policies, WDAG (Windows), Safari/Chrome settings (macOS) |
| E8-5 | Restrict Administrative Privileges | Local admin group size, LAPS, UAC (Windows); sudo rules, root SSH, NOPASSWD (Linux/macOS) |
| E8-6 | Patch Operating Systems | OS version currency, pending OS updates, automatic update configuration |
| E8-7 | Multi-Factor Authentication | RDP NLA, smart card policy (Windows); SSH key-only auth, PAM MFA (Linux); screensaver lock (macOS) |
| E8-8 | Regular Backups | VSS snapshots (Windows), cron jobs + restic (Linux), Time Machine (macOS) |

### Maturity Levels

| Level | Label | Meaning |
|-------|-------|---------|
| ML0 | Not Implemented | Control is absent |
| ML1 | Partially Implemented | Basic or ad hoc implementation |
| ML2 | Mostly Implemented | Implemented but not consistently enforced |
| ML3 | Fully Implemented | Fully implemented, enforced, and maintained |

---

## Prerequisites

**Backend and agent:**
- Python 3.9+

**Frontend:**
- Node.js 18+ and npm

---

## Docker Installation (Recommended)

The easiest way to run the full stack. Requires [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/).

### 1. Clone the repo

```bash
git clone https://github.com/CyberDemonn/essentialeight.git
cd essentialeight
```

### 2. Configure environment

```bash
cp .env.example .env
```

Edit `.env` and set secure values:

```env
E8_SECRET_KEY=your-long-random-secret-key
E8_ADMIN_PASSWORD=your-secure-password
```

Generate a strong secret key with:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### 3. Build and start

```bash
docker-compose up -d --build
```

This starts two containers:
- **backend** — FastAPI on port 8000 (internal only)
- **frontend** — Nginx serving the React dashboard on port 80

### 4. Open the dashboard

Navigate to **http://localhost** and log in with:
- **Username:** `admin`
- **Password:** the value you set in `.env` (default: `admin`)

### Common Docker commands

```bash
# View logs
docker-compose logs -f backend
docker-compose logs -f frontend

# Stop
docker-compose down

# Rebuild after code changes
docker-compose up -d --build

# Reset everything (WARNING: deletes all assessment data)
docker-compose down -v
```

### Persistent data

Assessment data is stored in a Docker volume (`e8_data`) mapped to `/app/data/e8_tool.db` inside the backend container. It survives container restarts. To back it up:

```bash
docker cp $(docker-compose ps -q backend):/app/data/e8_tool.db ./e8_backup.db
```

---

## Manual Installation

### 1. Clone and set up the backend

```bash
git clone https://github.com/CyberDemonn/essentialeight.git
cd e8-tool
pip3 install -r requirements.txt
```

### 2. Set up the frontend

```bash
cd frontend
npm install
cd ..
```

---

## Running the Application

### Start the backend

```bash
cd e8-tool
uvicorn backend.main:app --reload
# API available at http://localhost:8000
# Swagger docs at http://localhost:8000/docs
```

On first startup, a default admin user is created:
- **Username:** `admin`
- **Password:** `admin`

Change the password immediately via the dashboard or:

```bash
curl -X POST http://localhost:8000/api/auth/change-password \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"current_password": "admin", "new_password": "your-new-password"}'
```

To use a custom secret key and password, set environment variables before starting:

```bash
export E8_SECRET_KEY="a-long-random-secret-key"
export E8_ADMIN_PASSWORD="your-secure-password"
uvicorn backend.main:app --reload
```

### Start the frontend

```bash
cd e8-tool/frontend
npm run dev
# Dashboard at http://localhost:3000
```

---

## Running the Agent

The agent must run with elevated privileges (Administrator on Windows, sudo on Linux/macOS) to access system configuration.

### Standalone mode — saves a local report

```bash
# macOS / Linux
sudo python3 agent/e8_agent.py --output /tmp/e8_report.json

# Windows (run as Administrator)
python agent\e8_agent.py --output C:\Temp\e8_report.json
```

This produces two files:
- `e8_report.json` — machine-readable full assessment
- `e8_report.html` — human-readable report, viewable in any browser

### Push mode — sends results directly to the dashboard

```bash
# Get a token first
# Note: use port 80 (nginx) not 8000 — port 8000 is internal to Docker
TOKEN=$(curl -s -X POST http://localhost/api/auth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Verify the token was captured
echo $TOKEN

# Run the agent
sudo python3 agent/e8_agent.py --server http://localhost --api-key "$TOKEN"
```

### Upload a standalone report to the dashboard

If a machine has no network path to the server, upload the JSON file via the dashboard sidebar ("Upload Report") or via API:

```bash
curl -X POST http://localhost/api/assessments/upload \
  -H "Authorization: Bearer <token>" \
  -F "file=@/tmp/e8_report.json"
```

### Agent options

| Flag | Description | Default |
|------|-------------|---------|
| `--server URL` | Backend API URL to push results to | None (stdout) |
| `--api-key KEY` | JWT token for backend authentication | None |
| `--output FILE` | Save report to this JSON file (also creates `.html`) | None |
| `--target-level N` | Target maturity level to assess against (1, 2, or 3) | 3 |
| `--machine-label LABEL` | Override the machine display name | Hostname |
| `--no-elevation-warning` | Suppress the elevation warning | Off |

---

## API Reference

The backend exposes a REST API documented interactively at `http://localhost:8000/docs`.

### Authentication

```
POST /api/auth/token              — Get a JWT token (form: username, password)
GET  /api/auth/me                 — Get current user info
POST /api/auth/change-password    — Change password
```

### Assessments

```
POST /api/assessments/ingest      — Agent push endpoint (JSON body)
POST /api/assessments/upload      — Upload a standalone JSON report file
GET  /api/assessments/            — List assessments (?machine_id=<uuid>)
GET  /api/assessments/{id}        — Full assessment detail with all controls
GET  /api/assessments/history/{machine_uuid}  — Historical trend for a machine
```

### Machines

```
GET    /api/machines/             — List all machines with latest assessment
GET    /api/machines/{uuid}       — Machine detail with recent assessments
DELETE /api/machines/{uuid}       — Delete machine and all its assessments
```

### Reports

```
GET /api/reports/{id}/json        — Assessment as JSON
GET /api/reports/{id}/html        — Assessment as a standalone HTML report
GET /api/reports/dashboard/summary — Aggregate summary for the dashboard
```

---

## Dashboard Pages

### Login
Username and password login. Token is stored in `localStorage` with a 24-hour expiry.

### Dashboard
- Overall average maturity badge and stat cards (machines assessed, fully compliant, gaps)
- Radar chart showing average per-control maturity across all machines
- Per-control progress bars
- Recent assessments table with links to detail views

### Machines
- Table of all registered machines with OS, last seen date, latest maturity, and gap count
- Delete a machine (removes all its assessments)
- Link to the latest assessment for each machine

### Assessment Detail
- Per-control maturity with expandable findings and gaps
- Historical maturity trend line chart (if multiple assessments exist)
- Links to the HTML report and remediation page

### Remediation
- All remediation steps from the assessment, sorted by priority (high → medium → low)
- Each step shows: priority, description, current ML → target ML, ACSC guidance link
- Copy-paste ready PowerShell / bash / zsh scripts with a one-click copy button

---

## Security Notes

- **The agent is read-only.** It never modifies system state — all commands are queries only.
- **Change the default password** before exposing the backend on a network.
- **Set a strong `E8_SECRET_KEY`** in production. The default is insecure.
- **Bind to localhost only** if the dashboard is not intended to be network-accessible:
  ```bash
  uvicorn backend.main:app --host 127.0.0.1 --port 8000
  ```
- Assessment data is stored in `e8_tool.db` (SQLite). Restrict file permissions as appropriate for your environment.

---

## Extending the Tool

### Adding a new check

1. Create `agent/checks/my_check.py` subclassing `BaseCheck` from `agent/checks/base.py`
2. Implement `control_id`, `control_name`, and `run()` returning a `CheckResult`
3. Add your check class to the `ALL_CHECKS` list in `agent/e8_agent.py`

```python
from agent.checks.base import BaseCheck, CheckResult, MaturityLevel

class MyCheck(BaseCheck):
    control_id = "E8-X"
    control_name = "My Control"

    def run(self) -> CheckResult:
        result = self._base_result()
        # ... perform checks ...
        result.maturity_level = MaturityLevel.FULLY_IMPLEMENTED
        result.findings.append("Control is in place.")
        return result
```

### Adding platform support to an existing check

Each check module has `_check_windows()`, `_check_linux()`, and `_check_macos()` methods. The `run()` method dispatches based on `platform.system()`. Add a new branch there.

---

## Dependencies

### Backend (Python)

| Package | Purpose |
|---------|---------|
| `fastapi` | REST API framework |
| `uvicorn` | ASGI server |
| `sqlalchemy` | ORM and SQLite interface |
| `python-jose[cryptography]` | JWT token generation and validation |
| `passlib[bcrypt]` | Password hashing |
| `python-multipart` | File upload support |
| `requests` | Agent push mode HTTP client |
| `psutil` | Cross-platform process/system info |
| `packaging` | Version comparison utilities |

### Frontend (Node.js)

| Package | Purpose |
|---------|---------|
| `react` + `react-dom` | UI framework |
| `react-router-dom` | Client-side routing |
| `recharts` | Radar chart and trend line chart |
| `axios` | HTTP client with JWT interceptor |
| `lucide-react` | Icon set |
| `tailwindcss` | Utility-first CSS |
| `vite` | Frontend build tool and dev server |
