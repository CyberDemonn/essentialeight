#!/usr/bin/env bash
# verify_e8.sh — Ground-truth verification for the E8 agent on Ubuntu/Linux
#
# Runs the agent to generate a baseline report, then independently re-runs
# the same commands the agent uses and prints a side-by-side comparison.
#
# Usage:
#   sudo bash verify_e8.sh            # run agent + verify
#   sudo bash verify_e8.sh --fresh    # force re-run of agent even if report exists
#   sudo bash verify_e8.sh --no-run   # skip agent run, use existing /tmp/e8_report_verify.json

set -uo pipefail

REPORT=/tmp/e8_report_verify.json
PASS=0
FAIL=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

die()    { echo -e "${RED}[ERROR]${NC} $1" >&2; exit 1; }
info()   { echo -e "  ${YELLOW}→${NC} $1"; }
header() { echo -e "\n${BOLD}── $1 ──${NC}"; }

[ "$(id -u)" -eq 0 ] || die "Re-run with sudo: sudo bash verify_e8.sh"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Step 1: Generate agent report ────────────────────────────────────────────

ARG="${1:-}"
if [ "$ARG" != "--no-run" ] && { [ ! -f "$REPORT" ] || [ "$ARG" = "--fresh" ]; }; then
    echo -e "${BOLD}[+] Running E8 agent → $REPORT${NC}"
    python3 -m agent.e8_agent --output "$REPORT" --no-elevation-warning 2>/dev/null || true
    echo ""
else
    echo -e "${BOLD}[+] Using existing report: $REPORT${NC} (pass --fresh to regenerate)"
    echo ""
fi

[ -f "$REPORT" ] || die "Report not found at $REPORT. Run the agent first."

# ── Helpers ───────────────────────────────────────────────────────────────────

agent_ml() {
    python3 - <<PYEOF
import json, sys
with open('$REPORT') as f:
    d = json.load(f)
for ctrl in d['controls']:
    if ctrl['control_id'] == '$1':
        print(ctrl['maturity_level'])
        sys.exit(0)
print(-1)
PYEOF
}

agent_detail() {
    python3 - <<PYEOF
import json
with open('$REPORT') as f:
    d = json.load(f)
for ctrl in d['controls']:
    if ctrl['control_id'] == '$1':
        for s in ctrl.get('findings', []):
            print(f'    + {s}')
        for s in ctrl.get('gaps', []):
            print(f'    ! {s}')
        break
PYEOF
}

compare() {
    local ctrl="$1" name="$2" expected="$3"
    local reported
    reported=$(agent_ml "$ctrl")
    printf "  Agent ML%-1s | Ground Truth ML%-1s  " "$reported" "$expected"
    if [ "$reported" = "$expected" ]; then
        echo -e "${GREEN}[MATCH]${NC}"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}[MISMATCH]${NC}"
        FAIL=$((FAIL + 1))
    fi
    agent_detail "$ctrl"
}

# ── Cache apt simulate output (used by E8-2 and E8-6) ────────────────────────

echo "[+] Running apt-get update (needed for patch checks, may take a moment)..."
apt-get update -qq 2>/dev/null || true
APT_SIMULATE=$(apt-get --simulate upgrade 2>/dev/null || true)

echo ""
echo "=========================================================="
echo "  E8 Agent Verification — Ubuntu/Linux"
echo "=========================================================="

# ── E8-1: Application Control ─────────────────────────────────────────────────

header "E8-1: Application Control"
e1_ml=0
if aa-status --json &>/dev/null 2>&1; then
    e1_ml=3
    info "AppArmor: enforcing (aa-status --json exited 0)"
else
    AA_TEXT=$(apparmor_status 2>/dev/null || true)
    if echo "$AA_TEXT" | grep -qi "enforce"; then
        e1_ml=3
        info "AppArmor: enforcing (apparmor_status)"
    elif echo "$AA_TEXT" | grep -qi "complain"; then
        e1_ml=1
        info "AppArmor: complaining mode (not enforcing)"
    else
        SEL=$(getenforce 2>/dev/null || echo "Disabled")
        info "AppArmor: not active | SELinux: $SEL"
        if [ "$SEL" = "Enforcing" ]; then
            e1_ml=3
        elif [ "$SEL" = "Permissive" ]; then
            e1_ml=1
        fi
    fi
fi
compare "E8-1" "Application Control" "$e1_ml"

# ── E8-2: Patch Applications ──────────────────────────────────────────────────

header "E8-2: Patch Applications"
PENDING_APPS=$(echo "$APT_SIMULATE" | grep -c "^Inst " 2>/dev/null || echo -1)
AUTO_UP=$(systemctl is-active unattended-upgrades 2>/dev/null || echo "inactive")
info "Pending app packages (apt): $PENDING_APPS"
info "unattended-upgrades service: $AUTO_UP"
if [ "$PENDING_APPS" -eq 0 ] 2>/dev/null && [ "$AUTO_UP" = "active" ]; then
    e2_ml=3
elif [ "$PENDING_APPS" -eq 0 ] 2>/dev/null; then
    e2_ml=2
elif [ "$PENDING_APPS" -le 10 ] 2>/dev/null; then
    e2_ml=1
else
    e2_ml=0
fi
compare "E8-2" "Patch Applications" "$e2_ml"

# ── E8-3: Office Macro Settings ───────────────────────────────────────────────

header "E8-3: Office Macro Settings (LibreOffice)"
if ! which libreoffice &>/dev/null 2>&1; then
    e3_ml=3
    info "LibreOffice: not installed (no macro risk → ML3)"
else
    LO_CONFIG="$HOME/.config/libreoffice/4/user/registrymodifications.xcu"
    if [ -f "$LO_CONFIG" ] && grep -q "MacroSecurityLevel" "$LO_CONFIG" 2>/dev/null; then
        LO_LEVEL=$(python3 -c "
with open('$LO_CONFIG', 'r', errors='ignore') as f:
    lines = f.readlines()
for line in lines:
    if 'MacroSecurityLevel' in line and 'value=' in line:
        print(line.split('value=\"')[1].split('\"')[0])
        break
else:
    print(-1)
" 2>/dev/null || echo "-1")
        info "LibreOffice MacroSecurityLevel: $LO_LEVEL"
        case "$LO_LEVEL" in
            3) e3_ml=3 ;;
            2) e3_ml=2 ;;
            1) e3_ml=1 ;;
            *) e3_ml=0 ;;
        esac
    else
        info "LibreOffice: installed but config not found / MacroSecurityLevel not set"
        e3_ml=0
    fi
fi
compare "E8-3" "Office Macro Settings" "$e3_ml"

# ── E8-4: User Application Hardening ─────────────────────────────────────────

header "E8-4: User Application Hardening"
score4=0
max_score4=3

if ! which java &>/dev/null 2>&1; then
    score4=$((score4 + 1)); info "Java: not installed (+1)"
else
    info "Java: installed (0)"
fi

FLASH_PATHS=("/usr/lib/flashplugin-installer/libflashplayer.so"
             "/usr/lib/pepperflashplugin-nonfree/libpepflashplayer.so")
FLASH_FOUND=0
for fp in "${FLASH_PATHS[@]}"; do
    [ -f "$fp" ] && FLASH_FOUND=1 && break
done
if [ "$FLASH_FOUND" -eq 0 ]; then
    score4=$((score4 + 1)); info "Flash: not detected (+1)"
else
    info "Flash: detected (0)"
fi

POLICY_DIRS=("/etc/opt/chrome/policies/managed"
             "/etc/chromium/policies/managed"
             "/usr/lib/firefox/distribution")
POLICY_FOUND=0
for pd in "${POLICY_DIRS[@]}"; do
    [ -d "$pd" ] && POLICY_FOUND=1 && info "Browser policy dir: $pd (+1)" && break
done
[ "$POLICY_FOUND" -eq 0 ] && info "Browser policies: none found (0)"
score4=$((score4 + POLICY_FOUND))

info "Score: $score4/$max_score4"
# score/3 → ratio: 3=1.0→ML3, 2=0.667→ML1, 1=0.333→ML0
if [ "$score4" -eq 3 ]; then
    e4_ml=3
elif [ "$score4" -eq 2 ]; then
    e4_ml=1  # ratio 0.667 >= 0.5 but < 0.75 → PARTIAL
else
    e4_ml=0  # ratio < 0.5
fi
compare "E8-4" "User App Hardening" "$e4_ml"

# ── E8-5: Restrict Administrative Privileges ─────────────────────────────────

header "E8-5: Restrict Administrative Privileges"
issues5=0

# Sudoers lines
SUDO_USERS_RAW=$(grep -r "ALL=(ALL" /etc/sudoers /etc/sudoers.d/ 2>/dev/null \
    | grep -v "^[[:space:]]*#" | grep -v "^.*:.*#" | awk '{print $1}' | sort -u || true)
# Group members
GROUP_MEMBERS=$(for grp in sudo wheel admin; do
    getent group "$grp" 2>/dev/null | cut -d: -f4 | tr ',' '\n'
done | grep -v "^$" | sort -u || true)
ALL_SUDO=$(printf '%s\n%s\n' "$SUDO_USERS_RAW" "$GROUP_MEMBERS" | sort -u | grep -v "^$" | wc -l)
info "Unique sudo users/entries: $ALL_SUDO"
[ "$ALL_SUDO" -gt 3 ] && { issues5=$((issues5 + 1)); info "  → excessive sudo users (issue)"; }

# Root SSH login
if grep -qi "permitrootlogin yes" /etc/ssh/sshd_config 2>/dev/null; then
    issues5=$((issues5 + 1))
    info "PermitRootLogin: YES (issue)"
else
    info "PermitRootLogin: disabled or not 'yes'"
fi

# NOPASSWD
if grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null \
        | grep -qv "^[[:space:]]*#"; then
    issues5=$((issues5 + 1))
    info "NOPASSWD sudo rules: found (issue)"
else
    info "NOPASSWD sudo rules: none"
fi

info "Issues: $issues5"
if   [ "$issues5" -eq 0 ]; then e5_ml=3
elif [ "$issues5" -eq 1 ]; then e5_ml=2
else                             e5_ml=1
fi
compare "E8-5" "Restrict Admin Privileges" "$e5_ml"

# ── E8-6: Patch Operating Systems ────────────────────────────────────────────

header "E8-6: Patch Operating Systems"
KERNEL=$(uname -r)
info "Kernel: $KERNEL"

SEC_PENDING=$(echo "$APT_SIMULATE" | grep "^Inst" | grep -ci "security" 2>/dev/null || echo 0)
info "Pending security updates (apt): $SEC_PENDING"

AUTO_UP6=$(systemctl is-active unattended-upgrades 2>/dev/null || echo "inactive")
if [ "$AUTO_UP6" != "active" ]; then
    AUTO_UP6=$(systemctl is-active dnf-automatic.timer 2>/dev/null || echo "inactive")
fi
info "Auto-update service: $AUTO_UP6"

issues6=0
[ "$SEC_PENDING" -gt 0 ] 2>/dev/null && issues6=$((issues6 + 1))
[ "$AUTO_UP6" != "active" ]           && issues6=$((issues6 + 1))
info "Issues: $issues6"

if   [ "$issues6" -eq 0 ]; then e6_ml=3
elif [ "$issues6" -eq 1 ]; then e6_ml=2
else                             e6_ml=1
fi
compare "E8-6" "Patch Operating Systems" "$e6_ml"

# ── E8-7: Multi-Factor Authentication ────────────────────────────────────────

header "E8-7: Multi-Factor Authentication"
issues7=0

SSHD=$(systemctl is-active sshd 2>/dev/null || echo "inactive")
info "sshd service: $SSHD"

if [ "$SSHD" = "active" ]; then
    if grep -qi "passwordauthentication no" /etc/ssh/sshd_config 2>/dev/null; then
        info "PasswordAuthentication: disabled (key-only)"
    else
        issues7=$((issues7 + 1))
        info "PasswordAuthentication: NOT explicitly disabled (issue)"
    fi
fi

PAM_MFA=0
for PAM_FILE in /etc/pam.d/sshd /etc/pam.d/login /etc/pam.d/common-auth; do
    if [ -f "$PAM_FILE" ] && \
       grep -qi "pam_google_authenticator\|pam_u2f\|pam_fido2\|pam_oath" "$PAM_FILE" 2>/dev/null; then
        PAM_MFA=1
        info "PAM MFA module found in $PAM_FILE"
        break
    fi
done
if [ "$PAM_MFA" -eq 0 ]; then
    issues7=$((issues7 + 1))
    info "PAM MFA (TOTP/FIDO2): not configured (issue)"
fi

info "Issues: $issues7"
if   [ "$issues7" -eq 0 ]; then e7_ml=3
elif [ "$issues7" -eq 1 ]; then e7_ml=2
else                             e7_ml=1
fi
compare "E8-7" "Multi-Factor Authentication" "$e7_ml"

# ── E8-8: Regular Backups ─────────────────────────────────────────────────────

header "E8-8: Regular Backups"
issues8=0

# Detect backup tool
BACKUP_TOOL=""
for cmd in restic rsync duplicati bconsole amdump borg; do
    if which "$cmd" &>/dev/null 2>&1; then
        BACKUP_TOOL="$cmd"
        info "Backup tool: $cmd"
        break
    fi
done
if [ -z "$BACKUP_TOOL" ]; then
    issues8=$((issues8 + 1))
    info "Backup tool: none detected (issue)"
fi

# Cron backup jobs
CRON_FOUND=0
for CRON_DIR in /etc/cron.daily /etc/cron.weekly /etc/cron.d /var/spool/cron; do
    if [ -d "$CRON_DIR" ]; then
        if grep -rl "rsync\|restic\|duplicati\|backup\|bacula\|amanda\|tar" \
                "$CRON_DIR" 2>/dev/null | grep -q .; then
            CRON_FOUND=1
            info "Cron backup job found in $CRON_DIR"
            break
        fi
    fi
done
if [ "$CRON_FOUND" -eq 0 ]; then
    issues8=$((issues8 + 1))
    info "Cron backup jobs: none found (issue)"
fi

# Last backup age
LAST_DAYS=-1
if [ "$BACKUP_TOOL" = "restic" ]; then
    LAST_DAYS=$(restic snapshots --last --json 2>/dev/null | python3 -c "
import json, sys
from datetime import datetime, timezone
try:
    data = json.load(sys.stdin)
    if data:
        ts = data[-1].get('time','')
        if ts:
            dt = datetime.fromisoformat(ts.split('.')[0].replace('Z','+00:00'))
            print((datetime.now(timezone.utc)-dt).days)
            sys.exit(0)
except Exception:
    pass
print(-1)
" 2>/dev/null || echo -1)
fi
if [ "$LAST_DAYS" = "-1" ]; then
    for LOG in /var/log/backup.log /var/log/rsync.log /var/log/duplicati.log; do
        if [ -f "$LOG" ]; then
            LAST_DAYS=$(python3 -c "
import os, time
print(int((time.time()-os.path.getmtime('$LOG'))/86400))
" 2>/dev/null || echo -1)
            info "Backup log ($LOG): ${LAST_DAYS}d old"
            break
        fi
    done
fi

if [ "$LAST_DAYS" = "-1" ]; then
    issues8=$((issues8 + 1))
    info "Last backup: could not determine (issue)"
elif [ "$LAST_DAYS" -gt 7 ] 2>/dev/null; then
    issues8=$((issues8 + 1))
    info "Last backup: ${LAST_DAYS} days ago — older than 7 days (issue)"
else
    info "Last backup: ${LAST_DAYS} days ago"
fi

info "Issues: $issues8"
if   [ "$issues8" -eq 0 ]; then e8_ml=3
elif [ "$issues8" -eq 1 ]; then e8_ml=2
elif [ "$issues8" -eq 2 ]; then e8_ml=1
else                             e8_ml=0
fi
compare "E8-8" "Regular Backups" "$e8_ml"

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "=========================================================="
printf "  Results: "
echo -e "${GREEN}${PASS} MATCH${NC}  |  ${RED}${FAIL} MISMATCH${NC}"
echo "=========================================================="

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "  Mismatches: check agent/checks/<control>.py for the exact condition"
    echo "  causing the discrepancy. The raw_data field in the JSON report"
    echo "  shows what the agent actually captured: python3 -c \""
    echo "    import json; d=json.load(open('$REPORT'))"
    echo "    [print(c['control_id'], c['raw_data']) for c in d['controls']]\""
    exit 1
fi
echo ""
echo "  All checks match. The agent is reporting accurately."
