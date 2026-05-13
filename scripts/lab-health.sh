#!/usr/bin/env bash
# Lab-host orientation report. Reads ghidra-headless-mcp sidecar PID files
# and Ghidra project lockfiles to surface zombies vs live MCPs.
#
# Closes SHAKEDOWN_NOTES.md items #24/#25 (workstation half). Pair with the
# `pid-tagging-and-shutdown.patch` that ghidra-headless-mcp must carry for
# the sidecar files to exist (see Skills/offensive-macos-tooling-ghidra-headless/PATCHES.md).
#
# Reports five sections:
#
#   1. host facts: df on the projects root, vm_stat / swap, hw.memsize/ncpu
#   2. all live ghidra-headless-mcp processes via sidecar JSON: PID, age,
#      Claude Code session id, open project + lockfile per session
#   3. STALE sidecars: PID is dead but sidecar wasn't cleaned up. Caller
#      should `rm` these (passes --remove-stale to do it automatically).
#   4. ORPHAN lockfiles: Ghidra project has a `.lock` but no live sidecar
#      claims it. These are the PASS-001 stop condition.
#   5. java processes (any -- not just MCP): cross-check against #2 to
#      catch orphan PyGhidra JVMs the operator may want to clean up.
#
# Usage (from workstation, runs over SSH on the lab host):
#   scripts/lab-health.sh
#   scripts/lab-health.sh --host NightBlood
#   scripts/lab-health.sh --remove-stale         # rm stale sidecar files
#
# Usage (directly on lab host):
#   MACRE_LAB_LOCAL=1 scripts/lab-health.sh
#
# Exit codes: 0 if no orphan lockfiles or stale sidecars, 1 if any present.

set -euo pipefail

REMOTE_HOST="${MACRE_LAB_HOST:-NightBlood}"
RUN_LOCAL="${MACRE_LAB_LOCAL:-}"
REMOVE_STALE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)          REMOTE_HOST="$2"; shift 2;;
        --remove-stale)  REMOVE_STALE=1; shift;;
        --local)         RUN_LOCAL=1; shift;;
        -h|--help)
            sed -n '2,30p' "$0"
            exit 0;;
        *) echo "unknown flag: $1" >&2; exit 2;;
    esac
done

# The body below runs on the lab host. We pipe it via `ssh <host> bash -s`
# (or run it locally if --local). Anything that needs to be substituted at
# wrapping-time goes through the env vars exported below.
LAB_BODY="$(cat <<'BODY'
set -u

PROJECTS_ROOT="${MACRE_GHIDRA_PROJECTS_ROOT:-$HOME/ghidra-projects}"
SIDECAR_DIR="$HOME/.ghidra-headless-mcp/sessions"
EXIT_NONZERO=0

# --- 1. host facts -----------------------------------------------------
echo "=== host facts ==="
echo "uname:    $(uname -a)"
echo "hostname: $(hostname)"
echo "uptime:   $(uptime)"
if [[ -d "$PROJECTS_ROOT" ]]; then
    df -h "$PROJECTS_ROOT" | awk 'NR==1 || NR==2 { print "  df " $0 }'
else
    echo "  df: $PROJECTS_ROOT does not exist"
fi
sysctl -n hw.memsize hw.ncpu 2>/dev/null | awk 'NR==1 { printf "  hw.memsize: %s bytes (~%d GB)\n", $1, $1/1024/1024/1024 } NR==2 { print "  hw.ncpu:    " $1 }'
sysctl -n vm.swapusage 2>/dev/null | awk '{ print "  swap:      " $0 }' || true
echo

# --- 2. live MCPs from sidecars ---------------------------------------
echo "=== live ghidra-headless-mcp sessions (from sidecar JSON) ==="
LIVE_LOCKFILES=""
if [[ -d "$SIDECAR_DIR" ]]; then
    SIDECAR_COUNT=0
    for sidecar in "$SIDECAR_DIR"/*.json; do
        [[ -e "$sidecar" ]] || break
        SIDECAR_COUNT=$((SIDECAR_COUNT + 1))
        pid="$(basename "$sidecar" .json)"
        if kill -0 "$pid" 2>/dev/null; then
            started=$(awk -F'[":,]' '/"started_at"/ { for (i=1;i<=NF;i++) if ($i ~ /^[0-9]+\.[0-9]+$/ || $i ~ /^[0-9]+$/) { print $i; exit } }' "$sidecar")
            cs_id=$(awk -F'"' '/"claude_code_session_id"/ { print $4 }' "$sidecar")
            now=$(date +%s)
            age_min=$(( (now - ${started%%.*}) / 60 ))
            echo "  pid=$pid LIVE  age=${age_min}m  claude_session=${cs_id:-<unset>}"
            # Pull lockfile lines as plain text — extract everything between "lockfile":"  and "
            grep -oE '"lockfile":[[:space:]]*"[^"]*"' "$sidecar" | sed 's/.*"lockfile":[[:space:]]*"//; s/"$//' | while IFS= read -r lock; do
                [[ -n "$lock" ]] || continue
                printf '    holds: %s ' "$lock"
                if [[ -e "$lock" ]]; then echo "[lockfile present]"
                else echo "[!!! lockfile MISSING — sidecar/Ghidra disagree]"
                fi
            done
            grep -oE '"lockfile":[[:space:]]*"[^"]*"' "$sidecar" | sed 's/.*"lockfile":[[:space:]]*"//; s/"$//' >> /tmp/lab-health.live.locks.$$
        fi
    done
    [[ "$SIDECAR_COUNT" -eq 0 ]] && echo "  (no sidecars)"
else
    echo "  (sidecar dir does not exist: $SIDECAR_DIR)"
fi
echo

# --- 3. stale sidecars -------------------------------------------------
echo "=== stale sidecars (sidecar present, PID dead) ==="
STALE_COUNT=0
if [[ -d "$SIDECAR_DIR" ]]; then
    for sidecar in "$SIDECAR_DIR"/*.json; do
        [[ -e "$sidecar" ]] || break
        pid="$(basename "$sidecar" .json)"
        if ! kill -0 "$pid" 2>/dev/null; then
            STALE_COUNT=$((STALE_COUNT + 1))
            echo "  STALE pid=$pid file=$sidecar"
            if [[ "${REMOVE_STALE:-}" == "1" ]]; then
                rm -f "$sidecar"
                echo "    removed."
            fi
        fi
    done
fi
[[ "$STALE_COUNT" -eq 0 ]] && echo "  (none)"
[[ "$STALE_COUNT" -gt 0 && "${REMOVE_STALE:-}" != "1" ]] && EXIT_NONZERO=1
echo

# --- 4. orphan project lockfiles --------------------------------------
echo "=== orphan project lockfiles (Ghidra .lock with no live sidecar) ==="
ORPHAN_COUNT=0
if [[ -d "$PROJECTS_ROOT" ]]; then
    while IFS= read -r lock; do
        [[ -n "$lock" ]] || continue
        if [[ -f /tmp/lab-health.live.locks.$$ ]] && grep -Fxq "$lock" /tmp/lab-health.live.locks.$$; then
            continue
        fi
        ORPHAN_COUNT=$((ORPHAN_COUNT + 1))
        printf '  ORPHAN %s' "$lock"
        # Pull human-readable Username + Timestamp from the lockfile.
        user=$(awk -F= '/^Username/ { gsub(/\\/,""); print $2 }' "$lock" 2>/dev/null | head -1 | tr -d ' ')
        ts=$(awk -F= '/^Timestamp/ { gsub(/\\/,""); print $2 }' "$lock" 2>/dev/null | head -1)
        [[ -n "$user" ]] && printf ' user=%s' "$user"
        [[ -n "$ts" ]] && printf ' ts=%s' "$ts"
        printf '\n'
    done < <(find "$PROJECTS_ROOT" -name '*.lock' -type f 2>/dev/null)
fi
[[ "$ORPHAN_COUNT" -eq 0 ]] && echo "  (none)"
[[ "$ORPHAN_COUNT" -gt 0 ]] && EXIT_NONZERO=1
echo

# --- 5. java/python processes cross-check -----------------------------
echo "=== ps cross-check (any java + ghidra-headless-mcp python procs) ==="
ps -e -o pid,etime,user,command 2>/dev/null \
    | awk 'NR==1 || /java/ || /ghidra[-_]headless[-_]mcp/ || /pyghidra_launcher/' \
    | sed 's/^/  /'
echo

# Cleanup helper temp file.
rm -f /tmp/lab-health.live.locks.$$ 2>/dev/null

exit $EXIT_NONZERO
BODY
)"

if [[ -n "$RUN_LOCAL" ]]; then
    REMOVE_STALE_VAL="${REMOVE_STALE:-}" bash -c "REMOVE_STALE='${REMOVE_STALE:-}'; $LAB_BODY"
else
    if ! command -v ssh >/dev/null 2>&1; then
        echo "lab-health: ssh not on PATH" >&2
        exit 2
    fi
    ssh -o BatchMode=yes "$REMOTE_HOST" "REMOVE_STALE='${REMOVE_STALE:-}' bash -s" <<<"$LAB_BODY"
fi
