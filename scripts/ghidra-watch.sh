#!/usr/bin/env bash
# 60-s heartbeat poller for a running Ghidra headless scan on the lab host.
#
# PASS-001 lost two hours to swap-thrashing that looked identical to
# "making progress" because Ghidra's auto-analysis emits < 1 stdout line
# per minute on large binaries. This emits one structured line per
# interval covering: phase, cpu/rss, db_size delta, stdout/stderr line
# delta, swap, and anchor row count once the script begins emitting TSV.
#
# A few derived heuristics surface trouble automatically (printed as
# RED-FLAG lines):
#
#   - swap_used > 0 on a dedicated lab VM   -> heap is too large for RAM
#   - db_size flat for >=3 polls            -> analyzer deadlock or I/O stall
#   - cpu < 10% AND no anchor rows yet      -> done with cleanup or hung post-script
#
# Usage (workstation):
#   ssh NightBlood 'bash -s' < scripts/ghidra-watch.sh \
#       --project rocket_chat --target-id ef-arm64 \
#       --out-dir ~/scans/electron-framework
#
# Or directly on the lab host:
#   scripts/ghidra-watch.sh --project rocket_chat --target-id ef-arm64 --out-dir ~/scans/...
#
# Stops when no java process exists with the expected -Dghidra.* args, or
# on SIGINT. Default interval 60 s; override with --interval <seconds>.

set -euo pipefail

PROJECT_NAME=""
TARGET_ID=""
OUT_DIR=""
INTERVAL_SEC=60
MAX_POLLS=0   # 0 = run until process disappears or interrupted

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project)    PROJECT_NAME="$2"; shift 2;;
        --target-id)  TARGET_ID="$2";    shift 2;;
        --out-dir)    OUT_DIR="$2";      shift 2;;
        --interval)   INTERVAL_SEC="$2"; shift 2;;
        --max-polls)  MAX_POLLS="$2";    shift 2;;
        *) echo "unknown flag: $1" >&2; exit 2;;
    esac
done

for var in PROJECT_NAME TARGET_ID OUT_DIR; do
    eval "val=\${$var}"
    if [[ -z "${val}" ]]; then
        echo "missing --$(echo $var | tr A-Z a-z | tr _ -)" >&2
        exit 2
    fi
done

PROJECTS_ROOT="${MACRE_GHIDRA_PROJECTS_ROOT:-$HOME/ghidra-projects}"
PROJECT_DIR="$PROJECTS_ROOT/$PROJECT_NAME"
GPR_DIR="$PROJECT_DIR/$TARGET_ID.rep"

# stat varies between BSD (macOS) and GNU. Try BSD first.
file_size() {
    local path="$1"
    if [[ ! -e "$path" ]]; then echo 0; return; fi
    stat -f %z "$path" 2>/dev/null || stat -c %s "$path" 2>/dev/null || echo 0
}

dir_size_bytes() {
    local path="$1"
    if [[ ! -d "$path" ]]; then echo 0; return; fi
    # du -sk gives 1024-byte blocks. Multiply for bytes.
    local kb
    kb=$(du -sk "$path" 2>/dev/null | awk '{print $1}')
    echo $(( kb * 1024 ))
}

human_bytes() {
    awk -v b="$1" 'BEGIN {
        if (b >= 1073741824)      printf "%.2fG", b/1073741824;
        else if (b >= 1048576)    printf "%.1fM", b/1048576;
        else if (b >= 1024)       printf "%.1fK", b/1024;
        else                      printf "%dB", b;
    }'
}

ghidra_pid() {
    # Find the analyzeHeadless / pyghidra_launcher java process for this project.
    pgrep -f "ghidra.* $TARGET_ID|$PROJECT_NAME.*$TARGET_ID|analyzeHeadless.*$TARGET_ID" 2>/dev/null \
        | head -1
}

cpu_rss_for_pid() {
    local pid="$1"
    if [[ -z "$pid" ]]; then echo "- -"; return; fi
    ps -o pcpu=,rss= -p "$pid" 2>/dev/null | awk '{printf "%.0f %d", $1, $2}'
}

swap_used_bytes() {
    if command -v vm_stat >/dev/null 2>&1; then
        # macOS: sysctl vm.swapusage gives total/used/free in MB
        sysctl -n vm.swapusage 2>/dev/null \
            | awk '{
                for (i = 1; i <= NF; i++) {
                    if ($i ~ /^used/) {
                        gsub(/used = /, "", $i);
                        n = $(i+1); gsub(/M$/, "", n);
                        printf "%d", n * 1024 * 1024;
                        exit;
                    }
                }
                print 0;
            }'
    else
        echo 0
    fi
}

LAST_DB_SIZE=0
DB_FLAT_POLLS=0
LAST_STDOUT_LINES=0
LAST_STDERR_LINES=0
POLL_COUNT=0

trap 'echo "[ghidra-watch] interrupted at poll #$POLL_COUNT" >&2; exit 0' INT TERM

while :; do
    POLL_COUNT=$((POLL_COUNT + 1))
    TS=$(date -u +%Y-%m-%dT%H:%MZ)

    PID=$(ghidra_pid || true)
    if [[ -z "$PID" ]]; then
        echo "[ghidra-watch] ts=$TS no_ghidra_process_for=$TARGET_ID poll=$POLL_COUNT — exiting"
        exit 0
    fi

    CPU_RSS=$(cpu_rss_for_pid "$PID")
    CPU=$(echo "$CPU_RSS" | awk '{print $1}')
    RSS_KB=$(echo "$CPU_RSS" | awk '{print $2}')
    RSS_BYTES=$(( RSS_KB * 1024 ))

    DB_SIZE=$(dir_size_bytes "$GPR_DIR")
    DB_DELTA=$(( DB_SIZE - LAST_DB_SIZE ))
    if [[ $POLL_COUNT -gt 1 && $DB_DELTA -eq 0 ]]; then
        DB_FLAT_POLLS=$((DB_FLAT_POLLS + 1))
    else
        DB_FLAT_POLLS=0
    fi

    STDOUT_LINES=0
    STDERR_LINES=0
    ANCHOR_ROWS=0
    SCRIPT_STARTED=no

    # Find the most recent stdout/stderr log in OUT_DIR.
    if [[ -d "$OUT_DIR" ]]; then
        LATEST_STDOUT=$(ls -t "$OUT_DIR"/*.stdout.log 2>/dev/null | head -1 || true)
        LATEST_STDERR=$(ls -t "$OUT_DIR"/*.stderr.log 2>/dev/null | head -1 || true)
        if [[ -n "$LATEST_STDOUT" ]]; then
            STDOUT_LINES=$(wc -l < "$LATEST_STDOUT" | awk '{print $1}')
            # Anchor rows = data lines minus the header + INFO wrappers.
            ANCHOR_ROWS=$(grep -cE '^[^#].*\t[ABC]\t' "$LATEST_STDOUT" 2>/dev/null || echo 0)
            if [[ $STDOUT_LINES -gt 0 ]]; then SCRIPT_STARTED=yes; fi
        fi
        if [[ -n "$LATEST_STDERR" ]]; then
            STDERR_LINES=$(wc -l < "$LATEST_STDERR" | awk '{print $1}')
        fi
    fi
    STDOUT_DELTA=$(( STDOUT_LINES - LAST_STDOUT_LINES ))
    STDERR_DELTA=$(( STDERR_LINES - LAST_STDERR_LINES ))

    SWAP_BYTES=$(swap_used_bytes)

    echo "[ghidra-watch] ts=$TS pid=$PID cpu=${CPU}% rss=$(human_bytes $RSS_BYTES) db=$(human_bytes $DB_SIZE) db_delta=$(human_bytes $DB_DELTA) stdout=${STDOUT_LINES}(+${STDOUT_DELTA}) stderr=${STDERR_LINES}(+${STDERR_DELTA}) anchors=$ANCHOR_ROWS script=$SCRIPT_STARTED swap=$(human_bytes $SWAP_BYTES) poll=$POLL_COUNT"

    if [[ $SWAP_BYTES -gt 0 ]]; then
        echo "[ghidra-watch] RED-FLAG swap_in_use=$(human_bytes $SWAP_BYTES) — heap likely too large for physical RAM"
    fi
    if [[ $DB_FLAT_POLLS -ge 3 ]]; then
        echo "[ghidra-watch] RED-FLAG db_size_flat_for=${DB_FLAT_POLLS}_polls — analyzer deadlock or I/O stall suspected"
    fi
    if [[ ${CPU%.*} -lt 10 && "$SCRIPT_STARTED" == "no" && $POLL_COUNT -ge 3 ]]; then
        echo "[ghidra-watch] WARN low_cpu=${CPU}% with no script output — analyzer may be done or hung"
    fi

    LAST_DB_SIZE=$DB_SIZE
    LAST_STDOUT_LINES=$STDOUT_LINES
    LAST_STDERR_LINES=$STDERR_LINES

    if [[ $MAX_POLLS -gt 0 && $POLL_COUNT -ge $MAX_POLLS ]]; then
        exit 0
    fi
    sleep "$INTERVAL_SEC"
done
