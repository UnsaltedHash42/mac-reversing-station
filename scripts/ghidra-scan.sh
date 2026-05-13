#!/usr/bin/env bash
# Drive Ghidra headless + a hunt script against a single Mach-O binary on
# the primary lab host, persisting the analyzed project for reuse.
#
# Design decisions:
# - NEVER uses -readOnly. The analyzed DB is expensive to rebuild (tens of
#   minutes to hours on large binaries). One project per (target, slice)
#   on the lab host; subsequent scans of the same binary reuse the DB.
# - Uses pyghidra_launcher.py -H so @runtime PyGhidra scripts load.
# - Universal Mach-Os should be pre-sliced with `lipo -thin <arch>` before
#   being passed here. Headless analyzeHeadless has no flag for slice
#   selection on universal Mach-Os; pre-slicing is the only correct path.
# - Project dir naming: ~/ghidra-projects/<project-name>/<target-id>-<slice>
#   Callers choose the names; we do not synthesize.
# - Script stdout goes to <out-dir>/stdout.log, stderr to <out-dir>/stderr.log.
#
# Usage:
#   scripts/ghidra-scan.sh \
#       --binary <remote-path> \
#       --project <project-name> \
#       --target-id <id>-<slice> \
#       --script <ghidra-script.py> \
#       --out-dir <remote-output-dir> \
#       [--script-args '<args>']
#
# Example:
#   ssh NightBlood 'bash -s' < scripts/ghidra-scan.sh \
#       --binary ~/scans/electron-framework/electron-framework-arm64 \
#       --project rocket_chat \
#       --target-id ef-arm64 \
#       --script scan_tcc_prompt_surface.py \
#       --out-dir ~/scans/electron-framework
#
# Exit codes:
#   0  scan ok (post-script exit code)
#   2  missing required flag
#   3  binary not found
#   4  ghidra/pyghidra launch missing
#   5  disk-preflight tripwire (override with MACRE_SKIP_DISK_PREFLIGHT=1)

set -euo pipefail

BINARY=""
PROJECT_NAME=""
TARGET_ID=""
SCRIPT_NAME=""
OUT_DIR=""
SCRIPT_ARGS=""
HEAP_SIZE="${MACRE_GHIDRA_HEAP:-10g}"  # rule of thumb: physical_ram_gb - 6. Tune to the lab VM.

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary)      BINARY="$2";        shift 2;;
        --project)     PROJECT_NAME="$2";  shift 2;;
        --target-id)   TARGET_ID="$2";     shift 2;;
        --script)      SCRIPT_NAME="$2";   shift 2;;
        --out-dir)     OUT_DIR="$2";       shift 2;;
        --script-args) SCRIPT_ARGS="$2";   shift 2;;
        *) echo "unknown flag: $1" >&2; exit 2;;
    esac
done

for var in BINARY PROJECT_NAME TARGET_ID SCRIPT_NAME OUT_DIR; do
    if [[ -z "${!var}" ]]; then
        # ${var,,} is Bash 4+; macOS still ships Bash 3.2.
        flag=$(echo "$var" | tr '[:upper:]_' '[:lower:]-')
        echo "missing --${flag}" >&2; exit 2
    fi
done

if [[ ! -f "$BINARY" ]]; then
    echo "binary not found: $BINARY" >&2; exit 3
fi

# Disk preflight. PASS-001's tripwire was 5 GB; below that, ENOSPC mid-analysis
# leaves a corrupt .gpr that you have to nuke + reimport. Refuse if free disk
# is below max(5 GB, 2x binary size). Override via MACRE_SKIP_DISK_PREFLIGHT=1.
if [[ -z "${MACRE_SKIP_DISK_PREFLIGHT:-}" ]]; then
    BIN_SIZE_BYTES=$(stat -f %z "$BINARY" 2>/dev/null || stat -c %s "$BINARY" 2>/dev/null || echo 0)
    MIN_FREE_BYTES=$((5 * 1024 * 1024 * 1024))
    DOUBLE_BIN=$((BIN_SIZE_BYTES * 2))
    if [[ $DOUBLE_BIN -gt $MIN_FREE_BYTES ]]; then
        REQUIRED=$DOUBLE_BIN
    else
        REQUIRED=$MIN_FREE_BYTES
    fi
    # df -k -> 1024-byte blocks in column 4 (Avail). Resolve disk for OUT_DIR's parent.
    OUT_PARENT="$(dirname "$OUT_DIR")"
    [[ -d "$OUT_PARENT" ]] || OUT_PARENT="$HOME"
    FREE_KB=$(df -k "$OUT_PARENT" 2>/dev/null | awk 'NR==2 {print $4}')
    FREE_BYTES=$(( ${FREE_KB:-0} * 1024 ))
    if [[ $FREE_BYTES -lt $REQUIRED ]]; then
        printf 'ERROR: insufficient free disk on %s\n' "$OUT_PARENT" >&2
        printf '  free=%d MiB, required=%d MiB (max(5GB, 2x binary size %d MiB))\n' \
            $((FREE_BYTES / 1048576)) $((REQUIRED / 1048576)) $((BIN_SIZE_BYTES / 1048576)) >&2
        printf '  override with MACRE_SKIP_DISK_PREFLIGHT=1\n' >&2
        exit 5
    fi
fi

GHIDRA_HOME="${MACRE_GHIDRA_HOME:-$HOME/Applications/ghidra_12.0.4_PUBLIC}"
JDK_HOME="${MACRE_JDK_HOME:-$HOME/Applications/jdk-21.0.11+10/Contents/Home}"
VENV_PY="${MACRE_PYGHIDRA_PYTHON:-$HOME/.venvs/ghidra-headless-mcp/bin/python}"
LAUNCHER="$GHIDRA_HOME/Ghidra/Features/PyGhidra/support/pyghidra_launcher.py"
SCRIPT_DIR="${MACRE_GHIDRA_SCRIPT_DIR:-$HOME/ghidra-scripts}"

for p in "$GHIDRA_HOME/support/analyzeHeadless" "$LAUNCHER" "$VENV_PY"; do
    if [[ ! -e "$p" ]]; then
        echo "missing: $p" >&2; exit 4
    fi
done

export JAVA_HOME="$JDK_HOME"
export PATH="$JAVA_HOME/bin:$PATH"
export _JAVA_OPTIONS="-Xmx${HEAP_SIZE}"

# Persist projects under ~/ghidra-projects/<project-name>/
# Re-importing into an existing project reuses the analyzed DB.
PROJECTS_ROOT="${MACRE_GHIDRA_PROJECTS_ROOT:-$HOME/ghidra-projects}"
PROJECT_DIR="$PROJECTS_ROOT/$PROJECT_NAME"
mkdir -p "$PROJECT_DIR" "$OUT_DIR"

LOG_STDOUT="$OUT_DIR/${SCRIPT_NAME%.py}.stdout.log"
LOG_STDERR="$OUT_DIR/${SCRIPT_NAME%.py}.stderr.log"

# Decide whether this is first import or a re-scan of an existing project.
EXISTING_GPR="$PROJECT_DIR/$TARGET_ID.gpr"
if [[ -f "$EXISTING_GPR" ]]; then
    # Reuse analyzed DB. -process picks the existing imported program.
    # Match by the binary's basename so -process finds the right entry.
    BIN_BASENAME="$(basename "$BINARY")"
    MODE_ARGS=(-process "$BIN_BASENAME" -noanalysis)
    RUN_MODE="reuse"
else
    # First run: import + analyze + script.
    MODE_ARGS=(-import "$BINARY")
    RUN_MODE="import"
fi

START=$(date +%s)
echo "[ghidra-scan] mode=$RUN_MODE project=$PROJECT_DIR/$TARGET_ID script=$SCRIPT_NAME" >&2

# NB: no -readOnly. We want the analyzed DB persisted for future scans.
# Use pyghidra_launcher.py -H so @runtime PyGhidra scripts are honored.
SCRIPT_ARGS_ARR=()
if [[ -n "$SCRIPT_ARGS" ]]; then
    # shellcheck disable=SC2206
    SCRIPT_ARGS_ARR=($SCRIPT_ARGS)
fi

"$VENV_PY" "$LAUNCHER" "$GHIDRA_HOME" -H \
    "$PROJECT_DIR" "$TARGET_ID" \
    "${MODE_ARGS[@]}" \
    -scriptPath "$SCRIPT_DIR" \
    -postScript "$SCRIPT_NAME" ${SCRIPT_ARGS_ARR[@]+"${SCRIPT_ARGS_ARR[@]}"} \
    > "$LOG_STDOUT" 2> "$LOG_STDERR"
RC=$?
END=$(date +%s)
echo "[ghidra-scan] exit=$RC elapsed=$((END-START))s stdout=$LOG_STDOUT stderr=$LOG_STDERR" >&2
exit $RC
