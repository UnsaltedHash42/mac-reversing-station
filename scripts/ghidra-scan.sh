#!/usr/bin/env bash
# Drive Ghidra headless + a hunt script against a single Mach-O binary on
# the primary lab host, persisting the analyzed project for reuse.
#
# Design decisions:
# - NEVER uses -readOnly. The analyzed DB is expensive to rebuild (tens of
#   minutes to hours on large binaries). One project per (target, slice)
#   on the lab host; subsequent scans of the same binary reuse the DB.
# - Uses pyghidra_launcher.py -H so @runtime PyGhidra scripts load.
# - Universal Mach-Os: when the input is a fat binary, scan every slice
#   serially. analyzeHeadless has no flag for slice selection, so we
#   `lipo -thin <arch>` into a sibling .slices-<target-id>/ dir and run
#   the script once per slice. PR #13's heap-vs-RAM preflight gates each
#   slice; serial (not parallel) so two slices' Ghidra projects never
#   pin the heap budget at once. Pre-sliced inputs (`lipo -info` reports
#   "Non-fat file:") follow the single-pass path unchanged.
# - Project dir naming: ~/ghidra-projects/<project-name>/<target-id>.gpr
#   for single-arch; <target-id>-<arch>.gpr per slice on universal inputs
#   (synthesized — operator passes the bare <target-id>).
# - Script stdout goes to <out-dir>/<script>.stdout.log, stderr to
#   <out-dir>/<script>.stderr.log. A cleaned <script>.tsv (PyGhidra
#   `INFO ... (GhidraScript)` wrappers stripped) is also emitted, suitable
#   for piping into triage.py without per-call sed.
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
#   6  heap-vs-RAM preflight tripwire (override with MACRE_SKIP_RAM_PREFLIGHT=1)
#   7  lipo failure on a universal binary (slice extraction)
#   8  pyghidra-preflight tripwire (override with MACRE_SKIP_PYGHIDRA_PREFLIGHT=1)
# When the input is universal, the exit code is the worst of the per-slice
# scan rcs (0 only if all slices succeeded). Slice rcs are also surfaced in
# the trailer line so the operator can see which slice failed.

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

# Heap-vs-RAM preflight. PASS-001's 4 GB VM with -Xmx12g caused 2+ hours of swap
# thrashing before detection. Refuse if MACRE_GHIDRA_HEAP exceeds physical_ram_gb
# minus 6 GB headroom (JVM non-heap + Ghidra off-heap + OS userspace + page cache).
# Override via MACRE_SKIP_RAM_PREFLIGHT=1.
if [[ -z "${MACRE_SKIP_RAM_PREFLIGHT:-}" ]]; then
    HEAP_LOWER="$(printf '%s' "$HEAP_SIZE" | tr '[:upper:]' '[:lower:]')"
    case "$HEAP_LOWER" in
        *g) HEAP_GB=${HEAP_LOWER%g} ;;
        *m) HEAP_GB=$(( ${HEAP_LOWER%m} / 1024 )) ;;
        *)
            printf 'ERROR: cannot parse MACRE_GHIDRA_HEAP=%s (expected <N>g or <N>m)\n' "$HEAP_SIZE" >&2
            printf '  override with MACRE_SKIP_RAM_PREFLIGHT=1\n' >&2
            exit 6
            ;;
    esac
    if ! [[ "$HEAP_GB" =~ ^[0-9]+$ ]]; then
        printf 'ERROR: cannot parse MACRE_GHIDRA_HEAP=%s (non-integer magnitude)\n' "$HEAP_SIZE" >&2
        printf '  override with MACRE_SKIP_RAM_PREFLIGHT=1\n' >&2
        exit 6
    fi
    MEMSIZE_BYTES=$(sysctl -n hw.memsize 2>/dev/null || echo 0)
    if [[ "$MEMSIZE_BYTES" -gt 0 ]]; then
        PHYS_GB=$(( MEMSIZE_BYTES / 1073741824 ))
        MAX_HEAP_GB=$(( PHYS_GB - 6 ))
        if [[ $MAX_HEAP_GB -lt 1 ]]; then MAX_HEAP_GB=1; fi
        if [[ $HEAP_GB -gt $MAX_HEAP_GB ]]; then
            printf 'ERROR: MACRE_GHIDRA_HEAP=%s exceeds physical_ram_gb-6\n' "$HEAP_SIZE" >&2
            printf '  physical_ram_gb=%d, max_heap_gb=%d, requested_heap_gb=%d\n' \
                "$PHYS_GB" "$MAX_HEAP_GB" "$HEAP_GB" >&2
            printf '  override with MACRE_SKIP_RAM_PREFLIGHT=1\n' >&2
            exit 6
        fi
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

# PyGhidra preflight. PASS-001 hit "Ghidra was not started with PyGhidra. Python
# is not available" until we figured out pyghidra_launcher.py -H with the MCP
# venv's Python is the required entry point. The path-existence check above
# only proves the files are there; a venv re-created without re-pip-install
# will pass that check and still fail at script runtime. Probe by importing
# pyghidra from the venv Python — cheap (~50 ms), source-of-truth.
# Override via MACRE_SKIP_PYGHIDRA_PREFLIGHT=1.
if [[ -z "${MACRE_SKIP_PYGHIDRA_PREFLIGHT:-}" ]]; then
    if ! "$VENV_PY" -c 'import pyghidra' >/dev/null 2>&1; then
        printf 'ERROR: %s cannot import pyghidra\n' "$VENV_PY" >&2
        printf '  fix with: uv pip install --python %s pyghidra (or rerun scripts/install-ghidra-host.sh --install)\n' "$VENV_PY" >&2
        printf '  override with MACRE_SKIP_PYGHIDRA_PREFLIGHT=1\n' >&2
        exit 8
    fi
fi

export JAVA_HOME="$JDK_HOME"
export PATH="$JAVA_HOME/bin:$PATH"
export _JAVA_OPTIONS="-Xmx${HEAP_SIZE}"

# Persist projects under ~/ghidra-projects/<project-name>/
# Re-importing into an existing project reuses the analyzed DB.
PROJECTS_ROOT="${MACRE_GHIDRA_PROJECTS_ROOT:-$HOME/ghidra-projects}"
PROJECT_DIR="$PROJECTS_ROOT/$PROJECT_NAME"
mkdir -p "$PROJECT_DIR" "$OUT_DIR"

# run_one_scan <binary-path> <target-id> <log-suffix>
# log-suffix is "" for single-arch (logs go to <script>.stdout.log) or
# "-<arch>" for per-slice runs (logs go to <script>-<arch>.stdout.log).
# Sets RC to the analyzeHeadless exit code; emits a cleaned .tsv too.
run_one_scan() {
    local one_binary="$1"
    local one_target_id="$2"
    local one_suffix="$3"
    local log_stdout="$OUT_DIR/${SCRIPT_NAME%.py}${one_suffix}.stdout.log"
    local log_stderr="$OUT_DIR/${SCRIPT_NAME%.py}${one_suffix}.stderr.log"
    local log_tsv="$OUT_DIR/${SCRIPT_NAME%.py}${one_suffix}.tsv"

    local existing_gpr="$PROJECT_DIR/$one_target_id.gpr"
    local mode_args run_mode
    if [[ -f "$existing_gpr" ]]; then
        # Reuse analyzed DB. -process matches the basename of the prior import.
        mode_args=(-process "$(basename "$one_binary")" -noanalysis)
        run_mode="reuse"
    else
        mode_args=(-import "$one_binary")
        run_mode="import"
    fi

    local script_args_arr=()
    if [[ -n "$SCRIPT_ARGS" ]]; then
        # shellcheck disable=SC2206
        script_args_arr=($SCRIPT_ARGS)
    fi

    local start
    start=$(date +%s)
    echo "[ghidra-scan] mode=$run_mode project=$PROJECT_DIR/$one_target_id script=$SCRIPT_NAME" >&2

    # NB: no -readOnly. We want the analyzed DB persisted for future scans.
    # Use pyghidra_launcher.py -H so @runtime PyGhidra scripts are honored.
    # Don't let `set -e` short-circuit on a non-zero script exit -- we still
    # want to emit the cleaned TSV from whatever stdout was captured.
    set +e
    "$VENV_PY" "$LAUNCHER" "$GHIDRA_HOME" -H \
        "$PROJECT_DIR" "$one_target_id" \
        "${mode_args[@]}" \
        -scriptPath "$SCRIPT_DIR" \
        -postScript "$SCRIPT_NAME" ${script_args_arr[@]+"${script_args_arr[@]}"} \
        > "$log_stdout" 2> "$log_stderr"
    RC=$?
    set -e

    # Emit a cleaned .tsv alongside the raw .stdout.log. PyGhidra wraps each
    # println call as `INFO  <script>.py> <line> (GhidraScript)`; strip the
    # prefix and trailing tag so the file pipes cleanly into triage.py without
    # per-call sed. Best-effort: failures here do not change RC.
    if [[ -s "$log_stdout" ]]; then
        sed -E 's/^INFO  [^>]+> //; s/ \(GhidraScript\) +$//' "$log_stdout" > "$log_tsv" || \
            echo "[ghidra-scan] WARN: failed to emit cleaned tsv at $log_tsv" >&2
    fi

    local end
    end=$(date +%s)
    echo "[ghidra-scan] exit=$RC elapsed=$((end-start))s stdout=$log_stdout stderr=$log_stderr tsv=$log_tsv" >&2
}

# Universal-Mach-O detection. lipo prints either:
#   Architectures in the fat file: <path> are: x86_64 arm64e
#   Non-fat file: <path> is architecture: arm64
# When lipo is unavailable (Linux lab host), fall back to single-pass.
ARCHES=()
if command -v lipo >/dev/null 2>&1; then
    LIPO_OUT="$(lipo -info "$BINARY" 2>/dev/null || true)"
    if [[ "$LIPO_OUT" == "Architectures in the fat file:"* ]]; then
        # `... are: <a> <b> ...` — everything after "are: " is the arch list.
        ARCH_LIST="${LIPO_OUT##*are: }"
        # shellcheck disable=SC2206
        ARCHES=($ARCH_LIST)
    fi
fi

if [[ ${#ARCHES[@]} -gt 1 ]]; then
    echo "[ghidra-scan] universal-binary detected: scanning ${#ARCHES[@]} slices serially (${ARCHES[*]})" >&2
    SLICE_DIR="$OUT_DIR/.slices-$TARGET_ID"
    mkdir -p "$SLICE_DIR"
    WORST_RC=0
    declare -a SLICE_RCS=()
    for arch in "${ARCHES[@]}"; do
        SLICE_BIN="$SLICE_DIR/$(basename "$BINARY")-$arch"
        if [[ ! -f "$SLICE_BIN" ]]; then
            if ! lipo "$BINARY" -thin "$arch" -output "$SLICE_BIN" 2>&1; then
                echo "[ghidra-scan] ERROR: lipo -thin $arch failed for $BINARY" >&2
                exit 7
            fi
        fi
        run_one_scan "$SLICE_BIN" "$TARGET_ID-$arch" "-$arch"
        SLICE_RCS+=("$arch=$RC")
        if [[ $RC -gt $WORST_RC ]]; then WORST_RC=$RC; fi
    done
    echo "[ghidra-scan] universal-binary done: ${SLICE_RCS[*]} worst_rc=$WORST_RC" >&2
    exit "$WORST_RC"
fi

run_one_scan "$BINARY" "$TARGET_ID" ""
exit "$RC"
