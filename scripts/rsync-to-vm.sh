#!/usr/bin/env bash
# One-way sync of the current project's ./targets/ directory into
# ~/Targets/<project-name>/ on the primary lab host so Ghidra and
# macre-vm-mcp can operate on the binaries.
#
# - Project name auto-detected from `basename $(pwd)` (overridable via
#   env var MACRE_PROJECT=...).
# - Syncs target binaries and bundles while excluding source code,
#   notes, dSYMs, hidden files, and common secrets.
# - Fails fast if ./targets/ doesn't exist (prevents accidental empty
#   sync with --delete).
#
# Usage:
#     scripts/rsync-to-vm.sh [--record <target-id>] [./targets/]
#
# Exit codes:
#     0  sync ok
#     2  no ./targets/ (or provided path) — refuse to sync
#     3  VM unreachable or ssh config missing
set -euo pipefail

HOST="${MACRE_MACHINE:-lab-host}"
SOURCE="./targets/"
PROJECT="${MACRE_PROJECT:-$(basename "$(pwd)")}"
REMOTE_ROOT="${MACRE_REMOTE_TARGETS:-/Users/<remote-user>/Targets}"
REMOTE_DIR="${REMOTE_ROOT}/${PROJECT}"
RECORD_TARGET_ID=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --record)
            [[ $# -ge 2 ]] || {
                echo "ERROR: --record requires a target id." >&2
                exit 2
            }
            RECORD_TARGET_ID="$2"
            shift 2
            ;;
        --help|-h)
            sed -n '1,18p' "$0"
            exit 0
            ;;
        *)
            SOURCE="$1"
            shift
            ;;
    esac
done

if [[ ! -d "${SOURCE}" ]]; then
    echo "ERROR: ${SOURCE} does not exist. Create ./targets/ and drop binaries into it first." >&2
    exit 2
fi

# Sanity-check VM reachability in ≤5s.
if ! ssh -o BatchMode=yes -o ConnectTimeout=5 "${HOST}" true 2>/dev/null; then
    echo "ERROR: cannot reach ${HOST} via ssh." >&2
    echo "Check ~/.ssh/config for ${HOST}; re-run scripts/install-vm-ssh-key.sh if key auth is not working." >&2
    exit 3
fi

# Ensure the per-project remote dir exists.
ssh -o BatchMode=yes "${HOST}" "mkdir -p '${REMOTE_DIR}'"

echo "==> rsync ${SOURCE} -> ${HOST}:${REMOTE_DIR}/ (project=${PROJECT})"
# Allowlist rules:
#   * Mach-O bundles: *.app, *.framework, *.xpc, *.bundle, *.dylib, *.kext
#   * Plain binaries (any file with no extension or a bare name)
#   * Code signature and plist metadata inside bundles
#   * Installer packages: *.pkg, *.mpkg
# Explicitly EXCLUDE source code, dSYM, hidden files, notes, secrets.
rsync \
    --archive --delete --compress \
    --prune-empty-dirs \
    --exclude='.git' \
    --exclude='.*' \
    --exclude='.DS_Store' \
    --exclude='*.dSYM' \
    --exclude='*.dSYM/**' \
    --exclude='*.swift' \
    --exclude='*.m' \
    --exclude='*.c' \
    --exclude='*.cpp' \
    --exclude='*.h' \
    --exclude='*.py' \
    --exclude='*.md' \
    --exclude='*.txt' \
    --exclude='*.log' \
    --exclude='.env*' \
    --exclude='*.key' \
    --exclude='*.pem' \
    --include='*/' \
    --include='*.app' \
    --include='*.app/**' \
    --include='*.framework' \
    --include='*.framework/**' \
    --include='*.xpc' \
    --include='*.xpc/**' \
    --include='*.bundle' \
    --include='*.bundle/**' \
    --include='*.kext' \
    --include='*.kext/**' \
    --include='*.dylib' \
    --include='*.pkg' \
    --include='*.mpkg' \
    --include='*' \
    -e "ssh -o BatchMode=yes" \
    "${SOURCE%/}/" "${HOST}:${REMOTE_DIR}/"

echo ""
echo "OK — ${PROJECT} synced. Remote contents:"
ssh -o BatchMode=yes "${HOST}" "ls -la '${REMOTE_DIR}'"

if [[ -n "${RECORD_TARGET_ID}" && -f "CORPUS.md" ]]; then
    SYNCED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    python3 - "CORPUS.md" "${RECORD_TARGET_ID}" "${SOURCE%/}" "${HOST}:${REMOTE_DIR}" "${SYNCED_AT}" <<'PY'
from pathlib import Path
import sys

corpus_path = Path(sys.argv[1])
target_id = sys.argv[2]
local_path = sys.argv[3]
remote_path = sys.argv[4]
synced_at = sys.argv[5]

text = corpus_path.read_text(encoding="utf-8")
row_key = f"| {target_id} | {local_path} | {remote_path} |"
if row_key not in text:
    heading = "## Lab Host Path Mapping"
    lines = text.splitlines()
    try:
        heading_line = lines.index(heading)
    except ValueError:
        raise SystemExit(f"ERROR: {heading} missing from CORPUS.md")

    insert_at = None
    for index in range(heading_line + 1, min(len(lines), heading_line + 10)):
        line = lines[index].strip()
        if line.startswith("|") and set(line.replace("|", "").strip()) <= {"-", ":"}:
            insert_at = index + 1
            break
    if insert_at is None:
        raise SystemExit(f"ERROR: table separator missing under {heading}")

    lines.insert(insert_at, f"| {target_id} | {local_path} | {remote_path} | {synced_at} | rsync-to-vm.sh |")
    corpus_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
    echo "Recorded sync mapping in CORPUS.md: ${RECORD_TARGET_ID} -> ${HOST}:${REMOTE_DIR}"
fi
