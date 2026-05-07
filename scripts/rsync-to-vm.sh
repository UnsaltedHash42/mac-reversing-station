#!/usr/bin/env bash
# One-way sync of the current project's ./targets/ directory into
# ~/Targets/<project-name>/ on NightBlood so Hopper and macre-vm-mcp
# can operate on the binaries.
#
# - Project name auto-detected from `basename $(pwd)` (overridable via
#   env var MACRE_PROJECT=...).
# - Explicit allowlist of file shapes — we do NOT sync source code,
#   notes, dSYMs, hidden files, or secrets.
# - Fails fast if ./targets/ doesn't exist (prevents accidental empty
#   sync with --delete).
#
# Usage:
#     scripts/rsync-to-vm.sh [./targets/]
#
# Exit codes:
#     0  sync ok
#     2  no ./targets/ (or provided path) — refuse to sync
#     3  VM unreachable or ssh config missing
set -euo pipefail

HOST="NightBlood"
SOURCE="${1:-./targets/}"
PROJECT="${MACRE_PROJECT:-$(basename "$(pwd)")}"
REMOTE_ROOT="/Users/szeth/Targets"
REMOTE_DIR="${REMOTE_ROOT}/${PROJECT}"

if [[ ! -d "${SOURCE}" ]]; then
    echo "ERROR: ${SOURCE} does not exist. Create ./targets/ and drop binaries into it first." >&2
    exit 2
fi

# Sanity-check VM reachability in ≤5s.
if ! ssh -o BatchMode=yes -o ConnectTimeout=5 "${HOST}" true 2>/dev/null; then
    echo "ERROR: cannot reach ${HOST} via ssh." >&2
    echo "Check ~/.ssh/config NightBlood block; re-run scripts/install-vm-ssh-key.sh if key auth is not working." >&2
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
