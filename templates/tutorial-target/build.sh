#!/usr/bin/env bash
# Build and ad-hoc sign the tutorial daemon.
# Run from this directory or from the repo root.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${SCRIPT_DIR}/src/tutorial_daemon.m"
ENT="${SCRIPT_DIR}/src/entitlements.plist"
OUT="${SCRIPT_DIR}/bin/tutorial_daemon"

mkdir -p "$(dirname "${OUT}")"

clang -framework Foundation -framework Security \
    -fobjc-arc \
    -arch arm64 \
    -mmacosx-version-min=13.0 \
    -o "${OUT}" "${SRC}"

codesign --force --sign - \
    --entitlements "${ENT}" \
    --options runtime \
    "${OUT}"

echo "OK - built and ad-hoc signed: ${OUT}"
codesign -dvv "${OUT}" 2>&1 | grep -E "Identifier|CDHash|Signature"
echo ""
echo "To inspect entitlements:"
echo "  codesign -d --entitlements - ${OUT}"
