#!/usr/bin/env bash
# Build and ad-hoc sign the tutorial-target-2 bundle (PluginHost.app).
# Run from this directory or from the repo root.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${SCRIPT_DIR}/src"
PLISTS="${SCRIPT_DIR}/plists"
APP="${SCRIPT_DIR}/PluginHost.app"

# Layout
HOST_DIR="${APP}/Contents"
HOST_MACOS="${HOST_DIR}/MacOS"
HOST_RES="${HOST_DIR}/Resources"
HOST_PLUGINS="${HOST_RES}/plugins"
XPC_BUNDLE="${HOST_DIR}/XPCServices/PluginHelper.xpc"
XPC_DIR="${XPC_BUNDLE}/Contents"
XPC_MACOS="${XPC_DIR}/MacOS"

rm -rf "${APP}"
mkdir -p "${HOST_MACOS}" "${HOST_PLUGINS}" "${XPC_MACOS}"

# Bundle Info.plists
cp "${PLISTS}/PluginHost-Info.plist"   "${HOST_DIR}/Info.plist"
cp "${PLISTS}/PluginHelper-Info.plist" "${XPC_DIR}/Info.plist"

# Host binary
clang -framework Foundation \
    -fobjc-arc \
    -arch arm64 \
    -mmacosx-version-min=13.0 \
    -o "${HOST_MACOS}/PluginHost" \
    "${SRC}/PluginHost.m"

# Helper binary (bundled XPC service)
clang -framework Foundation \
    -fobjc-arc \
    -arch arm64 \
    -mmacosx-version-min=13.0 \
    -o "${XPC_MACOS}/PluginHelper" \
    "${SRC}/PluginHelper.m"

# Sample (legitimate) plugin
clang -dynamiclib \
    -arch arm64 \
    -mmacosx-version-min=13.0 \
    -o "${HOST_PLUGINS}/sample.dylib" \
    "${SRC}/sample_plugin.c"

# Codesign helper FIRST (nested bundles must be signed before the outer bundle)
codesign --force --sign - \
    --entitlements "${SRC}/PluginHelper-entitlements.plist" \
    --options runtime \
    "${XPC_MACOS}/PluginHelper"
codesign --force --sign - \
    --options runtime \
    "${XPC_BUNDLE}"

# Codesign the sample plugin so the happy path doesn't trip library validation
codesign --force --sign - "${HOST_PLUGINS}/sample.dylib"

# Codesign host binary, then the .app as a whole
codesign --force --sign - \
    --entitlements "${SRC}/PluginHost-entitlements.plist" \
    --options runtime \
    "${HOST_MACOS}/PluginHost"
codesign --force --sign - \
    --options runtime \
    "${APP}"

echo "OK - built and ad-hoc signed: ${APP}"
codesign -dvv "${APP}" 2>&1 | grep -E "Identifier|CDHash|Signature"
echo ""
echo "To inspect host entitlements:"
echo "  codesign -d --entitlements - ${HOST_MACOS}/PluginHost"
echo "To inspect helper entitlements:"
echo "  codesign -d --entitlements - ${XPC_MACOS}/PluginHelper"
