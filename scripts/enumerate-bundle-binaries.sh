#!/usr/bin/env bash
# Enumerate all Mach-O executables in a macOS .app bundle (or arbitrary directory).
# Outputs a TSV: path, type, role, arch, entitlements_summary
#
# Usage:
#   scripts/enumerate-bundle-binaries.sh /Applications/Falcon.app
#   scripts/enumerate-bundle-binaries.sh /Applications/Falcon.app --entitlements findings/analysis/PASS-001-entitlements.json
#
# The --entitlements flag writes a JSON file with full per-binary entitlements.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/enumerate-bundle-binaries.sh <bundle-path> [--entitlements <output.json>]

Arguments:
  <bundle-path>       Path to .app, .systemextension, or directory to scan
  --entitlements      Write full per-binary entitlements to a JSON file

Output (stdout): TSV with columns:
  path    type    role    arch    entitlements_count
EOF
}

BUNDLE=""
ENT_OUTPUT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --entitlements) ENT_OUTPUT="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        -*) echo "ERROR: unknown flag: $1" >&2; usage >&2; exit 2 ;;
        *) BUNDLE="$1"; shift ;;
    esac
done

if [[ -z "${BUNDLE}" ]]; then
    echo "ERROR: bundle path required" >&2
    usage >&2
    exit 2
fi

if [[ ! -d "${BUNDLE}" ]]; then
    echo "ERROR: not a directory: ${BUNDLE}" >&2
    exit 2
fi

python3 - "${BUNDLE}" "${ENT_OUTPUT}" <<'PY'
import json
import os
import plistlib
import subprocess
import sys
from pathlib import Path

bundle = Path(sys.argv[1])
ent_output = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else None

def is_macho(path):
    """Check if a file is a Mach-O binary by reading its magic bytes."""
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
    except (OSError, PermissionError):
        return False
    # MH_MAGIC, MH_MAGIC_64, FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64
    macho_magics = {
        b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",  # MH_MAGIC, MH_MAGIC_64
        b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",  # MH_CIGAM, MH_CIGAM_64
        b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",  # FAT_MAGIC, FAT_CIGAM
        b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",  # FAT_MAGIC_64, FAT_CIGAM_64
    }
    return magic in macho_magics

def classify_role(path, rel):
    """Classify the binary's role within the bundle."""
    rel_lower = rel.lower()
    parts = rel.split("/")

    if ".systemextension/" in rel:
        return "system-extension"
    if ".networkextension/" in rel or "NetworkExtension" in rel:
        return "network-extension"
    if ".appex/" in rel:
        return "app-extension"
    if ".xpc/" in rel or "XPCServices" in rel:
        return "xpc-service"
    if ".dext/" in rel:
        return "driverkit-extension"
    if "HelperTools" in rel or "Helper" in parts:
        return "privileged-helper"
    if "Updater" in rel or "updater" in rel_lower:
        return "updater"
    if "LaunchDaemons" in rel or "LaunchAgents" in rel:
        return "launchd-helper"
    if "Frameworks" in rel and ".framework/" in rel:
        return "framework"
    if "PlugIns" in rel or "Plugins" in rel:
        return "plugin"
    if "/MacOS/" in rel and parts.count("Contents") == 1:
        return "main-executable"
    if "Library/LoginItems" in rel:
        return "login-item"
    return "other"

def classify_type(path):
    """Thin vs fat, arm64 vs x86_64."""
    try:
        result = subprocess.run(
            ["file", str(path)], capture_output=True, text=True, timeout=5
        )
        out = result.stdout
    except (subprocess.TimeoutExpired, OSError):
        return "unknown"

    if "universal binary" in out or "fat file" in out:
        return "fat"
    if "arm64" in out:
        return "arm64"
    if "x86_64" in out:
        return "x86_64"
    if "Mach-O" in out:
        return "macho"
    return "unknown"

def get_entitlements(path):
    """Extract entitlements plist from a signed binary."""
    try:
        result = subprocess.run(
            ["codesign", "-d", "--entitlements", ":-", str(path)],
            capture_output=True, timeout=10
        )
        if result.returncode != 0 or not result.stdout.strip():
            return {}
        return plistlib.loads(result.stdout)
    except (subprocess.TimeoutExpired, OSError, plistlib.InvalidFileException):
        return {}

# Find all Mach-O binaries
binaries = []
for root, dirs, files in os.walk(bundle):
    # Skip .git and __pycache__
    dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", ".DS_Store")]
    for name in files:
        filepath = Path(root) / name
        if filepath.is_symlink():
            continue
        if is_macho(filepath):
            binaries.append(filepath)

# Sort by role priority: main exec first, then helpers, then frameworks
binaries.sort(key=lambda p: (
    0 if "MacOS" in str(p) else
    1 if "systemextension" in str(p).lower() else
    2 if "Helper" in str(p) or "XPCServices" in str(p) else
    3 if "Frameworks" in str(p) else 4,
    str(p)
))

# Collect data
rows = []
all_entitlements = {}

print("path\ttype\trole\tarch\tentitlements_count")

for filepath in binaries:
    rel = str(filepath.relative_to(bundle))
    role = classify_role(filepath, rel)
    arch = classify_type(filepath)
    ents = get_entitlements(filepath)
    ent_count = len(ents)

    print(f"{rel}\t{arch}\t{role}\t{arch}\t{ent_count}")

    if ent_output:
        all_entitlements[rel] = {
            "path": rel,
            "role": role,
            "arch": arch,
            "entitlement_count": ent_count,
            "entitlements": {k: str(v) if not isinstance(v, (str, bool, int, float, list)) else v
                            for k, v in ents.items()},
        }

if ent_output:
    out_path = Path(ent_output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(all_entitlements, indent=2, default=str) + "\n")
    print(f"\nEntitlements written to: {ent_output}", file=sys.stderr)

print(f"\nTotal Mach-O binaries: {len(binaries)}", file=sys.stderr)
PY
