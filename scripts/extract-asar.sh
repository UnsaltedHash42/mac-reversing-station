#!/usr/bin/env bash
# Tolerant asar extractor wrapper.
#
# Closes SHAKEDOWN_NOTES.md item #27. Upstream `asar` and `@electron/asar`
# both ENOENT-bail when an asar header claims a file is unpacked but the
# corresponding `<asar>.unpacked/<path>` is missing on disk. PASS-001 hit
# this on Rocket.Chat 4.13.0 and lost ~30 minutes diagnosing the empty
# extract directory before writing this trick.
#
# This wrapper invokes scripts/extract-asar.js, which walks the asar
# header directly and substitutes empty buffers for missing unpacked
# files (recording each substitution in a manifest). No npm install,
# no asar package required.
#
# Usage:
#   scripts/extract-asar.sh <input.asar> <out-dir>
#
# Requires Node 14+. Tested on Node 20.15. The companion .js intentionally
# avoids `@electron/asar` because that package requires Node 22.12+ and the
# old `asar@3` is unmaintained.

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $(basename "$0") <input.asar> <out-dir>" >&2
    exit 2
fi

INPUT_ASAR="$1"
OUT_DIR="$2"

if ! command -v node >/dev/null 2>&1; then
    echo "extract-asar: node not on PATH" >&2
    exit 2
fi

NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
if [[ "$NODE_MAJOR" -lt 14 ]]; then
    echo "extract-asar: need Node >=14, found $(node -v)" >&2
    exit 2
fi

if [[ ! -f "$INPUT_ASAR" ]]; then
    echo "extract-asar: no such file: $INPUT_ASAR" >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec node "$SCRIPT_DIR/extract-asar.js" "$INPUT_ASAR" "$OUT_DIR"
