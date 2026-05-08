#!/usr/bin/env bash
# Structural smoke test for Ghidra hunt scripts.
#
# Verifies:
#   - the shared library exists and exposes ANCHOR_HEADER
#   - every scan / dump / export script parses with valid Python syntax
#   - every scan / dump / export script imports from _re_lib (so the
#     unified tiered-anchor contract is in force)
#   - the README is present
#
# Live emission of the unified TSV header is verified by the `--live`
# wave, which actually runs each script under Ghidra.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="${ROOT}/ghidra-scripts"

python3 - <<'PY' "${SCRIPT_DIR}"
from __future__ import annotations

import ast
import sys
from pathlib import Path

script_dir = Path(sys.argv[1])

# Every scan / dump / export script in this dir is expected to use the
# tiered anchor contract via _re_lib. Helpers (files starting with `_`)
# and the README are excluded.
expected_scripts = sorted(
    p.name for p in script_dir.glob("*.py") if not p.name.startswith("_")
)

errors: list[str] = []

# 1. _re_lib.py exists and exposes ANCHOR_HEADER + key helpers.
re_lib = script_dir / "_re_lib.py"
if not re_lib.is_file():
    errors.append("missing ghidra-scripts/_re_lib.py")
else:
    text = re_lib.read_text(encoding="utf-8")
    if "ANCHOR_HEADER" not in text:
        errors.append("_re_lib.py missing ANCHOR_HEADER")
    for symbol in ("class AnchorWriter", "class StringIndex", "def find_external", "def callers_of"):
        if symbol not in text:
            errors.append(f"_re_lib.py missing {symbol!r}")

# 2. Every script parses and imports from _re_lib.
for name in expected_scripts:
    path = script_dir / name
    text = path.read_text(encoding="utf-8")
    try:
        ast.parse(text, filename=str(path))
    except SyntaxError as exc:
        errors.append(f"{name}: syntax error: {exc}")
        continue
    if "from _re_lib import" not in text and "import _re_lib" not in text:
        errors.append(f"{name}: does not import _re_lib (tiered-anchor contract)")

# 3. README exists.
readme = script_dir / "README.md"
if not readme.is_file():
    errors.append("missing ghidra-scripts/README.md")

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    raise SystemExit(1)

print(f"OK - {len(expected_scripts)} Ghidra scripts use the tiered anchor contract.")
PY
