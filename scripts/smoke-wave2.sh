#!/usr/bin/env bash
# End-to-end sanity check for the Wave 2 macOS bug-hunting station.
# Wave 3 structural checks live in scripts/smoke-wave3.sh; pass --live there
# to include this live NightBlood/Ghidra smoke.
set -u

cd "$(dirname "$0")/.."
FAILS=0
PASSES=0
RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RESET=$'\033[0m'

ok() { printf "  %sPASS%s  %s\n" "$GREEN" "$RESET" "$1"; PASSES=$((PASSES+1)); }
fail() { printf "  %sFAIL%s  %s\n  %s   %s-> %s%s\n" "$RED" "$RESET" "$1" " " "$YELLOW" "$2" "$RESET"; FAILS=$((FAILS+1)); }
section() { printf "\n== %s ==\n" "$1"; }

section "Skills"
if python3 scripts/validate_workstation_bundles.py --root . --doc docs/workstation/skill-bundles.md >/dev/null 2>&1; then
    ok "skill bundle index validates"
else
    fail "skill bundle index failed" "python3 scripts/validate_workstation_bundles.py"
fi

if python3 - <<'PY'
from pathlib import Path
import sys
bad = []
for path in Path("Skills").glob("offensive-macos-*/SKILL.md"):
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        bad.append(f"{path}: missing frontmatter")
        continue
    parts = text.split("---", 2)
    if len(parts) < 3 or "description:" not in parts[1]:
        bad.append(f"{path}: missing description")
if bad:
    print("\n".join(bad))
    sys.exit(1)
PY
then
    ok "skill frontmatter shape is sane"
else
    fail "skill frontmatter shape failed" "inspect Skills/offensive-macos-*/SKILL.md"
fi

section "MCP config"
if python3 -m json.tool "${HOME}/.cursor/mcp.json" >/dev/null 2>&1; then
    ok "Cursor MCP JSON parses"
else
    fail "Cursor MCP JSON invalid" "python3 -m json.tool ~/.cursor/mcp.json"
fi

if python3 - <<'PY'
import json
from pathlib import Path
cfg = json.loads(Path.home().joinpath(".cursor/mcp.json").read_text())
servers = cfg.get("mcpServers", {})
if "ghidra-mcp" not in servers:
    raise SystemExit("missing ghidra-mcp")
if "hopper-mcp" in servers:
    raise SystemExit("hopper-mcp should be absent")
PY
then
    ok "ghidra-mcp present and hopper-mcp absent"
else
    fail "MCP server set is wrong" "edit ~/.cursor/mcp.json"
fi

section "NightBlood"
if ssh -o BatchMode=yes -o ConnectTimeout=5 NightBlood true >/dev/null 2>&1; then
    ok "SSH key auth to NightBlood works"
else
    fail "NightBlood SSH key auth failed" "bash scripts/install-vm-ssh-key.sh"
fi

if bash scripts/install-ghidra-host.sh --smoke >/dev/null 2>&1; then
    ok "Ghidra headless MCP live smoke passes"
else
    fail "Ghidra headless MCP smoke failed" "bash scripts/install-ghidra-host.sh --smoke"
fi

section "Ghidra scripts"
if bash tests/ghidra-scripts/smoke.sh >/dev/null 2>&1; then
    ok "Ghidra hunt scripts pass structural smoke"
else
    fail "Ghidra hunt script smoke failed" "bash tests/ghidra-scripts/smoke.sh"
fi

section "Findings template"
TMPDIR="$(mktemp -d)"
if cp -R templates/findings-repo "${TMPDIR}/test-re" && (cd "${TMPDIR}/test-re" && bash scripts/smoke-findings-repo.sh >/dev/null 2>&1); then
    ok "findings-repo template clones and smokes"
else
    fail "findings-repo template smoke failed" "bash templates/findings-repo/scripts/smoke-findings-repo.sh"
fi
rm -rf "${TMPDIR}"

section "Retirement checks"
if python3 - <<'PY'
from pathlib import Path
bad = []
for root in ("docs", "scripts", "Skills"):
    for path in Path(root).rglob("*"):
        if path.is_dir():
            continue
        if path.parts[:2] == ("Skills", "offensive-macos-tooling-hopper"):
            continue
        if str(path) in {"scripts/smoke-wave1.sh", "scripts/smoke-wave2.sh"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if "hopper-mcp" in text or "HopperMCP" in text:
            bad.append(str(path))
if bad:
    print("\n".join(bad))
    raise SystemExit(1)
PY
then
    ok "no stale Hopper MCP references outside deprecated Hopper skill"
else
    fail "stale Hopper MCP references remain" "search docs scripts Skills excluding tooling-hopper"
fi

printf "\nSummary: %s pass, %s fail\n" "$PASSES" "$FAILS"
if [[ "$FAILS" -ne 0 ]]; then
    exit 1
fi
