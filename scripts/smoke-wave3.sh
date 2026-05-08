#!/usr/bin/env bash
# Structural sanity check for the macOS reversing station.
set -u

cd "$(dirname "$0")/.."
FAILS=0
PASSES=0
LIVE=0
RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RESET=$'\033[0m'

for arg in "$@"; do
    case "$arg" in
        --live) LIVE=1 ;;
        -h|--help)
            printf "usage: %s [--live]\n" "$0"
            printf "  default: structural checks only\n"
            printf "  --live: also run lab-host/Ghidra live checks from smoke-wave2\n"
            exit 0
            ;;
        *)
            printf "unknown argument: %s\n" "$arg" >&2
            exit 2
            ;;
    esac
done

ok() { printf "  %sPASS%s  %s\n" "$GREEN" "$RESET" "$1"; PASSES=$((PASSES+1)); }
fail() { printf "  %sFAIL%s  %s\n  %s   %s-> %s%s\n" "$RED" "$RESET" "$1" " " "$YELLOW" "$2" "$RESET"; FAILS=$((FAILS+1)); }
section() { printf "\n== %s ==\n" "$1"; }

section "Skill bundles"
if python3 scripts/validate_workstation_bundles.py --root . --doc docs/workstation/skill-bundles.md >/dev/null 2>&1; then
    ok "skill bundle index referenced paths validate"
else
    fail "skill bundle index failed" "python3 scripts/validate_workstation_bundles.py"
fi

if python3 - <<'PY'
from pathlib import Path
import sys

doc = Path("docs/workstation/skill-bundles.md").read_text(encoding="utf-8")
missing = []
bad_frontmatter = []
for path in sorted(Path("Skills").glob("offensive-macos-*/SKILL.md")):
    skill_dir = str(path.parent)
    if skill_dir not in doc:
        missing.append(skill_dir)
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        bad_frontmatter.append(f"{path}: missing frontmatter")
        continue
    parts = text.split("---", 2)
    if len(parts) < 3 or "description:" not in parts[1]:
        bad_frontmatter.append(f"{path}: missing description")

if missing or bad_frontmatter:
    for item in missing:
        print(f"missing skill-bundles.md citation: {item}")
    for item in bad_frontmatter:
        print(item)
    sys.exit(1)
PY
then
    ok "all offensive macOS skills are indexed and have sane frontmatter"
else
    fail "skill index/frontmatter inverse check failed" "inspect Skills/offensive-macos-*/SKILL.md and docs/workstation/skill-bundles.md"
fi

section "Station docs"
if python3 - <<'PY'
from pathlib import Path
import sys

required = [
    "docs/ontology/README.md",
    "docs/ontology/macos-vulnerability-classes.md",
    "docs/playbooks/third-party-app-families.md",
    "docs/playbooks/privileged-helpers-updaters.md",
    "docs/playbooks/enterprise-security-agents.md",
    "docs/playbooks/developer-tools.md",
    "docs/playbooks/tcc-heavy-consumer-apps.md",
    "docs/playbooks/os-components.md",
    "docs/playbooks/adding-target-families.md",
    "docs/playbooks/investigation-recipes.md",
    "docs/research/macos-cve-survey-2026.md",
    "templates/findings-repo/VM_ACTIONS.md",
    "templates/findings-repo/POC_SCAFFOLDING.md",
    "templates/findings-repo/templates/poc/README.md.template",
    "ghidra-scripts/scan_launchd_machservice_topology.py",
    "ghidra-scripts/scan_system_extension_surface.py",
    "ghidra-scripts/scan_endpoint_security_client.py",
    "ghidra-scripts/scan_private_framework_dependency.py",
]
missing = [path for path in required if not Path(path).is_file()]
if missing:
    print("\n".join(missing))
    sys.exit(1)
PY
then
    ok "ontology and playbook docs exist"
else
    fail "station docs missing" "inspect docs/ontology and docs/playbooks"
fi

if python3 scripts/validate-recipes.py --root . >/dev/null; then
    ok "investigation recipe registry validates"
else
    fail "investigation recipe registry failed" "python3 scripts/validate-recipes.py --root ."
fi

section "Setup scripts"
if bash scripts/setup-keep.sh --help >/dev/null && \
   bash scripts/init-project.sh --help >/dev/null && \
   python3 scripts/configure-cursor-mcp.py --host lab-host --remote-home /Users/remote --dry-run >/dev/null; then
    ok "setup scripts expose help and MCP config dry-run"
else
    fail "setup script smoke failed" "check scripts/setup-keep.sh, scripts/init-project.sh, and scripts/configure-cursor-mcp.py"
fi

section "Findings template"
if bash templates/findings-repo/scripts/smoke-findings-repo.sh >/dev/null 2>&1; then
    ok "findings-repo template smokes"
else
    fail "findings-repo template smoke failed" "bash templates/findings-repo/scripts/smoke-findings-repo.sh"
fi

section "Ghidra scripts"
if bash tests/ghidra-scripts/smoke.sh >/dev/null 2>&1; then
    ok "Ghidra hunt scripts pass structural smoke"
else
    fail "Ghidra hunt script smoke failed" "bash tests/ghidra-scripts/smoke.sh"
fi

section "Triage"
if python3 -m unittest tests.test_triage >/dev/null 2>&1; then
    ok "candidate triage CLI passes unit tests"
else
    fail "triage unit tests failed" "python3 -m unittest tests.test_triage"
fi

section "Station hygiene"
if python3 - <<'PY'
from pathlib import Path
import sys

bad = []
for root in ("docs", "scripts", "Skills", "ghidra-scripts", "templates"):
    for path in Path(root).rglob("*"):
        if path.is_dir():
            continue
        if str(path) in {"scripts/smoke-wave1.sh", "scripts/smoke-wave2.sh", "scripts/smoke-wave3.sh"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if "hopper-mcp" in text or "HopperMCP" in text:
            bad.append(f"stale Hopper MCP reference: {path}")
        # Best-effort tripwire only. Templates may name placeholders, but should not
        # contain copied target rows, PoC dumps, or real artifact paths.
        if "BEGIN REAL TARGET ARTIFACT" in text or "PASS-METRICS-DUMP" in text:
            bad.append(f"possible target artifact leakage: {path}")

if bad:
    print("\n".join(bad))
    sys.exit(1)
PY
then
    ok "station hygiene checks passed"
else
    fail "station hygiene check failed" "inspect stale Hopper references or target artifact tripwire hits"
fi

section "Live workstation checks"
if [[ "$LIVE" -eq 1 ]]; then
    if bash scripts/smoke-wave2.sh >/dev/null 2>&1; then
        ok "live lab-host workstation smoke passes"
    else
        fail "live lab-host workstation smoke failed" "bash scripts/smoke-wave2.sh"
    fi
else
    ok "live lab-host/Ghidra checks skipped by default; pass --live to run them"
fi

printf "\nSummary: %s pass, %s fail\n" "$PASSES" "$FAILS"
if [[ "$FAILS" -ne 0 ]]; then
    exit 1
fi
