#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

[[ -f "${ROOT}/REPO_MODE" ]] || fail "REPO_MODE missing"
[[ "$(tr -d '[:space:]' < "${ROOT}/REPO_MODE")" == "analysis" ]] || fail "REPO_MODE must contain analysis"

for path in \
    "LAB_SAFETY.md" \
    "CORPUS.md" \
    "METRICS.md" \
    "INDEX.md" \
    "REPORTING.md" \
    "SUBMISSION_TRIAGE.md" \
    "EVIDENCE_LEDGER.md" \
    "FLIGHT_RECORDER.md" \
    "HANDOFF.md.template" \
    "machines.md.template" \
    ".cursor/rules/rule-analysis.mdc" \
    "findings/analysis" \
    "findings/reports" \
    "artifacts" \
    "tools/custom"
do
    [[ -e "${ROOT}/${path}" ]] || fail "required path missing: ${path}"
done

grep -q "Pass ID" "${ROOT}/INDEX.md" || fail "INDEX.md must include Pass ID column"
grep -q "Pass Funnel" "${ROOT}/METRICS.md" || fail "METRICS.md must include Pass Funnel"
grep -q "Target Inventory" "${ROOT}/CORPUS.md" || fail "CORPUS.md must include Target Inventory"
grep -q "Discovered Components" "${ROOT}/CORPUS.md" || fail "CORPUS.md must include Discovered Components"
grep -q "Surface Classification" "${ROOT}/CORPUS.md" || fail "CORPUS.md must include Surface Classification"
grep -q "Scryer Decision Support" "${ROOT}/CORPUS.md" || fail "CORPUS.md must include Scryer Decision Support"
grep -q "Source-Binary Correlation" "${ROOT}/CORPUS.md" || fail "CORPUS.md must include Source-Binary Correlation"
grep -q "Family Labels And Routing" "${ROOT}/CORPUS.md" || fail "CORPUS.md must include Family Labels And Routing"
grep -q "Lab Host Path Mapping" "${ROOT}/CORPUS.md" || fail "CORPUS.md must include Lab Host Path Mapping"
grep -q "Ledger Anchors" "${ROOT}/CORPUS.md" || fail "CORPUS.md must include Ledger Anchors"
grep -q "Current Hypotheses And Worklist" "${ROOT}/CORPUS.md" || fail "CORPUS.md must include Current Hypotheses And Worklist"
grep -q "Destructive-Test Checklist" "${ROOT}/LAB_SAFETY.md" || fail "LAB_SAFETY.md must include Destructive-Test Checklist"
grep -q "Report Modes" "${ROOT}/REPORTING.md" || fail "REPORTING.md must include Report Modes"
grep -q "Anchor ID" "${ROOT}/EVIDENCE_LEDGER.md" || fail "EVIDENCE_LEDGER.md must include Anchor ID"
grep -q "Time UTC" "${ROOT}/FLIGHT_RECORDER.md" || fail "FLIGHT_RECORDER.md must include Time UTC"

if [[ ! -d "${ROOT}/.git" ]]; then
    echo "WARN: git is not initialized yet. Run: git init"
else
    git -C "${ROOT}" status --short >/dev/null
fi

echo "OK - findings repo template structure is valid."
