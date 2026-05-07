# Findings Index

Use one row per candidate or confirmed finding. Link every row to a pass ID in `METRICS.md` so closed false positives and blockers are counted as research output.

| ID | Pass ID | Title | Class | Status | Severity | Primary Artifact | Next Action |
|----|---------|-------|-------|--------|----------|------------------|-------------|

## Status Values

- `hypothesis` — plausible class match, not yet backed by scanner or dynamic evidence.
- `scan-hit` — static or metadata sweep produced a candidate row.
- `hold` — likely worth revisiting, but not the current pass priority.
- `blocked` — cannot proceed until a lab, corpus, version, tool, or authorization issue is resolved.
- `escalated` — promoted from triage to focused deep dive.
- `reproducing` — active dynamic confirmation or PoC minimization.
- `confirmed` — lab reproduction and root cause are understood.
- `report-ready` — evidence package is ready for a report mode in `REPORTING.md`.
- `reported` — sent to vendor, internal team, red-team stakeholder, or Apple/platform channel.
- `closed` — closed with rationale. This is useful negative work and should be counted in `METRICS.md`.

## Closure Rationale

Every `closed` row must state why:

- Expected behavior.
- Already gated by authorization.
- No reachability from the attacker model.
- Duplicate of another row.
- Tooling false positive.
- Out of scope for the current authorization.
