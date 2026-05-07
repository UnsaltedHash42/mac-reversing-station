---
name: offensive-macos-ledger-evidence
description: >-
  Use when linking claims, artifacts, decisions, and handoff state across a
  macOS reversing project.
folder: offensive-macos-ledger-evidence
source: skillz-wave4
trigger_phrases:
  - "ledger"
  - "evidence graph"
  - "flight recorder"
  - "why do we believe"
---

# Ledger Evidence

> **Channel boundary:** `REPO_MODE=analysis`. The Ledger preserves evidence and
> decisions. It does not store target binaries, PoCs, or sensitive artifacts in
> the station template.

## When To Use

- A static or dynamic output changes a hypothesis, candidate status, or next action.
- A future session needs to reconstruct why a decision was made.
- A Ghidra, LLDB, DTrace, source, or Electron artifact should be linked to a candidate.

## Workflow

1. Use the target ID and pass ID from `CORPUS.md`.
2. Add or update an anchor row in `EVIDENCE_LEDGER.md` with the claim, evidence path, status, and next action.
3. Append a concise event to `FLIGHT_RECORDER.md` when the investigation direction changes.
4. Reflect candidate status changes in `INDEX.md` and counts in `METRICS.md`.
5. Update `HANDOFF.md` so the next agent can resume from the latest evidence path.

## See Also

- `templates/findings-repo/EVIDENCE_LEDGER.md`
- `templates/findings-repo/FLIGHT_RECORDER.md`
- `Skills/offensive-macos-scryer-static-analysis/SKILL.md`
