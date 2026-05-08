---
name: offensive-macos-scriptorium-evidence
description: >-
  Use when linking claims, artifacts, decisions, and handoff state across a
  macOS reversing project.
folder: offensive-macos-scriptorium-evidence
source: skillz-wave4
trigger_phrases:
  - "scriptorium"
  - "evidence graph"
  - "flight recorder"
  - "why do we believe"
---

# Scriptorium Evidence

> **Channel boundary:** `REPO_MODE=analysis`. The Scriptorium preserves evidence and
> decisions. It does not store target binaries, PoCs, or sensitive artifacts in
> the station template.

## When To Use

- A static or dynamic output changes a hypothesis, candidate status, or next action.
- A future session needs to reconstruct why a decision was made.
- A Ghidra, LLDB, DTrace, source, or Electron artifact should be linked to a candidate.

## Workflow

1. Use the target ID and pass ID from `CORPUS.md`.
2. **Candidates are JSON files**, not freeform rows. Create with `scripts/triage.py create`; transition with `scripts/triage.py transition C-NNN <status>`. Every transition records history + evidence + timestamp automatically.
3. Add or update an anchor row in `SCRIPTORIUM.md` with the claim, evidence path, candidate id, and the binary's sha256 (hash-pin every claim).
4. Append a concise event to `CHRONICLE.md` when the investigation direction changes.
5. After candidate transitions, run `scripts/triage.py render` so `INDEX.md` reflects current state. `INDEX.md` is generated; never hand-edit.
6. Update `METRICS.md` counts on close / escalate / report transitions.
7. Update `HANDOFF.md` so the next session can resume from the latest evidence path.

## Hash-pinning

Every dynamic transcript and decompilation citation should include the sha256
of the Mach-O slice that produced it. This protects against silent target
updates: if the slice changes, evidence written against the old slice no
longer counts.

```bash
shasum -a 256 targets/<target>
# or, on the lab host where the binary actually ran
ssh <lab-host> shasum -a 256 /Users/<remote-user>/Targets/<target>
```

Pass via `scripts/triage.py transition C-NNN <status> --binary-sha256 <hex>`.

## See Also

- `scripts/triage.py`
- `templates/findings-repo/SCRIPTORIUM.md`
- `templates/findings-repo/CHRONICLE.md`
- `templates/findings-repo/INDEX.md` (schema + state machine reference)
- `Skills/offensive-macos-watch-static-analysis/SKILL.md`
