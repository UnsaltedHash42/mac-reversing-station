# Findings Index

This file is **regenerated** by `scripts/triage.py render` from
`findings/candidates/*.json`. To add or change rows, edit candidate
files via the triage CLI rather than this file.

## How candidates work

Every candidate is one JSON file at `findings/candidates/C-NNN.json`.
The schema:

```json
{
  "id": "C-001",
  "pass_id": "PASS-001",
  "target_id": "T-001",
  "title": "tccd should-accept-1",
  "vuln_class": "wrong-door",
  "status": "scan-hit",
  "severity": "medium",
  "primary_artifact": "findings/analysis/PASS-001-tccd-xpc-endpoints.tsv",
  "anchor": {
    "tier": "A",
    "kind": "xpc_listener_callsite",
    "name": "_setup_listener",
    "address": "0x100008abc"
  },
  "evidence": [],
  "history": [{"status": "scan-hit", "at": "2026-05-07T12:00:00Z"}],
  "next_action": "confirm in lldb",
  "closure_reason": "<required when status == closed>"
}
```

Required fields: `id`, `pass_id`, `target_id`, `title`, `vuln_class`,
`status`, `severity`, `primary_artifact`. `closure_reason` is required
when `status == "closed"`.

## CLI

```bash
# Create a new candidate (id auto-assigned)
scripts/triage.py create \
  --pass-id PASS-001 --target T-001 \
  --title 'tccd should-accept-1' --vuln-class wrong-door \
  --severity medium \
  --primary-artifact findings/analysis/PASS-001-tccd.tsv \
  --anchor-tier A --anchor-kind xpc_listener_callsite \
  --anchor-name _setup_listener --anchor-address 0x100008abc

# Transition a candidate (history + evidence recorded automatically)
scripts/triage.py transition C-001 escalated
scripts/triage.py transition C-001 reproducing
scripts/triage.py transition C-001 closed \
  --reason 'audit token resolved before authorization; expected behavior' \
  --evidence-path artifacts/PASS-001-c001.lldb.log \
  --evidence-kind lldb_transcript \
  --binary-sha256 <hex>

# List + filter
scripts/triage.py list --status escalated
scripts/triage.py list --pass PASS-001

# Validate the schema of every candidate file
scripts/triage.py validate

# Regenerate this file from the candidate files
scripts/triage.py render
```

## Status values

- `hypothesis` -- plausible class match, no evidence yet.
- `scan-hit` -- static / metadata sweep produced this candidate row.
- `hold` -- worth revisiting, not the current pass priority.
- `blocked` -- cannot proceed until a lab / auth / tool issue is fixed.
- `escalated` -- promoted from triage to focused deep dive.
- `reproducing` -- active dynamic confirmation or PoC minimization.
- `confirmed` -- lab reproduction and root cause understood.
- `report-ready` -- evidence package is ready for `REPORTING.md`.
- `reported` -- sent to vendor / internal team / Apple.
- `closed` -- closed with rationale. Closures count in `METRICS.md`.

## State machine

```
hypothesis -> scan-hit | hold | closed | blocked
scan-hit   -> escalated | hold | closed | blocked
hold       -> scan-hit | escalated | closed | blocked
blocked    -> scan-hit | escalated | closed
escalated  -> reproducing | hold | closed | blocked
reproducing-> confirmed | hold | closed | blocked
confirmed  -> report-ready | closed
report-ready -> reported | closed
reported   -> closed
closed     -> (terminal; reopen by hand-editing the JSON)
```

The triage CLI rejects illegal transitions and requires `--reason`
when entering `closed`.

## Closure rationale

Every `closed` candidate must carry a `closure_reason`. Common values:

- Expected behavior.
- Already gated by authorization.
- No reachability from the attacker model.
- Duplicate of another candidate.
- Tooling false positive.
- Out of scope for the current authorization.

## Generated table

| ID | Pass ID | Target | Title | Class | Status | Severity | Primary Artifact | Next Action |
|----|---------|--------|-------|-------|--------|----------|------------------|-------------|

(Run `scripts/triage.py render` to populate this table from
`findings/candidates/*.json`.)
