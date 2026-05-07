# Metrics

Metrics make research throughput visible. A pass with no confirmed findings can still be valuable when coverage, closures, and blockers are recorded.

## Pass Funnel

| Pass ID | Target Family Labels | Targets | Major Binaries | Surfaces Enumerated | Candidates | Closed | Hold | Blocked | Escalated | Confirmed | Report Ready | Notes |
|---------|----------------------|---------|----------------|---------------------|------------|--------|------|---------|-----------|-----------|--------------|-------|

## Closure Quality

| Candidate ID | Pass ID | Closure Type | Rationale | Reuse In Future Triage |
|--------------|---------|--------------|-----------|------------------------|

Closure types:

- `expected-behavior`
- `already-gated`
- `not-reachable`
- `duplicate`
- `tooling-false-positive`
- `out-of-scope`
- `needs-version`

## Blocker Rollup

| Pass ID | Blocker Type | Count | Most Important Next Action |
|---------|--------------|-------|----------------------------|

Blocker types:

- `authorization`
- `corpus`
- `lab`
- `tooling`
- `version`
- `reproduction`
- `scope`

## Family Coverage Rollup

Use this section when you want to see which evidence-derived app family labels have been exercised. Add new family labels only after repeated projects prove they need a distinct workflow.

| Target Family | Pass ID | Status | Notes |
|---------------|---------|--------|-------|
| privileged helpers / updaters | | pending | |
| enterprise / security agents | | pending | |
| developer tools | | pending | |
| TCC-heavy consumer apps | | pending | |
