# Corpus

Track the authorized targets and surfaces for each research pass.

## Corpus Passes

| Pass ID | Date | Target Family | Corpus Slice | Authorization Ref | Status | Metrics Row |
|---------|------|---------------|--------------|-------------------|--------|-------------|

## Target Inventory

| Target ID | App / Component | Version | Source | Family | Primary Surfaces | Notes |
|-----------|-----------------|---------|--------|--------|------------------|-------|

## Surface Checklist

Use this checklist per pass. Mark `n/a` with rationale rather than leaving blanks.

- [ ] App bundle metadata collected.
- [ ] LaunchAgents / LaunchDaemons inspected.
- [ ] MachServices / XPC services enumerated.
- [ ] Privileged helpers identified.
- [ ] Entitlements and code-signing metadata saved.
- [ ] Updater framework or custom updater checked.
- [ ] TCC / Accessibility / Automation surfaces checked.
- [ ] Sandbox and app group state checked.
- [ ] Keychain and persistent authorization stores checked when relevant.
- [ ] Candidate rows linked in `INDEX.md`.
- [ ] Metrics row updated in `METRICS.md`.

## Blockers

| Pass ID | Blocker | Type | Next Action |
|---------|---------|------|-------------|

Blocker types: `authorization`, `corpus`, `lab`, `tooling`, `version`, `reproduction`, `scope`.
