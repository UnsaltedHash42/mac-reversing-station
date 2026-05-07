# Corpus

Agent-maintained state for target intake, surface coverage, family labels, and pass progress. Authorization is an operator precondition; record only project-specific scope notes needed for the investigation.

## Corpus Passes

| Pass ID | Date | Target Family Labels | Corpus Slice | Scope Notes | Status | Metrics Row |
|---------|------|----------------------|--------------|-------------|--------|-------------|

## Target Inventory

| Target ID | App / Component | Version | Source | Family Labels | Primary Surfaces | Notes |
|-----------|-----------------|---------|--------|---------------|------------------|-------|

## Discovered Components

Agent-maintained component inventory. Keep this summarized; large generated maps belong in `findings/analysis/`.

| Target ID | Component | Kind | Path | Notes |
|-----------|-----------|------|------|-------|

## Surface Classification

| Target ID | Pass ID | Surfaces | Ontology Candidates | Evidence Path | Notes |
|-----------|---------|----------|---------------------|---------------|-------|

## Family Labels And Routing

Family labels are evidence-derived and may be multi-valued. Use `unknown/mixed` when the inventory does not cleanly match an existing playbook.

| Target ID | Family Labels | Confidence | Unknown / Mixed Notes | Next Playbook |
|-----------|---------------|------------|-----------------------|---------------|

## Lab Host Path Mapping

Use this after syncing targets to the lab host for Ghidra, LLDB, DTrace, logs, or dynamic checks.

| Target ID | Local Path | Remote Path | Synced At | Notes |
|-----------|------------|-------------|-----------|-------|

## Current Hypotheses And Worklist

| Pass ID | Hypothesis / Task | Evidence So Far | Next Action | Status |
|---------|-------------------|-----------------|-------------|--------|

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
