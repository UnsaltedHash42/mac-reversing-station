# Findings Repo Template

Copy this directory into the root of a project clone to start local findings files.

```bash
git clone https://github.com/UnsaltedHash42/mac-reversing-station ~/re/<program-name>
cd ~/re/<program-name>
rsync -a --ignore-existing templates/findings-repo/ ./
bash scripts/smoke-findings-repo.sh
```

Keep target-specific work private. It is for findings, artifacts, harnesses, and handoffs. Use Cursor from the project clone and ask it to use the relevant offensive-macos skills.

## Required Files

- `AUTHORIZATION.md` — records the authority, scope, prohibited targets, and review constraints for the research program.
- `LAB_SAFETY.md` — records machine roles, test users, snapshots, privacy/TCC hygiene, and destructive-test rules.
- `CORPUS.md` — records target families, app inventory, surface coverage, and pass IDs.
- `METRICS.md` — records candidate funnels, closures, escalations, confirmed findings, and blockers per pass.
- `INDEX.md` — tracks candidate and finding rows.
- `REPORTING.md` — explains report modes and evidence packaging.

## Daily Loop

1. Read `REPO_MODE`, `AUTHORIZATION.md`, `LAB_SAFETY.md`, `CORPUS.md`, `METRICS.md`, `INDEX.md`, `SUBMISSION_TRIAGE.md`, and `HANDOFF.md` if one exists.
2. Choose one target family, corpus pass, or candidate.
3. Confirm the pass ID and scope before collecting artifacts.
4. Save raw scan output under `findings/analysis/`.
5. Save logs, crash reports, screenshots, and proof artifacts under `artifacts/`.
6. Save custom harnesses under `tools/custom/<target>/`.
7. Update `INDEX.md`, `METRICS.md`, and `HANDOFF.md` before ending the session.

## Boundaries

This template is for authorized reverse engineering and vulnerability research. Keep operational exploit chaining, persistence, evasion, command-and-control, deployment tradecraft, and unrelated tooling out of this repo.

Real target names, PoCs, logs, metrics, and authorization records belong in this private findings repo. Do not copy them back into the station repo.
