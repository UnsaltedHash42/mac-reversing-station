# Findings Repo Template

Copy this directory into the root of a project clone to start local findings files.

```bash
git clone https://github.com/UnsaltedHash42/mac-reversing-station ~/re/<program-name>
cd ~/re/<program-name>
rsync -a --ignore-existing templates/findings-repo/ ./
bash scripts/smoke-findings-repo.sh
```

Keep target-specific work private. It is for findings, artifacts, harnesses, and handoffs. Use Cursor from the project clone and ask it to use the relevant offensive-macos skills.

## Start From A Target Path

After copying this template into a project clone, point the station at an app bundle, installer, framework, or binary:

```bash
python3 scripts/start-target.py "/Applications/<App Name>.app" --pass-id PASS-001
```

The script copies the target under `targets/`, writes a target map and dossier under `findings/analysis/`, and updates `CORPUS.md` with initial inventory, surfaces, family labels, Watch decision support, and Scriptorium anchors.

## Required Files

- `LAB_SAFETY.md` — records machine roles, test users, snapshots, privacy/TCC hygiene, and destructive-test rules.
- `CORPUS.md` — records target families, app inventory, surface coverage, and pass IDs.
- `METRICS.md` — records candidate funnels, closures, escalations, confirmed findings, and blockers per pass.
- `INDEX.md` — tracks candidate and finding rows.
- `REPORTING.md` — explains report modes and evidence packaging.
- `SCRIPTORIUM.md` — links claims, decisions, and evidence paths across sessions.
- `CHRONICLE.md` — records concise investigation events and next actions.

## Daily Loop

1. Read `REPO_MODE`, `LAB_SAFETY.md`, `CORPUS.md`, `METRICS.md`, `INDEX.md`, `SUBMISSION_TRIAGE.md`, and `HANDOFF.md` if one exists.
2. Confirm authorization as an operator precondition and record any project-specific scope notes in `CORPUS.md` or `HANDOFF.md`.
3. Choose one target path, corpus pass, or candidate.
4. Save raw scan output under `findings/analysis/`.
5. Save logs, crash reports, screenshots, and proof artifacts under `artifacts/`.
6. Save custom harnesses under `tools/custom/<target>/`.
7. Update `INDEX.md`, `METRICS.md`, `SCRIPTORIUM.md`, `CHRONICLE.md`, and `HANDOFF.md` before ending the session.

## Boundaries

This template is for authorized reverse engineering and vulnerability research. Keep operational exploit chaining, persistence, evasion, command-and-control, deployment tradecraft, and unrelated tooling out of this repo.

Real target names, PoCs, logs, metrics, and scope-sensitive records belong in this private findings repo. Do not copy them back into the station repo.
