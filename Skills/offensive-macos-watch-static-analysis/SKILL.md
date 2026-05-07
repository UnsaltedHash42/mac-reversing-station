---
name: offensive-macos-watch-static-analysis
description: >-
  Use when turning target intake, dossier facts, and first-pass static sweeps
  into decision support for a macOS reversing pass.
folder: offensive-macos-watch-static-analysis
source: skillz-wave4
trigger_phrases:
  - "watch"
  - "static decision support"
  - "recommend the first sweep"
  - "what should we analyze next"
---

# Watch Static Analysis

> **Channel boundary:** `REPO_MODE=analysis`. Triage, root-cause analysis,
> defensive mapping, and reporting only. Watch recommends next evidence; it
> does not claim proof.

## When To Use

- Target intake has produced a target map or dossier.
- The operator asks what static sweep, recipe, or manual check should happen next.
- A pass needs coverage gaps and decision support summarized before dynamic work.

## Workflow

1. Read `CORPUS.md`, the target map, and the dossier under `findings/analysis/`.
2. Identify observed surfaces, family labels, Electron/source indicators, and coverage gaps.
3. Select recipes from `docs/playbooks/investigation-recipes.md`.
4. Recommend one next artifact: a Ghidra TSV, decompile note, source-correlation note, Electron IPC note, or Gatehouse LLDB confirmation plan.
5. Update `CORPUS.md`, `SCRIPTORIUM.md`, `CHRONICLE.md`, and `HANDOFF.md` when the decision changes project state.

## Output Shape

```markdown
## Watch Recommendation

- Target ID:
- Pass ID:
- Dossier:
- Observed surfaces:
- Recommended recipe:
- First artifact to produce:
- Coverage gaps:
- Stop condition:
```

## See Also

- `scripts/start-target.py`
- `templates/findings-repo/CORPUS.md`
- `docs/playbooks/investigation-recipes.md`
- `Skills/offensive-macos-bundle-intake/SKILL.md`
