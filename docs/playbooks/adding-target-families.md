# Adding Target Families

Target families are workflow shortcuts, not taxonomy labels for their own sake. Add one only when repeated projects show that a group of targets needs a distinct starting path that the existing families and ontology do not cover well.

## When Not To Add A Family

- A single app has unusual branding but ordinary XPC, updater, TCC, or developer-tool surfaces.
- The target can be handled by multiple existing labels plus `unknown/mixed` notes.
- The proposed family does not change the first three actions an agent should take.
- The difference is mostly audience, vendor, or product category rather than technical surface.

## Evidence Required

Before adding a family, collect:

- At least two or three targets where the same surface pattern repeats.
- The shared boundaries, attacker-controlled inputs, and expected artifacts.
- Mapped ontology classes from `docs/ontology/macos-vulnerability-classes.md`.
- False-positive traps that differ from existing playbooks.
- First-pass static sweeps and dynamic checks that are meaningfully different.
- A reason `unknown/mixed` is no longer enough.

## Family Template

```markdown
## <Family Name>

- Repeated target evidence:
- Distinct surfaces:
- Ontology classes:
- First inventory signals:
- First static sweeps:
- Dynamic tests that require lab-safety confirmation:
- False-positive traps:
- Metrics fields or corpus notes:
- Skills to update:
```

## Files To Update

- Add or update a playbook under `docs/playbooks/`.
- Add a Cursor skill under `Skills/offensive-macos-family-<name>/` only if it changes agent behavior.
- Register any new skill in `docs/workstation/skill-bundles.md`.
- Update `docs/playbooks/third-party-app-families.md`.
- Update `scripts/smoke-wave3.sh` only when structural checks need to know about the new family.

Keep the built-in set small. A good `unknown/mixed` route with strong ontology notes is better than a family that no one can apply consistently.
