---
name: offensive-macos-bundle-intake
description: >-
  Use when starting a macOS reversing pass from an app bundle, installer,
  framework, XPC bundle, helper, or bare binary path. Fires on "start target",
  "inventory this app", "point at this bundle", "begin PASS", and "target
  intake".
folder: offensive-macos-bundle-intake
source: skillz-bundle-first
trigger_phrases:
  - "start target"
  - "inventory this app"
  - "point at this bundle"
  - "begin PASS"
  - "target intake"
---

# Bundle Intake

> **Channel boundary:** `REPO_MODE=analysis`. Root-cause analysis, lab
> reproduction planning, defensive mapping, and reporting guidance only. No
> persistence, evasion, command-and-control, deployment, or live exploitation
> workflow.

## When To Use

- The operator gives a path such as `/Applications/<App>.app`, `targets/<App>.app`, a `.pkg`, `.framework`, `.xpc`, helper tool, or bare Mach-O binary.
- A new pass needs initial target state before selecting a family playbook or recipe.
- `CORPUS.md` needs agent-maintained target inventory, surface labels, family routing, Watch decision support, Scriptorium anchors, and worklist entries.

## Lab Topology — Where To Run This

| Step | Surface | How |
|------|---------|-----|
| Target intake | workstation/project clone | `python3 scripts/start-target.py "<target-path>" --pass-id <PASS-ID>` |
| Durable state | project clone | `CORPUS.md`, `SCRIPTORIUM.md`, `CHRONICLE.md`, `INDEX.md`, `METRICS.md`, `HANDOFF.md`, `findings/analysis/` |
| Static RE | lab host via Cursor | `ghidra-mcp` against the recorded `Lab Host Path Mapping` |
| Metadata/dynamic prep | lab host via Cursor | `macre-vm-mcp`, only after `LAB_SAFETY.md` allows the test shape |
| Manual confirmation | human operator | approve state-changing commands and dynamic tests before they run |

## Workflow

1. Confirm `REPO_MODE=analysis` and that authorization is an operator precondition.
2. Read `LAB_SAFETY.md`, `machines.md` if present, `CORPUS.md`, `METRICS.md`, `INDEX.md`, and `HANDOFF.md` if present.
3. Ask for a target path and pass ID if either is missing.
4. Run target intake when a local path exists:

   ```bash
   python3 scripts/start-target.py "<target-path>" --pass-id <PASS-ID>
   ```

5. If the target is already under `targets/` or the script cannot run, emulate the same work manually:
   - identify bundle metadata, main executable, helpers, XPC services, launchd plists, updater components, entitlements, code-signing flags, and privacy strings;
   - write a target map and dossier under `findings/analysis/`;
   - update `CORPUS.md` target inventory, discovered components, surface classification, Watch decision support, family labels, Scriptorium anchors, and worklist sections.
6. Classify from inventory first. Assign one or more family labels, or `unknown/mixed` when the surfaces do not clearly match a built-in family.
7. Use Watch recommendations and `docs/playbooks/investigation-recipes.md` to propose the first static sweep and expected evidence. Do not run dynamic tests until `LAB_SAFETY.md` identifies the host, user, snapshot/rollback, and allowed test shape.
8. When Ghidra or dynamic tooling needs the lab-host copy, sync and record the mapping:

   ```bash
   MACRE_MACHINE=<lab-host> MACRE_REMOTE_TARGETS=/Users/<remote-user>/Targets bash scripts/rsync-to-vm.sh --record <target-id> targets/
   ```

9. Use the recorded `CORPUS.md` `Lab Host Path Mapping` row for later Ghidra prompts.
10. Update `HANDOFF.md` with the target map path, selected family labels, next artifact, and any blocker.

## Output Shape

```markdown
## Intake Summary

- Pass ID:
- Target ID:
- Local target path:
- Target map:
- Dossier:
- Watch recommendation:
- Scriptorium anchor:
- Family labels:
- Primary surfaces:
- Recommended first sweep:
- Lab-host path, if synced:
- Dynamic testing status:
```

## Stop And Ask Before

- Running installers, helpers, launchd jobs, login items, or updaters.
- Attaching LLDB, running DTrace, resetting TCC, modifying keychain state, or triggering crash/DoS behavior.
- Copying target-specific evidence back into the station template repo.

## See Also

- `scripts/start-target.py`
- `scripts/rsync-to-vm.sh`
- `templates/findings-repo/CORPUS.md`
- `docs/playbooks/third-party-app-families.md`
- `Skills/offensive-macos-vuln-ontology/SKILL.md`
- `Skills/offensive-macos-station-topology/SKILL.md`
