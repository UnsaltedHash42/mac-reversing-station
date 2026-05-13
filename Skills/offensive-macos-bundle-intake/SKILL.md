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
6. **Derive trigger signals from entitlement values, not just family labels** (see "Entitlement Trigger Signals" below). PASS-001 missed `application-groups = S6UPZG7ZR3.chat.rocket` as a keychain-confused-deputy signal because the intake recipe only routed off family labels. The trigger table below routes specific entitlement values to the hunt skills they imply; record each match in `CORPUS.md` under "Trigger signals" so `offensive-macos-vuln-ontology` reads them when generating hypotheses.
7. Classify from inventory first. Assign one or more family labels, or `unknown/mixed` when the surfaces do not clearly match a built-in family.
8. Use Watch recommendations and `docs/playbooks/investigation-recipes.md` to propose the first static sweep and expected evidence. Do not run dynamic tests until `LAB_SAFETY.md` identifies the host, user, snapshot/rollback, and allowed test shape.
9. When Ghidra or dynamic tooling needs the lab-host copy, sync and record the mapping:

   ```bash
   MACRE_MACHINE=<lab-host> MACRE_REMOTE_TARGETS=/Users/<remote-user>/Targets bash scripts/rsync-to-vm.sh --record <target-id> targets/
   ```

10. Use the recorded `CORPUS.md` `Lab Host Path Mapping` row for later Ghidra prompts.
11. Update `HANDOFF.md` with the target map path, selected family labels, next artifact, and any blocker.

## Entitlement Trigger Signals

Map specific entitlement keys (or values) to the hunt skill or scanner
they imply. Record each match in `CORPUS.md` under a `Trigger signals`
section so the ontology layer reads them when generating hypotheses.

| Entitlement | Triggers | Why |
|---|---|---|
| `com.apple.security.application-groups` (any value) | `offensive-macos-hunt-keychain-access-group` | Application-group identifiers are also valid keychain access-group identifiers. If credentials are stored under the group with ACLs that don't pin to a code-signing identity, any other app signed by the same team reads them. Classic confused-deputy. |
| `com.apple.security.automation.apple-events` | `offensive-macos-hunt-url-scheme-hijack` (companion check) + AppleScript-target audit | App can send AppleEvents to control other apps. An IPC handler that takes an AppleEvent target from the renderer or a URL handler is a renderer→arbitrary-app-control pivot. |
| `com.apple.developer.endpoint-security.client` | `offensive-macos-family-enterprise-agents` | EDR-class surface; daemon runs as root with a kernel callback; entirely different review shape. |
| `com.apple.security.cs.allow-unsigned-executable-memory` | `offensive-macos-shellcode-arm64` (signal, not skill) | Unsigned executable memory == JIT or runtime patching. Search for `mmap` / `mprotect` with `PROT_EXEC` and identify the JIT region's protection lifecycle. |
| `com.apple.security.cs.disable-library-validation` | `offensive-macos-hunt-private-framework-hijack` | Library validation off means a tampered or substituted dylib loads without rejection. Combine with rpath / weak-link audit. |
| `com.apple.private.security.no-sandbox` | `offensive-macos-family-os-components` | Apple-signed binary opting out of sandbox. Review attack surface as if it had no boundary. |
| `com.apple.private.tcc.allow-prompting` (any) | `offensive-macos-hunt-tcc-prompt-attribution` | App takes part in TCC prompt routing; check responsible-process accounting. |

Add new rows when a new pass surfaces a new entitlement-to-skill mapping.
A row should only land here when at least one real target's entitlement
value would fire it — speculative entries dilute the signal.

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
