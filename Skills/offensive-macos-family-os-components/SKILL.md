---
name: offensive-macos-family-os-components
description: >-
  Use when auditing Apple OS internals on macOS - Apple-signed app bundles,
  daemons, agents, frameworks, PrivateFrameworks, system extensions, network
  extensions, Endpoint Security clients, DriverKit/IOKit-adjacent components,
  XPC services, and launchd/MachService surfaces. Fires on "OS component",
  "Apple OS internals", "system daemon", "PrivateFramework", "system
  extension", "network extension", "Endpoint Security", "DriverKit", and
  "launchd MachService".
folder: offensive-macos-family-os-components
source: skillz-wave5
trigger_phrases:
  - "OS component"
  - "Apple OS internals"
  - "system daemon"
  - "PrivateFramework"
  - "system extension"
  - "network extension"
  - "Endpoint Security"
  - "DriverKit"
  - "launchd MachService"
---

# Family: Apple OS Components

> **Channel boundary:** `REPO_MODE=analysis`. Static analysis, lab
> reproduction, defensive mapping, and reporting guidance only. PoC code,
> chain artifacts, and operational tradecraft live in private project clones,
> not in the reusable template.

## When To Use

- Target intake recognizes Apple-signed binaries, daemons, agents, frameworks, PrivateFrameworks, or extension bundles.
- Target intake's `os-component` umbrella surface fires (system-extension, network-extension, appex, driverkit, endpoint-security-client, apple-signed, private-framework-dep, dyld-shared-cache-origin, or launchd-machservices).
- The operator wants to research a specific Apple subsystem (TCC, sharing, fileproviderd, softwareupdated, installd, etc.) rather than an enclosing app.

## Lab Topology — Where To Run This

| Step | Where it runs | How |
|------|---------------|-----|
| Bundle / binary intake | Workstation | `python3 scripts/start-target.py <path>` |
| Apple source pull | Workstation | `python3 scripts/fetch-apple-source.py <component> --release <id>` |
| Launchd / MachService inventory | Lab VM | `macre-vm-mcp` tool `launchd_machservices` |
| System extension inventory | Lab VM | `macre-vm-mcp` tool `system_extension_list` |
| Framework dependency map | Lab VM | `macre-vm-mcp` tool `framework_dependency_map` |
| OS build / SIP snapshot | Lab VM | `macre-vm-mcp` tool `os_build_snapshot` |
| Static decompilation | Lab VM (Ghidra) | `ghidra-mcp` decomp + dedicated scanners |
| Dynamic confirmation | Lab VM | `macre-vm-mcp` LLDB/DTrace tools, recorded to `VM_ACTIONS.md` |

See `Skills/offensive-macos-station-topology/SKILL.md` for the full picture.

## Workflow

1. Confirm authorization as an operator precondition.
2. Confirm lab VM disposability and snapshot strategy in `LAB_SAFETY.md`; record dynamic actions in `VM_ACTIONS.md`.
3. Create or select a corpus pass in `CORPUS.md`.
4. Inventory the bundle, framework, daemon, or extension via `scripts/start-target.py`.
5. Read `docs/playbooks/os-components.md` and respect the maturity tiers — do not overclaim recipe support for surfaces that are basic-inventory or manual-route-needed.
6. Pull Apple-published source (when useful) via `scripts/fetch-apple-source.py` and route it through the source-binary correlation lane.
7. Map surfaces to ontology classes; pick the matching Maproom recipe (`os-component-inventory`, `inspect-launchd-machservice-topology`, `inspect-system-or-network-extension`, `inspect-endpoint-security-client`, `private-framework-dependency-map`, `apple-signed-build-drift-check`, `apple-source-correlation`).
8. Record candidates and chain hypotheses in CORPUS Exploitability And Chainability; promote chains via the chain-discovery skill before investing in PoC authoring.
9. Save evidence anchors in Scriptorium and chronicle decisions in `CHRONICLE.md`.

## Primary Classes

- `VULN-XPC-CLIENT-VALIDATION`
- `VULN-PRIV-HELPER-AUTHZ`
- `VULN-LAUNCHD-EXPOSURE`
- `VULN-IPC-CONFUSED-DEPUTY`
- `VULN-CODESIGN-ENTITLEMENT`
- `VULN-TCC-ATTRIBUTION`
- `VULN-SANDBOX-ESCAPE-PRIMITIVE`
- `VULN-SCOPED-BOOKMARKS`
- `VULN-KEYCHAIN-TRUST`
- `VULN-FILE-AUTHORITY-TRANSFER`
- `VULN-SYMLINK-RACE`
- `VULN-UPDATER-TRUST`

## Pitfalls

- SIP state changes which targets are even readable on the VM; record `csrutil status` before drawing conclusions about reachability.
- The dyld shared cache hides framework backing — `otool -L` shows logical paths even when no on-disk file exists. Extract via `dyld_shared_cache_util -extract` for static work.
- OS build drift between workstation, lab VM, and the public artifact under analysis can flip behavior; always pin the OS build observed.
- Apple-signed and broad entitlements are common by design; only a trust-boundary or authorization gap with an attacker-reachable path counts as a finding.
- Recipes are routing aids, not proof. Surfaces in the basic-inventory or manual-route-needed maturity tier still need operator-driven confirmation before any candidate row claims more than `scan-hit` status.

## See Also

- `docs/playbooks/os-components.md`
- `docs/ontology/macos-vulnerability-classes.md`
- `docs/playbooks/investigation-recipes.md`
- `Skills/offensive-macos-bundle-intake/SKILL.md`
- `Skills/offensive-macos-station-topology/SKILL.md`
- `Skills/offensive-macos-submission-packet/SKILL.md`
