# Developer Tools

Use this playbook for terminals, editors, package managers, build helpers, virtualization tools, local CI agents, language runtimes, and developer productivity apps.

## Common Artifacts

- Shell, build, package, and plugin execution paths.
- Privileged helpers for virtualization, networking, installers, or device access.
- Update frameworks and auto-installers.
- Project-local configuration files, caches, sockets, and extensions.
- Code-signing checks for plugins, helper tools, or downloaded components.

## Primary Ontology Classes

- `VULN-UPDATER-TRUST`
- `VULN-PRIV-HELPER-AUTHZ`
- `VULN-SYMLINK-RACE`
- `VULN-CODESIGN-ENTITLEMENT`
- `VULN-IPC-CONFUSED-DEPUTY`
- `VULN-FILE-AUTHORITY-TRANSFER`
- `VULN-LAUNCHD-EXPOSURE`

## First-Pass Checks

- Separate expected dangerous capability from boundary failure.
- Identify where project-controlled files influence privileged helpers, updates, or host-level actions.
- Inspect plugin trust, downloaded tool trust, helper authorization, and file operation boundaries.
- Check whether package or build outputs cross into privileged install or update flows.
- Record expected-dangerous closures explicitly so future passes do not re-triage the same behavior.

## False-Positive Traps

- Developer tools intentionally execute code.
- Project-local configuration may be attacker-controlled only when the threat model includes opening untrusted projects.
- Package-manager behavior can be dangerous but documented and expected.
- A finding needs a boundary crossing, not just arbitrary code execution inside the developer's chosen project.

## Minimum Evidence For Escalation

- Threat model: untrusted project, local user, helper client, or update path.
- Boundary crossed beyond expected developer-tool behavior.
- Operation reachable from project-controlled or low-privilege input.
- Lab proof that does not rely on social engineering beyond the authorized scenario.
