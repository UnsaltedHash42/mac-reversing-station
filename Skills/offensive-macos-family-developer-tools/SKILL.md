---
name: offensive-macos-family-developer-tools
description: >-
  Use when auditing macOS developer tools such as terminals, editors, package
  managers, build helpers, virtualization tools, local CI agents, plugins, or
  language runtimes. Fires on "developer tool", "package manager", "build
  helper", "terminal app", and "plugin trust".
folder: offensive-macos-family-developer-tools
source: skillz-wave3
trigger_phrases:
  - "developer tool"
  - "package manager"
  - "build helper"
  - "terminal app"
  - "plugin trust"
---

# Family: Developer Tools

> **Channel boundary:** `REPO_MODE=analysis`. RCA, lab reproduction,
> defensive mapping, and reporting guidance only. No persistence, evasion,
> command-and-control, deployment, or live exploitation workflow.

## When To Use

- Target intake shows code execution, tool spawning, package install, build, plugin, or developer-environment surfaces.
- The operator needs to separate expected dangerous capability from a true boundary crossing.
- A project-controlled input may influence privileged helpers, updates, plugins, or host-level actions.

## Workflow

1. Confirm authorization as an operator precondition and lab state in `LAB_SAFETY.md`.
2. Define the threat model in `CORPUS.md`: untrusted project, local user, helper client, updater, or plugin.
3. Inventory the bundle or binary before committing to a family label.
4. Read `docs/playbooks/developer-tools.md`.
5. Map expected capabilities and possible boundary failures to ontology classes.
6. Record expected-dangerous closures in `INDEX.md` to improve future triage.
7. Escalate only when the behavior crosses a boundary beyond expected developer-tool operation.

## Primary Classes

- `VULN-UPDATER-TRUST`
- `VULN-PRIV-HELPER-AUTHZ`
- `VULN-SYMLINK-RACE`
- `VULN-CODESIGN-ENTITLEMENT`
- `VULN-IPC-CONFUSED-DEPUTY`
- `VULN-FILE-AUTHORITY-TRANSFER`
- `VULN-LAUNCHD-EXPOSURE`

## See Also

- `docs/playbooks/developer-tools.md`
- `docs/ontology/macos-vulnerability-classes.md`
- `templates/findings-repo/METRICS.md`
