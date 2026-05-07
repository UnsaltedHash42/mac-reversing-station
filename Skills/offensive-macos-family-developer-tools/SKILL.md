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

- A target app executes code, spawns tools, installs packages, runs builds, or manages developer environments.
- The operator needs to separate expected dangerous capability from a true boundary crossing.
- A project-controlled input may influence privileged helpers, updates, plugins, or host-level actions.

## Workflow

1. Define the threat model in `CORPUS.md`: untrusted project, local user, helper client, updater, or plugin.
2. Read `docs/playbooks/developer-tools.md`.
3. Map expected capabilities and possible boundary failures to ontology classes.
4. Record expected-dangerous closures in `INDEX.md` to improve future triage.
5. Escalate only when the behavior crosses a boundary beyond expected developer-tool operation.

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
