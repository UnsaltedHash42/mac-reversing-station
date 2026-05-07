---
name: offensive-macos-family-privileged-helpers
description: >-
  Use when auditing third-party macOS apps with privileged helpers, updaters,
  installers, Sparkle services, LaunchDaemons, or root XPC services. Fires on
  "privileged helper", "updater audit", "Sparkle", "SMJobBless", and
  "helper tool".
folder: offensive-macos-family-privileged-helpers
source: skillz-wave3
trigger_phrases:
  - "privileged helper"
  - "updater audit"
  - "Sparkle"
  - "SMJobBless"
  - "helper tool"
---

# Family: Privileged Helpers And Updaters

> **Channel boundary:** `REPO_MODE=analysis`. RCA, lab reproduction,
> defensive mapping, and reporting guidance only. No persistence, evasion,
> command-and-control, deployment, or live exploitation workflow.

## When To Use

- Target intake shows root helpers, updater frameworks, installer tools, or LaunchDaemons.
- The operator wants a corpus pass over helper/updater surfaces.
- A Sparkle-style XPC or updater trust issue is suspected.

## Workflow

1. Confirm authorization as an operator precondition and lab state in `LAB_SAFETY.md`.
2. Create a pass in `CORPUS.md`.
3. Inventory the bundle or binary before committing to a family label.
4. Read `docs/playbooks/privileged-helpers-updaters.md`.
5. Map surfaces to ontology classes with `Skills/offensive-macos-vuln-ontology/SKILL.md`.
6. Run applicable metadata and Ghidra sweeps.
7. Add candidates to `INDEX.md` and update `METRICS.md`.

## Primary Classes

- `VULN-XPC-CLIENT-VALIDATION`
- `VULN-PRIV-HELPER-AUTHZ`
- `VULN-UPDATER-TRUST`
- `VULN-SYMLINK-RACE`
- `VULN-LAUNCHD-EXPOSURE`
- `VULN-CODESIGN-ENTITLEMENT`
- `VULN-IPC-CONFUSED-DEPUTY`

## See Also

- `docs/playbooks/privileged-helpers-updaters.md`
- `docs/ontology/macos-vulnerability-classes.md`
