---
name: offensive-macos-family-tcc-heavy-apps
description: >-
  Use when auditing macOS apps with heavy privacy permissions: TCC,
  Accessibility, Screen Recording, Automation, camera, microphone,
  Desktop/Documents, Full Disk Access, security-scoped bookmarks, or file
  authority transfer. Fires on "TCC-heavy", "privacy permissions",
  "Accessibility audit", "screen recording", and "security-scoped bookmarks".
folder: offensive-macos-family-tcc-heavy-apps
source: skillz-wave3
trigger_phrases:
  - "TCC-heavy"
  - "privacy permissions"
  - "Accessibility audit"
  - "screen recording"
  - "security-scoped bookmarks"
---

# Family: TCC-Heavy Consumer Apps

> **Channel boundary:** `REPO_MODE=analysis`. RCA, lab reproduction,
> defensive mapping, and reporting guidance only. No persistence, evasion,
> command-and-control, deployment, or live exploitation workflow.

## When To Use

- A target app requests privacy-sensitive permissions or brokers access to protected files/devices.
- The operator needs to reason about prompt attribution, grant recipient, persistent access, or helper-mediated privacy access.
- A privacy or persistent-authorization pass touches TCC attribution, scoped bookmarks, or file-authority transfer patterns.

## Workflow

1. Use synthetic data and a dedicated test user.
2. Confirm privacy and destructive-test hygiene in `LAB_SAFETY.md`.
3. Read `docs/playbooks/tcc-heavy-consumer-apps.md`.
4. Map observed privacy surfaces to ontology classes.
5. Capture prompt/grant/access evidence carefully and save it in the private findings repo.
6. Update `METRICS.md` even when a prompt or access path is closed as expected behavior.

## Primary Classes

- `VULN-TCC-ATTRIBUTION`
- `VULN-SANDBOX-ESCAPE-PRIMITIVE`
- `VULN-SCOPED-BOOKMARKS`
- `VULN-KEYCHAIN-TRUST`
- `VULN-FILE-AUTHORITY-TRANSFER`
- `VULN-XPC-CLIENT-VALIDATION`
- `VULN-IPC-CONFUSED-DEPUTY`

## See Also

- `docs/playbooks/tcc-heavy-consumer-apps.md`
- `Skills/offensive-macos-rediscover-tcc-prompt-attribution/SKILL.md`
- `Skills/offensive-macos-rediscover-scoped-bookmarks/SKILL.md`
