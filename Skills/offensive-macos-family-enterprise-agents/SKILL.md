---
name: offensive-macos-family-enterprise-agents
description: >-
  Use when auditing enterprise, security, EDR-adjacent, MDM, network-filter,
  telemetry, or device-management macOS agents. Fires on "enterprise agent",
  "security agent", "EDR", "MDM client", and "endpoint agent".
folder: offensive-macos-family-enterprise-agents
source: skillz-wave3
trigger_phrases:
  - "enterprise agent"
  - "security agent"
  - "EDR"
  - "MDM client"
  - "endpoint agent"
---

# Family: Enterprise And Security Agents

> **Channel boundary:** `REPO_MODE=analysis`. RCA, lab reproduction,
> defensive mapping, and reporting guidance only. No persistence, evasion,
> command-and-control, deployment, or live exploitation workflow.

## When To Use

- A target runs always-on agents, root daemons, filters, or management clients.
- A red-team or internal assessment needs app-level root cause and remediation evidence.
- The operator needs to separate expected security-agent power from a boundary failure.

## Workflow

1. Confirm authorization and engagement constraints in `AUTHORIZATION.md`.
2. Confirm lab isolation and test users in `LAB_SAFETY.md`.
3. Create a corpus pass in `CORPUS.md`.
4. Read `docs/playbooks/enterprise-security-agents.md`.
5. Map surfaces to ontology classes and record hypotheses.
6. Save candidates and metrics in the private findings repo.

## Primary Classes

- `VULN-XPC-CLIENT-VALIDATION`
- `VULN-PRIV-HELPER-AUTHZ`
- `VULN-LAUNCHD-EXPOSURE`
- `VULN-IPC-CONFUSED-DEPUTY`
- `VULN-CODESIGN-ENTITLEMENT`
- `VULN-KEYCHAIN-TRUST`
- `VULN-FILE-AUTHORITY-TRANSFER`

## See Also

- `docs/playbooks/enterprise-security-agents.md`
- `docs/ontology/macos-vulnerability-classes.md`
- `Skills/offensive-macos-submission-packet/SKILL.md`
