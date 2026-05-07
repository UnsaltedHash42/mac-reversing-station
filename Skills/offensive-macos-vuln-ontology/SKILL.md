---
name: offensive-macos-vuln-ontology
description: >-
  Use when mapping a macOS target's attack surfaces to reusable vulnerability
  classes, generating hunt hypotheses for a new third-party app, or deciding
  which playbook or scanner applies. Fires on "vulnerability ontology",
  "bug-class map", "what bug classes apply", "generate hypotheses", and
  "classify this macOS surface".
folder: offensive-macos-vuln-ontology
source: skillz-wave3
trigger_phrases:
  - "vulnerability ontology"
  - "bug-class map"
  - "what bug classes apply"
  - "generate hypotheses"
  - "classify this macOS surface"
---

# macOS Vulnerability Ontology

> **Channel boundary:** `REPO_MODE=analysis`. Root-cause analysis, lab
> reproduction, defensive mapping, and reporting guidance only. No persistence,
> evasion, command-and-control, deployment, or live exploitation workflow.

## When To Use

- A new third-party macOS app has been added to an authorized corpus and needs a structured attack-surface map.
- Static analysis finds XPC services, helpers, TCC strings, sandbox/bookmark usage, updater code, launchd services, or code-signing checks and the operator needs hypotheses.
- A scanner row needs to be classified before triage, deep dive, or reporting.

## Canonical Reference

Use `docs/ontology/macos-vulnerability-classes.md` as the source of truth. Each class includes:

- Boundary.
- Attacker-controlled inputs.
- Likely impact.
- Static signals.
- Dynamic confirmation.
- False-positive traps.
- Evidence.
- Hypothesis prompts.

Do not invent new class names in a findings repo. If a target does not fit an existing class, record it as `needs-ontology-review` in the private findings repo and update the station ontology only after the pattern is understood.

## Workflow

1. Identify the target family:
   - Privileged helper or updater.
   - Enterprise/security agent.
   - Developer tool.
   - TCC-heavy consumer app.
2. Read the relevant family playbook under `docs/playbooks/` if it exists.
3. Map observed surfaces to ontology IDs:
   - `VULN-XPC-CLIENT-VALIDATION`
   - `VULN-PRIV-HELPER-AUTHZ`
   - `VULN-UPDATER-TRUST`
   - `VULN-TCC-ATTRIBUTION`
   - `VULN-SANDBOX-ESCAPE-PRIMITIVE`
   - `VULN-SCOPED-BOOKMARKS`
   - `VULN-KEYCHAIN-TRUST`
   - `VULN-SYMLINK-RACE`
   - `VULN-LAUNCHD-EXPOSURE`
   - `VULN-CODESIGN-ENTITLEMENT`
   - `VULN-IPC-CONFUSED-DEPUTY`
   - `VULN-FILE-AUTHORITY-TRANSFER`
4. Generate hypotheses from the class prompts.
5. Save target-specific candidates and metrics in the copied findings repo, never in `skillz`.

## Output Shape

For a new target, produce a concise map:

```markdown
## Attack-Surface Map

- Target family:
- Observed surfaces:
- Likely ontology classes:
- First-pass scanners or manual checks:
- Hypotheses:
- False-positive traps:
- Evidence to collect:
- Metrics pass ID:
```

## Triage Discipline

- A class match is not a vulnerability.
- A scanner hit is not proof.
- A connection or prompt is not enough; identify the authority boundary and operation-level effect.
- Closed false positives with rationale are useful research output and should update `METRICS.md` in the findings repo.

## See Also

- `docs/ontology/README.md`
- `docs/ontology/macos-vulnerability-classes.md`
- `docs/playbooks/third-party-app-families.md`
- `Skills/offensive-macos-agent-discipline/SKILL.md`
