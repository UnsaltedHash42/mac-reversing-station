---
name: offensive-macos-submission-packet
description: >-
  Use when turning a verified macOS bug into an audience-aware finding packet:
  vendor disclosure, internal remediation, red-team reporting, Apple/platform
  disclosure, PoC hardening, evidence packaging, affected versions, root-cause
  summary, and follow-up tracking. Fires on "prep this finding", "report packet",
  "vendor disclosure", "internal remediation", "red-team report", "submit to
  Apple", "security.apple.com", and "rdar".
folder: offensive-macos-submission-packet
source: skillz-wave2
trigger_phrases:
  - "submit to Apple"
  - "submission packet"
  - "report packet"
  - "vendor disclosure"
  - "internal remediation"
  - "red-team report"
  - "security.apple.com"
  - "prep this finding"
  - "rdar"
---

# Finding Report Packet

> **Channel boundary:** `REPO_MODE=analysis`. RCA, lab reproduction, defensive
> mapping, and reporting guidance only. No persistence, evasion,
> command-and-control, deployment tradecraft, or live exploitation workflow.

## When To Use

- A candidate has lab reproduction and root-cause evidence.
- The operator needs a vendor disclosure, internal remediation note, red-team report, or Apple/platform submission.
- A systemic finding needs one concrete proof plus scan or corpus evidence.
- Cross-platform or audience-specific evidence is incomplete and the finding is not report-ready yet.

## Shared Evidence Core

Every report mode starts with the same evidence core:

- Minimal proof or reproduction is deterministic and self-contained.
- Preconditions state user, entitlements, SIP state, hardware, OS build, target version, network, and physical access.
- Reproduction starts from a clean machine state or documented snapshot.
- Impact is explicit: data exposure, privacy bypass, privilege boundary crossing, unauthorized privileged operation, sandbox escape, DoS, or hardening gap.
- Root cause names the trust boundary and the missing or misplaced check.
- Logs, screenshots, crash reports, Ghidra notes, command output, and proof artifacts are saved under `artifacts/` in the private findings repo.
- Affected and unaffected versions are separated.
- Cross-platform matrix is filled or marked not applicable with rationale.
- Report content avoids unnecessary exploit chaining, persistence, evasion, deployment detail, or unrelated weaponization.

## Report Modes

### Vendor Disclosure

Use for third-party applications, frameworks, helpers, or updaters.

- Emphasize affected product versions, root cause, impact, reproduction, and fix direction.
- Include enough proof for the vendor to reproduce in a lab.
- Avoid red-team engagement details unless the operator explicitly approves sharing them.
- Track disclosure status in `SUBMISSION_TRIAGE.md` or `REPORTING.md`.

### Internal Remediation

Use for in-house developed apps or components.

- Emphasize owner, affected component, root cause, practical fix direction, regression tests, and deployment risk.
- Include remediation priority and suggested validation steps.
- Write for engineers who can change the code, not for a bounty triager.

### Red-Team Report

Use when research supports an authorized assignment.

- Emphasize business impact, affected controls, realistic preconditions, and defensive recommendations.
- Keep exploitability evidence lab-bound.
- Do not include persistence, evasion, command-and-control, deployment, or operational chaining instructions.
- If dual-use reproduction detail is necessary for RCA but risky for distribution, keep it in the evidence core and require operator review before adding it to the audience-facing report.

### Apple / Platform Disclosure

Use when third-party research reveals a macOS platform bug or when the affected component is Apple's.

- Preserve Apple Security expectations: minimal proof, affected/unaffected versions, clear impact, and cross-platform data where relevant.
- Track submission IDs or radar references.
- If a third-party vendor is also affected, require an explicit operator decision on coordination order before preparing multiple packets.

## Cross-Platform Re-Verification

| Role | Required Evidence |
|------|-------------------|
| primary | clean proof run and logs on the main target OS |
| crash-test | destructive or panic reproduction when applicable |
| cross-platform | same test on a different Apple Silicon generation |
| intel-baseline | x86_64/macOS behavior or reason not applicable |

For each run record: machine alias, chip, OS build, SIP state, target version, command or action, expected result, actual result, and artifact path.

## Writeup Template

```markdown
# <Short Vulnerability Title>

## Report Mode
<vendor-disclosure | internal-remediation | red-team-report | apple-platform-disclosure>

## Summary
<One paragraph: affected component, boundary crossed, impact.>

## Severity / Priority
<High/Medium/Low or engagement-specific priority with rationale.>

## Affected Versions
- Confirmed affected:
- Confirmed unaffected:
- Not tested:

## Preconditions
- User:
- Entitlements:
- SIP:
- Hardware:
- OS build:
- Target version:
- Physical/network access:

## Reproduction
1. Prepare:
2. Run:
3. Observe:

## Expected Result
<What should happen.>

## Actual Result
<What happens.>

## Root Cause
<Authorization/checking/parsing/state-management mistake.>

## Evidence
- Proof:
- Logs:
- Crash/panic:
- Static analysis:
- Metrics / corpus pass:
- Cross-platform matrix:

## Suggested Fix Direction
<Gate earlier, validate caller identity, bind authorization to the operation, harden updater/helper, etc.>

## Coordination Notes
<Vendor/internal/red-team/Apple routing, embargo, or follow-up constraints.>
```

## Apple Platform Flow

1. Create a private findings repo branch or snapshot for the submission packet.
2. Fill the writeup template.
3. Attach minimal proof source and build instructions.
4. Attach logs/crash reports needed to reproduce, not the whole research archive.
5. Submit via https://security.apple.com/.
6. Record the submission ID / rdar in `SUBMISSION_TRIAGE.md`.
7. Track: submitted -> acknowledged -> needs info -> fixed -> credit/publication.

## Post-Submission Tracking

Keep a row per submission:

```markdown
| ID | Title | Audience | Sent | External ID | Status | Last Action | Next Action |
|----|-------|----------|------|-------------|--------|-------------|-------------|
```

If a recipient asks for more info, respond with one focused artifact or answer at a time. Do not send unrelated scan dumps unless they directly support the reported bug.

## Attribution

Submission triage shape adapted from dmaynor/AVR-INTERNAL, 2026 (see https://github.com/dmaynor/AVR-INTERNAL). This station imports the packet discipline, not AVR-INTERNAL's specific findings.

## See Also

- `templates/findings-repo/SUBMISSION_TRIAGE.md`
- `templates/findings-repo/REPORTING.md`
- `templates/findings-repo/HANDOFF.md.template`
- `Skills/offensive-macos-agent-discipline/SKILL.md`
- `Skills/offensive-macos-lab-roster/SKILL.md`
