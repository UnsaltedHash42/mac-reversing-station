# Reporting

Use this file to decide how a confirmed finding should be packaged. Keep audience-specific packets under `findings/reports/`.

## Evidence Core

- Summary:
- Affected versions:
- Preconditions:
- Reproduction:
- Expected result:
- Actual result:
- Root cause:
- Impact:
- Evidence:
- Suggested fix direction:

## Report Modes

- `vendor-disclosure` — third-party vendor report with affected versions, reproduction, root cause, impact, and fix direction.
- `internal-remediation` — engineering handoff for in-house apps or components, emphasizing owner, fix path, tests, and rollout risk.
- `red-team-report` — engagement report focused on impact and defensive recommendations, without persistence, evasion, C2, deployment, or operational chaining.
- `apple-platform-disclosure` — Apple/platform report when research uncovers a macOS platform bug or Apple-owned affected component.

## Routing Queue

| Finding ID | Audience | Owner / Recipient | Status | Packet Path | Next Action |
|------------|----------|-------------------|--------|-------------|-------------|

## Coordination Notes

- If a finding affects both a third-party vendor and Apple/platform behavior, the operator must choose coordination order before multiple packets are prepared.
- If reproduction detail is dual-use, keep it in the evidence core until the operator approves audience-facing inclusion.
- Do not copy real target packets or evidence into the station repo.

See the station reporting skill before sending any report.
