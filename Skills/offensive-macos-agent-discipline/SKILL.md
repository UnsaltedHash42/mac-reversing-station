---
name: offensive-macos-agent-discipline
description: >-
  Use when a macOS bug-hunting session is stuck, drifting, brute-forcing,
  choosing machines, handling crashes, or coordinating agent work. Fires on
  "failure taxonomy", "RE parallel rule", "I'm stuck", "which machine should I
  run this on", "commit cadence", "no /tmp", and "lsof after every action".
folder: offensive-macos-agent-discipline
source: skillz-wave2
trigger_phrases:
  - "failure taxonomy"
  - "RE parallel rule"
  - "I'm stuck"
  - "commit discipline"
  - "no /tmp"
---

# Agent Discipline For macOS Hunting

> **Channel boundary:** `REPO_MODE=analysis`. RCA, lab reproduction, defensive
> mapping, and tooling guidance only. No operational exploit authoring against
> live third-party targets.

## When To Use

- The agent has tried several probes without progress.
- A test can crash a daemon, panic a machine, or corrupt state.
- A session needs a handoff, a fresh sub-agent, or a crisp stop/continue decision.

## Operating Rules

- Breadth first, then depth. Touch many targets briefly, escalate only the rows with real signal.
- Ten minutes or twenty attempts without new evidence means stop brute-forcing and run RE in parallel.
- Use the right machine role before running anything destructive.
- Do not use `/tmp` for research state. Panics clear it. Use repo `.tmp/`, `artifacts/`, or `tools/custom/`.
- Run `lsof` or an equivalent process/socket check after a new daemon action so you know what is alive.
- Commit or checkpoint frequently when working in a real findings repo. In this `skillz/` directory, there may be no git repo; if so, record progress in docs and smoke output.

## L1-L6 Failure Taxonomy

| Level | Meaning | Diagnosis | Remediation |
|------|---------|-----------|-------------|
| L1 API | Agent/tool API failure | MCP error, schema mismatch, tool timeout | list tools, inspect schema, retry one known-good call |
| L2 local | Local host failure | missing file, path typo, bad env var | verify cwd, absolute paths, interpreter versions |
| L3 environment | Machine/OS state failure | daemon not running, SIP mismatch, stale launchd state | reboot/restart target, verify OS/SIP/user |
| L4 tooling | RE/debugger/tool failure | Ghidra cache, LLDB attach denial, DTrace provider missing | isolate with minimal binary/tool smoke |
| L5 app | Target behavior failure | target exits, feature disabled, hardware absent | collect logs, identify prerequisites, close or defer |
| L6 process | Research process failure | looping, too many guesses, no artifact trail | stop, write current hypothesis, spawn parallel RE or ask operator |

Do not change strategy until you know which level failed. Infrastructure failure is not evidence that the vulnerability hypothesis is wrong.

## RE Parallel Rule

When a dynamic probe stalls:

1. Stop after 10 minutes or 20 attempts without new evidence.
2. Freeze the last command, logs, and observed failure in the findings repo.
3. Start a Ghidra path in parallel:
   - Open the target with `ghidra-mcp`.
   - Find the relevant strings/selectors.
   - Decompile one caller and one callee.
   - Return with a specific next probe, not a vague "try more."
4. If Ghidra also stalls, classify the blocker with L1-L6 and decide whether to close, defer, or ask the operator.

## Machine Discipline

- Primary: do static analysis, non-crashing dynamic probes, and normal MCP work.
- Crash-test: run panic-prone kernel, driver, daemon-crash, and fuzzing tests.
- Cross-platform: verify Apple Silicon generation differences.
- Intel baseline: verify legacy macOS/x86_64 behavior.

Pair this with `Skills/offensive-macos-lab-roster/SKILL.md`.

## lsof Discipline

After starting, killing, attaching to, or repeatedly messaging a target, record what is alive:

```bash
lsof -nP -p <pid>
```

If the process disappears, classify whether it was a clean exit, crash, launchd restart, SIGKILL, or panic. This prevents mistaking a dead target for a rejected client.

## Handoff Discipline

Every research chunk should leave:

- Current hypothesis.
- Last known-good command.
- Last failure and L1-L6 classification.
- Machine used and why.
- Artifacts produced.
- Next recommended action.

## Named Agent Conventions

Use bounded sub-agents by role:

- SAT-analysis: roadblocks and alternate hypotheses.
- Zero-analysis: calibration and "are we fooling ourselves?"
- Strategic-Advisor: scope/priority decisions.
- RCA: failures, crashes, and surprising test outcomes.

These names are conventions, not shipped tools.

## Attribution

Methodology adapted from dmaynor/AVR-INTERNAL's `CLAUDE.md` and `HANDOFF.md`, 2026 (see https://github.com/dmaynor/AVR-INTERNAL).

## See Also

- `Skills/offensive-macos-lab-roster/SKILL.md`
- `Skills/offensive-macos-tooling-ghidra-headless/SKILL.md`
- `templates/findings-repo/HANDOFF.md.template`
