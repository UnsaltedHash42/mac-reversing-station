---
name: offensive-macos-SLUG
description: >-
  One to three sentences written in Cursor's auto-invoke voice. Name the INPUT SITUATION
  (e.g. "when analyzing a Mach-O binary's load commands", "when auditing an XPC service
  for client-signature validation"), not the output capability. Max 1024 characters.
  Be specific — vague descriptions prevent auto-invocation.
folder: offensive-macos-SLUG
source: skillz-wave1
trigger_phrases:
  - "example trigger phrase 1"
  - "example trigger phrase 2"
---

# Skill Title

> **Channel boundary:** This skill operates under `REPO_MODE=analysis`
> (see `cursor/rule-analysis.mdc`). Root-cause analysis, lab reproduction,
> defensive mapping, and tooling guidance only. No operational exploit
> authoring against live third-party targets.

## When to use

Plain-language fit criteria for the agent. Two or three concrete situations
where this skill should fire, written from the agent's point of view.

## Lab topology — where to run this

Short block that routes each step of the workflow to the right surface:

| Step | Where it runs | How |
|------|---------------|-----|
| Example: disassemble function | VM (Ghidra) | `ghidra-mcp` tool `decomp.function` |
| Example: dump entitlements | VM | `macre-vm-mcp` tool `entitlement_dump` |
| Example: quick Mach-O header sanity | Workstation | `otool -h /path/to/binary` |

Link back to the topology skill for the full picture:
see `Skills/offensive-macos-station-topology/SKILL.md`.

## Theory

The reversible knowledge. Structured paragraphs or subsections. Ground every
non-obvious claim in Apple open-source code, Apple developer docs, tool output,
or a local lab transcript.

## Workflow

Numbered step-by-step procedure the agent (or operator) follows. Each step
names its artifact (what comes in, what goes out) and the exact MCP tool call
or CLI command where applicable. Prefer MCP tool calls over raw SSH when both
are available.

1. ...
2. ...
3. ...

## Current Bug-Class Anchors

One to three real bug classes where this theory matters in practice.
For each: one-paragraph summary, link to a public upstream write-up when
useful, and a one-sentence note about which step of the workflow the bug
class exercises.

## Pitfalls

- SIP state gotchas (SIP is OFF on NightBlood; note what changes if SIP is on elsewhere)
- AMFI / codesigning gotchas
- macOS version drift (current lab VM: macOS 26.4.1 arm64)
- Common false positives or confusing Hopper output

## Micro-exercise

One worked task the operator can reproduce in 15–30 minutes on the VM, using
only what this skill documents. State: starting artifact, steps, expected
output, what success looks like.

## See also

- Adjacent Wave 1 skills: `Skills/offensive-macos-<other>/SKILL.md`
- External write-ups, Apple headers, Project Zero posts
