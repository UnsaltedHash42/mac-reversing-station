# Skills Map

Thirty skills, five tiers. Read this once and you will know which one to look for.

```
                        ┌──────────────────────────┐
                        │       agent loop         │
                        │                          │
                        │  intake → watch → recipe │
                        │     → scan → triage      │
                        │     → confirm → record   │
                        │     → repeat | chain     │
                        │     | close              │
                        └────────────┬─────────────┘
                                     │
        ┌──────────────┬─────────────┼─────────────┬──────────────┐
        ▼              ▼             ▼             ▼              ▼
  Foundations      Tooling       Families       Hunts        Orchestrators
  (deep refs)    (drive tools)   (target shape)  (one bug class)  (loop glue)
```

## Foundations — read once, refer back forever

Deep reference. Consult when the question is "how does this part of macOS actually work."

| Skill | Use when |
|---|---|
| [foundations-macho](offensive-macos-foundations-macho/SKILL.md) | Mach-O header, load commands, segments, chained fixups, dyld shared cache, fat binaries |
| [foundations-objc-runtime](offensive-macos-foundations-objc-runtime/SKILL.md) | ObjC class metadata, selectors, `objc_msgSend` dispatch, swizzling, runtime introspection |
| [foundations-swift-abi](offensive-macos-foundations-swift-abi/SKILL.md) | Swift name mangling, metadata, witness tables, ABI stability rules, calling convention |
| [shellcode-arm64](offensive-macos-shellcode-arm64/SKILL.md) | arm64 instruction families, ROP/JOP gadget shape, Apple Silicon mitigations, PAC |

## Tooling — how to drive what you have

Read the foundation; use the tool through these.

| Skill | Use when |
|---|---|
| [tooling-cli-static](offensive-macos-tooling-cli-static/SKILL.md) | `otool`, `nm`, `lipo`, `codesign`, `pagestuff`, `strings` — workstation triage |
| [tooling-ghidra-headless](offensive-macos-tooling-ghidra-headless/SKILL.md) | Driving `ghidra-mcp` from the agent: open, decompile, run scripts, extract anchors |
| [tooling-lldb](offensive-macos-tooling-lldb/SKILL.md) | Scripted lldb sessions, breakpoint sourcing, structured register/stack capture |
| [tooling-dtrace](offensive-macos-tooling-dtrace/SKILL.md) | DTrace providers, predicates, SIP gotchas, syscall/objc/Apple-trace probes |

## Families — what shape is the target

Pick one based on intake. Multi-label is fine; `unknown/mixed` is fine when nothing fits.

| Skill | Target shape |
|---|---|
| [family-privileged-helpers](offensive-macos-family-privileged-helpers/SKILL.md) | `SMJobBless` helpers, updaters, installer payloads, authorization-gated services |
| [family-tcc-heavy-apps](offensive-macos-family-tcc-heavy-apps/SKILL.md) | Apps that prompt for Documents / Camera / FDA / Apple Events / Accessibility |
| [family-enterprise-agents](offensive-macos-family-enterprise-agents/SKILL.md) | EDR, MDM clients, content filters, Endpoint Security clients, network extensions |
| [family-developer-tools](offensive-macos-family-developer-tools/SKILL.md) | IDEs, build tools, package managers, language servers running with operator trust |
| [family-os-components](offensive-macos-family-os-components/SKILL.md) | Apple-signed daemons, frameworks, PrivateFrameworks, launchd MachService surfaces |
| [electron-surface-pack](offensive-macos-electron-surface-pack/SKILL.md) | Electron / Catalyst / hybrid bundles — ASAR, preload, native modules, IPC |

## Hunts — one bug class each

Open one when the family points at it. A hunt names the static evidence, the dynamic confirmation, and the closure rule.

| Skill | Bug class |
|---|---|
| [hunt-wrong-door](offensive-macos-hunt-wrong-door/SKILL.md) | XPC clients trusted by daemons that should validate them |
| [hunt-defaults-bypass](offensive-macos-hunt-defaults-bypass/SKILL.md) | Security checks gated on user-writable `defaults` keys |
| [hunt-catalyst-porting-gap](offensive-macos-hunt-catalyst-porting-gap/SKILL.md) | iOS-style entitlement assumptions that did not survive the macOS port |

## Orchestrators — the loop glue

These are the skills that keep the agent honest across a session.

| Skill | Role in the loop |
|---|---|
| [station-topology](offensive-macos-station-topology/SKILL.md) | Where each step runs, how MCPs are wired, how to recover when something breaks |
| [bundle-intake](offensive-macos-bundle-intake/SKILL.md) | **Entry point.** Operator gives a path; intake produces dossier + Watch row |
| [watch-static-analysis](offensive-macos-watch-static-analysis/SKILL.md) | **Decision layer.** Reads intake, names the next artifact, picks a Maproom recipe |
| [maproom-recipes](offensive-macos-maproom-recipes/SKILL.md) | Recipe registry — operator goal → skills + scripts + expected evidence |
| [vuln-ontology](offensive-macos-vuln-ontology/SKILL.md) | The bug-class taxonomy used by hunts, watch, chain-discovery |
| [gatehouse-ghidra-lldb](offensive-macos-gatehouse-ghidra-lldb/SKILL.md) | **Static→dynamic handoff.** Ghidra anchor → lldb stop with slide accounting |
| [scriptorium-evidence](offensive-macos-scriptorium-evidence/SKILL.md) | Evidence continuity. Every claim points at a hash + file + transcript |
| [source-binary-correlation](offensive-macos-source-binary-correlation/SKILL.md) | When source is available, map source claims to shipped binary symbols |
| [chain-discovery](offensive-macos-chain-discovery/SKILL.md) | Two primitives → exploitability rating → next experiment |
| [poc-authoring](offensive-macos-poc-authoring/SKILL.md) | Confirmed candidate → minimal harness → reproducible artifact |
| [submission-packet](offensive-macos-submission-packet/SKILL.md) | **Exit point.** Confirmed bug → vendor-ready report bundle |
| [agent-discipline](offensive-macos-agent-discipline/SKILL.md) | What "good output" looks like; when to stop, escalate, ask the operator |
| [lab-roster](offensive-macos-lab-roster/SKILL.md) | Naming hosts, recording SIP state, snapshots, allowed test shapes |

## When to write a new skill vs. extend an existing one

Two valid skill shapes:

- **Reference skill** (Foundations / Tooling) — long. Theory + tool surface + worked examples. Read once, cited often.
- **Workflow skill** (Family / Hunt / Orchestrator) — short. `When to use`, `Workflow` (numbered), `Output Shape`, `See Also`. Reads in under 60 seconds.

When you discover a new bug class, write a hunt skill. When a new target shape recurs (3+ targets in your queue), write a family skill. When you find yourself rereading the same Apple header, write a foundation skill.

Templates:

- [_template/SKILL.md](_template/SKILL.md) — generic shape (split into reference vs. workflow once you know which)

## Consuming skills

Cursor and Claude Code both auto-invoke skills by description; you do not need to name them. Just describe the situation:

- "start a pass on /Applications/Foo.app" → bundle-intake fires
- "what should I look at next" → watch-static-analysis fires
- "confirm this Ghidra anchor with lldb" → gatehouse-ghidra-lldb fires
- "stitch these two primitives" → chain-discovery fires

When auto-invoke misses, name the skill explicitly: `Use Skills/offensive-macos-hunt-wrong-door/SKILL.md ...`
