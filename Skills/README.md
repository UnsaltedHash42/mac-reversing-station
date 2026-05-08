# Skills map

Thirty-five skills, organized into five tiers. This page is the map, not the index.

```
                  intake -> watch -> recipe -> scan
                            -> triage -> confirm -> record
                            -> repeat | chain | close

    Foundations    deep references; read once, refer back forever
    Tooling        how to drive Ghidra, lldb, dtrace, the CLI
    Families       target shape (helpers, TCC apps, OS components, ...)
    Hunts          one bug class each
    Orchestrators  the loop glue (Watch, Maproom, Scriptorium, ...)
```

## Foundations

Long reference docs. Read once when you start. Cite when something's confusing.

- [foundations-macho](offensive-macos-foundations-macho/SKILL.md) — Mach-O header, load commands, segments, chained fixups, fat binaries, dyld shared cache.
- [foundations-objc-runtime](offensive-macos-foundations-objc-runtime/SKILL.md) — class metadata, selectors, `objc_msgSend`, swizzling, runtime introspection.
- [foundations-swift-abi](offensive-macos-foundations-swift-abi/SKILL.md) — name mangling, metadata, witness tables, ABI stability, calling convention.
- [shellcode-arm64](offensive-macos-shellcode-arm64/SKILL.md) — arm64 instruction families, gadget shape, Apple Silicon mitigations, PAC.

## Tooling

Read after the foundation. Use the tool through these.

- [tooling-cli-static](offensive-macos-tooling-cli-static/SKILL.md) — `otool`, `nm`, `lipo`, `codesign`, `pagestuff`, `strings`.
- [tooling-ghidra-headless](offensive-macos-tooling-ghidra-headless/SKILL.md) — driving `ghidra-mcp` from the agent.
- [tooling-lldb](offensive-macos-tooling-lldb/SKILL.md) — scripted lldb, breakpoint sourcing, register and stack capture.
- [tooling-dtrace](offensive-macos-tooling-dtrace/SKILL.md) — providers, predicates, SIP gotchas, syscall / objc / Apple-trace probes.

## Families

Pick one based on what intake found. Multi-label is fine. `unknown/mixed` is fine when nothing fits.

- [family-privileged-helpers](offensive-macos-family-privileged-helpers/SKILL.md) — SMJobBless helpers, updaters, installer payloads, authorization-gated services.
- [family-tcc-heavy-apps](offensive-macos-family-tcc-heavy-apps/SKILL.md) — apps that prompt for Documents / Camera / FDA / Apple Events / Accessibility.
- [family-enterprise-agents](offensive-macos-family-enterprise-agents/SKILL.md) — EDR, MDM clients, content filters, ES clients, network extensions.
- [family-developer-tools](offensive-macos-family-developer-tools/SKILL.md) — IDEs, build tools, package managers, language servers.
- [family-os-components](offensive-macos-family-os-components/SKILL.md) — Apple-signed daemons, frameworks, PrivateFrameworks, launchd MachServices.
- [electron-surface-pack](offensive-macos-electron-surface-pack/SKILL.md) — Electron / Catalyst / hybrid bundles, ASAR, preload, native modules, IPC.

## Hunts

One bug class each. Read the matching hunt before the sweep.

| Skill | Bug class | Paired scan |
|---|---|---|
| [hunt-wrong-door](offensive-macos-hunt-wrong-door/SKILL.md) | XPC daemons trusting clients they should validate | `scan_wrong_door`, `dump_xpc_listeners` |
| [hunt-defaults-bypass](offensive-macos-hunt-defaults-bypass/SKILL.md) | Security checks gated on user-writable defaults keys | `scan_defaults_bypass` |
| [hunt-catalyst-porting-gap](offensive-macos-hunt-catalyst-porting-gap/SKILL.md) | iOS-style entitlement assumptions in Catalyst code | `scan_catalyst_porting_gap` |
| [hunt-tcc-prompt-attribution](offensive-macos-hunt-tcc-prompt-attribution/SKILL.md) | TCC prompts naming the wrong app | `scan_tcc_prompt_surface` |
| [hunt-iokit-userclient](offensive-macos-hunt-iokit-userclient/SKILL.md) | IOKit user-client selector validation | `scan_iokit_user_clients` |
| [hunt-private-framework-hijack](offensive-macos-hunt-private-framework-hijack/SKILL.md) | Attacker-influenced `dlopen` and `NSClassFromString` paths | `scan_private_framework_dependency` |
| [hunt-url-scheme-hijack](offensive-macos-hunt-url-scheme-hijack/SKILL.md) | URL scheme dispatchers trusting URL parameters | `scan_url_scheme_handlers` |
| [hunt-mig-subsystem](offensive-macos-hunt-mig-subsystem/SKILL.md) | MIG-derived Mach-trap kernel surface | `scan_iokit_user_clients` (callsites that lead to MIG dispatch) |
| [hunt-keychain-access-group](offensive-macos-hunt-keychain-access-group/SKILL.md) | Keychain access-group confused deputies | `scan_persistent_authorization` |

## Orchestrators

The loop glue.

- [station-topology](offensive-macos-station-topology/SKILL.md) — where each step runs, how MCPs are wired, how to recover from breakage.
- [bundle-intake](offensive-macos-bundle-intake/SKILL.md) — entry point. Operator gives a path, intake produces a dossier and a Watch row.
- [watch-static-analysis](offensive-macos-watch-static-analysis/SKILL.md) — decision layer. Reads intake, names the next artifact, picks a recipe.
- [maproom-recipes](offensive-macos-maproom-recipes/SKILL.md) — the recipe registry.
- [vuln-ontology](offensive-macos-vuln-ontology/SKILL.md) — bug-class taxonomy used by hunts, watch, chain-discovery.
- [gatehouse-ghidra-lldb](offensive-macos-gatehouse-ghidra-lldb/SKILL.md) — Ghidra-anchor → lldb-stop handoff with slide accounting.
- [scriptorium-evidence](offensive-macos-scriptorium-evidence/SKILL.md) — evidence continuity. Hash-pinned claims.
- [source-binary-correlation](offensive-macos-source-binary-correlation/SKILL.md) — when source is available, map source claims to shipped symbols.
- [chain-discovery](offensive-macos-chain-discovery/SKILL.md) — two primitives, exploitability rating, next experiment.
- [poc-authoring](offensive-macos-poc-authoring/SKILL.md) — confirmed candidate to minimal harness.
- [submission-packet](offensive-macos-submission-packet/SKILL.md) — exit point. Confirmed bug to vendor-ready report.
- [agent-discipline](offensive-macos-agent-discipline/SKILL.md) — what good output looks like; when to stop, escalate, ask.
- [lab-roster](offensive-macos-lab-roster/SKILL.md) — naming hosts, recording SIP state, snapshots, allowed test shapes.

## When to write a new skill

Two skill shapes:

**Reference** (Foundations / Tooling) — long. Theory, tool surface, worked examples. Read once, cited often.

**Workflow** (Family / Hunt / Orchestrator) — short. `When to use`, `Workflow`, `Output Shape`, `See Also`. Reads in under a minute.

When you find a new bug class, write a hunt. When a target shape recurs three times, write a family. When you keep rereading the same Apple header, write a foundation.

Templates: [_template/SKILL.md](_template/SKILL.md).

## Triggering skills

Cursor and Claude Code auto-invoke by description. Describe the situation, not the skill.

```
start a pass on /Applications/Foo.app          → bundle-intake
what should I look at next                     → watch-static-analysis
confirm this Ghidra anchor with lldb           → gatehouse-ghidra-lldb
stitch these two primitives into a chain        → chain-discovery
```

When auto-invoke misses, name the skill: `Use Skills/offensive-macos-hunt-wrong-door/SKILL.md ...`.
