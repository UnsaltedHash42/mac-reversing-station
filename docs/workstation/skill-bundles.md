# Skill bundles — macOS RE station

This document is the canonical index of skill bundles for the
`REPO_MODE=analysis` macOS reverse-engineering station. Every directory
under `Skills/` that ships a `SKILL.md` must be inline-cited here so
`scripts/validate_workstation_bundles.py` can see it.

Bundles follow the `Skills/offensive-macos-<area>-<topic>/` naming
convention and live alongside canonical Cursor skills (symlinked into
`~/.cursor/skills/` by `cursor/skill-link.sh`).

## Wave 1 — Foundations, Tooling, Shellcode, Topology

### Topology

- `Skills/offensive-macos-station-topology` — how the Mac workstation and
  the NightBlood VM divide labor, which MCP server owns which task, how
  binaries move between them, and what to do when a piece breaks.

### Foundations

- `Skills/offensive-macos-foundations-macho` — Mach-O header, load
  commands, universal binaries, sections, chained fixups, and the dyld
  shared cache. Grounded in Apple `loader.h` and practical Ghidra usage.
- `Skills/offensive-macos-foundations-objc-runtime` — Objective-C class
  layout, selectors, IMPs, `objc_msgSend` on ARM64, the `__objc_*`
  Mach-O sections, and how Ghidra/Hopper render all of the above.
- `Skills/offensive-macos-foundations-swift-abi` — Swift name mangling,
  metadata, runtime, and `@objc` interop; what to expect in Ghidra when
  reversing a Swift binary.

### Tooling

- `Skills/offensive-macos-tooling-ghidra-headless` — Ghidra workflow
  driven over headless MCP: opening Mach-O binaries, listing functions,
  decompiling, and running custom hunt scripts.
- `Skills/offensive-macos-tooling-lldb` — breakpoints, disassembly,
  register and memory read/write, live code patch, attaching to a
  running PID, and scripted batch runs via `macre-vm-mcp`.
- `Skills/offensive-macos-tooling-dtrace` — probes, providers,
  aggregations, canonical one-liners, and DTrace scripting routed
  through `macre-vm-mcp`.
- `Skills/offensive-macos-tooling-cli-static` — `otool`, `nm`, `jtool2`,
  `codesign`, `spctl`, `strings`, `class-dump`, and `plutil`, split
  between workstation-local runs and VM-resident runs via
  `macre-vm-mcp`.

### Shellcode craft

- `Skills/offensive-macos-shellcode-arm64` — ARM64 calling conventions,
  macOS syscall numbering, assembly shellcode construction, eliminating
  PC-relative addressing, locating `execv` via the dyld shared cache,
  and building minimal lab-only shellcode exercises.

## Wave 2 — Hunt Methodology

The Wave 2 station pivots from one-binary reversing to systemic bug hunting.
The first added bundle is `Skills/offensive-macos-tooling-ghidra-headless`;
the hunt-methodology bundles are appended as they land.

- `Skills/offensive-macos-hunt-wrong-door` — hunt workflow for entitlement
  gates attached to one XPC listener while sibling listeners remain reachable
  or defer authorization inconsistently.
- `Skills/offensive-macos-hunt-defaults-bypass` — hunt workflow for
  user-writable defaults or feature flags that disable entitlement,
  privacy, trust, pairing, or validation checks.
- `Skills/offensive-macos-hunt-catalyst-porting-gap` — hunt workflow for
  Mac Catalyst/platform-condition branches that weaken entitlement or
  sandbox enforcement.
- `Skills/offensive-macos-agent-discipline` — L1-L6 failure taxonomy,
  RE-parallel rule, machine discipline, no-`/tmp` rule, `lsof` discipline,
  and handoff conventions for agent-led research loops.
- `Skills/offensive-macos-lab-roster` — role-based machine model covering
  primary, crash-test, cross-platform Apple Silicon, and Intel baseline hosts;
  NightBlood is the current primary.
- `Skills/offensive-macos-submission-packet` — last-mile checklist for
  packaging verified findings for vendor disclosure, internal remediation,
  red-team reporting, or Apple/platform disclosure while preserving the
  shared evidence core and analysis boundary.

## Wave 3 — Third-Party App Research

Wave 3 expands the station from seed systemic classes into a broader
finding-rate-driven third-party macOS application research workflow.

- `Skills/offensive-macos-vuln-ontology` — shared vulnerability-class
  ontology for mapping macOS app surfaces to reusable hunt hypotheses,
  evidence expectations, false-positive traps, and reporting impact.
- `Skills/offensive-macos-family-privileged-helpers` — target-family
  workflow for privileged helpers, updaters, installers, Sparkle services,
  LaunchDaemons, and root XPC surfaces.
- `Skills/offensive-macos-family-enterprise-agents` — target-family
  workflow for enterprise, security, EDR-adjacent, MDM, telemetry, and
  endpoint agent research.
- `Skills/offensive-macos-family-developer-tools` — target-family workflow
  for terminals, editors, package managers, build helpers, plugins,
  virtualization tools, and local developer agents.
- `Skills/offensive-macos-family-tcc-heavy-apps` — target-family workflow
  for privacy-permission-heavy apps involving TCC, Accessibility, Automation,
  Screen Recording, protected files, bookmarks, or file authority transfer.

