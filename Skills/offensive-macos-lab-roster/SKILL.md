---
name: offensive-macos-lab-roster
description: >-
  Use when choosing or adding macOS research machines: primary, crash-test,
  cross-platform Apple Silicon, and Intel baseline. Fires on "add a lab
  machine", "which machine should run this", "primary lab host", "crash-test",
  "Intel baseline", and "cross-platform verification".
folder: offensive-macos-lab-roster
source: skillz-wave2
trigger_phrases:
  - "add a lab machine"
  - "which machine should run this"
  - "primary lab host"
  - "crash-test"
  - "Intel baseline"
  - "VM sizing"
  - "how much RAM"
  - "Ghidra heap"
---

# macOS Lab Roster

> **Channel boundary:** `REPO_MODE=analysis`. RCA, lab reproduction, defensive
> mapping, and tooling guidance only. No operational exploit authoring against
> live third-party targets.

## When To Use

- A task may crash a daemon or panic a machine.
- You need cross-platform confirmation before a submission.
- The operator is adding a new machine to the station.

## Current Roster

| Role | Current Host | Status |
|------|--------------|--------|
| primary | `<lab-host>` | Fill in your SSH alias, architecture, SIP state, Ghidra version, and installed MCP servers |
| crash-test | operator to fill | Needed for panic-prone PoCs and destructive daemon tests |
| cross-platform | operator to fill | Needed for different Apple Silicon generation confirmation |
| intel-baseline | operator to fill | Needed for x86_64/macOS legacy comparison |

The primary host is the concrete floor. The other roles are checklist-driven additions, not blockers for static hunting.

## Role Definitions

| Role | Use It For | Do Not Use It For |
|------|------------|-------------------|
| primary | static analysis, Ghidra, routine XPC probes, notes | panic-prone kernel tests once a crash-test host exists |
| crash-test | panics, fuzzing, daemon DoS, unsafe harnesses | long-lived notes or single source of truth |
| cross-platform | verifying Apple Silicon generation drift | first-run destructive unknowns |
| intel-baseline | checking x86_64/macOS 14-style behavior | Apple Silicon mitigation conclusions |

## VM Sizing

Resource recommendations by role. Source: PASS-001 (Rocket.Chat 4.13.0,
2026-05-11) — a 4 GB / 2-core VM with `-Xmx12g` swap-thrashed for 2+ hours
on a 177 MB Electron Framework before being killed; 16 GB / 8-core with
`-Xmx10g` ran clean (RSS peaked ~4 GB, zero swap).

| Role | vCPU | RAM | Disk | Rationale |
|------|------|-----|------|-----------|
| smoke-test / small binaries | 2 | 4 GB | 60 GB | Main execs and helpers under ~10 MB. Not for Apple frameworks or Electron bodies. |
| primary (Electron, consumer apps) | 8 | 16 GB | 256 GB | Survives 100-200 MB Mach-Os. Headroom for persistent projects across 5-10 targets. |
| primary (Apple framework + dyld cache extraction) | 8 | 32 GB | 512 GB | Apple framework analyses need more heap; cache extracts eat disk fast. |
| crash-test | 4 | 8 GB | 128 GB | Dynamic-only; never runs Ghidra. Runs lldb, dtrace, sample PoCs. |

### Heap sizing rule

**`-Xmx = physical_ram_gb - 6`.** The 6 GB budget covers OS + MCP servers
+ APFS compressor + headroom for bursts. On a 16 GB VM, `-Xmx10g`. On a
32 GB VM, `-Xmx24g`.

This is encoded in `scripts/ghidra-scan.sh` as a default + comment on
`HEAP_SIZE`. Override with `MACRE_GHIDRA_HEAP=<N>g`.

### Cores

Ghidra's serial analyzer phases (decompile-switch-analyzer, function-body
repair, data-type-archive application) only use 1 core; parallel phases
(function discovery, string walkers, propagation) scale. **4 cores is the
sweet spot for a single-binary workflow.** 8 cores earns its keep when
you fan out: concurrent Helper sweeps, lldb attach during DTrace capture,
parallel Ghidra projects on the same host. Default to 8 unless the VM
budget is tight.

## Setup Checklist For A New Machine

1. Add an SSH alias in `~/.ssh/config`:

   ```sshconfig
   Host CrashTest
     HostName <ip-or-hostname>
     User <user>
     PreferredAuthentications publickey,password
     PubkeyAuthentication yes
   ```

2. Install key auth:

   ```bash
   MACRE_MACHINE=CrashTest scripts/install-vm-ssh-key.sh
   ```

3. Verify:

   ```bash
   ssh -o BatchMode=yes CrashTest 'uname -m; sw_vers -productVersion'
   ```

4. Optional dynamic tooling:

   ```bash
   MACRE_MACHINE=CrashTest scripts/deploy-macre-vm-mcp.sh
   ```

5. Record machine facts in the findings repo `machines.md`:
   - alias
   - role
   - chip/model
   - OS build
   - SIP state
   - reboot/autologin behavior
   - what tests are allowed there

## Primary Machine Checklist

- `ssh -o BatchMode=yes <lab-host> true` succeeds.
- `scripts/install-ghidra-host.sh --smoke` passes.
- `macre-vm-mcp` smoke passes.
- `class-dump`, `jtool2`, `otool`, `nm`, `codesign`, `plutil`, and `log` are available or documented as missing.
- Hopper may remain installed for human GUI depth work, but Cursor routes static analysis through `ghidra-mcp`.

## SIP Guidance

- SIP off is acceptable on primary if the operator accepts the compromise and fidelity tradeoff.
- Crash-test may need SIP off for kernel/driver work.
- Cross-platform and Intel baseline should generally preserve realistic SIP-on state unless the test explicitly requires otherwise.

## Attribution

Machine-role discipline adapted from dmaynor/AVR-INTERNAL, 2026 (see https://github.com/dmaynor/AVR-INTERNAL). This station maps the pattern to a primary-lab-host-first workflow.

## See Also

- `Skills/offensive-macos-agent-discipline/SKILL.md`
- `docs/topology.md`
- `README.md`
