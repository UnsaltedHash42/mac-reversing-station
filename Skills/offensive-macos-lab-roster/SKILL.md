---
name: offensive-macos-lab-roster
description: >-
  Use when choosing or adding macOS research machines: primary, crash-test,
  cross-platform Apple Silicon, and Intel baseline. Fires on "add a lab
  machine", "which machine should run this", "NightBlood role", "crash-test",
  "Intel baseline", and "cross-platform verification".
folder: offensive-macos-lab-roster
source: skillz-wave2
trigger_phrases:
  - "add a lab machine"
  - "which machine should run this"
  - "NightBlood role"
  - "crash-test"
  - "Intel baseline"
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
| primary | `NightBlood` | Active. Apple Silicon VM, SIP off, Ghidra 12.0.4, `ghidra-mcp`, `macre-vm-mcp`, Hopper for manual GUI depth |
| crash-test | operator to fill | Needed for panic-prone PoCs and destructive daemon tests |
| cross-platform | operator to fill | Needed for different Apple Silicon generation confirmation |
| intel-baseline | operator to fill | Needed for x86_64/macOS legacy comparison |

NightBlood is the concrete floor. The other roles are checklist-driven additions, not blockers for static hunting.

## Role Definitions

| Role | Use It For | Do Not Use It For |
|------|------------|-------------------|
| primary | static analysis, Ghidra, routine XPC probes, notes | panic-prone kernel tests once a crash-test host exists |
| crash-test | panics, fuzzing, daemon DoS, unsafe harnesses | long-lived notes or single source of truth |
| cross-platform | verifying Apple Silicon generation drift | first-run destructive unknowns |
| intel-baseline | checking x86_64/macOS 14-style behavior | Apple Silicon mitigation conclusions |

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

- `ssh -o BatchMode=yes NightBlood true` succeeds.
- `scripts/install-ghidra-host.sh --smoke` passes.
- `macre-vm-mcp` smoke passes.
- `class-dump`, `jtool2`, `otool`, `nm`, `codesign`, `plutil`, and `log` are available or documented as missing.
- Hopper may remain installed for human GUI depth work, but Cursor routes static analysis through `ghidra-mcp`.

## SIP Guidance

- SIP off is acceptable on primary if the operator accepts the compromise and fidelity tradeoff.
- Crash-test may need SIP off for kernel/driver work.
- Cross-platform and Intel baseline should generally preserve realistic SIP-on state unless the test explicitly requires otherwise.

## Attribution

Machine-role discipline adapted from dmaynor/AVR-INTERNAL, 2026 (see https://github.com/dmaynor/AVR-INTERNAL). This station maps the pattern to the local NightBlood-first lab.

## See Also

- `Skills/offensive-macos-agent-discipline/SKILL.md`
- `docs/topology.md`
- `docs/operator-guide.md`
