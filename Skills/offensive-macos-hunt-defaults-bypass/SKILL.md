---
name: offensive-macos-hunt-defaults-bypass
description: >-
  Use when auditing macOS binaries for security decisions controlled by
  user-writable defaults: `NSUserDefaults`, `CFPreferences`, `defaults write`,
  debug/test/internal keys, entitlement bypass strings, or feature flags that
  can disable validation. Fires on "defaults bypass", "user-defaults security
  gate", "defaults write bypass", and "scan for defaults-gated checks".
folder: offensive-macos-hunt-defaults-bypass
source: skillz-wave2
trigger_phrases:
  - "defaults bypass"
  - "user-defaults security gate"
  - "defaults write bypass"
  - "scan for defaults-gated checks"
---

# Hunt: User Defaults Security Bypass

> **Channel boundary:** `REPO_MODE=analysis`. RCA, lab reproduction, defensive
> mapping, and tooling guidance only. No operational exploit authoring against
> live third-party targets.

## When To Use

- A binary contains strings like `Bypassing entitlement checks`, `skip validation`, `defaults write`, `internal setting`, `debug override`, or `feature flag disabled`.
- The target is a LaunchAgent or user-context process whose defaults domain may be writable by UID 501.
- You need to decide whether a bypass string is dead debug text, root-only configuration, or an actual production security switch.

## Lab Topology — Where To Run This

| Step | Surface | How |
|------|---------|-----|
| Static string/script sweep | NightBlood via Cursor | `ghidra-mcp` + `/Users/szeth/ghidra-scripts/scan_defaults_bypass.py` |
| Process classification | NightBlood | launchd plist inspection via CLI or `macre-vm-mcp` |
| Defaults write test | primary or crash-test | run as UID 501, never root first |
| Runtime confirmation | NightBlood | `log stream`, daemon restart, DTrace/LLDB only if needed |
| Evidence record | Findings repo | TSV + before/after logs under `findings/analysis/` |

## Vulnerability Class Definition

The defaults-bypass pattern exists when a security decision is controlled by a user-writable preference key without an internal-build gate, entitlement gate, root-only configuration boundary, or signed configuration profile. The bug is not "the binary reads defaults"; it is "a user-controlled key disables or weakens a check that protects another user, the system, credentials, sensors, pairing, identity, privacy indicators, or entitlement enforcement."

LaunchAgents matter most because they run in a user context. A sandboxed app can often write that user's defaults domain. LaunchDaemons are lower priority for unprivileged bugs because their defaults normally live in root/system domains, but they can still indicate design risk or a confused-deputy path.

## Anchor Pattern

Strong anchors:

- Bypass language near defaults APIs: `NSUserDefaults`, `CFPreferences`, `standardUserDefaults`, `defaults write`.
- Explicit instructions or domain/key names in production strings.
- Security nouns near override words: entitlement, validation, trust, pairing, auth, privacy, screen capture, location, identity, certificate, MAC, sandbox.
- LaunchAgent context, or a daemon that reads preferences from a user domain.

Weak anchors:

- Generic feature flags with no security noun.
- Root-only LaunchDaemon defaults.
- Internal-build strings that are conclusively gated by `isInternalBuild` and boot-arg checks.

## Harness Invocation

1. Open the target:

   ```text
   program.open(path="/path/to/binary", project_location="/Users/szeth/ghidra-projects", project_name="defaults-<target>", read_only=true, update_analysis=true)
   ```

2. Run:

   ```text
   ghidra.script(session_id="<session>", path="/Users/szeth/ghidra-scripts/scan_defaults_bypass.py", script_args=[])
   ```

3. Save TSV:

   ```text
   target	type	domains	keys	bypass_strings	confidence	evidence
   /path/to/agent	launchagent-or-user-context	2	5	9	high	defaults_api=...
   ```

4. Rank:

   - Tier 1: LaunchAgent/user-context + high confidence + explicit security bypass strings.
   - Tier 2: LaunchDaemon/system-context + high confidence, or LaunchAgent + medium confidence.
   - Tier 3: generic debug strings, root-only, or internal-build gated.

## Behavioral Confirmation

1. Identify the domain/key candidate from strings and decompiled call sites.
2. Capture baseline behavior and logs.
3. As UID 501, write the candidate default:

   ```bash
   defaults write <domain> <key> -bool true
   ```

4. Restart or trigger the target in the least invasive way.
5. Capture logs:

   ```bash
   log stream --style compact --predicate 'process == "<target>"'
   ```

6. Confirm one of:
   - The bypass branch executes.
   - A security check is skipped or downgraded.
   - The key is read but rejected by entitlement/internal-build logic.
   - The string is dead or unreachable.

## Micro-Hunt

1. Pick one LaunchAgent or user-context daemon with high `scan_defaults_bypass.py` confidence.
2. Decompile the function around the strongest key/string.
3. Prove the defaults domain and type.
4. Try one UID 501 `defaults write` and capture before/after logs.
5. Write a one-paragraph conclusion: exploitable, blocked by gate, root-only, or false positive.

## Pitfalls

- Defaults domains are easy to guess wrong. Confirm the exact domain and key at the read call, not just from adjacent strings.
- A key may only be honored in internal builds. Find the internal-build predicate before claiming impact.
- Some privacy/security UI state is cached. Reset the key and restart the minimal process before retesting.
- Do not convert a bypass string into a claim until runtime confirms the branch can be influenced by UID 501.

## Attribution

Pattern adapted from dmaynor/AVR-INTERNAL, 2026 (see https://github.com/dmaynor/AVR-INTERNAL). This station imports the methodology and classification discipline; it does not claim AVR-INTERNAL's specific findings as ours.

## See Also

- `Skills/offensive-macos-tooling-ghidra-headless/SKILL.md`
- `Skills/offensive-macos-agent-discipline/SKILL.md`
- `ghidra-scripts/scan_defaults_bypass.py`
