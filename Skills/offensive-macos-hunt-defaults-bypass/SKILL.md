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
| Static string/script sweep | lab host via Cursor | `ghidra-mcp` + `/Users/<remote-user>/ghidra-scripts/scan_defaults_bypass.py` |
| Process classification | lab host | launchd plist inspection via CLI or `macre-vm-mcp` |
| Defaults write test | primary or crash-test | run as UID 501, never root first |
| Runtime confirmation | lab host | `log stream`, daemon restart, DTrace/LLDB only if needed |
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
   program.open(path="/path/to/binary", project_location="/Users/<remote-user>/ghidra-projects", project_name="defaults-<target>", read_only=true, update_analysis=true)
   ```

2. Run:

   ```text
   ghidra.script(session_id="<session>", path="/Users/<remote-user>/ghidra-scripts/scan_defaults_bypass.py", script_args=[])
   ```

3. Save TSV. The unified tiered-anchor contract emits:

   ```text
   target  tier  anchor_kind                       name                   address      evidence
   /path/to/agent  A  cfprefs_copyappvalue_callsite  _check_internal_mode   0x100008abc  api=CFPreferencesCopyAppValue; site=0x100008abc; key=disable-validation
   /path/to/agent  A  cfprefs_getbool_callsite       _maybe_skip_check      0x10000a020  api=CFPreferencesGetAppBooleanValue; site=...; key=internal.allow-test-build
   /path/to/agent  B  bypass_gate_impl               _disable_amfi_check    0x10000ce00  function=_disable_amfi_check
   /path/to/agent  C  defaults_key_candidate         debug-skip-validation  -            key=debug-skip-validation
   ```

   The literal **key** recovered by `CFPreferencesCopyAppValue` (et al.)
   is the high-leverage signal. Each tier-A row points you at exactly
   one decompiled function reading exactly one defaults key -- look at
   that function and the gate is right there.

4. Rank by tier-imbalance:

   - **Strong**: tier-A `cfprefs_*_callsite` with key=<security-shaped name>
     in a LaunchAgent / user-context binary. The recovered key tells
     you what to `defaults write` to flip the gate. This is a candidate.
   - **Medium**: tier-A callsite with key=<generic flag name> + tier-B
     `bypass_gate_impl` function nearby in the call graph. The flag
     might be reachable but not security-relevant; check the gate it
     guards.
   - **Weak**: tier-C `defaults_key_candidate` rows with no matching
     tier-A callsite. The string exists but is not necessarily read.
     Promote only after Ghidra navigation finds the actual read.

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
