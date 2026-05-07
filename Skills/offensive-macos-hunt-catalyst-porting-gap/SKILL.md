---
name: offensive-macos-hunt-catalyst-porting-gap
description: >-
  Use when auditing Mac Catalyst or platform-conditional entitlement logic:
  strings like `is-catalyst-binary`, `MacCatalyst`, `non macos platform`,
  platform checks that skip entitlements, or service behavior that differs for
  Catalyst/iOS-on-mac clients. Fires on "Catalyst bypass", "platform-conditional
  entitlement", "Mac Catalyst entitlement", and "porting gap".
folder: offensive-macos-hunt-catalyst-porting-gap
source: skillz-wave2
trigger_phrases:
  - "Catalyst bypass"
  - "platform-conditional entitlement"
  - "Mac Catalyst entitlement"
  - "porting gap"
---

# Hunt: Catalyst Porting Gap

> **Channel boundary:** `REPO_MODE=analysis`. RCA, lab reproduction, defensive
> mapping, and tooling guidance only. No operational exploit authoring against
> live third-party targets.

## When To Use

- A daemon branches on Catalyst, iOS-on-mac, platform info, `is-catalyst-binary`, or "non macOS platform" before checking entitlements.
- A service treats platform identity as a substitute for authorization.
- You need to verify whether a Catalyst app can reach a path that native macOS clients cannot, or vice versa.

## Lab Topology — Where To Run This

| Step | Surface | How |
|------|---------|-----|
| Static sweep | NightBlood via Cursor | `ghidra-mcp` + `/Users/szeth/ghidra-scripts/scan_catalyst_porting_gap.py` |
| Platform branch RE | NightBlood via Cursor | `function.by_name`, `decomp.function`, strings/xrefs |
| App identity confirmation | primary + cross-platform | build minimal native/Catalyst clients when needed |
| Dynamic service reachability | crash-test preferred | XPC harness under native app and Catalyst app identities |
| Matrix | Findings repo | native macOS vs Catalyst vs Intel/cross-platform if available |

## Vulnerability Class Definition

A Catalyst porting gap occurs when code imported from iOS/macOS compatibility layers changes an authorization decision based on platform type rather than capability. The dangerous version is not "the daemon knows a process is Catalyst." The dangerous version is "Catalyst/native/iOS-on-mac classification suppresses entitlement, sandbox, trust, or validation checks for a service that still exposes privileged macOS behavior."

Common branch inputs:

- `is-catalyst-binary`
- `isMacCatalystForPID:`
- platform-info lookup failures
- `targetEnvironment(macCatalyst)` equivalents
- strings such as `non macos platform`, `no entitlement check required`, `temporarily allowing`, or `no entitlements are required`

## Anchor Pattern

Strong anchors combine three facts:

1. Platform/Catalyst detection exists.
2. Entitlement/security language exists nearby.
3. The branch appears to land on an allow/skip/bypass path.

Medium anchors include platform strings and entitlement strings in the same binary but not yet tied to one function. Weak anchors are generic Catalyst support strings with no security noun.

## Harness Invocation

1. Open target:

   ```text
   program.open(path="/path/to/daemon", project_location="/Users/szeth/ghidra-projects", project_name="catalyst-<target>", read_only=true, update_analysis=true)
   ```

2. Run:

   ```text
   ghidra.script(session_id="<session>", path="/Users/szeth/ghidra-scripts/scan_catalyst_porting_gap.py", script_args=[])
   ```

3. Save TSV:

   ```text
   target	catalyst_refs	platform_checks	entitlement_refs	bypass_refs	confidence	evidence
   /path/to/daemon	2	5	7	1	high	catalyst=...
   ```

4. Decompile around the strongest evidence string and draw a reachability diagram:

   ```text
   client pid -> platform lookup -> Catalyst/native branch -> entitlement decision -> service method
   ```

## Exploitation Test Shape

The proof path is a comparison, not a single run:

- Native macOS command-line harness with no special entitlements.
- Minimal Catalyst app or Catalyst-shaped client identity, when required.
- Same service, same method, same user, same OS build.
- Record `ACCEPTED`, `REPLIED`, `REJECTED`, and logs for both clients.

Do not build the Catalyst app until static analysis shows the platform branch can plausibly affect authorization. Many Catalyst references are harmless compatibility code.

## Micro-Hunt

1. Pick one high-confidence row from `scan_catalyst_porting_gap.py`.
2. Find the exact function that references the Catalyst/platform string.
3. Decompile that function and one caller.
4. Write the branch condition in plain English.
5. Decide whether a native-vs-Catalyst dynamic test is justified.

## Pitfalls

- Platform checks can make enforcement stricter, not weaker. Read both sides of the branch.
- Catalyst status alone is not an entitlement. Treat it as identity context that must still be paired with capability checks.
- Platform detection failure paths are important; a failed lookup that falls open can be as interesting as an explicit Catalyst allow.
- Cross-version testing matters. Porting gaps often drift between Apple Silicon generations and Intel.

## Attribution

Pattern adapted from dmaynor/AVR-INTERNAL, 2026 (see https://github.com/dmaynor/AVR-INTERNAL). This station imports the methodology and pattern taxonomy; it does not claim AVR-INTERNAL's specific findings as ours.

## See Also

- `Skills/offensive-macos-tooling-ghidra-headless/SKILL.md`
- `Skills/offensive-macos-hunt-defaults-bypass/SKILL.md`
- `Skills/offensive-macos-lab-roster/SKILL.md`
- `ghidra-scripts/scan_catalyst_porting_gap.py`
