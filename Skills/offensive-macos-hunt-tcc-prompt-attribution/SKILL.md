---
name: offensive-macos-hunt-tcc-prompt-attribution
description: >-
  Use when auditing TCC-mediating daemons or apps for prompt-attribution
  bugs: a daemon prompts the user about app A but the request actually
  came from app B; responsible-process accounting laundered through a
  launchd intermediary; a privileged daemon proxies a request and asks
  for consent on behalf of itself rather than its caller. Fires on
  "tcc prompt attribution", "wrong responsible process", "tcc
  responsibility laundering", "consent on behalf of", "audit token vs
  responsible parent".
folder: offensive-macos-hunt-tcc-prompt-attribution
source: skillz-wave6
trigger_phrases:
  - "tcc prompt attribution"
  - "wrong responsible process"
  - "tcc responsibility laundering"
  - "consent on behalf of"
  - "audit token vs responsible parent"
---

# Hunt: TCC prompt attribution confusion

> Channel boundary: `REPO_MODE=analysis`. RCA, lab reproduction, defensive
> mapping, reporting guidance only.

## When to use

A daemon mediates TCC-protected access for multiple clients. Or a daemon resolves the requesting client via pid / bundleIdentifier / executablePath instead of `audit_token_t`. Or the privacy UI shows the wrong app name. Or a helper sits in an XPC chain and ends up taking the prompt.

## Lab topology

| Step | Surface | How |
|---|---|---|
| Static sweep | lab host | `ghidra-mcp` + `~/ghidra-scripts/scan_tcc_prompt_surface.py` |
| Dossier check | workstation | confirm `tcc-prompt-broker` in `findings/analysis/PASS-*-dossier.json` |
| Decompile attribution path | lab host | `ghidra-mcp decomp.function` on each `tccaccessrequest_callsite` |
| TCC database read-only | lab host | `sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db .schema` |
| Reachability harness | crash-test | minimal child process or Mach-port relay routing through the daemon |
| Evidence | findings repo | logs and lldb transcripts under `artifacts/`, hash-pinned via `triage.py transition --binary-sha256` |

## What the bug class is

The kernel can't decide whether a user has authorized a process to access a protected resource; the user has to be asked. The bug class is the daemon mediating that consent decision misidentifying the asking process.

Three known shapes.

Pid-only attribution. The daemon takes an XPC connection, calls `xpc_connection_get_pid` (or reads a process identifier from the dictionary), and uses that pid for the prompt. Pids reuse and are not kernel-vouched. The right primitive is `xpc_connection_get_audit_token` paired with `SecCodeCopyGuestWithAttributes(...kSecGuestAttributeAudit...)`.

Responsible-process laundering. A child inherits a "responsible" parent attribute from launchd. If the responsible parent is the privileged daemon itself instead of the original caller, the prompt names the daemon. The user clicks Allow on the wrong app. CVE-2020-9934 (tccd / cfprefsd) is the canonical example.

Substituted bundle identity. The daemon trusts a bundle identifier or executable path string from the connection's main bundle. The app can rename or symlink itself, or the daemon reads from a path the attacker controls.

The invariant: every consent decision should tie back to an `audit_token_t` resolved into a code-signature identity inside the daemon's own process, not into a string or pid the client can influence.

## Anchor pattern

From `scan_tcc_prompt_surface.py`:

Strong signals are tier-A `tccaccessrequest_callsite` (or the AVFoundation / Photos objc dispatch equivalents) with a recovered service name, when the same containing function also has tier-B `weak_identity_check` rows nearby. Identity resolution and TCC request live in the same call graph.

Also strong: tier-A `sectaskcopyentitlement_callsite` with a recovered `entitlement=com.apple.private.tcc.allow*`. The daemon is doing the right thing in *one* place. Check that every TCC path goes through this gate, not just the one you found.

Medium: tier-A `tcc_callsite` rows but no tier-B `audit_token_user`. The daemon may be resolving identity from process-identifier-shaped fields.

Weak: tier-C `tcc_string` and `privacy_service_string` rows alone. The binary is in the TCC graph somewhere; navigate to find the actual mediator.

The reverse pattern is also informative. A daemon with many tier-A `tccaccessrequest_callsite` rows but zero `audit_token_user` tier-B rows is doing pid-only attribution somewhere.

## Harness

Open the target:

```text
program.open(path="/System/Library/PrivateFrameworks/TCC.framework/Support/tccd",
             project_location="/Users/<remote-user>/ghidra-projects",
             project_name="tcc-attribution-<target>",
             read_only=true, update_analysis=true)
```

Run the scan:

```text
ghidra.script(session_id="<session>",
              path="/Users/<remote-user>/ghidra-scripts/scan_tcc_prompt_surface.py",
              script_args=[])
```

For each tier-A `tccaccessrequest_callsite`, decompile and trace how the calling subject's identity is determined. Is `xpc_connection_get_audit_token` called? Is the audit token passed to `SecCodeCopyGuestWithAttributes`? Or is the prompt populated from `bundleIdentifier`, `executablePath`, or `processIdentifier`?

Build a decision diagram:

```
incoming connection
  -> identity extraction (audit_token | pid | bundle_id | path)
    -> code-signature resolution (SecCode + SecRequirement | none)
      -> prompt subject (real caller | daemon-self | inherited responsible parent)
        -> TCC.db row (correct attribution | wrong attribution)
```

Anywhere the diagram has a non-audit-token branch, you have a candidate.

## Behavioral confirmation

Read-only first; don't change TCC state on a real machine.

Snapshot the lab VM. Confirm `LAB_SAFETY.md` allows lldb attach to the daemon.

Run a benign client that asks the daemon for the protected resource:

```bash
/usr/bin/osascript -e 'tell application "Finder" to set x to count of files in folder "Documents" of home'
```

Capture the prompt UI:

```bash
log stream --style compact --predicate \
  'subsystem == "com.apple.tccd" AND eventMessage CONTAINS "prompt"'
```

Compare the responsible / requesting subject named in the log to the actual caller. Mismatch is the bug.

For laundering specifically: spawn the same call through a known-laundering surface (`Automator`, `osascript`, `open` with a URL scheme) and watch whether the prompt subject changes.

## Reachability for unprivileged clients

If the daemon exposes an XPC interface, use the wrong-door reachability probe (see `Skills/offensive-macos-hunt-wrong-door/SKILL.md`) to confirm a UID-501 client can reach the same TCC-mediated path.

## Triage

Enumerate every `tccaccessrequest_callsite` and `tccaccesspreflight_callsite`. For each, decompile and classify identity resolution: audit_token, pid, bundle_id, path, or inherited.

Promote to `escalated` only when at least one path is non-audit-token *and* a low-privilege caller can drive it.

Confirm with a live attach (read-only) and a paired `tccd` log capture.

Close as `expected behavior` only when every path is audit-token-resolved and the responsible parent is taken from the connection's audit token, not from launchd inheritance.

## Pitfalls

TCC.db is mutable on a real machine. Snapshot first. Never run dynamic flips on a non-disposable host.

Apple frameworks centralize prompts. A thin daemon may delegate to `tccd` via a private framework; the bug may live in the framework. Trace `dlopen_callsite` rows from `scan_private_framework_dependency.py`.

Prompt UI is cached. The first prompt of a session shows the strongest signal; subsequent calls may be cached "allowed" and look benign.

macOS version matters. Apple has tightened TCC attribution across releases. A 2023 finding may be patched on 2026. Pin the lab VM build into Scriptorium with `os_build_snapshot`.

## Public anchors

CVE-2020-9934 (Synacktiv) showed launchd-mediated responsibility attribution let a sandboxed app inherit a parent's TCC grants.

Patrick Wardle's Objective-See has multiple posts on Mac TCC consent UI diverging from actual permission state.

## See also

- `Skills/offensive-macos-family-tcc-heavy-apps/SKILL.md`
- `Skills/offensive-macos-hunt-wrong-door/SKILL.md`
- `Skills/offensive-macos-vuln-ontology/SKILL.md`
- `Skills/offensive-macos-gatehouse-ghidra-lldb/SKILL.md`
- `ghidra-scripts/scan_tcc_prompt_surface.py`
- `ghidra-scripts/dump_xpc_listeners.py`
