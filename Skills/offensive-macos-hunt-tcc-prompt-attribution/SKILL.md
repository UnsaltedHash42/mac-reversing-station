---
name: offensive-macos-hunt-tcc-prompt-attribution
description: >-
  Use when auditing TCC-mediated daemons or apps for prompt-attribution and
  responsibility confusion: the daemon prompts the user about app A but the
  request actually came from app B; the responsible-process accounting is
  laundered through a launchd intermediary; or a privileged daemon proxies
  a request and asks for consent on behalf of itself rather than its caller.
  Fires on "tcc prompt attribution", "wrong responsible process", "tcc
  responsibility laundering", "consent on behalf of", and "audit token vs
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

# Hunt: TCC Prompt Attribution Confusion

> **Channel boundary:** `REPO_MODE=analysis`. Root-cause analysis, lab
> reproduction, defensive mapping, and reporting guidance only. No
> operational exploit authoring against live third-party targets.

## When To Use

- A daemon mediates TCC-protected access (Documents, Camera, FDA, Apple Events, Accessibility) on behalf of multiple clients.
- The daemon resolves the requesting client via `pid_t` / `bundleIdentifier` / `executablePath` rather than a kernel-vouched `audit_token_t`.
- Privacy UI shows the wrong app name when access is requested through an XPC chain or login-item launcher.
- A helper or shared-process intermediary participates in a TCC consent flow.

## Lab Topology — Where To Run This

| Step | Surface | How |
|------|---------|-----|
| Static script sweep | lab host via Cursor | `ghidra-mcp` + `~/ghidra-scripts/scan_tcc_prompt_surface.py` |
| Dossier check | workstation | confirm `tcc-prompt-broker` surface is in `findings/analysis/PASS-*-dossier.json` |
| Decompile prompt-attribution path | lab host | `ghidra-mcp` `decomp.function` on each `tccaccessrequest_callsite` row |
| TCC database read-only inspect | lab host | `macre-vm-mcp` future `tcc_db_inspect` (fall back to `sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db .schema`) |
| Reachability harness | crash-test | minimal child process / Mach-port relay that requests through the daemon |
| Evidence record | findings repo | log streams + lldb transcripts under `artifacts/`, hash-pinned via `triage.py transition --binary-sha256` |

## Vulnerability Class Definition

The TCC consent UI exists because the kernel cannot, by itself, decide whether a user has authorized a process to access a protected resource. The user must be asked. The bug class is: **the daemon mediating that consent decision identifies the asking process incorrectly.**

Three known shapes:

1. **Pid-only attribution.** The daemon receives an XPC connection, calls `xpc_connection_get_pid` or reads the connection's process identifier, and uses that pid to drive the prompt. Pids are not stable across reuse and are not kernel-vouched. The right primitive is `xpc_connection_get_audit_token` paired with `SecCodeCopyGuestWithAttributes(...kSecGuestAttributeAudit...)`.

2. **Responsible-process laundering.** A child process inherits a "responsible" parent attribute from launchd. If the responsible parent is the privileged daemon itself (instead of the original caller), the prompt names the daemon, not the caller. The user clicks "Allow" on the wrong app. This is the class of bug that drove [CVE-2020-9934](https://www.synacktiv.com/sites/default/files/2021-01/cve-2020-9934-tccd.pdf) (tccd / cfprefsd shared XPC connection) and several follow-ups.

3. **Substituted bundle identity.** The daemon trusts a bundle identifier or executable path string from the connection's main bundle. An app can rename or symlink itself, or the daemon can be tricked into reading from a path the attacker controls.

The strong invariant: every consent decision should be tied to an `audit_token_t` resolved into a code-signature identity inside the daemon's own process, not into any string or pid the client can influence.

## Anchor Pattern

From `scan_tcc_prompt_surface.py`:

- **Strong**: tier-A `tccaccessrequest_callsite` with a recovered `service=` arg whose value is a kTCCService name, *and* the same containing function has tier-B `weak_identity_check` rows nearby (functions named `*pid`, `*bundleIdentifier`, `*executablePath`). Strong because identity resolution and TCC request live in the same call graph.
- **Strong**: tier-A `sectaskcopyentitlement_callsite` with a recovered `entitlement=com.apple.private.tcc.allow*`. The daemon is doing the right thing in *one* place — but check that *every* TCC path goes through this gate, not just the one you found.
- **Medium**: tier-A `tcc_callsite` rows but no tier-B `audit_token_user`. The daemon may be resolving identity from process-identifier-shaped fields.
- **Weak**: tier-C `tcc_string` and `privacy_service_string` rows alone. Indicates the binary is in the TCC graph somewhere; navigate to find the actual mediator.

The reverse pattern is also informative: a daemon with many tier-A `tccaccessrequest_callsite` rows but **zero** `audit_token_user` tier-B rows is doing pid-only attribution somewhere.

## Harness Invocation

1. Open the target:
   ```text
   program.open(path="/System/Library/PrivateFrameworks/TCC.framework/Support/tccd",
                project_location="/Users/<remote-user>/ghidra-projects",
                project_name="tcc-attribution-<target>",
                read_only=true, update_analysis=true)
   ```

2. Run the scan:
   ```text
   ghidra.script(session_id="<session>",
                 path="/Users/<remote-user>/ghidra-scripts/scan_tcc_prompt_surface.py",
                 script_args=[])
   ```

3. For each tier-A `tccaccessrequest_callsite` row:
   ```text
   decomp.function(session_id="<session>", address=<row.address>)
   ```
   Read the function. Trace **how the calling subject's identity is determined**:
   - Is `xpc_connection_get_audit_token` called?
   - Is the audit token passed to `SecCodeCopyGuestWithAttributes`?
   - Or is the prompt populated from `bundleIdentifier` / `executablePath` / `processIdentifier`?

4. Build a decision diagram:
   ```text
   incoming connection
     -> identity extraction (audit_token | pid | bundle_id | path)
       -> code-signature resolution? (SecCode + SecRequirement | none)
         -> prompt subject (real caller | daemon-self | inherited responsible parent)
           -> TCC.db row (correct attribution | wrong attribution)
   ```

   Anywhere the diagram has a non-audit-token branch, you have a candidate.

## Behavioral Confirmation

Read-only first; do not change TCC state on a real machine.

1. Snapshot the lab VM. Confirm `LAB_SAFETY.md` allows lldb attach to the daemon.
2. Run a benign client that asks the daemon for the protected resource:
   ```bash
   # example: Documents folder access through a child
   /usr/bin/osascript -e 'tell application "Finder" to set x to count of files in folder "Documents" of home'
   ```
3. Capture the prompt UI:
   ```bash
   log stream --style compact --predicate \
     'subsystem == "com.apple.tccd" AND eventMessage CONTAINS "prompt"'
   ```
4. Compare the responsible / requesting subject named in the log to the actual caller. Mismatch is the bug.
5. For attribution-laundering specifically: spawn the same call through a known-laundering surface (e.g., `Automator` workflow, `osascript`, `open` with a URL scheme) and watch whether the prompt subject changes.

## UID 501 Reachability

If the daemon exposes an XPC interface, use the wrong-door reachability probe (see `Skills/offensive-macos-hunt-wrong-door/SKILL.md`) to confirm an unprivileged client can reach the same TCC-mediated path.

## Triage Workflow

1. Enumerate every `tccaccessrequest_callsite` and `tccaccesspreflight_callsite`.
2. For each, decompile and classify identity resolution: `audit_token` / `pid` / `bundle_id` / `path` / `inherited`.
3. Promote to `escalated` only when at least one path is non-audit-token *and* a low-privilege caller can drive that path.
4. Confirm with a live attach (read-only) and a paired `tccd` log capture.
5. Close as `expected behavior` only when every path is audit-token-resolved and the responsible parent is taken from the connection's audit token, not from launchd inheritance.

## Pitfalls

- **TCC.db is mutable on a real machine.** Snapshot first. Never run dynamic flips on a non-disposable host.
- **Apple frameworks centralize prompts.** A thin daemon may delegate to `tccd` via a private framework; the bug may live in the framework, not the daemon. Trace the `dlopen_callsite` rows from `scan_private_framework_dependency.py`.
- **Prompt UI is cached.** The first prompt of a session shows the strongest signal; subsequent calls may be cached "allowed" and look benign.
- **macOS version drift matters.** Apple has tightened TCC attribution across releases. A 2023 finding may be patched on 2026 builds. Pin your lab VM build into Scriptorium with `os_build_snapshot`.

## Known Public Anchors

- [CVE-2020-9934 / "responsibility laundering" via cfprefsd](https://www.synacktiv.com/publications/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-unauthorized-access-to-sensitive-user-data.html) — Synacktiv showed launchd-mediated responsibility attribution let a sandboxed app inherit a parent's TCC grants.
- [Patrick Wardle's TCC research](https://www.objective-see.com/) — multiple posts on Mac TCC consent UI divergence from actual permission state.

## See Also

- `Skills/offensive-macos-family-tcc-heavy-apps/SKILL.md`
- `Skills/offensive-macos-hunt-wrong-door/SKILL.md`
- `Skills/offensive-macos-vuln-ontology/SKILL.md`
- `Skills/offensive-macos-gatehouse-ghidra-lldb/SKILL.md`
- `ghidra-scripts/scan_tcc_prompt_surface.py`
- `ghidra-scripts/dump_xpc_listeners.py`
