# Ghidra Hunt Scripts

These scripts are small, read-only postScripts for the Ghidra-first macOS hunt station. They are designed to be invoked through `ghidra-mcp` scripting tools against one already-open program at a time, then aggregated by the agent into hunt TSVs.

The scripts intentionally bias toward stable triage signals over proof. A positive row means "open this candidate and verify dynamically," not "this is a vulnerability."

## Scripts

- `scan_wrong_door.py`
  - TSV: `daemon	listeners	ent_refs	should_accept_impls	audit_token_uses	evidence`
  - Looks for XPC listener strings, entitlement strings, delegate implementations, and audit-token references.

- `scan_defaults_bypass.py`
  - TSV: `target	type	domains	keys	bypass_strings	confidence	evidence`
  - Looks for `NSUserDefaults` / `CFPreferences` usage near bypass-shaped keys.

- `scan_catalyst_porting_gap.py`
  - TSV: `target	catalyst_refs	platform_checks	entitlement_refs	bypass_refs	confidence	evidence`
  - Looks for Catalyst/platform conditionals near entitlement or bypass vocabulary.

- `scan_flags_zero.py`
  - TSV: `target	code_sign_refs	flags_zero_refs	amfi_refs	confidence	evidence`
  - Looks for code-signing, AMFI, and flag-check strings/functions.

- `dump_xpc_listeners.py`
  - TSV: `target	mach_services	listener_delegate_impls	xpc_strings	evidence`
  - Dumps likely mach-service names and XPC listener/delegate anchors.

- `scan_xpc_client_validation.py`
  - TSV: `target	mach_services	should_accept_refs	audit_token_refs	weak_identity_refs	team_id_refs	confidence	evidence`
  - Looks for Mach/XPC services, connection-acceptance methods, audit-token usage, and weaker identity checks.

- `scan_privileged_helper_surface.py`
  - TSV: `target	helpers	launchd_refs	authz_refs	install_refs	privileged_ops	confidence	evidence`
  - Looks for helper, LaunchDaemon, authorization, installer/updater, and privileged-operation vocabulary.

- `scan_tcc_prompt_surface.py`
  - TSV: `target	tcc_refs	prompt_refs	bundle_identity_refs	apple_event_refs	privacy_services	confidence	evidence`
  - Looks for TCC, prompt attribution, identity, Apple Events, and privacy-service strings.

- `scan_persistent_authorization.py`
  - TSV: `target	bookmark_refs	keychain_refs	container_store_refs	sandbox_refs	file_access_refs	confidence	evidence`
  - Looks for security-scoped bookmarks, keychain, container persistence, sandbox extension, and file-access strings.

- `export_lldb_anchors.py`
  - TSV: `target	functions	entry_points	evidence`
  - Exports capped function entry anchors for Bridge workflows that need LLDB confirmation.

## Invocation Pattern

From an MCP-capable agent:

1. Open or import the target program with `ghidra-mcp`.
2. Run the relevant script by name with the server's script execution tool.
3. Save the returned TSV in the active findings repo under `findings/analysis/`.
4. Rank rows for dynamic follow-up with `macre-vm-mcp`, LLDB, DTrace, or a small ObjC harness.

Example operator request:

```text
Use ghidra-mcp to open /System/Library/PrivateFrameworks/TCC.framework/Support/tccd, run scan_wrong_door.py, and save the TSV into this findings repo.
```

## Output Contract

Every script prints exactly one header row and one result row for the current program. A future aggregator may loop over many binaries and concatenate rows while preserving only the first header.
