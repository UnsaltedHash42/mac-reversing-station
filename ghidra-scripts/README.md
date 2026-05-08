# Ghidra hunt scripts

Read-only postScripts for the macOS reversing studio. Each script runs against one already-loaded program through `ghidra-mcp` and emits **tiered anchor rows** to stdout in a unified TSV contract.

These scripts run on the lab host where Ghidra is installed. The agent on the workstation invokes them through `ghidra-mcp`'s script-execution tool.

## The output contract

Every script emits one TSV header row followed by zero or more anchor rows:

```
target  tier  anchor_kind  name  address  evidence
```

`tier` carries the trust level of each row:

- **A** — decompiler- or callsite-verified. The `address` points at real code in the loaded binary. Hand it to `lldb_run_anchors` directly.
- **B** — Mach-O / ObjC metadata, embedded plists, exported symbols. The address is meaningful (callsite, function entry, or metadata location) but the row reflects metadata rather than recovered semantics.
- **C** — string heuristic. A starting point in Ghidra; do not trust the row alone. Use it to navigate, not to claim.

`evidence` is `key=value` pairs joined by `; `. Pipes (`|`) separate multi-valued lists; tabs and newlines are stripped.

A scan with nothing to report emits the header row and zero anchor rows. Per-scan summary statistics (`anchors=N (A=x B=y C=z)`, plus warnings like `string_index_truncated_at_20000`) are written to stderr so they never pollute the TSV.

## Shared library

`_re_lib.py` provides:

- `AnchorWriter` — buffer + flush anchor rows in stable order
- `StringIndex` / `FunctionIndex` — capped, truncation-aware program walks
- `find_external` / `callers_of` — symbol resolution and xref walking for tier-A enrichment
- `StringRule` + `run_string_scan` — declarative regex-bag runner for the simpler scans

Every scan script imports `_re_lib`. The smoke test enforces that.

## Scripts

### Hunt scans

| Script | Anchor kinds it can emit |
|---|---|
| `scan_wrong_door.py` | tier B `should_accept_impl`, `audit_token_user`; tier C `listener_string`, `ent_string`, `audit_token_string` |
| `scan_xpc_client_validation.py` | tier A `xpc_listener_callsite`; tier B `should_accept_impl`, `audit_token_user`, `weak_identity_check`; tier C `mach_service_string`, `team_id_string` |
| `scan_privileged_helper_surface.py` | tier A `authorization_callsite`, `exec_callsite`; tier B `helper_install_impl`, `privileged_op_impl`; tier C `helper_string`, `launchd_string`, `authz_string`, `install_string` |
| `scan_tcc_prompt_surface.py` | tier A `tcc_callsite`; tier B `prompt_handler`, `identity_resolver`; tier C `tcc_string`, `apple_event_string`, `privacy_service_string`, `identity_string` |
| `scan_persistent_authorization.py` | tier A `keychain_callsite`, `bookmark_callsite`; tier B `bookmark_handler`, `sandbox_extension_handler`; tier C `bookmark_string`, `keychain_string`, `sandbox_string`, `container_string` |
| `scan_defaults_bypass.py` | tier A `defaults_callsite`; tier B `bypass_gate_impl`; tier C `defaults_api_string`, `defaults_key_candidate`, `defaults_domain` |
| `scan_flags_zero.py` | tier A `csops_callsite`; tier B `code_sign_check_impl`, `flag_check_impl`; tier C `code_sign_string`, `flags_string`, `amfi_string` |
| `scan_catalyst_porting_gap.py` | tier B `platform_branch`; tier C `catalyst_string`, `platform_string`, `ent_string`, `bypass_string` |
| `scan_endpoint_security_client.py` | tier A `es_client_callsite`; tier B `es_handler_impl`, `policy_decision_impl`; tier C `es_client_string`, `es_event_string`, `cache_string`, `policy_string` |
| `scan_system_extension_surface.py` | tier B `extension_lifecycle_impl`, `ne_provider_impl`; tier C `extension_string`, `es_string`, `ext_entitlement_string`, `approval_string` |
| `scan_launchd_machservice_topology.py` | tier A `bootstrap_callsite`; tier B `listener_setup_impl`; tier C `mach_service_string`, `listener_api_string`, `entitlement_string` |
| `scan_private_framework_dependency.py` | tier A `dlopen_callsite`; tier B `dynamic_resolver_impl`; tier C `private_framework_path`, `public_framework_path`, `dyld_token`, `weak_link_token` |

### Specialized

| Script | Anchor kinds it can emit |
|---|---|
| `dump_xpc_listeners.py` | tier A `xpc_registration_callsite` (decompiler-recovered service names), `nsxpc_delegate_impl`, `nsxpc_listener_init`; tier B `interesting_entitlement`; tier C `service_name_string` |
| `export_lldb_anchors.py` | tier A `lldb_anchor_symbol` (exports / entrypoints / mod_init); tier B `lldb_anchor_metadata` (api callers / non-system ObjC methods); tier C `lldb_anchor_fanin` (high in-degree only); also writes a `<binary>.anchors.lldb` sidecar with `breakpoint set` commands keyed by symbol |

`scan_xpc_client_validation.py` and `dump_xpc_listeners.py` overlap deliberately. Use `dump_xpc_listeners.py` when you want decompiler-recovered Mach service names; use `scan_xpc_client_validation.py` when you want the broader sweep including weak-identity-check candidates.

## Invocation pattern

From an MCP-capable agent:

1. Open or import the target program with `ghidra-mcp`.
2. Run the relevant script by name with `ghidra-mcp`'s script-execution tool.
3. Save the returned TSV in the active project clone under `findings/analysis/`.
4. Promote tier-A rows to candidate files via `scripts/triage.py`. Hand them to `lldb_run_anchors` for dynamic confirmation.

Example operator request:

```text
Use ghidra-mcp to open /System/Library/PrivateFrameworks/TCC.framework/Support/tccd, run scan_wrong_door.py, and save the TSV into this findings repo.
```

## Reading an anchor row

```
target                                                                tier  anchor_kind            name                                                  address      evidence
/.../tccd                                                             A     xpc_listener_callsite  ___setup_tccd_listener                                0x100008abc  api=xpc_connection_create_listener; site=0x100008abc
/.../tccd                                                             A     should_accept_impl     -[TCCDXPCConnection listener:shouldAcceptNewConnection:]  0x10000bcd0  selector=listener:shouldAcceptNewConnection:
/.../tccd                                                             B     interesting_entitlement com.apple.private.tcc.allow                          -            entitlement=com.apple.private.tcc.allow
/.../tccd                                                             C     mach_service_string    com.apple.tccd                                        -            string=com.apple.tccd
```

A useful first triage:

- Tier A rows go to `scripts/triage.py create` as `scan-hit` candidates. They have addresses you can hand to lldb.
- Tier B rows are reads — open in Ghidra, confirm or reject the metadata claim.
- Tier C rows are search starting points. Promote to a candidate only after Ghidra navigation finds the underlying call.

## Conventions

- Every script writes the header row once. There is no "old" pre-header text on stdout.
- Per-scan caps live in `_re_lib.py` (`DEFAULT_MAX_STRINGS=20000`, `DEFAULT_MAX_FUNCTIONS=50000`). When the cap is hit, the stderr summary carries `string_index_truncated_at_<n>` so the operator knows the row count is bounded by the cap, not by reality.
- New scripts should use `_re_lib`. The smoke test enforces it.
