# Ghidra hunt scripts

Read-only postScripts for the macOS reversing studio. Each script runs against one already-loaded program through `ghidra-mcp` and emits **tiered anchor rows** to stdout.

These run on the lab host where Ghidra is installed. The agent on the workstation invokes them through `ghidra-mcp`'s script-execution tool.

## Output contract

Every script emits one TSV header followed by zero or more anchor rows:

```
target  tier  anchor_kind  name  address  evidence
```

Three tiers:

- **A** — decompiler- or callsite-verified. The address points at real code in the loaded binary; hand it to `lldb_run_anchors` directly. Most A rows also carry the literal recovered argument (Mach service name, defaults key, IOConnect selector, etc.) in the evidence column.
- **B** — Mach-O / ObjC metadata, embedded plists, exported symbols. The address is meaningful (callsite, function entry, metadata location) but the row reflects metadata rather than recovered semantics.
- **C** — string heuristic. Useful as a navigation starting point. Don't trust the row alone.

`evidence` is `key=value` pairs joined by `; `. Pipes (`|`) separate multi-valued lists; tabs and newlines are stripped from values.

A scan with nothing to report emits the header and zero rows. Per-scan summary stats (`anchors=N (A=x B=y C=z)`, plus warnings like `string_index_truncated_at_20000`) go to stderr so they never pollute the TSV.

## Shared library

`_re_lib.py` is what makes the scans tight. It provides:

- `AnchorWriter` — buffer and flush anchor rows in stable order.
- `StringIndex` / `FunctionIndex` — capped, truncation-aware program walks.
- `find_external` / `callers_of` — symbol resolution and xref walking.
- `DecompCache` — lazy `DecompInterface` wrapper for argument recovery.
- `recover_string_at` — handles four common cases: Ghidra-defined data, `__cfstring` constants (dereferences at +0x10), `__objc_selrefs` / `__got` indirection, raw NUL-terminated reads.
- `recover_call_string_arg` / `recover_call_const_arg` / `recover_call_arg_fast` — pcode-driven argument extraction with a backwards-instruction fallback. The const path folds `INT_OR` / `INT_AND` / `INT_LEFT` / `INT_RIGHT` / `INT_XOR` / `INT_ADD` / `INT_SUB` / `INT_MULT` so flag-arithmetic args resolve.
- `recover_objc_selector` — recovers the SEL at arg 1 of an `objc_msgSend` callsite.
- `APISpec` + `enrich_callsite_args` — declarative tier-A recovery for C-style API callers.
- `ObjCSelectorSpec` + `enrich_objc_msgsend` — declarative tier-A recovery for ObjC dispatch. A scan declares `[ObjCSelectorSpec("openURL:"), ObjCSelectorSpec("application:openURL:")]` and the lib walks every `_objc_msgSend*` callsite, recovers the selector, and emits one tier-A row per match.
- `is_apple_framework_function` — drops Apple framework symbol matches from tier-B function-name regex by default.
- `StringRule` + `run_string_scan` — declarative regex-bag runner that ties tier-B and tier-C passes together.

Every scan imports `_re_lib`. The smoke test enforces it.

## Scripts

### Hunt scans

| Script | Anchor kinds it can emit |
|---|---|
| `scan_wrong_door.py` | A `xpc_listener_callsite` + service, `xpc_mach_service_callsite` + service, `sectask_entitlement_callsite` + entitlement; B `should_accept_impl`, `audit_token_user`; C `listener_string`, `ent_string`, `audit_token_string` |
| `scan_xpc_client_validation.py` | A `xpc_listener_callsite`, `xpc_mach_service_callsite`, `xpc_dict_read_callsite` + key, `sectask_entitlement_callsite` + entitlement, `xpc_get_audit_token_callsite`; B `should_accept_impl`, `audit_token_user`, `weak_identity_check`; C `mach_service_string`, `team_id_string` |
| `scan_privileged_helper_surface.py` | A `smjobbless_callsite` + label, `authcreate_callsite` + flags const, `authcopyrights_callsite` + flags const, `authexec_callsite` + path, `rightset_callsite` + right, exec callsites + path/cmd; B `helper_install_impl`, `privileged_op_impl`; C `helper_string`, `launchd_string`, `authz_string`, `install_string` |
| `scan_tcc_prompt_surface.py` | A `tccaccessrequest_callsite` + service, `tccaccesspreflight_callsite` + service, `sectaskcopyentitlement_callsite` + entitlement; A objc dispatch: `avfoundation_request_access_callsite`, `photos_request_authorization_callsite`, etc.; B `prompt_handler`, `identity_resolver`; C `tcc_string`, `apple_event_string`, `privacy_service_string`, `identity_string` |
| `scan_persistent_authorization.py` | A `secitemadd_callsite`, `seckeychainadd_callsite` + service, `seckeychainfind_callsite` + service, `bookmark_create_callsite` + options, `sandbox_extension_consume_callsite` + token, `sandbox_extension_issue_callsite` + path; B `bookmark_handler`, `sandbox_extension_handler`; C `bookmark_string`, `keychain_string`, `sandbox_string`, `container_string` |
| `scan_defaults_bypass.py` | A `cfprefs_*_callsite` + key (CFPreferences family); A objc: `nsuserdefaults_*forkey_callsite` + key; B `bypass_gate_impl`; C `defaults_api_string`, `defaults_key_candidate`, `defaults_domain` |
| `scan_flags_zero.py` | A `csops_callsite` + ops const, `sec_static_code_check_callsite` + flags, `sec_code_check_callsite` + flags; B `code_sign_check_impl`, `flag_check_impl`; C `code_sign_string`, `flags_string`, `amfi_string` |
| `scan_catalyst_porting_gap.py` | B `platform_branch`; C `catalyst_string`, `platform_string`, `ent_string`, `bypass_string` |
| `scan_endpoint_security_client.py` | A `es_subscribe_callsite` + event count, `es_respond_auth_callsite` + decision const, `es_mute_path_callsite` + path, `es_unmute_path_callsite` + path; B `es_handler_impl`, `policy_decision_impl`; C `es_client_string`, `es_event_string`, `cache_string`, `policy_string` |
| `scan_system_extension_surface.py` | B `extension_lifecycle_impl`, `ne_provider_impl`; C `extension_string`, `es_string`, `ext_entitlement_string`, `approval_string` |
| `scan_launchd_machservice_topology.py` | A `bootstrap_check_in_callsite` + service, `bootstrap_register_callsite` + service, `xpc_create_mach_service_callsite` + service; B `listener_setup_impl`; C `mach_service_string`, `listener_api_string`, `entitlement_string` |
| `scan_private_framework_dependency.py` | A `dlopen_callsite` + path, `dlsym_callsite` + symbol, `nsclassfromstring_callsite` + class, `nsselectorfromstring_callsite` + selector, `nslinkmodule_callsite` + path; B `dynamic_resolver_impl`; C `private_framework_path`, `public_framework_path`, `dyld_token`, `weak_link_token` |
| `scan_iokit_user_clients.py` | A `ioservice_matching_callsite` + class, `ioconnect_call_method_callsite` + selector const, `ioconnect_call_async_callsite` + selector const, `ioconnect_map_memory_callsite` + memory_type const; B `user_client_handler_impl`, `ioservice_open_impl`; C `io_service_class_string`, `io_kit_string` |
| `scan_url_scheme_handlers.py` | A `ls_set_default_handler_callsite` + scheme, `cfurl_create_with_string_callsite` + url; A objc: `application_openurl_callsite`, `apple_event_geturl_callsite`, `appleeventmanager_seteventhandler_callsite`; B `open_url_handler_impl`, `url_validator_impl`; C `url_scheme_string`, `cfbundle_url_key_string`, `nsappletevent_url_string` |

### Specialized

| Script | Anchor kinds it can emit |
|---|---|
| `dump_xpc_listeners.py` | A `xpc_registration_callsite` (decompiler-recovered Mach service names), `nsxpc_delegate_impl`, `nsxpc_listener_init`; B `interesting_entitlement` (extracted from `__TEXT,__entitlements`); C `service_name_string` |
| `dump_objc_protocols.py` | A `objc_method_impl` (implementations of NSXPCListenerDelegate, URL handlers, sandbox extension consumers, TCC prompts, auth prompts) + group label; A `objc_msgsend_caller` (callsites that pass these selectors). Edit `SELECTOR_GROUPS` in the script to focus on a different protocol. |
| `export_lldb_anchors.py` | A `lldb_anchor_symbol` (exports / entrypoints / mod_init); B `lldb_anchor_metadata` (api callers / non-system ObjC methods); C `lldb_anchor_fanin` (high in-degree only). Also writes a `<binary>.anchors.lldb` sidecar with `breakpoint set` commands. |

`scan_xpc_client_validation.py` and `dump_xpc_listeners.py` overlap deliberately. Use the `dump` script when you want decompiler-recovered Mach service names and ObjC delegate metadata. Use the `scan` script for the broader sweep including weak-identity-check candidates.

## Invocation

From an MCP-capable agent:

1. Open or import the target program with `ghidra-mcp`.
2. Run the relevant script by name with `ghidra-mcp`'s script-execution tool.
3. Save the returned TSV under `findings/analysis/`.
4. Promote tier-A rows to candidates via `scripts/triage.py create`.
5. Hand them to `lldb_run_anchors` for dynamic confirmation.

```text
Use ghidra-mcp to open /System/Library/PrivateFrameworks/TCC.framework/Support/tccd, run scan_wrong_door.py, and save the TSV into this findings repo.
```

## Reading an anchor row

```
target                                                                tier  anchor_kind             name                                                  address      evidence
/.../tccd                                                             A     xpc_listener_callsite   _setup_tccd_listener                                  0x100008abc  api=xpc_connection_create_listener; site=0x100008abc; service=com.apple.tccd
/.../tccd                                                             A     should_accept_impl      -[TCCDXPCConnection listener:shouldAcceptNewConnection:]  0x10000bcd0  selector=listener:shouldAcceptNewConnection:
/.../tccd                                                             B     interesting_entitlement com.apple.private.tcc.allow                           -            entitlement=com.apple.private.tcc.allow
/.../tccd                                                             C     mach_service_string     com.apple.tccd                                        -            string=com.apple.tccd
```

A useful first triage: tier-A rows with arg recovery go to `triage.py create` as `scan-hit` candidates, addresses can be handed to lldb. Tier-B rows are reads — open in Ghidra, confirm or reject the metadata claim. Tier-C rows are search starting points; promote only after Ghidra navigation finds the underlying call.

## Conventions

Caps: `DEFAULT_MAX_STRINGS=20000`, `DEFAULT_MAX_FUNCTIONS=50000` in `_re_lib.py`. When the cap is hit the stderr summary carries `string_index_truncated_at_<n>` so the operator knows the row count is bounded by the cap, not by reality.

Apple-framework function names are dropped from tier-B regex matches by default. A scan that wants to keep them passes `apple_filter=False` to `run_string_scan`.

New scripts use `_re_lib`. The smoke enforces the import.
