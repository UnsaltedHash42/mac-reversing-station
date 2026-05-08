# Investigation Recipe Registry

The Maproom is the station's recipe registry. A recipe maps an operator goal to the skills, static sweeps, MCP tools, expected artifacts, and project-state updates that make the next move repeatable.

Recipes are routing aids, not proof. They should produce evidence that can be linked from `CORPUS.md`, `INDEX.md`, `METRICS.md`, `HANDOFF.md`, and the Scriptorium.

## bundle-dossier

Recipe ID: `bundle-dossier`

- **Use when:** Starting any target pass.
- **Inputs:** Target path, pass ID, `LAB_SAFETY.md`, and `CORPUS.md`.
- **Run:** `Skills/offensive-macos-bundle-intake`, `scripts/start-target.py`.
- **Expected outputs:** Target map, dossier JSON, Watch decision row, Scriptorium anchor.
- **State updates:** `CORPUS.md` inventory, Watch row, worklist row.

## map-xpc-endpoints

Recipe ID: `map-xpc-endpoints`

- **Use when:** Intake finds XPC services, MachServices, or listener/delegate names.
- **Run:** `Skills/offensive-macos-tooling-ghidra-headless`, `ghidra-scripts/dump_xpc_listeners.py`, `ghidra-scripts/scan_xpc_client_validation.py`.
- **Expected outputs:** TSV under `findings/analysis/`, candidate rows for weak identity validation.
- **State updates:** `INDEX.md`, `METRICS.md`, Scriptorium evidence path.

## inspect-privileged-helper-or-updater

Recipe ID: `inspect-privileged-helper-or-updater`

- **Use when:** Intake finds helper tools, launchd jobs, installer/update strings, or privileged operation vocabulary.
- **Run:** `Skills/offensive-macos-family-privileged-helpers`, `ghidra-scripts/scan_privileged_helper_surface.py`.
- **Expected outputs:** Helper/updater trust-boundary TSV and candidate triage rows.
- **State updates:** `INDEX.md`, `METRICS.md`, `HANDOFF.md`.

## review-tcc-and-persistent-authorization

Recipe ID: `review-tcc-and-persistent-authorization`

- **Use when:** Intake finds privacy usage strings, keychain hints, bookmarks, sandbox containers, or Apple Events.
- **Run:** `Skills/offensive-macos-family-tcc-heavy-apps`, `ghidra-scripts/scan_tcc_prompt_surface.py`, `ghidra-scripts/scan_persistent_authorization.py`.
- **Expected outputs:** Prompt attribution, persistence, and authority-transfer candidates.
- **State updates:** `INDEX.md`, `METRICS.md`, Scriptorium evidence path.

## review-electron-ipc-and-packaging

Recipe ID: `review-electron-ipc-and-packaging`

- **Use when:** Watch detects ASAR archives, Electron frameworks, package metadata, preload scripts, or native `.node` modules.
- **Run:** `Skills/offensive-macos-electron-surface-pack`.
- **Expected outputs:** Electron IPC and packaging surface notes tied back to the shipped app bundle.
- **State updates:** `CORPUS.md` surface classification, `INDEX.md` candidates only after binary or packaged-artifact evidence exists.

## correlate-source-to-binary

Recipe ID: `correlate-source-to-binary`

- **Use when:** Source is available for an open-source or in-house target.
- **Run:** `Skills/offensive-macos-source-binary-correlation`.
- **Expected outputs:** Source ref confidence, source claims mapped to shipped binary symbols, strings, functions, or dossier facts.
- **State updates:** `CORPUS.md` Source-Binary Correlation row, worklist entries for binary confirmation.

## gatehouse-ghidra-lldb-confirmation

Recipe ID: `gatehouse-ghidra-lldb-confirmation`

- **Use when:** A Ghidra function, symbol, or address needs dynamic confirmation.
- **Run:** `Skills/offensive-macos-gatehouse-ghidra-lldb`, `Skills/offensive-macos-tooling-lldb`, `macre-vm-mcp/src/macre_vm_mcp/tools_lldb.py`.
- **Expected outputs:** LLDB batch transcript with anchor, registers, backtrace, image list, and uncertainty notes for slide or slice mismatch.
- **State updates:** Scriptorium anchor, `HANDOFF.md`, and candidate row evidence path.

## inventory-first-manual-routing

Recipe ID: `inventory-first-manual-routing`

- **Use when:** Watch cannot pick a family-specific first sweep from intake alone.
- **Run:** `Skills/offensive-macos-vuln-ontology`, `docs/playbooks/third-party-app-families.md`.
- **Expected outputs:** Observed surfaces, likely ontology classes, false-positive traps, and one concrete next artifact.
- **State updates:** `CORPUS.md` family routing and worklist rows.

## os-component-inventory

Recipe ID: `os-component-inventory`

- **Use when:** Intake records `apple-os-components` or the `os-component` surface.
- **Run:** `Skills/offensive-macos-family-os-components`, `docs/playbooks/os-components.md`, `scripts/start-target.py`.
- **Expected outputs:** OS-component topology row, Watch maturity summary, OS build/SIP notes, and first subsystem route.
- **State updates:** `CORPUS.md` OS Component Topology, Watch Decision Support, Scriptorium anchor.

## inspect-launchd-machservice-topology

Recipe ID: `inspect-launchd-machservice-topology`

- **Use when:** Intake finds launchd plists, MachServices, daemon names, XPC listener strings, or service registration code.
- **Run:** `Skills/offensive-macos-family-os-components`, `macre-vm-mcp/src/macre_vm_mcp/tools_system.py`, `ghidra-scripts/scan_launchd_machservice_topology.py`.
- **Expected outputs:** Launchd domain snapshot, MachService-to-program map, listener/delegate static anchors, and reachability notes.
- **State updates:** `CORPUS.md` OS Component Topology, `INDEX.md` candidates, Scriptorium evidence path, `VM_ACTIONS.md` for VM-side dynamic actions.

## inspect-system-or-network-extension

Recipe ID: `inspect-system-or-network-extension`

- **Use when:** Intake finds `.systemextension`, `.networkextension`, `.appex`, DriverKit, or extension approval strings.
- **Run:** `Skills/offensive-macos-family-os-components`, `macre-vm-mcp/src/macre_vm_mcp/tools_system.py`, `ghidra-scripts/scan_system_extension_surface.py`.
- **Expected outputs:** Extension inventory, approval/entitlement strings, parent app relationship, and maturity caveat (`basic-inventory` until a full recipe lands).
- **State updates:** `CORPUS.md` OS Component Topology, Watch Decision Support coverage gaps, Scriptorium evidence path.

## inspect-endpoint-security-client

Recipe ID: `inspect-endpoint-security-client`

- **Use when:** Intake or strings identify Endpoint Security clients, `es_new_client`, event subscriptions, or cache/policy handlers.
- **Run:** `Skills/offensive-macos-family-os-components`, `macre-vm-mcp/src/macre_vm_mcp/tools_system.py`, `ghidra-scripts/scan_endpoint_security_client.py`.
- **Expected outputs:** ES client calls, event subscription hints, policy/cache strings, entitlement references, and operator-led reachability questions.
- **State updates:** `CORPUS.md` OS Component Topology, `INDEX.md` candidates only after reachability evidence, Scriptorium evidence path.

## private-framework-dependency-map

Recipe ID: `private-framework-dependency-map`

- **Use when:** Intake detects `/System/Library/PrivateFrameworks/` dependencies or dyld shared-cache origin.
- **Run:** `Skills/offensive-macos-family-os-components`, `macre-vm-mcp/src/macre_vm_mcp/tools_system.py`, `ghidra-scripts/scan_private_framework_dependency.py`.
- **Expected outputs:** Dependency map, PrivateFramework references, weak-link hints, dyld-cache origin note, and target/source correlation candidates.
- **State updates:** `CORPUS.md` OS Component Topology, Source-Binary Correlation, Scriptorium evidence path.

## apple-signed-build-drift-check

Recipe ID: `apple-signed-build-drift-check`

- **Use when:** Comparing workstation, lab VM, and target artifact behavior for Apple-signed components.
- **Run:** `Skills/offensive-macos-family-os-components`, `macre-vm-mcp/src/macre_vm_mcp/tools_system.py`.
- **Expected outputs:** `sw_vers`, SIP state, architecture/build notes, and a decision about whether version drift blocks the claim.
- **State updates:** `CORPUS.md` OS Component Topology, `LAB_SAFETY.md` machine roles if the lab build changes, Scriptorium evidence path.

## vm-snapshot-and-action-log

Recipe ID: `vm-snapshot-and-action-log`

- **Use when:** A dynamic action may crash, corrupt state, reset TCC/keychain data, restart services, or otherwise change the lab VM.
- **Run:** `Skills/offensive-macos-agent-discipline`, `templates/findings-repo/LAB_SAFETY.md`, `templates/findings-repo/VM_ACTIONS.md`.
- **Expected outputs:** Snapshot decision, action row, outcome row, and evidence pointer for the dynamic run.
- **State updates:** `VM_ACTIONS.md`, `CHRONICLE.md` for noteworthy state changes, Scriptorium anchor when evidence supports a claim.

## chain-discovery

Recipe ID: `chain-discovery`

- **Use when:** Candidate primitives may combine into a higher-impact chain or need an exploitability rating before PoC investment.
- **Run:** `Skills/offensive-macos-chain-discovery`, `docs/ontology/macos-vulnerability-classes.md`.
- **Expected outputs:** Exploitability rating, chain hypothesis, reachability/reliability notes, and the next experiment.
- **State updates:** `CORPUS.md` Exploitability And Chainability, `INDEX.md` for promoted chains, Scriptorium evidence path.

## poc-authoring

Recipe ID: `poc-authoring`

- **Use when:** A confirmed candidate or non-theoretical chain is ready for a reproducible PoC harness.
- **Run:** `Skills/offensive-macos-poc-authoring`, `templates/findings-repo/POC_SCAFFOLDING.md`, `templates/findings-repo/templates/poc/README.md.template`.
- **Expected outputs:** `pocs/<target-id>/<POC-ID>/` scaffold, PoC README, run records, reliability notes, and evidence links.
- **State updates:** `CORPUS.md` PoC Tracking, Scriptorium anchor, `CHRONICLE.md`, `VM_ACTIONS.md`.

## apple-source-correlation

Recipe ID: `apple-source-correlation`

- **Use when:** Apple-published source can clarify an OS component, but the shipped binary remains authoritative.
- **Run:** `scripts/fetch-apple-source.py`, `Skills/offensive-macos-source-binary-correlation`, `scripts/start-target.py`.
- **Expected outputs:** Gitignored Apple source cache path, source ref/URL metadata, binary-correlation questions, and confidence state.
- **State updates:** `CORPUS.md` Apple Source Map, Source-Binary Correlation, Watch Decision Support coverage gaps.

## tcc-prompt-attribution

Recipe ID: `tcc-prompt-attribution`

- **Use when:** A TCC-mediating daemon resolves the requesting client identity via pid / bundle id / executable path rather than `audit_token_t`, or a privacy prompt names the wrong responsible app.
- **Run:** `Skills/offensive-macos-hunt-tcc-prompt-attribution`, `ghidra-scripts/scan_tcc_prompt_surface.py`, `ghidra-scripts/dump_xpc_listeners.py`.
- **Expected outputs:** Tier-A `tccaccessrequest_callsite` rows with recovered service names, decompiled identity-resolution paths, classification of each path as `audit_token` / `pid` / `bundle_id` / `path` / `inherited`.
- **State updates:** `INDEX.md`, `METRICS.md`, Scriptorium evidence path.

## iokit-userclient-selectors

Recipe ID: `iokit-userclient-selectors`

- **Use when:** A user-mode binary opens an IOKit user client and you want the (driver class, selector list) inventory before going kernel-side.
- **Run:** `Skills/offensive-macos-hunt-iokit-userclient`, `ghidra-scripts/scan_iokit_user_clients.py`.
- **Expected outputs:** Tier-A `ioservice_matching_callsite` + class arg rows; tier-A `ioconnect_call_*_callsite` + selector-const rows; (class, selector, kernel-method) inventory after correlating with the kext / dext.
- **State updates:** `INDEX.md`, `METRICS.md`, Scriptorium evidence path. **Lab safety:** kernel work on crash-test VM only.

## private-framework-hijack

Recipe ID: `private-framework-hijack`

- **Use when:** A binary weak-links a PrivateFramework, calls `dlopen` with a constructed path, or uses `NSClassFromString` with a name from defaults / config.
- **Run:** `Skills/offensive-macos-hunt-private-framework-hijack`, `ghidra-scripts/scan_private_framework_dependency.py`, `ghidra-scripts/scan_defaults_bypass.py`.
- **Expected outputs:** Tier-A `dlopen_callsite` + path arg, `nsclassfromstring_callsite` + class arg, classification by path source (literal / bundle resource / user-writable / xpc arg / network).
- **State updates:** `INDEX.md`, `METRICS.md`, Scriptorium evidence path.

## url-scheme-hijack

Recipe ID: `url-scheme-hijack`

- **Use when:** A bundle declares `CFBundleURLTypes` and implements `application:openURL:` / `application:openURLs:`.
- **Run:** `Skills/offensive-macos-hunt-url-scheme-hijack`, `ghidra-scripts/scan_url_scheme_handlers.py`.
- **Expected outputs:** Tier-A `ls_set_default_handler_callsite` + scheme arg, `cfurl_create_with_string_callsite` + url arg; (scheme, action, validation) inventory from decompiled `application:openURL:` impls.
- **State updates:** `INDEX.md`, `METRICS.md`, Scriptorium evidence path.
