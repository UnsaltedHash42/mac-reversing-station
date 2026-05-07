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
