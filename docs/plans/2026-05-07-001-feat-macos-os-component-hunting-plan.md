---
title: "feat: macOS OS Component Hunting Lane"
type: feat
status: active
date: 2026-05-07
origin: docs/brainstorms/2026-05-07-macos-os-component-hunting-requirements.md
---

# feat: macOS OS Component Hunting Lane

## Summary

Extend the station with a phased macOS-internals lane: intake recognizes broad OS shapes immediately, Watch records honest per-subsystem maturity, and project state grows to carry exploitability ratings, chain hypotheses, PoC tracking, and an Apple-source correlation slot. New skills ship for chain discovery and PoC authoring; new Maproom recipes route OS-component, Apple-source, chain-discovery, and PoC-authoring work; new MCP tools and Ghidra scanners feed the OS-component surfaces; a recent-macOS-CVE survey grounds prioritization; and validation/registry/README updates keep the station structurally consistent.

---

## Problem Frame

The station's bundle-first intake handles app bundles, helpers, XPC services, frameworks, and bare binaries, but treats every target as an app-shaped thing. macOS internals — daemons, launchd jobs, MachServices, frameworks/PrivateFrameworks, system extensions, network extensions, Endpoint Security clients, DriverKit/IOKit-adjacent components — have different topology, signing/SIP/debugging constraints, OS-build drift, and dynamic-action risk. Findings also need a path forward: rating exploitability, identifying chains, and authoring PoCs in the same Cursor environment with a different model selection. See origin: docs/brainstorms/2026-05-07-macos-os-component-hunting-requirements.md.

---

## Requirements

Carried forward verbatim from origin (R1–R25). The plan does not invent new product requirements; planning-time decisions for HOW to satisfy them live in Key Technical Decisions and Implementation Units below.

**Origin actors:** A1 Operator, A2 Cursor agent, A3 Watch, A4 Lab VM, A5 Future planner

**Origin flows:** F1 Third-party shakedown, F2 Enterprise/security-agent, F3 Apple OS-component, F4 Exploitability/chain/PoC authoring, F5 Long-term private target queue

**Origin acceptance examples:** AE1 (R1, R2, R4), AE2 (R3, R11–R13, R15), AE3 (R5–R10, R14, R22), AE4 (R16–R18, R23, R24), AE5 (R19, R20), AE6 (R21), AE7 (R25)

---

## Scope Boundaries

- Per origin: no exploit weaponization output in this pass (the authoring skill is built; running it on a real candidate happens later).
- Per origin: no per-CVE rediscovery walkthroughs (the CVE survey informs, doesn't rediscover).
- Per origin: no full iOS implementation; README mention only.
- Per origin: no Apple source mirrors, target queues, PoCs, chains, or operational notes committed to the template repo.
- Per origin: no claim of full automation for every macOS subsystem in this pass; deferred subsystems get inventory + manual-route maturity.
- Per origin: no replacement of Watchtower vocabulary; additive only.

### Deferred to Follow-Up Work

- Full recipes for System Extensions, Network Extensions, DriverKit, Endpoint Security clients (this pass: inventory + manual-route maturity; later pass: full recipes once the survey and first targets confirm the dominant patterns).
- iOS lane: separate later plan.
- Per-CVE pattern hunt skills (e.g., `Skills/offensive-macos-hunt-<pattern>/`) only when the CVE survey or real targets surface a clear recurring pattern.
- Automatic version pinning of the Apple source cache against the lab VM's exact OS build (this pass: operator picks the release; later pass: auto-match).
- Promoting `TARGET_QUEUE.md` from prose-sectioned markdown to a typed agent-sortable format. This pass keeps the existing markdown shape and documents a stable section convention; structured promotion is a separate change.

---

## Context & Research

### Relevant Code and Patterns

- **Intake**: `scripts/start-target.py` — `inventory_target`, `find_components`, `classify_surfaces`, `classify_families`, `build_decision_support`, `build_dossier`, `update_corpus` (idempotent table-row insertion via `ensure_table_row`). New OS-component logic extends these functions.
- **Project state mutation**: the `ensure_table_row` pattern (heading → `|---|` separator → upsert by leading row key) is the canonical way to update `CORPUS.md` tables; reused by `scripts/rsync-to-vm.sh --record`.
- **Maproom recipes**: `docs/playbooks/investigation-recipes.md` (recipe shape: `Recipe ID`, `Use when`, `Run`, `Expected outputs`, `State updates`); enforced by `scripts/validate-recipes.py` `REQUIRED_RECIPE_IDS` constant + broken-backtick path check.
- **Skill bundles**: every `Skills/offensive-macos-*/SKILL.md` must be inline-cited in `docs/workstation/skill-bundles.md`; enforced by `scripts/validate_workstation_bundles.py`. Skill scaffold lives in `Skills/_template/SKILL.md`.
- **Ghidra scanners**: `ghidra-scripts/*.py` print exactly one TSV header + one row per program; structurally tested by `tests/ghidra-scripts/smoke.sh` `expected_headers` dict.
- **MCP tools**: `macre-vm-mcp/src/macre_vm_mcp/tools_*.py` — each module exports `register(mcp: FastMCP)`; new tools must be added to `EXPECTED_TOOLS` in `macre-vm-mcp/tests/test_server_smoke.py`.
- **Findings template**: `templates/findings-repo/CORPUS.md`, `LAB_SAFETY.md`, `SCRIPTORIUM.md`, `CHRONICLE.md`, `INDEX.md`, `METRICS.md`, `HANDOFF.md.template`; structural smoke at `templates/findings-repo/scripts/smoke-findings-repo.sh`.
- **Family playbook + skill pairing**: each `Skills/offensive-macos-family-*/SKILL.md` has a companion `docs/playbooks/<family>.md` with shared section headings.
- **Watchtower vocabulary**: Watch (decision support) → Maproom (recipes) → Scriptorium/Chronicle (evidence) → Gatehouse (Ghidra→LLDB). New OS-component work extends these layers; no new top-level metaphor.
- **Existing source-binary correlation**: `Skills/offensive-macos-source-binary-correlation/SKILL.md` already accepts `--source-root`/`--source-ref`/`--source-url` from `scripts/start-target.py`; the Apple-source fetcher should produce inputs that drop into the same lane.

### Institutional Learnings

- `docs/solutions/` is empty in this repo — no prior `/ce-compound` entries to draw on. The CVE survey research note (U13) intentionally seeds it for future deepening.
- `Skills/offensive-macos-agent-discipline/` already encodes lab-roster/machine-discipline rules and L1–L6 failure taxonomy. Host-action approval (R14) extends it rather than introducing a parallel doctrine.
- `docs/playbooks/adding-target-families.md` sets the bar for new family labels (repeated evidence, distinct first moves, ontology mapping). The OS-component family clears that bar; speculative subsystem-specific families (e.g., a separate "endpoint-security" family) do not yet — surface them with `unknown/mixed` plus rich Watch decision support until evidence justifies promotion.
- `Skills/offensive-macos-vuln-ontology/` warns against inventing class names in findings repos; new OS-component classes go through the canonical ontology file or are absorbed into existing classes (e.g., `VULN-LAUNCHD-EXPOSURE`, `VULN-CODESIGN-ENTITLEMENT`, `VULN-FILE-AUTHORITY-TRANSFER`) where they fit.

### External References

- Apple Developer documentation for SIP, Hardened Runtime, System Extensions, Endpoint Security, and Network Extensions defines current entitlement, provisioning, and approval flows. Skills and playbooks should anchor to current Apple docs rather than ad hoc forum recipes.
- `launchctl print` for `system/`, `user/<uid>/`, `gui/<uid>/` domains is the authoritative way to observe MachService state at runtime.
- `dyld_shared_cache_util -extract` is the standard way to obtain framework backing files for static analysis on the workstation; paths shift across releases (Preboot/Cryptexes-related trees on newer macOS).
- https://opensource.apple.com/releases/ is the source-of-record for Apple-published component releases.

---

## Key Technical Decisions

- **Inventory-first OS-component intake**: extend `start-target.py` to produce OS-component facts (kind, signing authority, OS build, MachServices, framework deps, dyld cache origin) at intake time, before any family/lane label. Aligns with R9 and the existing inventory-first routing rule.
- **Maturity stored alongside surfaces, not as a separate axis**: each surface in the dossier carries a `maturity` value (`full-recipe` | `basic-inventory` | `manual-route-needed`). Watch decision support surfaces this in `CORPUS.md`. Avoids a parallel maturity registry the operator has to keep in sync.
- **OS-component family is a single new label**: `apple-os-components`, multi-label-friendly, used when intake evidence matches the OS-component shape. Subsystem nuance (system-extension, network-extension, endpoint-security, driverkit) lives in surfaces, not in family labels — clears `adding-target-families.md`'s bar without proliferating labels.
- **Ontology**: this pass adds two classes only — `VULN-SYSTEM-EXTENSION-TRUST` and `VULN-DYLD-SHARED-CACHE-ORIGIN` — and a Hypothesis-Prompts amendment to existing classes (`VULN-LAUNCHD-EXPOSURE`, `VULN-CODESIGN-ENTITLEMENT`, `VULN-FILE-AUTHORITY-TRANSFER`) for OS-component framing. Network Extension and Endpoint Security control-plane bugs are folded under existing `VULN-XPC-CLIENT-VALIDATION` / `VULN-PRIV-HELPER-AUTHZ` until the CVE survey and real targets demonstrate a distinct class is needed.
- **Lab disposability is recorded, not assumed**: the project clone records `lab_disposable: true|false` (or equivalent) in `LAB_SAFETY.md`. When `false`, R11/R13 dynamic actions on the lab host require the same explicit operator approval R14 demands for workstation actions.
- **VM action log is its own template file**: `templates/findings-repo/VM_ACTIONS.md` (append-only table). Chronicle remains the human-narrated event log; `VM_ACTIONS.md` is the structured per-action audit trail. Avoids overloading Chronicle with mechanical entries.
- **PoC scaffolding lives in the project clone, gitignored from the template**: `pocs/<target-id>/<chain-id-or-finding-id>/` directory convention plus a `templates/findings-repo/POC_SCAFFOLDING.md` doc that explains the layout and CORPUS linkage. Actual PoC code is gitignored; the scaffolding contract is tracked.
- **Chain-discovery and PoC-authoring are skills, not just scripts**: chain-discovery reasons over `CORPUS.md` rows, candidate findings, and ontology classes; PoC authoring guides harness/lab-state/reliability/evidence work. Both are read by the same Cursor agent with model selection appropriate to the task (per origin Key Decision).
- **Apple source fetcher is a workstation script, not an MCP tool**: `scripts/fetch-apple-source.py` resolves a release name to a tarball URL on opensource.apple.com, downloads to a workstation-local gitignored cache, and emits `--source-root`/`--source-ref`/`--source-url` arguments suitable for `start-target.py`. MCP placement would force the fetch to run on the lab VM, which contradicts the workstation-side correlation lane.
- **Ghidra scanners follow existing single-TSV-header convention**: new scanners are read-only postScripts, one TSV row per program; structurally tested via `tests/ghidra-scripts/smoke.sh` `expected_headers` dict.
- **macre-vm-mcp tool surface grows in `tools_system.py`**: the OS-component metadata tools (launchctl print, system extension list, framework dep map, OS build snapshot) are system-level reads, not new tool families. Adding a separate `tools_launchd.py` would split related tools across modules.
- **CVE survey is research, not skills**: lands as `docs/research/macos-cve-survey-2026.md` informing ontology coverage, subsystem prioritization, exploitability rating dimensions, and seed chain examples. If the survey reveals a recurring pattern, a follow-up plan can promote it to a hunt skill — that promotion is explicitly out of scope here (Deferred to Follow-Up Work).
- **TARGET_QUEUE format stays as-is for this pass**: the existing prose-sectioned markdown is sufficient for R19/R20; promoting it to a typed format is deferred. Document the stable section convention in a tracked doc so the operator's gitignored queue stays compatible.

---

## Open Questions

### Resolved During Planning

- **Watch maturity representation**: per-surface `maturity` field on dossier surfaces and CORPUS Watch Decision Support, instead of a separate per-subsystem registry doc. (Origin question on R9/R10.)
- **VM action log location**: dedicated `templates/findings-repo/VM_ACTIONS.md` table; Chronicle stays narrative-only. (Origin question on R12/R13.)
- **Apple source caching**: workstation-local gitignored cache via `scripts/fetch-apple-source.py`; not VM-mirrored. (Origin question on R22.)
- **Skill split for chain discovery vs PoC authoring**: two skills, not one — chain discovery runs upstream of PoC authoring and during pure static review; PoC authoring runs only when a candidate is committed to. (Origin question on R23/R24.)
- **CVE survey scope**: survey is bounded to ~10 CVEs across subsystems with explicit ontology-coverage and maturity-priority output sections; no per-CVE rediscovery walkthrough. (Origin question on R25.)
- **Family label growth**: only one new family label this pass (`apple-os-components`); subsystem-specific families wait for evidence. (`docs/playbooks/adding-target-families.md` bar.)

### Deferred to Implementation

- [Affects U10, U13][Needs research] Exact CVE list for the survey: which 10 maximize ontology validation across TCC, XPC, launchd, Sparkle/updaters, Endpoint Security, installd/softwareupdated, FileProvider, sharing, sandbox, and MachServices.
- [Affects U11][Technical] Whether `launchctl print` parsing should be lossy (key facts only) or preserve raw text alongside structured fields.
- [Affects U10][Technical] Apple source cache directory naming: `sources/apple/<component>-<release>/` versus `.apple-source-cache/<component>/<release>/` — both are gitignored; pick during implementation based on which reads cleaner from `start-target.py --source-root`.
- [Affects U12][Technical] Whether the launchd/MachService Ghidra scanner should refine existing `dump_xpc_listeners.py` or ship as a new daemon-side mapper; depends on overlap when implementing.
- [Affects U9][Technical] Whether `pocs/<target-id>/<finding-id>/README.md` is a template the skill writes on first PoC, or a manual operator step. Default: skill writes it from a tracked template doc.

---

## High-Level Technical Design

> *This illustrates the intended approach and is directional guidance for review, not implementation specification. The implementing agent should treat it as context, not code to reproduce.*

```
                              start-target.py
                                    │
                                    ▼
                       ┌─────────────────────────────┐
                       │  inventory_target           │
                       │  + OS-component recognizers │
                       │  (launchd, MachServices,    │
                       │   framework deps,           │
                       │   system/network ext,       │
                       │   dyld cache origin,        │
                       │   apple-signed, OS build)   │
                       └─────────────────────────────┘
                                    │
                                    ▼
                       ┌─────────────────────────────┐
                       │  classify_surfaces(...)     │
                       │  + maturity per surface     │
                       └─────────────────────────────┘
                                    │
                                    ▼
                       ┌─────────────────────────────┐
                       │  build_decision_support     │
                       │  → Watch row in CORPUS      │
                       │  → recommended recipes      │
                       │  → coverage gaps            │
                       └─────────────────────────────┘
                                    │
                                    ▼
       ┌──────────────────────┬─────────────────────┬──────────────────────┐
       │                      │                     │                      │
       ▼                      ▼                     ▼                      ▼
  Maproom recipe         chain-discovery       PoC authoring          source-binary
  (per surface)             skill                  skill              correlation lane
       │                      │                     │                      │
       ▼                      ▼                     ▼                      ▼
  Ghidra scanners +      CORPUS rows for       pocs/<target>/<id>/    fetch-apple-source.py
  macre-vm-mcp tools     candidate primitives  scaffolding +          → workstation cache
  (launchd, sysext,      and chain hypotheses  evidence linking       → start-target.py
   ES client, fwk dep)        │                     │                      --source-root
       │                      ▼                     ▼
       ▼                  Scriptorium anchor    Scriptorium anchor
  Scriptorium evidence     + Chronicle event    + Chronicle event
       │                                            │
       └────────────────────┬───────────────────────┘
                            ▼
                       VM_ACTIONS.md
                  (append-only audit trail)
```

The diagram shows additive flow only — no existing path is replaced. Watchtower layers (Watch / Maproom / Scriptorium+Chronicle / Gatehouse) remain the spine; OS-component support and PoC/chain work plug into them.

---

## Implementation Units

- U1. **OS-component intake recognition**

**Goal:** Extend `start-target.py` to recognize OS-component shapes at intake (Apple-signed binaries, launchd plists with MachServices dictionaries, frameworks/PrivateFrameworks, `.systemextension` / `.appex` / `.networkextension` / `.dext` bundles, dyld shared cache origin, OS build markers) and emit them as structured surfaces and dossier facts.

**Requirements:** R5, R6, R8, R9, R10 (Covers AE3.)

**Dependencies:** None.

**Files:**
- Modify: `scripts/start-target.py`
- Test: `tests/test_start_target.py`

**Approach:**
- Add component kinds: `system-extension`, `network-extension`, `endpoint-security-client`, `driverkit-extension`, `appex`, `framework`, `private-framework`, `daemon`, `agent`, `command-line-tool`.
- Add surfaces: `apple-signed`, `private-framework-dep`, `dyld-shared-cache-origin`, `system-extension`, `network-extension`, `endpoint-security-client`, `driverkit`, `launchd-machservices`, `os-component`.
- Detect Apple signing via `codesign -dv --json` style output when reachable; fall back to Team ID/identifier heuristics from the bundle when not.
- Detect dyld shared cache origin by absence of on-disk backing for `otool -L` entries that resolve into shared cache paths.
- Read launchd plists into structured `MachServices`, `Sockets`, `WatchPaths`, `ProgramArguments` fields stored on the component row.
- Treat bare daemon Mach-O input (no enclosing `.app`) as a valid intake path; emit `kind: daemon` rather than failing.
- Derive `os-component` family label only when at least two OS-component surfaces are present; otherwise leave as `unknown/mixed` with rich notes.

**Patterns to follow:**
- `inventory_target`, `find_components`, `classify_surfaces`, `classify_families` in `scripts/start-target.py` (current shapes).
- `ensure_table_row` idempotency for any new CORPUS rows (paired with U4).

**Test scenarios:**
- Happy path: Bare daemon Mach-O → intake records `kind: daemon`, `apple-signed`, `private-framework-dep`, `dyld-shared-cache-origin` surfaces, no Info.plist required.
- Happy path: `.app` containing a `.systemextension` → component row of kind `system-extension` and surface `system-extension` recorded; family label includes `apple-os-components`.
- Happy path: `.framework` target → `kind: framework` recorded, `private-framework-dep` surface populated from dependent libraries when applicable.
- Edge case: launchd plist with `MachServices` dict → component row carries structured `mach_services: ["com.example.helper"]`.
- Edge case: Re-running intake on the same target updates rows in place rather than appending duplicates (preserves existing `ensure_table_row` idempotency).
- Error path: Non-existent target path fails with `IntakeError` and exit code 2 (regression check; current behavior).
- Integration: Dossier JSON includes `apple_signed`, `os_build_target`, `dyld_cache_dependencies`, `mach_services` keys when detectable.

**Verification:** New intake fixtures pass `python -m unittest tests.test_start_target`; existing fixtures still pass.

---

- U2. **OS-component family playbook and skill**

**Goal:** Ship a new family playbook and family skill for `apple-os-components`, mirroring the structure of existing family pairs.

**Requirements:** R5, R6, R7, R10 (Covers AE3.)

**Dependencies:** U1 (the family label needs intake to produce it).

**Files:**
- Create: `docs/playbooks/os-components.md`
- Create: `Skills/offensive-macos-family-os-components/SKILL.md`
- Modify: `docs/playbooks/third-party-app-families.md` (add the OS-component row)
- Modify: `docs/workstation/skill-bundles.md` (Wave 5 entry)

**Approach:**
- Playbook headings mirror existing family playbooks (`Common Artifacts`, `Primary Ontology Classes`, `First-Pass Checks`, `False-Positive Traps`, `Minimum Evidence For Escalation`).
- Skill body opens with the standard `Channel boundary: REPO_MODE=analysis` quote, names trigger phrases, lists subsystem-specific intake checks (launchd, MachServices, frameworks, extensions, dyld shared cache, OS build), and points downstream to Maproom recipes added in U7.
- The "Adding Families" check in `docs/playbooks/adding-target-families.md` is satisfied by repeated OS-component evidence shape, distinct first inventory moves, and ontology mapping (existing classes plus U-driven additions).

**Patterns to follow:**
- `Skills/offensive-macos-family-enterprise-agents/SKILL.md` and `docs/playbooks/enterprise-security-agents.md` for shape.

**Test scenarios:**
- Test expectation: structural only — `python scripts/validate_workstation_bundles.py` passes with the new skill listed; `bash scripts/smoke-wave3.sh` passes with the new playbook listed.

**Verification:** Validators pass; the new family label is reachable from `start-target.py`'s family-routing output (verified by U1 tests).

---

- U3. **Watch maturity per surface**

**Goal:** Extend Watch decision support so each surface carries a maturity value (`full-recipe`, `basic-inventory`, `manual-route-needed`), exposed in dossier JSON and the CORPUS Watch Decision Support row.

**Requirements:** R6, R7, R9, R10 (Covers AE3.)

**Dependencies:** U1, U4.

**Files:**
- Modify: `scripts/start-target.py` (`build_decision_support`, `update_corpus`)
- Modify: `templates/findings-repo/CORPUS.md` (add Maturity column to Watch Decision Support)
- Test: `tests/test_start_target.py`

**Approach:**
- Maintain a small surface→maturity table inside `start-target.py`: full-recipe surfaces are those with at least one Maproom recipe and at least one supporting Ghidra scanner or MCP tool; basic-inventory surfaces have intake recognition but no recipe; manual-route-needed surfaces have intake recognition but require operator-led routing.
- For this pass: full-recipe = `xpc-services`, `launchd-jobs`, `privileged-helper-tools`, `private-framework-dep`, `apple-signed`, `os-component` (umbrella), and the existing app-family surfaces. Basic-inventory = `system-extension`, `network-extension`, `endpoint-security-client`, `driverkit`. Manual-route-needed = anything intake recognizes but has no recipe slot above.
- Watch decision support row adds `Maturity` column listing per-surface tiers; coverage gaps explicitly call out manual-route surfaces.
- Re-intake updates the row in place via `ensure_table_row`.

**Patterns to follow:**
- `build_decision_support` and `update_corpus` in `scripts/start-target.py`.
- Existing CORPUS table-row idempotency.

**Test scenarios:**
- Happy path: Intake of a target with a `system-extension` surface produces a Watch row whose `Maturity` column shows that surface as `basic-inventory` and lists it in `Coverage Gaps`.
- Happy path: Intake of a target with `xpc-services` and `private-framework-dep` shows both as `full-recipe`.
- Edge case: Re-intake of the same target after surfaces change updates Watch row in place; table does not gain duplicate entries.
- Integration: Dossier JSON's `decision_support` block includes a `maturity` mapping keyed by surface name.

**Verification:** New unit tests in `tests/test_start_target.py` exercise a synthetic target containing each surface kind; existing tests still pass.

---

- U4. **CORPUS template additions**

**Goal:** Add `OS Component Topology`, `Exploitability And Chainability`, `PoC Tracking`, and `Apple Source Map` tables to the findings-repo template, with idempotent upserts from `start-target.py`.

**Requirements:** R5, R12, R15, R16, R17, R18, R22 (Covers AE2, AE3, AE4.)

**Dependencies:** None for the template; `start-target.py` upserts depend on U1.

**Files:**
- Modify: `templates/findings-repo/CORPUS.md` (new tables, plus Maturity column update from U3)
- Modify: `templates/findings-repo/scripts/smoke-findings-repo.sh` (assert new headings)
- Modify: `scripts/start-target.py` (new `ensure_table_row` calls for OS Topology and Apple Source Map)
- Test: `tests/test_start_target.py`

**Approach:**
- `## OS Component Topology` columns: `Target ID | Kind | Signing Authority | OS Build | MachServices | Framework Deps | Maturity`.
- `## Exploitability And Chainability` columns: `Candidate ID | Target ID | Exploitability Rating | Chain Hypothesis | Reachability | Reliability Notes | Next Experiment`.
- `## PoC Tracking` columns: `PoC ID | Target ID | Candidate / Chain ID | Status | Lab State Required | Artifact Path | Evidence Path`.
- `## Apple Source Map` columns: `Target ID | Apple Component | Release | Cache Path | Confidence | Notes`.
- Exploitability and PoC rows are operator/skill-driven (chain-discovery and PoC-authoring skills update them); OS Topology and Apple Source Map rows are intake/source-fetcher driven.
- Smoke checks assert each heading and the column header line.

**Patterns to follow:**
- Existing CORPUS table headings + `|---|` separator pattern.
- `ensure_table_row` row-key conventions (leading column is the upsert key).

**Test scenarios:**
- Happy path: Fresh `init-project.sh` includes all four new tables.
- Happy path: `start-target.py` inserts an OS Topology row keyed by target id; second run updates it in place.
- Happy path: `smoke-findings-repo.sh` passes, asserting all four new headings.
- Edge case: A target with no OS-component surfaces still produces no spurious OS Topology row (table remains empty for that target id).
- Edge case: Apple Source Map row is only inserted when source metadata is supplied (paired with U10).

**Verification:** `python -m unittest tests.test_start_target` passes; `bash templates/findings-repo/scripts/smoke-findings-repo.sh` passes against a fresh project clone.

---

- U5. **Lab safety v2 and VM action log**

**Goal:** Record lab disposability explicitly, add a structured VM action log file, and update LAB_SAFETY destructive-test guidance for OS-component dynamic work.

**Requirements:** R11, R12, R13, R14 (Covers AE2.)

**Dependencies:** None.

**Files:**
- Modify: `templates/findings-repo/LAB_SAFETY.md` (add `lab_disposable` and snapshot guidance)
- Create: `templates/findings-repo/VM_ACTIONS.md` (append-only table template)
- Modify: `templates/findings-repo/scripts/smoke-findings-repo.sh` (assert VM_ACTIONS.md and new LAB_SAFETY sections)
- Modify: `scripts/init-project.sh` (rsync the new template file)

**Approach:**
- LAB_SAFETY.md gets a `## Lab Disposability` section the operator fills in: lab role, disposable yes/no, snapshot scheme, restore expectations. When `lab_disposable: false`, text reminds the operator that R11/R13 dynamic actions on the lab host then require explicit operator approval (R14 standard).
- VM_ACTIONS.md columns: `Time UTC | Pass ID | Target ID | Action | Tool / Command | Outcome | Snapshot Before | Evidence Path | Operator`.
- Append-only convention; agents/skills add rows when they run dynamic actions.

**Patterns to follow:**
- Existing template files (`SCRIPTORIUM.md`, `CHRONICLE.md`) for tone, scaffold, and smoke-test integration.

**Test scenarios:**
- Test expectation: structural only — `bash templates/findings-repo/scripts/smoke-findings-repo.sh` asserts VM_ACTIONS.md and the new LAB_SAFETY sections; `bash scripts/init-project.sh` produces a fresh clone containing both.

**Verification:** Findings-repo smoke passes; init-project produces VM_ACTIONS.md.

---

- U6. **Host-action approval discipline**

**Goal:** Encode R14 as a discipline rule the agent reads: actions affecting the workstation or non-disposable host require explicit operator approval before they run.

**Requirements:** R14 (Covers AE3.)

**Dependencies:** U5 (lab disposability is recorded; the discipline rule references it).

**Files:**
- Modify: `Skills/offensive-macos-agent-discipline/SKILL.md` (add a `## Host-Action Approval` section)
- Modify: `docs/topology.md` (note the three environments: workstation, lab host, lab VM, with the disposable-vs-non-disposable axis)

**Approach:**
- Skill addition lists categories that require approval: writes outside `findings/`, `targets/`, `pocs/`, the Apple source cache, or other gitignored project paths; any state change to `~/.cursor/`, `~/.ssh/`, system Launch{Daemons,Agents}, system frameworks; any reboot/sleep/login-state change; any package install on workstation.
- When `lab_disposable: false` is recorded in LAB_SAFETY, the skill instructs the agent to apply the same approval gate to the lab host for R11/R13 dynamic actions.
- Discipline rule is enforced by the agent reading the skill, not by tooling lockouts (consistent with existing skill-driven discipline).

**Patterns to follow:**
- Existing `Skills/offensive-macos-agent-discipline/SKILL.md` style and L1–L6 taxonomy.

**Test scenarios:**
- Test expectation: structural only — skill bundle validator passes; `bash scripts/smoke-wave3.sh` passes; topology doc updates render correctly.

**Verification:** Validators pass; manual review confirms the discipline rule is unambiguous.

---

- U7. **Maproom recipes for OS components, chain discovery, PoC authoring, Apple source**

**Goal:** Add recipes that route OS-component, chain-discovery, PoC-authoring, and Apple-source-correlation work, validated by `validate-recipes.py`.

**Requirements:** R5, R6, R7, R17, R18, R22, R23, R24 (Covers AE3, AE4.)

**Dependencies:** U1, U2, U3, U4, U8, U9, U10, U11, U12 (recipes reference state, skills, scripts, MCP tools, and scanners).

**Files:**
- Modify: `docs/playbooks/investigation-recipes.md`
- Modify: `scripts/validate-recipes.py` (extend `REQUIRED_RECIPE_IDS`)
- Modify: `scripts/smoke-wave3.sh` (no change required if recipe validator already runs there; verify)

**Approach:**
- New recipe IDs (all conform to existing recipe shape): `os-component-inventory`, `inspect-launchd-machservice-topology`, `inspect-system-or-network-extension`, `inspect-endpoint-security-client`, `private-framework-dependency-map`, `apple-signed-build-drift-check`, `vm-snapshot-and-action-log`, `chain-discovery`, `poc-authoring`, `apple-source-correlation`.
- Each recipe lists `Use when`, `Run` (skill + script paths), `Expected outputs`, `State updates` referencing CORPUS sections (including the new ones from U4).
- `os-component-inventory` is the universal OS-component starter, parallel to `bundle-dossier`.
- `apple-source-correlation` references `scripts/fetch-apple-source.py` (U10) and the existing source-binary correlation skill.
- Validator broken-backtick-paths check passes because U8/U9/U10/U11/U12 produce the referenced files.

**Patterns to follow:**
- Existing recipes in `docs/playbooks/investigation-recipes.md`.
- `scripts/validate-recipes.py` `REQUIRED_RECIPE_IDS` constant.

**Test scenarios:**
- Happy path: `python scripts/validate-recipes.py` passes with the new IDs present and all referenced paths existing.
- Edge case: Removing a referenced skill or script causes the broken-backtick check to fail (regression check; current behavior).

**Verification:** `python scripts/validate-recipes.py` returns 0; `bash scripts/smoke-wave3.sh` passes.

---

- U8. **Chain-discovery skill**

**Goal:** Ship a skill that surfaces plausible vulnerability chains from corpus state, candidate findings, and ontology classes.

**Requirements:** R17, R23 (Covers AE4.)

**Dependencies:** U4 (skill writes Exploitability and Chainability rows).

**Files:**
- Create: `Skills/offensive-macos-chain-discovery/SKILL.md`
- Modify: `docs/workstation/skill-bundles.md` (Wave 5 entry)

**Approach:**
- Skill body sections: `Channel boundary`, `When To Use`, `Lab Topology`, `Workflow`, `Output Shape`, `False-Positive Traps`, `See Also`.
- Workflow: read CORPUS Exploitability And Chainability + Surface Classification + Watch Decision Support rows; cross-reference primitives by ontology class; propose plausible bridges (e.g., sandbox escape primitive + helper authorization gap → privilege escalation chain); record candidates with explicit evidence quality gates (suspicion vs reachability vs proof).
- Output: chain-hypothesis rows added to `## Exploitability And Chainability` keyed by `Chain Hypothesis` text; Scriptorium anchor created for each promoted chain.

**Patterns to follow:**
- `Skills/offensive-macos-vuln-ontology/SKILL.md` for ontology-driven reasoning.
- `Skills/offensive-macos-watch-static-analysis/SKILL.md` for output-shape conventions.

**Test scenarios:**
- Test expectation: structural only — skill bundle validator passes; `bash scripts/smoke-wave3.sh` passes.

**Verification:** Validators pass.

---

- U9. **PoC authoring skill and scaffolding**

**Goal:** Ship a skill that guides PoC authoring within the same Cursor session (with model selection appropriate to the task) plus a scaffolding template the skill instantiates.

**Requirements:** R18, R24 (Covers AE4.)

**Dependencies:** U4 (PoC Tracking table), U5 (VM action log), U6 (host-action approval rules).

**Files:**
- Create: `Skills/offensive-macos-poc-authoring/SKILL.md`
- Create: `templates/findings-repo/POC_SCAFFOLDING.md` (operator-facing description of the `pocs/` layout, evidence linking, lab state requirements)
- Create: `templates/findings-repo/templates/poc/README.md.template` (per-PoC README scaffold the skill copies into `pocs/<target-id>/<id>/`)
- Modify: `templates/findings-repo/scripts/smoke-findings-repo.sh` (assert POC_SCAFFOLDING.md + templates/poc/ exist)
- Modify: `docs/workstation/skill-bundles.md`

**Approach:**
- Skill workflow: select primitive from chain-discovery output; choose lab state and snapshot strategy; create `pocs/<target-id>/<chain-or-finding-id>/` from the README template; capture harness, run record, reliability notes; append a Scriptorium anchor and Chronicle entry; update CORPUS PoC Tracking row.
- `POC_SCAFFOLDING.md` documents the operator-visible contract: where PoCs live, what the README captures, what is gitignored vs tracked, and how PoCs link back to evidence.
- `pocs/`, `poc/`, `chains/` already gitignored from this pass's earlier .gitignore update.

**Patterns to follow:**
- `Skills/offensive-macos-gatehouse-ghidra-lldb/SKILL.md` for the workflow shape that combines skills + macre-vm-mcp + evidence linking.

**Test scenarios:**
- Test expectation: structural only — skill validator passes; `bash templates/findings-repo/scripts/smoke-findings-repo.sh` asserts new template files; `bash scripts/smoke-wave3.sh` passes.
- Edge case: A fresh project clone has `pocs/` ignored at the template level (verified by attempting to add a file under `pocs/` and confirming `git check-ignore` reports ignored).

**Verification:** Validators pass; smoke tests pass.

---

- U10. **Apple source fetcher**

**Goal:** Ship `scripts/fetch-apple-source.py` that resolves an Apple component release name to a tarball URL on opensource.apple.com, downloads it to a workstation-local gitignored cache, and emits arguments suitable for `start-target.py --source-root`.

**Requirements:** R22 (Covers AE3.)

**Dependencies:** None for the script; recipe wiring depends on U7.

**Files:**
- Create: `scripts/fetch-apple-source.py`
- Create: `tests/test_fetch_apple_source.py`
- Modify: `.gitignore` (cache path already added in this pass; verify)

**Approach:**
- CLI: `fetch-apple-source.py <component> --release <release-id> [--cache-dir <path>]`. Default cache directory under a gitignored prefix (final naming chosen during implementation per the deferred question).
- Resolution: build the canonical opensource.apple.com URL from `<component>-<release>` (the public archive convention). Tarball is fetched via stdlib HTTP (no extra deps).
- Idempotency: skip download if the cache contains a non-empty unpacked directory for that release; integrity check is a size sanity check, not cryptographic verification (Apple does not publish per-tarball checksums on the archive page, so do not pretend to verify what cannot be verified — record the URL and timestamp).
- Output: prints the cache directory path and JSON suitable for piping into `start-target.py --source-root --source-ref --source-url`.
- Failure mode: HTTP failures and missing releases fail with a non-zero exit and a clear message; unit tests use a stubbed HTTP layer to exercise both paths without network.

**Patterns to follow:**
- `scripts/configure-cursor-mcp.py` for atomic write/idempotent CLI script style.
- `tests/test_configure_cursor_mcp.py` for unittest patterns.

**Test scenarios:**
- Happy path: `fetch_apple_source.resolve_url("dyld", "1042.1")` produces the expected `https://opensource.apple.com/...` URL pattern.
- Happy path: Stubbed-HTTP fetch writes a tarball to the cache, unpacks it, and returns the cache directory path.
- Happy path: Re-running with the same component+release is a no-op (cache hit).
- Edge case: Unknown component name fails with a clear error and exit code 2.
- Edge case: Network failure (stubbed) fails with a clear error rather than partial state.
- Integration: Cache directory is gitignored when run from the repo root (verified by `git check-ignore`).

**Verification:** `python -m unittest tests.test_fetch_apple_source` passes; `git check-ignore` confirms cache paths are ignored.

---

- U11. **macre-vm-mcp tools for OS-component metadata**

**Goal:** Add system-level VM tools that feed OS-component intake and recipes: `launchd_machservices`, `system_extension_list`, `framework_dependency_map`, `os_build_snapshot`.

**Requirements:** R5, R8, R12 (Covers AE3.)

**Dependencies:** None.

**Files:**
- Modify: `macre-vm-mcp/src/macre_vm_mcp/tools_system.py`
- Modify: `macre-vm-mcp/tests/test_server_smoke.py` (extend `EXPECTED_TOOLS`)
- Modify: `macre-vm-mcp/README.md` (document the new tools)

**Approach:**
- `launchd_machservices(domain: str = "system")` runs `launchctl print <domain>` (read-only) on the lab VM and returns parsed key facts (`mach-services`, `program-arguments`, `state`) plus raw text for the operator. Validation: domain must be one of `system`, `user/<uid>`, `gui/<uid>` patterns; reject otherwise.
- `system_extension_list()` runs `systemextensionsctl list` (read-only) and returns parsed rows.
- `framework_dependency_map(binary_path: str)` runs `otool -L` recursively (bounded depth) and returns dependent libraries with shared-cache origin annotations from `dyld_info` when available.
- `os_build_snapshot()` returns `sw_vers` + `system_profiler SPSoftwareDataType` + `csrutil status` as a single structured snapshot.
- All four are read-only; consistent with existing `tools_system.py` conventions.
- All four append to VM_ACTIONS.md when invoked through the recipe layer (recipe is responsible for the append; tool itself is pure).

**Patterns to follow:**
- Existing `tools_system.py` register pattern, Google-style docstrings, and `subprocess` invocation discipline.
- `lldb_run_anchors` validation pattern for argument sanitization.

**Test scenarios:**
- Happy path: All four tools are listed in `EXPECTED_TOOLS`; `pytest macre-vm-mcp/tests/test_server_smoke.py` passes.
- Happy path: Each tool's docstring names inputs, outputs, and lab caveats.
- Edge case: `launchd_machservices` rejects malformed domain strings.
- Edge case: `framework_dependency_map` rejects path strings containing shell metacharacters (no shell injection surface).

**Verification:** `pytest macre-vm-mcp/` passes.

---

- U12. **Ghidra scanners for OS-component surfaces**

**Goal:** Ship Ghidra postScripts that produce TSV output for launchd MachService topology, system extensions, Endpoint Security clients, and PrivateFramework dependency.

**Requirements:** R5, R6 (Covers AE3.)

**Dependencies:** None.

**Files:**
- Create: `ghidra-scripts/scan_launchd_machservice_topology.py`
- Create: `ghidra-scripts/scan_system_extension_surface.py`
- Create: `ghidra-scripts/scan_endpoint_security_client.py`
- Create: `ghidra-scripts/scan_private_framework_dependency.py`
- Modify: `ghidra-scripts/README.md` (document new scanners and TSV headers)
- Modify: `tests/ghidra-scripts/smoke.sh` (extend `expected_headers`)

**Approach:**
- Each script follows the existing read-only postScript convention: print one TSV header + one row per program; never modify program state.
- Suggested headers (final names chosen during implementation):
  - `target	listeners	mach_services	entitlement_refs	audit_token_uses	evidence` (launchd-machservice-topology, refining `dump_xpc_listeners.py` rather than replacing — final overlap decision deferred to implementation per Open Question).
  - `target	system_extension	es_subsystems	entitlement_refs	approval_strings	evidence` (system-extension-surface).
  - `target	es_client_calls	es_event_subscriptions	cache_handlers	policy_strings	evidence` (endpoint-security-client).
  - `target	framework_deps	private_framework_refs	dyld_cache_origin	weak_links	evidence` (private-framework-dependency).
- Output TSV rows feed CORPUS Exploitability And Chainability and OS Component Topology indirectly via operator-driven Maproom recipes from U7.

**Patterns to follow:**
- `ghidra-scripts/dump_xpc_listeners.py`, `ghidra-scripts/scan_xpc_client_validation.py` for shape and read-only discipline.
- `tests/ghidra-scripts/smoke.sh` `expected_headers` dict for header registration.

**Test scenarios:**
- Happy path: Each new script prints exactly its declared TSV header when run with no arguments (stub mode); `bash tests/ghidra-scripts/smoke.sh` passes.
- Edge case: Each script catches `Exception` around program-property access and continues with a partial row rather than crashing the headless run (matches existing scanner behavior).

**Verification:** `bash tests/ghidra-scripts/smoke.sh` passes.

---

- U13. **Recent macOS CVE survey research note**

**Goal:** Ship `docs/research/macos-cve-survey-2026.md` summarizing ~10 recent macOS CVEs across subsystems, mapping each to ontology classes, calling out exploitability and chainability dimensions, and listing maturity-priority recommendations for the OS-component lane.

**Requirements:** R25 (Covers AE7.)

**Dependencies:** None for the research; informs U2/U3/U7 maturity decisions if revisited.

**Files:**
- Create: `docs/research/macos-cve-survey-2026.md`
- Modify: `docs/workstation/skill-bundles.md` (only if the survey doc is referenced from a skill)

**Approach:**
- Sections: `Overview`, `Methodology`, `CVEs By Subsystem`, `Ontology Coverage`, `Maturity Priority Recommendations`, `Exploitability Rating Dimensions Observed`, `Chain Examples`, `References`.
- ~10 CVEs distributed across TCC, XPC, launchd/MachServices, Sparkle/updaters, Endpoint Security, installd/softwareupdated, FileProvider, sharing/AirDrop, sandbox, and at least one cross-cutting chain example.
- Each CVE entry: subsystem, public references, ontology class match (or gap), exploitability dimensions observed, chain potential, takeaway for station maturity.
- No exploitation steps, no PoC code, no operational tradecraft — research-grade summarization only.
- Specific CVE selection deferred to implementation per the deferred Open Question.

**Patterns to follow:**
- `docs/playbooks/investigation-recipes.md` and `docs/ontology/macos-vulnerability-classes.md` heading style.

**Test scenarios:**
- Test expectation: none — research note. Structural validation: `bash scripts/smoke-wave3.sh` passes (file exists with expected top-level sections if smoke is taught about it; otherwise no-op).

**Verification:** Manual review confirms the survey covers the listed subsystems and produces actionable maturity recommendations.

---

- U14. **Validation, registry, README, topology, gitignore polish**

**Goal:** Glue everything together: skill-bundles registry, topology doc, README OS-component lane line, smoke-wave3 structural checks, and final gitignore verification.

**Requirements:** All R-IDs benefit (closes the loop on R5–R24 by ensuring everything is discoverable and structurally validated).

**Dependencies:** All prior units.

**Files:**
- Modify: `docs/workstation/skill-bundles.md` (Wave 5 — OS Component Lane section, listing the new skills from U2/U8/U9 and the existing extensions in U6)
- Modify: `docs/topology.md` (three-environment description from U6, plus new playbook/scanner references)
- Modify: `README.md` (one-paragraph OS-component lane mention, alongside the existing iOS future direction)
- Modify: `scripts/smoke-wave3.sh` (assert new playbooks, recipes, template files, and skill directories)
- Modify: `.gitignore` (verify pocs/, chains/, sources/apple/, .apple-source-cache/ entries from this pass; add anything missed)

**Approach:**
- Skill bundles Wave 5 section names the new family skill, chain-discovery skill, and PoC-authoring skill, plus extension to agent-discipline (U6).
- Topology doc updates the workstation/lab-host/lab-VM model, adds the disposability axis, and references the OS-component playbook + new scanners.
- README adds a single paragraph (parallel to the existing "Future direction: iOS" line) noting the OS-component lane and PoC authoring path.
- Smoke-wave3 grows structural assertions: `docs/research/macos-cve-survey-2026.md` exists, new playbook file exists, new scanners cited, new template files exist.

**Patterns to follow:**
- Existing Wave 4 entries in `docs/workstation/skill-bundles.md`.
- Existing structural checks in `scripts/smoke-wave3.sh`.

**Test scenarios:**
- Happy path: `bash scripts/smoke-wave3.sh` passes end-to-end.
- Happy path: `python scripts/validate_workstation_bundles.py` passes.
- Happy path: `python scripts/validate-recipes.py` passes.
- Edge case: Removing any new file produces a clear smoke failure (regression check).

**Verification:** All structural validators pass; README and topology updates render correctly; `git diff --check` reports no whitespace issues.

---

## System-Wide Impact

- **Interaction graph:** `start-target.py` is the integration hub; new surfaces, maturity, and tables flow from it into Watch decision support, Maproom recipes, and Scriptorium anchors.
- **Error propagation:** Intake failures already raise `IntakeError` with exit code 2; new code paths must preserve this. MCP tool failures must not crash the server (existing pattern); they return structured error payloads.
- **State lifecycle risks:** Re-intake idempotency is load-bearing. The `ensure_table_row` pattern applies to every new CORPUS table; tests must verify duplicate-prevention on second-run.
- **API surface parity:** No public APIs change; CLI scripts and skills only.
- **Integration coverage:** End-to-end check is `bash scripts/smoke-wave3.sh` plus the per-component validators. New unit tests cover intake recognition, maturity emission, CORPUS upserts, Apple source fetcher, and MCP tool registration.
- **Unchanged invariants:** Watchtower vocabulary stays additive; bundle-first project start still works for app targets; existing recipe IDs and validators continue to pass.

---

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| Intake recognition produces false positives for OS-component surfaces (e.g., a third-party framework misclassified as `private-framework-dep`). | Anchor `private-framework-dep` to actual `/System/Library/PrivateFrameworks/` resolution paths from `otool -L`, not name heuristics. Unit tests cover both true and false cases. |
| Apple source fetcher attempts to verify integrity Apple does not publish. | Plan explicitly records URL + timestamp instead of pretending to verify checksums; documented in U10 approach. |
| MCP tool argument validation gap allows shell injection on the lab VM. | All four new tools validate inputs against strict patterns (domain regex, path metacharacter rejection); pattern follows `lldb_run_anchors`. |
| Skill bundle / recipe validators block the whole pass on a single missed citation. | Land U14 last; intermediate units can run their own validators as they go (`validate_workstation_bundles.py`, `validate-recipes.py`) before final smoke-wave3. |
| CVE survey drifts toward per-CVE rediscovery walkthroughs. | Plan and origin scope-boundary explicitly forbid this; survey shape (Ontology Coverage, Maturity Priority, Exploitability Dimensions, Chain Examples) keeps it research-grade. |
| Maturity claims for `system-extension`/`network-extension`/`endpoint-security-client` overstate support. | This pass deliberately marks them `basic-inventory`; U3 tests verify the surface→maturity mapping; U7 recipes for these subsystems are inventory-only or absent until a future plan promotes them. |
| Lab disposability `false` recorded but the agent ignores it and runs destructive actions. | U6 host-action approval discipline rule explicitly extends the approval gate to non-disposable lab hosts; the rule lives in agent-discipline skill, which is loaded for every session. |
| Re-intake corrupts CORPUS rows due to `ensure_table_row` edge cases on the new tables. | Reuse the same battle-tested `ensure_table_row` helper and add idempotency tests (U1, U3, U4) before landing. |

---

## Phased Delivery

### Phase A — Foundation

Lands first because every later unit depends on intake, state shape, and lab-safety primitives.

- U1 OS-component intake recognition
- U2 OS-component family playbook and skill
- U3 Watch maturity per surface
- U4 CORPUS template additions
- U5 Lab safety v2 and VM action log
- U6 Host-action approval discipline

### Phase B — Workflows and Tooling

Adds the new skills, scripts, MCP tools, and Ghidra scanners that the Maproom recipes will reference.

- U8 Chain-discovery skill
- U9 PoC authoring skill and scaffolding
- U10 Apple source fetcher
- U11 macre-vm-mcp tools for OS-component metadata
- U12 Ghidra scanners for OS-component surfaces

### Phase C — Integration and Research

Wires everything together and grounds the maturity decisions in current research.

- U7 Maproom recipes (depends on Phase A + B because recipes reference state, skills, scripts, and scanners)
- U13 Recent macOS CVE survey research note (parallelizable with Phase B)
- U14 Validation, registry, README, topology, gitignore polish (lands last)

---

## Documentation / Operational Notes

- **README**: one paragraph added in Phase C (U14); no installation flow changes.
- **Topology doc**: updated with the workstation / lab host / lab VM split and the disposability axis.
- **Skill bundles**: new "Wave 5 — OS Component Lane" section.
- **Operational rollout**: nothing to deploy; the station is a clone-from-template repo. After landing, an operator running `scripts/setup-keep.sh` on a fresh checkout picks up the new skills, recipes, scanners, and MCP tools automatically.
- **No migrations**: project state is markdown tables; new tables are additive and only populated when the new code paths run. Existing project clones can rsync the new template files in via `scripts/init-project.sh` without disrupting their current state.

---

## Sources & References

- **Origin document:** [docs/brainstorms/2026-05-07-macos-os-component-hunting-requirements.md](../brainstorms/2026-05-07-macos-os-component-hunting-requirements.md)
- Existing intake: `scripts/start-target.py`
- Existing recipe registry: `docs/playbooks/investigation-recipes.md`
- Existing validators: `scripts/validate-recipes.py`, `scripts/validate_workstation_bundles.py`, `templates/findings-repo/scripts/smoke-findings-repo.sh`, `tests/ghidra-scripts/smoke.sh`
- Existing MCP server: `macre-vm-mcp/src/macre_vm_mcp/server.py`, `macre-vm-mcp/src/macre_vm_mcp/tools_system.py`
- Existing skill template: `Skills/_template/SKILL.md`
- Existing skill bundle index: `docs/workstation/skill-bundles.md`
- Existing ontology: `docs/ontology/macos-vulnerability-classes.md`
- Adding-families policy: `docs/playbooks/adding-target-families.md`
- Apple source: https://opensource.apple.com/releases/
