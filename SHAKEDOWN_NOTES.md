# Shakedown Notes

Running log of environment / tooling / skill-utilization findings captured during live hunting passes. Each entry is either a **shortcoming** (something to fix), a **good-thing** (pattern worth keeping), or a **decision** (operator/agent choice worth writing down).

Source passes:
- **PASS-001 / T-001 — Rocket.Chat.app 4.13.0** (2026-05-11) — first end-to-end shakedown against an Electron consumer app. Exercised intake → MCP wiring → static sweep → persistence. Surfaced most of the items below.

## How to use

- Agents: append when you hit an env bump, a missed skill, or a pattern that worked well. Don't batch — one entry per issue, keep them short.
- Operator: read before planning infrastructure changes. Treat the **Fix priority** column as a backlog.
- Feed to the LLM developing future skill/env content: the shortcomings list is the prompt material.

---

## Tooling / Env Shortcomings (PASS-001)

| # | Issue | Where | Fix status | Priority |
|---|-------|-------|------------|----------|
| 1 | `scripts/configure-claude-code-mcp.py` wrote to `~/.claude/settings.json` instead of invoking `claude mcp add-json`. Claude Code ignored the resulting config. | `scripts/configure-claude-code-mcp.py` | Fixed 2026-05-11; script now shells out to `claude mcp add-json -s <scope>`. Mirrored to skillz. | shipped |
| 2 | All 19 ghidra-scripts carried `# @runtime Jython`. Under modern Ghidra, PyGhidra is the right runtime for these helpers; Jython 2.7 breaks the `_re_lib` shim design. | `ghidra-scripts/*.py` | Fixed 2026-05-11; all flipped to `# @runtime PyGhidra`. Mirrored to skillz. | shipped |
| 3 | `_re_lib.py` helpers referenced `currentProgram` and friends as bare globals, assuming Jython-style propagation into imported modules. PyGhidra injects via `__missing__` on the script globals dict — invisible to imports. | `ghidra-scripts/_re_lib.py` | Fixed 2026-05-11; `_bind_ghidra_globals_from_caller()` walks the caller stack and copies runtime names into `_re_lib.__dict__`. Wired at 13 public entry points. Idempotent. Mirrored to skillz. | shipped |
| 4 | `ghidra-headless-mcp` backend dropped `print()` from imported modules. PyGhidra's `println` wrapper only covers the script's globals dict; `_re_lib.emit`'s fallback-to-bare-`print` wrote to real `sys.stdout` and the MCP client received an empty TSV. | `ghidra-headless-mcp/ghidra_headless_mcp/backend.py` (upstream `mrphrazer/ghidra-headless-mcp @ b9c491a`) | Fixed 2026-05-11 on NightBlood editable install. Patch captured at `Skills/offensive-macos-tooling-ghidra-headless/pyghidra-script-stdout.patch` + rationale in `PATCHES.md`. Candidate for upstreaming. | ship upstream |
| 5 | `ghidra-scan.sh` defaulted to `-Xmx12g` with no regard for VM RAM. On a 4 GB VM this caused 2+ hours of swap thrashing before detection. | `scripts/ghidra-scan.sh` | Doc piece shipped — default dropped to 10g 2026-05-11; `physical_ram_gb - 6` rule encoded as comment in `ghidra-scan.sh` and as a documented section in `Skills/offensive-macos-lab-roster/SKILL.md` (commit `e8eec9c`, 2026-05-13). Remaining gap: automated heap preflight that reads `sysctl hw.memsize` and refuses if `MACRE_GHIDRA_HEAP` violates the rule — to be tracked as a Phase 5A follow-on item. | partial |
| 6 | No PyGhidra preflight check on lab host. `analyzeHeadless` directly errored with "Ghidra was not started with PyGhidra. Python is not available" until we figured out `pyghidra_launcher.py -H` with the MCP venv's Python is the required entry point. | `scripts/install-ghidra-host.sh` / `ghidra-scan.sh` | Fixed 2026-05-13. Third preflight in `scripts/ghidra-scan.sh` (after disk #7 / heap #34): probes `"$VENV_PY" -c 'import pyghidra'` and refuses with exit code 8 if it fails. Mirrors the existing preflight shape (env-var override `MACRE_SKIP_PYGHIDRA_PREFLIGHT=1`, dedicated exit code, three-line stderr block, header exit-code list updated in same commit). The path-existence check on `LAUNCHER` and `VENV_PY` (exit 4) only proves the files are present; this check proves the venv can actually load pyghidra (catches the partial-`uv venv`-rebuild failure mode where binaries exist but the package is missing). Verified end-to-end on NightBlood: negative path with `MACRE_PYGHIDRA_PYTHON=/usr/bin/python3` exits 8 with the documented stderr; positive path against `~/.venvs/ghidra-headless-mcp/bin/python` passes silently; `MACRE_SKIP_PYGHIDRA_PREFLIGHT=1` override works. | shipped |
| 7 | No disk-space preflight in `ghidra-scan.sh`. A large analysis that hits ENOSPC mid-run leaves a corrupt `.gpr`. Operator flagged 5 GB free as the manual tripwire. | `scripts/ghidra-scan.sh` | Fixed 2026-05-13 in commit `2d598a0`. `df` before launch, refuse if free space < `max(5_GB, 2x_binary_size)`, override via `MACRE_SKIP_DISK_PREFLIGHT=1`, dedicated exit code 5. | shipped |
| 8 | `-readOnly` was the default in ad-hoc scripts — analyzed Ghidra project discarded on exit. On a 177 MB binary this is 30-60 min of work thrown away per scan. | old one-off scripts | Fixed for SSH path via `ghidra-scan.sh` (no `-readOnly`, persistent project under `~/ghidra-projects/<project>/<target-id>.gpr`). **MCP `program.open` workflow in SKILL.md still documents `read_only=true` + `update_analysis=true`** — behavior under ghidra-headless-mcp needs verification; likely also needs reversal. | ship upstream |
| 9 | `scan_tcc_prompt_surface.py`'s `enrich_objc_msgsend` decompiles every `_objc_msgSend` caller before bucketing by selector. On a 177 MB Chromium+Cocoa binary that's hundreds of thousands of decomps; scan phase becomes multi-hour. | `ghidra-scripts/scan_tcc_prompt_surface.py` + `_re_lib.enrich_objc_msgsend` | Fixed 2026-05-13. (a) `enrich_objc_msgsend` now takes `max_total_callsites` (default `MACRE_MAX_TOTAL_CALLSITES=20000`) which bounds *iteration* across all msgsend variants — the prior per-selector cap only bounded emitted rows, not the decompiler work. Hitting the cap emits `objc_msgsend_total_callsites_capped_at_N` to the writer. (b) `run_string_scan` exposes `max_total_callsites` and the existing `fast_mode` kwarg is now documented + threaded through to both enrich phases (the `DecompCache(fast_mode=...)` plumbing already existed; this surfaces it). (c) Heuristic warning: when `objc_specs` are present, `fast_mode=False`, and the binary exceeds `MACRE_LARGE_TARGET_WARN_MB=50`, the writer emits `large_target_consider_fast_mode=<size>MB`. | shipped |
| 10 | No progress beacon during Ghidra auto-analysis. Stdout grows < 1 line/min on large binaries; "making progress" and "deadlocked" look identical without wall-clock + CPU comparison. | Ghidra headless + scan scripts | Fixed 2026-05-13. (a) `scripts/ghidra-watch.sh` 60-s heartbeat poller in commit `b6c47fb` with swap/db-flat/cpu-low heuristics. (b) `_re_lib` stderr heartbeat in `enrich_callsite_args` + `enrich_objc_msgsend` in commit `f65f509` (default every 100 callsites, override via `MACRE_HEARTBEAT_EVERY`). | shipped |
| 11 | Ghidra universal-Mach-O slice selection is implicit. No `-loader-arch` flag; caller must `lipo -thin <arch>` first. | `analyzeHeadless` docs + `ghidra-scan.sh` | Subsumed by #29 (shipped 2026-05-13). `ghidra-scan.sh` now auto-slices universal binaries and scans every slice; the documentation gap is closed by the implementation. | shipped |
| 12 | Ad-hoc ssh polling pattern: repeated `ssh NightBlood '<long command>'` invocations with full handshake each time. Probably minutes of handshake overhead accumulated during PASS-001. | Agent workflow + `~/.ssh/config` | Fixed 2026-05-13 in commit `5e5077a`. ControlMaster + `ControlPersist 10m` + `ServerAliveInterval 30` stanza published in `Skills/offensive-macos-station-topology/SKILL.md`; `scripts/install-vm-ssh-key.sh` prints a recommendation when the operator's `~/.ssh/config` lacks the stanza. Recommend-don't-write to avoid clobbering operator-specific entries. | shipped |
| 13 | `conv.md` exists in rocket_chat as a per-session handoff artifact but isn't in `.gitignore`. Risk of accidental commit. | rocket_chat template `.gitignore` | Fixed 2026-05-13. Repo-root `.gitignore` now lists `conv.md` and `conv-*.md`. Same rule applies to any findings repo cloned from this template. | shipped |
| 14 | No VM-sizing recommendation anywhere in skillz. `machines.md` / `offensive-macos-lab-roster` are silent on resources. Operators provision guess-based VMs. | `Skills/offensive-macos-lab-roster/SKILL.md` | Fixed 2026-05-13; "VM Sizing" section added with role table (smoke / primary-Electron / primary-Apple-framework / crash-test), `physical_ram_gb - 6` heap rule, and 4-vs-8-cores guidance lifted from PASS-001 observations. Trigger phrases extended (`VM sizing`, `how much RAM`, `Ghidra heap`). | shipped |
| 15 | No `Host NightBlood` SSH keepalive guidance. A long-running scan over a session-bound SSH MCP transport can drop on idle; `ServerAliveInterval 30` already exists in the MCP wrappers but isn't documented as station policy. | `Skills/offensive-macos-station-topology` | Fixed 2026-05-13 in commit `5e5077a`. Station-topology SKILL.md `## SSH Config (workstation)` section now publishes the full stanza (`ControlMaster`, `ControlPath`, `ControlPersist 10m`, `ServerAliveInterval 30`) and explains why each line matters — `ServerAliveInterval 30` is documented as station policy ("keeps long-running scans from dropping when the SSH session goes idle"). `scripts/install-vm-ssh-key.sh` recommends the stanza. Recovery on re-read of PR #10's audit: PR #9's `partial` was conservative; the doc lift is complete. | shipped |
| 16 | Ghidra's `CreateFunctionCmd` and `VarnodeContext` errors flood the log on complex binaries; drown meaningful INFO lines. Not a bug, but hurts signal-to-noise during polling. | Ghidra | Subsumed by #10 (shipped 2026-05-13 in commits `b6c47fb` + `f65f509`). `scripts/ghidra-watch.sh`'s structured one-line-per-poll output is the operator-facing replacement for tailing the raw log; the `_re_lib` stderr heartbeat surfaces script-phase progress separately. The underlying upstream noise remains, but the polling friction it caused is gone. | shipped |
| 17 | `scan_tcc_prompt_surface.py` `tcc_string` regex generates 24/24 false positives on Electron Framework. `(TCC\|TCCAccessRequest\|kTCCService\|com\.apple\.TCC\|tccd)` with `re.I` matches `TCC` inside base64 root-certificate PEMs. | `ghidra-scripts/scan_tcc_prompt_surface.py` | Fixed 2026-05-13 in commit `1053149`. Bare `TCC` alternative dropped; four specific forms (`TCCAccessRequest\|kTCCService\|com.apple.TCC\|tccd`) retained. Same-class re.I sweeps in other rules still warrant a future audit. | shipped |
| 18 | `run_string_scan` does not truncate the `name` column for string-rule anchors. On Electron Framework one PEM cert hit produced an **800 KB** single TSV row. Only the `evidence` column is truncated (120 char). | `ghidra-scripts/_re_lib.py` (run_string_scan) | Fixed 2026-05-13 in commit `1053149`. `name` column now truncated to 160 chars before `writer.add(...)`. | shipped |
| 19 | `callers_of(external_fn)` yields self-match rows for the import thunk itself. On PASS-001 this produced 2 spurious tier-A anchors whose "caller" is the external symbol `_SecTaskCopyValueForEntitlement` itself. | `ghidra-scripts/_re_lib.py` (callers_of or enrich_callsite_args) | Fixed 2026-05-13 in commit `1053149`. `callers_of` skips both same-name caller rows and entry-point self-refs. | shipped |
| 20 | String / function index default caps (20k / 50k) are too low for large Apple-framework or Electron binaries. Caps hit on Electron Framework → tier-C coverage bounded. | `ghidra-scripts/_re_lib.py` (`DEFAULT_MAX_STRINGS`, `DEFAULT_MAX_FUNCTIONS`) | Fixed 2026-05-13. `StringIndex` / `FunctionIndex` now auto-scale at first `_load()` once `currentProgram` is bound: cap = `clamp(size_mb * 200, 20k, 200k)` for strings, `clamp(size_mb * 500, 50k, 500k)` for functions. Resolution precedence is explicit constructor arg > `MACRE_MAX_STRINGS` / `MACRE_MAX_FUNCTIONS` env > auto-scale > floor. Chosen cap + source emitted to stderr at first `_load()` so `[StringIndex] max_strings=N source=auto(size_mb=M)` is visible to ghidra-watch.sh and operators. PASS-001 surfaced the bound when Electron Framework hit `string_index_truncated_at_20000`; the 177 MB Electron Framework now auto-scales above 35k strings (well past the cap-hit threshold). Old `DEFAULT_MAX_*` module constants kept as back-compat for the truncation-warning string. | shipped |
| 21 | Ghidra's PyGhidra wraps `println` output in `INFO <script>.py> <line> (GhidraScript)` prefix/suffix. The TSV isn't directly usable from the stdout log without post-processing. | ghidra-scan.sh + lab-host output convention | Fixed 2026-05-13. `scripts/ghidra-scan.sh` now emits `<out-dir>/<script>.tsv` alongside `.stdout.log` by piping through `sed -E 's/^INFO  [^>]+> //; s/ \(GhidraScript\) +$//'`. Best-effort (sed failure logs a warning, doesn't change exit code); preserves raw `.stdout.log` for forensics. Verified against synthetic PASS-001-shape input. | shipped |
| 22 | `mcp__ghidra-mcp__project_program_open_existing` requires `program_name` or `program_path` despite the tool's name + description implying you reopen a named existing project. Error from the server (`program_name or program_path is required`) is the only signal; the tool schema marks both optional. | `ghidra-headless-mcp` MCP schema + description | Not fixed. Either (a) make the description explicit: "opens a *program* inside a project — still needs program_name/program_path", or (b) accept an empty program and return the program list the caller can choose from. Also: the schema's `folder_path` / `program_path` don't cleanly distinguish the two paths; worth a docstring example. | med |
| 23 | Shakedown doc path drift: the operator refers to `~/tools/skills` but the actual dev repo is `~/tools/skillz`. Confusing for new agent sessions. | operator-facing docs | Fixed 2026-05-13. New "Workstation Paths" subsection in `Skills/offensive-macos-station-topology/SKILL.md` declares `~/tools/skillz` canonical. Opt-in `scripts/install-skills-symlink.sh` creates `~/tools/skills -> skillz` idempotently (refuses to overwrite existing real directory). Repo grep shows zero stale `tools/skills` references in tracked code or skill docs. | shipped |
| 24 | **Session-interrupt leaves Ghidra project locked.** A prior Claude Code session crashed/exited while its `ghidra-headless-mcp` subprocess held an exclusive lock on `~/ghidra-projects/<project>/<target>.gpr`. The zombie MCP process (PID 1736) survived the Claude Code exit and kept the `.lock`. Next session's `project_program_open_existing` failed with `LockException` even with `read_only=true`. Had to `kill <pid> && rm .lock .lock~` to recover. | `ghidra-headless-mcp` server + Claude Code session teardown + `ghidra-scan.sh` | Fixed 2026-05-13. Patch `Skills/offensive-macos-tooling-ghidra-headless/pid-tagging-and-shutdown.patch` adds `GhidraBackend.shutdown()` (closes all sessions on `SIGTERM`/`SIGINT`/`atexit`, releasing project locks via existing `session_close` semantics) and a sidecar JSON at `~/.ghidra-headless-mcp/sessions/<pid>.json`. `cli.main` installs the signal handlers. Reader half is `scripts/lab-health.sh`. | shipped |
| 25 | **Killing a zombie `ghidra-headless-mcp` can also kill the *active* MCP session** if you target the wrong PID. Both processes look identical in `ps`. I misread the PID list and disconnected my own MCP layer mid-session. Fallback to `ghidra-scan.sh` worked but it's friction. | operator workflow + `ghidra-headless-mcp` process metadata | Fixed 2026-05-13. The sidecar JSON written by the same patch records PID + open projects + claimed lockfile per running MCP. `scripts/lab-health.sh` reads the sidecar dir and surfaces (a) live MCPs with their open projects, (b) stale sidecars whose PID is dead, (c) orphan project lockfiles no live sidecar claims. Argv[0] tagging deferred — sidecar-based identification is richer than ps would give. | shipped |
| 26 | **`ghidra-scan.sh` arg-validation uses Bash 4+ `${var,,}` lowercase expansion, but macOS ships Bash 3.2.** Calling the script with a missing flag triggers `bad substitution` instead of a clear "missing --out-dir" message. The normal path works (Bash 3.2 handles most of the script fine), but error messages break. | `scripts/ghidra-scan.sh` line 64 | Fixed 2026-05-13 in commit `2d598a0`. `${var,,}` replaced with `tr '[:upper:]_' '[:lower:]-'` (line 66) so the missing-flag error path renders correctly under remote `bash 3.2` over SSH. | shipped |
| 27 | **Tolerant asar extraction is required for shipped Electron apps.** Rocket.Chat's `app.asar` header claims 111 files (mostly `LICENSE.txt`) are unpacked, but those files are missing from `app.asar.unpacked/`. Upstream asar extractors (both `asar@3` and `@electron/asar@4+`) throw `ENOENT` on the first missing unpacked file and bail, leaving the extract directory empty. Had to write a Node wrapper that monkey-patches `fs.readFileSync` to substitute empty buffers for missing unpacked files. Worth adding as `scripts/extract-asar.sh` so next operator doesn't rebuild the trick. | `scripts/extract-asar.sh` (doesn't exist) + Electron surface pack skill | Fixed 2026-05-13. Pure-Node `scripts/extract-asar.js` walks the asar header directly, substitutes empty buffers for missing `*.unpacked/` files, emits `.asar-extract-manifest.json` listing each substitution. `scripts/extract-asar.sh` is a thin wrapper with Node ≥14 preflight. Mentioned at step 2 of `offensive-macos-electron-surface-pack` SKILL.md. Verified against the PASS-001 reproduction (14174 files, substitute-path exercised by hiding one unpacked file). | shipped |
| 28 | **app.asar is >100 MB extracted, shouldn't live in `targets/` on disposable lab host.** I extracted locally on the workstation (which is fine per SHAKEDOWN §host-vs-lab-host rules) — but the lab host's `/Users/szeth/Targets/rocket_chat/` already has the asar and unpacked dirs shipped as part of the .app bundle. Workstation extract is redundant with the lab-host state when the operator later attaches an MCP for JS inspection. No tool in this station currently reads `targets/app-asar/` — it's static reference material for Ghidra-style grep. | workstation storage convention + skill docs | Not fixed. Decide: does the Electron surface-pack skill extract to workstation, lab host, or both? If both, document why (e.g., workstation for grep velocity, lab host for DTrace-on-node). | med |
| 29 | **Universal-Mach-O slice selection is silent in `ghidra-scan.sh`.** PASS-001 only scanned the arm64 slice of Electron Framework; an x86_64-only bug (compiler-specific ifdef, arch-specific hardening miss) would slip through. The TCC-native negative result is a statement about arm64, not the binary. Reframes item #11 from "documented" to "default coverage" — scanners should scan both slices on universal binaries, not silently pick one. | `scripts/ghidra-scan.sh` universal-binary handling | Fixed 2026-05-13. `scripts/ghidra-scan.sh` detects universal Mach-Os via `lipo -info` (matches the `Architectures in the fat file:` prefix), `lipo -thin <arch>`s each slice into `<out-dir>/.slices-<target-id>/<basename>-<arch>`, and runs the scan once per slice serially against `<target-id>-<arch>.gpr` projects. Per-slice logs/TSVs use `<script>-<arch>.{stdout.log,stderr.log,tsv}`; single-arch path is unchanged. Loud `[ghidra-scan] universal-binary detected: scanning N slices serially` to stderr satisfies the "no silent slice selection" rule. Worst-rc-wins exit code; trailer surfaces per-slice rcs. New exit code 7 for `lipo -thin` failure. Heap-vs-RAM preflight (PR #13 #34) gates each slice; serial execution prevents two concurrent Ghidra projects from breaching the heap budget. Subsumes item #11 ("documented but not auto-sliced"). | shipped |
| 30 | **`npx @electron/fuses read` not run at intake for Electron targets.** Fuses surface (`RunAsNode`, `EnableNodeCliInspectArguments`, `OnlyLoadAppFromAsar`, `EnableEmbeddedAsarIntegrityValidation`, `GrantFileProtocolExtraPrivileges`, `LoadBrowserProcessSpecificV8Snapshot`) is currently never inspected. Any one wrong fuse converts "renderer bug" into "full RCE" or "any read primitive → code loading". | `Skills/offensive-macos-electron-surface-pack/SKILL.md` + `offensive-macos-bundle-intake` recipe | Fixed 2026-05-13. Electron surface-pack SKILL.md step 4 now mandates `npx @electron/fuses read --app <Bundle>.app` and enumerates every fuse to record. Output Shape carries an `Electron fuses` row that cannot be empty for a complete review. | shipped |
| 31 | **IPC / contextBridge audit is "maybe later" rather than a default step in the Electron surface-pack skill.** PASS-001 found preload exposes `JitsiMeetElectron`, `RocketChatDesktop`, `videoCallWindow` to the renderer; never audited what each API exposes, whether arguments are type-checked before reaching the main process, whether `contextIsolation: true` is actually set. A bridge that hands the renderer a function which spawns shell commands — even framed as a "dev helper" — would be renderer-to-shell RCE with minimal renderer compromise. | `Skills/offensive-macos-electron-surface-pack/SKILL.md` step 2 | Fixed 2026-05-13. Electron surface-pack SKILL.md step 5 mandates per-`exposeInMainWorld`-call recording: bridge name, property names, type-check status, `contextIsolation` value. Output Shape `contextBridge calls` row cannot be empty for a complete review. Step header explicitly forbids deferring to "task #N". | shipped |
| 32 | **Native `.node` modules under `app.asar.unpacked` never enumerated.** A Mach-O shipped inside `app.asar.unpacked` runs in the renderer or browser process with full node privilege and bypasses codesign-validation of the main `.app` at dlopen time. PASS-001's `fsevents.node` was the only one shipped (uncontroversial), but no recipe says "enumerate every `**/*.node` and queue each as a scan target". | `Skills/offensive-macos-electron-surface-pack/SKILL.md` + `offensive-macos-bundle-intake` recipe | Fixed 2026-05-13. Electron surface-pack SKILL.md step 6 mandates `find <extract-dir>/app.asar.unpacked -name '*.node'` and the worklist entry per module. Output Shape `Native modules` row carries the T-00N scan-target id. | shipped |
| 33 | **`com.apple.security.application-groups` entitlement does not auto-trigger `offensive-macos-hunt-keychain-access-group`.** PASS-001 missed the signal: Rocket.Chat's `application-groups = S6UPZG7ZR3.chat.rocket` is a valid keychain access group identifier. If the app stores credentials under that group with ACLs that don't pin to the code-signing identity, any other `S6UPZG7ZR3`-signed app reads them — classic confused-deputy. Same gap likely for `com.apple.security.automation.apple-events` (AppleEvent target from renderer = renderer→arbitrary-app-control pivot). | `offensive-macos-bundle-intake` recipe + `offensive-macos-vuln-ontology` | Fixed 2026-05-13. Bundle-intake SKILL.md now has a workflow step 6 ("Derive trigger signals from entitlement values") + an "Entitlement Trigger Signals" table mapping seven entitlements to hunt skills (`application-groups`, `automation.apple-events`, `endpoint-security.client`, `cs.allow-unsigned-executable-memory`, `cs.disable-library-validation`, `private.security.no-sandbox`, `private.tcc.allow-prompting`). Vuln-ontology workflow step 1 reads the `Trigger signals` section before family-label classification. | shipped |
| 34 | **No automated heap-vs-RAM preflight in `ghidra-scan.sh`.** Item #5's documentation piece shipped (`physical_ram_gb - 6` rule in `Skills/offensive-macos-lab-roster` + `ghidra-scan.sh` comment), but no code-side check refuses a heap that exceeds physical RAM minus headroom. PASS-001's 4 GB / `-Xmx12g` swap-thrash is still reachable if a fresh agent ignores the rule. | `scripts/ghidra-scan.sh` (preflight section near disk check, lines ~75-99) | Fixed 2026-05-13. `scripts/ghidra-scan.sh` now reads `sysctl hw.memsize`, parses `MACRE_GHIDRA_HEAP` (`<N>g` or `<N>m`), computes `physical_ram_gb - 6` (clamped to 1 GB minimum), and refuses with exit code 6 when the requested heap exceeds the limit. Override via `MACRE_SKIP_RAM_PREFLIGHT=1`. Mirrors the `MACRE_SKIP_DISK_PREFLIGHT` shape (lines 77-99). When `sysctl` is unavailable (non-macOS host), the preflight skips silently rather than false-fail. | shipped |

---

## Skill Utilization (PASS-001)

Honest assessment of which skills fired, which should have but didn't, and which correctly stayed quiet.

### Skills that fired (explicitly or implicitly)

| Skill | How it was used |
|-------|-----------------|
| `offensive-macos-bundle-intake` | Drove the PASS-001-T-001 dossier + target-map shape. |
| `offensive-macos-source-binary-correlation` | Pulled `Rocket.Chat.Electron` source at tag 4.13.0; used to confirm source-vs-shipped-asar parity for C-005. |
| `offensive-macos-tooling-ghidra-headless` | Env work was essentially making this skill's MCP flow viable; `ghidra-scan.sh` became the fallback path when MCP disconnected mid-session. |
| `offensive-macos-scriptorium-evidence` | `PASS-001:T-001` anchor pattern in CORPUS.md + findings/analysis notes per candidate. |
| `offensive-macos-tooling-cli-static` (session 2) | Replaced 5 × 40-min Ghidra Helper scans with 30-sec `nm -u` + `otool -L` + `codesign -d --entitlements` pass. The big session-2 win. |
| `offensive-macos-agent-discipline` (session 2) | "Don't brute force" rule invoked when we were about to run 5 redundant Helper sweeps. Also invoked when deciding MCP-zombie cleanup was lab-disposable-safe. |
| `offensive-macos-electron-surface-pack` (session 2) | Full workflow followed for C-005: entrypoints → preload → IPC → deep-link handler → triage signal. |
| `offensive-macos-hunt-url-scheme-hijack` (session 2) | Correct fit for C-005's `rocketchat://auth` primitive. |
| `offensive-macos-foundations-macho` (session 2) | Used to reason about `@rpath/Electron` being a dynamically-loaded framework (Helpers can't carry TCC code) and fn-ptr table interpretation (ObjC IMP table structure). |

### Skills that should have fired but didn't (or did only late)

| Skill | Missed opportunity |
|-------|--------------------|
| `offensive-macos-foundations-macho` | Universal-binary slice selection issue hit during Electron Framework extraction. Solved from memory (`lipo -thin`) rather than by reading the skill first. Skill covers fat-header layout + slice extraction directly. |
| `offensive-macos-agent-discipline` | The 2-hour swap-thrashing episode is exactly the failure-taxonomy / "I'm stuck" case this skill targets. Didn't invoke. Would have forced earlier diagnosis of `sysctl hw.memsize` vs heap size. |
| `offensive-macos-family-tcc-heavy-apps` | The target-family playbook for Rocket.Chat. Should have driven sweep ordering explicitly (main exec → Electron Framework → Helpers → Login Helper). We did the right ordering anecdotally. |
| `offensive-macos-hunt-tcc-prompt-attribution` | The actual bug class being hunted. Should be the primary reference for triage priorities during candidate creation. Haven't reached triage yet, so not a failure — but flag for the next phase. |
| `offensive-macos-station-topology` | MCP-vs-SSH-fallback transport decision point. Would have caught the SSH ControlMaster gap. |
| `offensive-macos-watch-static-analysis` | The decision layer that turns intake + first-pass static facts into recommended recipes. The Electron Framework → Helper pivot hinted at by CORPUS.md "Coverage Gaps" was this skill's job; I reached the same conclusion manually. |
| `offensive-macos-vuln-ontology` (session 2) | Invoked only after TCC-native negative result, for the pivot gate. Should have run earlier — the entitlement-list dump alone (`application-groups`, `automation.apple-events`, `CFBundleURLSchemes`) was enough at intake to generate the ontology-hypothesis list before any Ghidra work. Would have surfaced C-005 as a hypothesis on day 1. |
| `offensive-macos-maproom-recipes` (session 2) | Never consulted. The maproom's recipe layer is the exact mechanism for "given dossier facts, which scanners + skills to run in what order" — i.e. the missing layer that allowed 86 minutes of Ghidra to happen when `offensive-macos-vuln-ontology` could have predicted the null result from intake. |
| `offensive-macos-poc-authoring` (session 2) | Queued correctly via task #9; not yet time-gate-appropriate. But its inputs (lab-state preparation, harness scaffolding) will matter for C-005 confirmation — the skill should fire the moment task #9 starts. |

### Skills correctly unused

`offensive-macos-hunt-iokit-userclient`, `offensive-macos-hunt-mig-subsystem`, `offensive-macos-hunt-wrong-door`, `offensive-macos-hunt-catalyst-porting-gap` — none match Rocket.Chat's surface. `offensive-macos-submission-packet` — correct phase gating; nothing report-ready yet.

**Flagged for revisit (session 2 reclassification):**
`offensive-macos-hunt-keychain-access-group` — was listed "correctly unused" in session 1. It should have fired: the intake dossier's entitlement dump shows `application-groups = S6UPZG7ZR3.chat.rocket`, which is a valid keychain access-group identifier. We should check whether Rocket.Chat stores credentials under this group and whether ACLs are pinned. Moved from "unused" to "missed opportunity — session 3 priority." See "Places we could be missing vulns" §keychain.

### Discipline improvement: explicit skill enumeration at intake

**Shortcoming:** agents name skills in prose but don't invoke them as active guidance. Implicit use = unreliable use.

**Fix:** intake template (dossier + HANDOFF) should carry an **"Active skills for this target"** field populated at intake time. Forces the agent to enumerate applicable skills upfront and reference them by name during sweep/triage phases. Low-cost, high discipline dividend.

Proposed addition to the target-intake recipe / `start-target.py` output:

```
Active skills (inferred from family labels + target surfaces):
- offensive-macos-family-tcc-heavy-apps   (privacy permissions detected)
- offensive-macos-family-privileged-helpers  (LoginItem + SMJobBless surface)
- offensive-macos-family-developer-tools     (Electron + plugin surface)
- offensive-macos-hunt-tcc-prompt-attribution (bundle-identity ambiguity)
- offensive-macos-foundations-macho          (universal binary handling)
```

Every skill named here should then be cited by ID in at least one CHRONICLE entry during the pass, giving a traceable audit of skill-guided decisions.

---

## Places we could be MISSING vulns (PASS-001)

The most important shakedown section. Each bullet is a surface PASS-001 either didn't cover, covered shallowly, or covered through tooling that has known blind spots. Each is a call to change the station — add a scanner, add a skill, add an intake column — so the next target gets coverage the Rocket.Chat pass didn't.

### Universal-binary: we only scanned arm64

The TCC-native negative result ("no `SecTaskCreateFromAuditToken` anywhere") is **only** a statement about the arm64 slice of Electron Framework. The x86_64 slice was never extracted, never imported into Ghidra, never scanned. Rocket.Chat ships universal — an x86_64-only bug in the Electron Framework code path (compiler-specific ifdef, arch-specific hardening miss) would slip through.

**Fix:** `ghidra-scan.sh` should either (a) scan both slices by default when the input is universal, or (b) loudly warn and require the operator to opt in to arm64-only. Current behavior is silent arch selection via pre-slice.

**Station change:** new shakedown item 29.

### Chromium/V8/Blink internals in Electron Framework are unscanned

We scanned Electron Framework arm64 for **anchor kinds we asked about** (SecTask*, AVCapture*, TCC_*, etc.). We did **not** scan for:

- Chromium IPC messages that cross renderer→browser process boundaries (`mojo::*`)
- V8 sandbox / `ArrayBuffer` backing-store confusion
- Blink serialization bugs (postMessage, SharedArrayBuffer)
- Chromium's own sandbox escape surface (specific to the chromium version embedded in Electron 32.x)
- CVEs known-fixed in later Electron versions that this Rocket.Chat pins-old on

Electron 32 inherits any pre-fix Chromium RCE. We never correlated Rocket.Chat 4.13.0's `electron` dep version against known CVEs. A renderer RCE chain through a **known** Chromium bug would be the highest-impact finding in this app, and we didn't look.

**Fix:** new skill or scanner — `offensive-macos-hunt-electron-version-cve` — that takes an Electron version and enumerates `chromium-security-advisories.json` entries for that range. Lives upstream of ontology; fires on every Electron-labeled target.

**Station change:** new shakedown item 30.

### contextBridge exposed APIs audited statically, not dynamically

Preload exposes `JitsiMeetElectron`, `RocketChatDesktop`, `videoCallWindow` to the renderer. I found the names this session; I did not audit what each API exposes, whether arguments are type-checked before reaching the main process, whether `exposeInMainWorld` is called with `contextIsolation: true` context (i.e. is the bridge actually isolated or does it leak via a shared prototype).

If the preload does `exposeInMainWorld('RocketChatDesktop', { run: (cmd) => childProcess.exec(cmd) })` even as a "dev" helper, that is renderer-to-shell RCE with minimal renderer compromise needed. We haven't checked. Task #8 is queued but is the one most likely to produce a bug bigger than C-005.

**Fix:** make IPC/contextBridge audit a **default** step in `offensive-macos-electron-surface-pack`, not a "maybe later" queued task. The static scan is cheap: one grep + 10 min of reading.

**Station change:** update SKILL.md for `offensive-macos-electron-surface-pack` to require Step 2's "preload / IPC surfaces" line to carry at least one grep result even in the absence of a concrete concern.

### Electron fuses never checked

`npx @electron/fuses read --app Rocket.Chat.app` in 5 seconds reports whether `RunAsNode`, `EnableNodeCliInspectArguments`, `OnlyLoadAppFromAsar`, `EnableEmbeddedAsarIntegrityValidation`, `GrantFileProtocolExtraPrivileges`, `LoadBrowserProcessSpecificV8Snapshot` are set. Any one of these being wrong can convert "renderer bug" into "full RCE" or "any read primitive → code loading". We never ran the command. Queued as task #5.

**Station change:** fuses check becomes a mandatory intake step for any Electron-labeled target, not a post-intake task. Add to `offensive-macos-bundle-intake` recipe.

### Sparkle-framework absence means Electron's built-in autoUpdater — untested

`app-update.yml` shows `electron-updater` via GitHub provider. electron-updater's default trust model is:
- HTTPS to GitHub Releases
- Signature verification via codesigning on macOS (only if `provider: github` + `publisherName` matches)
- No default pinning of publisher identity

If `publisherName` is unset in the app's build config, electron-updater accepts any signed binary. If the app runs with `SecPolicyCreateBasicX509` vs `SecPolicyCreateAppleIDSSLService`, cert-chain differences matter. We haven't read electron-updater's code in `app.asar.unpacked/node_modules/electron-updater/` to understand what Rocket.Chat actually signs against.

**Station change:** new skill `offensive-macos-hunt-electron-updater-trust` — or an addition to `offensive-macos-family-privileged-helpers` that covers the electron-updater trust model specifically. Fires on any target with `app-update.yml`.

### Native `.node` modules never audited

`fsevents.node` is the only `.node` shipped. It's a standard node-fsevents binding and historically uncontroversial. But in general, a Mach-O shipped inside `app.asar.unpacked` **runs in the renderer or browser process with full node privilege**, bypasses codesign-validation of the main .app at dlopen time, and has been a root-cause for past Electron CVEs. Our current TCC sweep script would happily scan a `.node` module if told to, but no skill or recipe says "enumerate all `.node` modules in every Electron target, scan each with scan_tcc_prompt_surface + scan_private_framework_dependency".

**Station change:** add a scan target enumeration step to the Electron surface-pack: every `**/*.node` under `app.asar.unpacked` gets queued as a scan target with a T-00N id.

### Keychain-access-groups entitlement signal not pivoted

Main-app entitlements include `application-groups = S6UPZG7ZR3.chat.rocket`. This **is** a valid keychain access group. We did not check whether Rocket.Chat actually stores credentials in the keychain under this group, nor whether the group's ACLs pin to the code-signing identity. If the app stores a login token under a keychain item with ACLs that allow any app signed by team `S6UPZG7ZR3`, any other S6UPZG7ZR3-signed app can read it — even if sandboxed differently. Classic confused-deputy.

**Fix:** the intake dossier should surface `com.apple.security.application-groups` as a signal that triggers `offensive-macos-hunt-keychain-access-group` by default. It didn't for this pass.

**Station change:** update `offensive-macos-bundle-intake` to emit "trigger signals" based on entitlement values, not just family labels.

### AppleScript / Automation surface ignored

Entitlements include `com.apple.security.automation.apple-events`. This is privileged — the app can send AppleEvents to control other apps (Mail, Finder, etc.) with user consent. We did not check whether Rocket.Chat uses this for anything user-controllable (e.g., "paste clipboard to a specific app" via IPC). An IPC handler that takes an AppleEvent target from the renderer would be a renderer → arbitrary-app-control pivot.

**Station change:** include `com.apple.security.automation.apple-events` in the ontology's "trigger signals" list.

### No dynamic confirmation done this pass

Every candidate C-001 through C-005 was ruled in or out by **static reading**. We have not actually launched Rocket.Chat.app, not attached lldb, not run DTrace on a single syscall. If `performAuthentication` branches differently at runtime (feature flags, environment variables, A/B test from `electron-store`), static reads miss it. A prudent pass runs the target at least once in a controlled lab with DTrace on `execve` / `loadURL` / `open-url` to confirm static findings.

**Station change:** make "one clean dynamic baseline run" a pre-candidate-creation step in `offensive-macos-agent-discipline`. One DTrace script capturing the first 60 seconds of the app's life should be mandatory before declaring any static finding "understood".

### Shipped patch-level not diffed against previous versions

Rocket.Chat ships a CHANGELOG; we saw one entry mentioning a deeplink fix (`#2160: Removes rid param/conditional to fix deeplink`). We never diffed 4.13.0 against 4.12 or 4.11 to see what they've recently **hardened** — a list of hardened areas is a list of previously-exploitable areas, and often what they hardened is incomplete. This is the standard "n-day hunt" pattern and we didn't do it.

**Station change:** add `offensive-macos-hunt-recent-patches` — a skill that, given a target with public source, pulls the last N releases' changelogs + commit logs for security-sounding keywords and produces a candidate hypothesis list.

### The Helpers got a 30-second scan

Our Helper-sweep decision was correct on the narrow question ("do these stubs carry TCC surface themselves"). It was **too fast** on the wider question ("are the Helpers interesting at all"). A Helper's `Info.plist` can claim privileges its parent doesn't; a Helper with `LSBackgroundOnly` and `NSAppTransportSecurity.NSAllowsArbitraryLoads` would be interesting. I never read Helper Info.plists. The entitlement dump I did showed identical entitlements across the 4 Chromium Helpers, but I didn't dump their Info.plist for non-entitlement keys.

**Station change:** `offensive-macos-bundle-intake` should dump each Helper's Info.plist fully, not just the entitlements. Short diff between Helpers reveals interesting asymmetries.

---

## SSH Transport — persistent connection vs per-command

### What we observed

Every ad-hoc `ssh NightBlood '<command>'` opens a fresh TCP connection and completes a full SSH handshake (~200-500 ms each). During PASS-001 the agent ran this pattern dozens of times (polling Ghidra progress, checking disk / memory, tailing logs). Cumulative overhead: minutes.

The MCP path is *not* affected — `ghidra-mcp` and `macre-vm-mcp` each hold a single persistent SSH connection for the session lifetime. Only the ad-hoc Bash-tool ssh usage pays the cost.

### Fix

Add to `~/.ssh/config` on the workstation (one-time, zero code change):

```
Host NightBlood
    ControlMaster auto
    ControlPath ~/.ssh/cm-%r@%h:%p
    ControlPersist 10m
    ServerAliveInterval 30
```

First ssh opens a master connection and holds it for 10 minutes idle. Every subsequent `ssh NightBlood '...'` within that window reuses it (sub-10 ms). Safe, transparent, no changes to scripts or MCP config.

### Document it where?

- `Skills/offensive-macos-station-topology` should publish this as expected station SSH config.
- `scripts/install-vm-ssh-key.sh` could emit the ControlMaster stanza into `~/.ssh/config` as part of setup (check first; don't clobber).

### What *not* to do

Don't try to hold an interactive `ssh NightBlood` session and pipe commands into it. Brittle for long-running ops (loses stdout on disconnect), worse than ControlMaster in every way.

---

## Progress Visibility

### Problem

Ghidra's auto-analysis on a 177 MB binary emits < 1 stdout line per minute once past the initial import. "Making progress" and "deadlocked" are visually identical over SSH. Today's PASS-001 wasted most of 2 hours on swap thrashing that looked healthy from log output alone.

### What would have caught it sooner

**Lab-host-side poller** (`ghidra-watch.sh`) that emits a concise heartbeat every 60 s:

```
ts=2026-05-11T14:45Z
  phase=ANALYZING (ApplyDataArchiveAnalyzer)
  cpu=147% rss=4.2g
  db_size=18MB  (growing: +6MB since last poll)
  errors_cumulative=1524 warns=1298
  swap_used=1.9g / 3.0g   ← RED FLAG if non-zero on a dedicated lab VM
  script_started=no
  anchor_rows=0
```

A couple of derived heuristics flag trouble automatically:

- `swap_used > 0` on a dedicated lab VM → heap too large for physical RAM. Kill + retry.
- `db_size` flat across 3 consecutive 60s polls → analyzer deadlock or I/O stall.
- `cpu < 10%` AND `script_started=no` → analyzer has finished cleanup but script hasn't started yet (check exit, probably done).

**Script-phase heartbeat** in `_re_lib`:

Add a stderr line every N processed callsites inside `enrich_callsite_args` and `enrich_objc_msgsend`:

```
[_re_lib.enrich_objc_msgsend] processed 4000 / ~50000 callsites (selector_hits=12)
```

Small patch. Prevents "the scan hung" anxiety for decomp-heavy scans.

### Good-thing: persistent project

Once the DB commits (first run), subsequent scans use `-process <bin> -noanalysis` and complete in seconds. The first run hurts; every follow-up is cheap. Keep the pattern.

---

## VM Sizing Guidance

### Observed on PASS-001

| Config | Result |
|--------|--------|
| 4 GB RAM, 2 cores, `-Xmx12g` | Swap thrashed for 2+ hours. Useless. Killed. |
| 16 GB RAM, 8 cores, `-Xmx10g` | Clean run. RSS peaked ~4 GB. Zero swap. Still CPU-bound at ~1.5 cores during serial analyzer phases. |

### Recommendations by role

| Lab host role | vCPU | RAM | Disk | Rationale |
|---------------|------|-----|------|-----------|
| Smoke-test / small binaries | 2 | 4 GB | 60 GB | Enough for main execs, helpers under ~10 MB. Not for Apple frameworks or Electron bodies. |
| Primary (Electron, consumer apps) | 8 | 16 GB | 256 GB | Survives 100-200 MB Mach-Os. Headroom for persistent projects across 5-10 targets. |
| Primary (Apple framework + dyld cache extraction) | 8 | 32 GB | 512 GB | Apple framework analyses need more heap; cache extracts eat disk fast. |
| Crash-test | 4 | 8 GB | 128 GB | Dynamic-only; never runs Ghidra. Runs lldb, dtrace, sample PoCs. |

### Heap sizing rule

`-Xmx = physical_ram_gb - 6`. The 6 GB budget covers OS + MCP servers + APFS compressor + headroom for bursts. On a 16 GB VM, `-Xmx10g`. On a 32 GB VM, `-Xmx24g`.

This is encoded in `scripts/ghidra-scan.sh` as a comment on the `HEAP_SIZE` default. Consider making it a preflight check that reads `sysctl hw.memsize` and warns if `MACRE_GHIDRA_HEAP` violates the rule.

### Were the 8 CPUs worth it on PASS-001?

**Partly.** Serial analyzer phases (decompile-switch-analyzer, function-body repair, data-type-archive application) only use 1 core. Parallel phases (function discovery, string walkers, some propagation) scale. Net: 4 cores would have been the sweet spot for *this single-binary workflow*.

**The 8 cores earn their keep once you fan out** — concurrent Helper sweeps, lldb attach during DTrace capture, parallel Ghidra projects. Keep 8; don't downsize.

---

## Host vs Lab-host offloading

### Rule

**If it needs Ghidra, it runs on the lab host.** If it's 2-second CLI static inspection, the workstation is fine.

### Why not run Ghidra on the workstation

1. **Host contamination.** The lab-host is disposable specifically so we can trust its state. Ghidra on the workstation breaks the "blast radius is the VM" contract.
2. **Tool parity.** `ghidra-headless-mcp`, `_re_lib` patches, `ghidra-scan.sh` all live on the lab host. Running on the workstation means maintaining two copies of everything.
3. **Evidence reproducibility.** Findings cite `NightBlood:/Users/szeth/ghidra-projects/<project>/<target>.gpr`. Mixing workstation-analyzed and VM-analyzed project files confuses provenance.

### What is fine on the workstation

- `otool`, `codesign`, `lipo`, `class-dump`, `jtool2`, `dyld_info`, `plutil` (covered by `offensive-macos-tooling-cli-static`)
- ASAR unpacking, source-binary correlation grepping, Electron source tree reads
- TSV triage, candidate JSON authoring, evidence copy-in

---

## Scripts to add (backlog)

| Script | Purpose | Size |
|--------|---------|------|
| `scripts/ghidra-watch.sh` | 60-s poller that emits one-line status (phase, cpu, rss, db_size, errors, swap, script-started, anchor-count) against a running scan. Replaces ad-hoc ssh polling. | ~30 lines |
| `scripts/lab-health.sh` | Session-start orientation: `df`, `vm_stat`, `sysctl vm.swapusage`, `hw.memsize`, `hw.ncpu`, running java procs. Also usable as the 5-GB-free tripwire. | ~20 lines |
| `scripts/slice-binary.sh` | Pre-slice universal Mach-Os; emit sha256 + size for evidence. Standardizes the `lipo -thin` step we keep doing manually. | ~20 lines |
| `scripts/ghidra-scan-preflight.sh` | Called by `ghidra-scan.sh` before launching. Checks: physical RAM vs heap, free disk vs binary size, PyGhidra availability, ghidra-scripts path. Refuses to run if any fail. | ~40 lines |

Each belongs in `skillz/scripts/` and mirrored to `NightBlood:~/bin/` on install via `install-ghidra-host.sh` (or equivalent deploy step).

---

## Good-thing list (patterns worth keeping)

- `_re_lib.py` design (shared helpers, tier A/B/C contract, capped indices, idempotent binder).
- TSV output contract (`target, tier, anchor_kind, name, address, evidence`). Stable, triage-friendly, pipes cleanly into `scripts/triage.py`.
- Persistent Ghidra project pattern (`ghidra-scan.sh` drops `-readOnly`). Pays off from scan #2 onward.
- Lab topology: MCP over SSH, disposable VM, persistent stdio transport. Correct architecture. Only the ad-hoc Bash SSH pattern needs optimization (ControlMaster).
- Environment-hardening discipline: when the empty-TSV happened, the response was to fix the env first (three stacked issues diagnosed + patched) rather than work around it. That's the right instinct.
- Handoff artifact shape (REPO_MODE, CORPUS.md, CHRONICLE.md, INDEX.md, HANDOFF.md) — survived session boundaries and token-limit events on PASS-001 without evidence loss.

---

## Operator decision log (PASS-001)

- `lab_disposable: true` confirmed; agent snapshots before destructive actions, escalates ambiguous cases.
- PoC authoring + exploitation in scope for Rocket.Chat pass.
- Patched-version pull deferred — gated on env health + zero operator dev work.
- Shared dyld cache extraction: on-demand per candidate, not upfront. Station default is app-side analysis only.
- VM resized mid-pass from 4 GB → 16 GB RAM, 2 → 8 cores, 60 GB disk kept (tight; resize with next maintenance window). Disk-resize threshold: 5 GB free triggers operator action.

