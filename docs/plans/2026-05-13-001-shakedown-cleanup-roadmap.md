# 2026-05-13-001 — Shakedown Cleanup Roadmap

> **Scope.** Immediate-fix roadmap for finishing out `SHAKEDOWN_NOTES.md`
> backlog plus the small set of cross-cutting environment improvements
> surfaced during the 2026-05-11 → 2026-05-13 PASS-001 / env-fix arc.
>
> **What this is not.** This does **not** override `docs/plans/2026-05-07-001-feat-macos-os-component-hunting-plan.md`. That plan is about analytical coverage (which targets, which bug classes, which skills). This plan is about environmental quality (the station's substrate). They are orthogonal — finish this and the os-component-hunting plan becomes faster to execute.
>
> **Source of truth for backlog.** `SHAKEDOWN_NOTES.md` at the repo root. Each item carries a `Fix status` column. Update the column in the same commit that ships the fix; never separate the work from the status.
>
> **Authoring convention.** New items get appended with absolute date (e.g. `2026-05-13`-style). Don't renumber existing items.

---

## Phase 0 — Stale-status reconciliation (do this first; ~10 minutes)

The current `SHAKEDOWN_NOTES.md` table contains at least two items whose code-side fix has already shipped but whose status column still says "Not fixed." If you pick from the table without reconciling first, you may waste a turn re-implementing something. Audit before you start.

| Item | Reality | Action |
|---|---|---|
| #7 (df preflight in `ghidra-scan.sh`) | Shipped in commit `2d598a0` (`scripts/ghidra-scan.sh` lines 77-99: `MACRE_SKIP_DISK_PREFLIGHT` env override + 5 GB tripwire). | Update status to `shipped` with commit ref + date. |
| #26 (Bash 3.2 `${var,,}` portability) | Same commit `2d598a0` removed `${var,,}`; line 65 of `ghidra-scan.sh` now uses portable case logic. | Update status to `shipped` with commit ref + date. |
| #5 (heap default tied to VM RAM) | `partial`, but the user-facing piece (the `physical_ram_gb - 6` rule) is now documented in lab-roster skill + `ghidra-scan.sh` comment. The remaining gap is automated preflight check. | Decide: spin out preflight check as its own item, or close #5 with the doc and reopen as new item #29. |

How to do the audit:

```bash
# Spot-check shipped commits for items that touch each open item's "Where" column.
git log --oneline main -- scripts/ ghidra-scripts/ Skills/
grep -nF '${var,,}' scripts/ghidra-scan.sh   # confirm it's gone
grep -nF 'MACRE_SKIP_DISK_PREFLIGHT' scripts/ghidra-scan.sh   # confirm preflight exists
```

Ship Phase 0 as one tiny PR titled "shakedown-notes: reconcile stale fix-status entries" — a 4-line table edit. Don't bundle with Phase 1+.

**Why first.** A 10-minute reconciliation pass prevents the 30-60 minute wrong-direction sprint that would happen if the next agent saw "Not fixed" and re-shipped what's already there.

---

## Phase 1 — Quick wins (sized for one PR each, ~10-30 minutes apiece)

Each of these is a self-contained PR. They can be parallelized across sessions. **Order is not load-bearing.** Pick whichever item the next session has appetite for.

### 1A. Item #13 — `conv.md` to gitignored template

PASS-001 produced a `conv.md` per-session handoff artifact that wasn't in the project template's `.gitignore`. Risk of accidental commit.

**Where to fix.** `templates/repo/.gitignore` (or wherever `init-project.sh` sources its gitignore template — grep first to confirm path). Add `conv.md` and `conv-*.md`.

**Verification.** `scripts/init-project.sh` against a scratch dir; confirm `.gitignore` has the pattern.

### 1B. Item #15 — Document SSH keepalive as station policy

`ServerAliveInterval 30` already exists inside the MCP wrapper scripts but isn't documented. A long scan can drop on idle SSH otherwise.

**Where to fix.** `Skills/offensive-macos-station-topology/SKILL.md` — new "SSH Transport" subsection. Promote the existing inline keepalive value to documented policy. Cross-reference `~/.ssh/config` `ServerAliveInterval 30` + `ControlMaster auto` (item #12 below).

### 1C. Item #12 — `ControlMaster` documentation + station snippet

PASS-001 burned minutes on per-command SSH handshakes. `ControlMaster auto` + `ControlPersist 10m` solves it.

**Where to fix.** Two parts:
- `Skills/offensive-macos-station-topology/SKILL.md` — recommend the `Host NightBlood` stanza explicitly.
- Optional: a `scripts/install-ssh-controlmaster-stanza.sh` that idempotently appends to `~/.ssh/config` if missing. Don't auto-mutate the user's config without `--apply`.

Note: this is a workstation-side change. Don't ship a fix that mutates the user's `~/.ssh/config` without explicit opt-in.

### 1D. Item #16 — Ghidra log filter (subsumed by `ghidra-watch.sh`)

Already partially closed by item #10b. Action: update item #16's status to `subsumed by item #10b` (which shipped in commit `b6c47fb` per session log).

### 1E. Item #21 — Clean TSV emission from `ghidra-scan.sh`

Currently `ghidra-scan.sh` writes the script's stdout into a `.log`; the TSV is buried under `INFO ... > ... (GhidraScript)` wrappers. Operator has to post-process by hand.

**Where to fix.** `scripts/ghidra-scan.sh` — at exit, also emit a clean `.tsv` alongside `.log`:

```bash
sed -E 's/^INFO  [^>]+> //; s/ \(GhidraScript\) +$//' "$LOG_PATH" > "${LOG_PATH%.log}.tsv"
```

**Verification.** Run a known scan, diff the two outputs; the `.tsv` should pipe cleanly into `triage.py`.

### 1F. Item #23 — Path drift `~/tools/skills` vs `~/tools/skillz`

Decide once. Two paths:
- (a) `ln -s skillz skills` in `~/tools/`. Both names work for everything.
- (b) Document the canonical name (`skillz`) in `Skills/offensive-macos-station-topology/SKILL.md` and grep for stale `tools/skills` references in the repo.

Recommend (a) + (b) together. Trivial; ~5 minutes.

---

## Phase 2 — Scan-quality items (each ~30-90 minutes, contained code change)

These touch `ghidra-scripts/_re_lib.py` or specific scanners. They each solve a real source of false positives or coverage gaps PASS-001 surfaced.

### 2A. Item #17 — Drop bare `TCC` alternative from `tcc_string` regex

Current regex (in `ghidra-scripts/scan_tcc_prompt_surface.py`) matches `TCC` with `re.I` and produces 24/24 false positives on Electron Framework (matches `TCC` inside base64 PEM cert bodies).

**Fix.** Drop the `|TCC` alternative; keep the four specific forms (`TCCAccessRequest`, `kTCCService`, `com.apple.TCC`, `tccd`). Re-test against `rocket_chat/` artifacts in the gitignored read-only reference snapshot.

**Risk.** Low. Test against the rocket_chat reference repo, confirm zero hits on Electron Framework, confirm hits still appear in cfprefsd / tccd / Apple targets known to use the four-specific-forms.

### 2B. Item #18 — Truncate `text` column in `run_string_scan`

A single PEM cert hit on Electron Framework produced an 800 KB single TSV row because only the `evidence` column was capped. The `name`/`text` column was unbounded.

**Fix.** `ghidra-scripts/_re_lib.py` `run_string_scan` — truncate `text` to ~160 chars before passing to `writer.add(...)`. Keep the truncation symbol (`…`) on the trimmed end.

### 2C. Item #19 — Skip self-match rows in `callers_of(external_fn)`

PASS-001 produced spurious tier-A anchors where the "caller" was the external symbol's own thunk. Real bug class: import thunks are real `FunctionDB` entries.

**Fix.** `ghidra-scripts/_re_lib.py` (in `callers_of` or `enrich_callsite_args`) — skip rows where `caller.getName() == external_name` OR where the callsite address equals the thunk's own entry.

### 2D. Item #20 — Raise default index caps / auto-scale by binary size

Default `DEFAULT_MAX_STRINGS=20000`, `DEFAULT_MAX_FUNCTIONS=50000` get hit on Electron Framework / Apple-framework targets, capping tier-C coverage.

**Fix.** Two options:
- (a) Raise defaults to 50k / 100k (cheap; accepts longer scans on small binaries).
- (b) Auto-scale: `DEFAULT_MAX_STRINGS = max(20000, binary_size_mb * 200)` or similar.

Recommend (b) — better behavior across the size spectrum.

### 2E. Item #9 — `fast_mode` / `max_total_callsites` cap on `enrich_objc_msgsend`

On large Cocoa+Chromium binaries, `enrich_objc_msgsend` decompiles every `_objc_msgSend` caller before bucketing. Hundreds of thousands of decomps; multi-hour scan phase.

**Fix.** Expose `fast_mode=True` and/or `max_total_callsites=N` to the top-level `run_string_scan` invocation. Add a "target size > N MB → warn" heuristic to suggest fast_mode.

**Sequencing.** Do #9 *after* #20 — both touch the scanner top-level signature, and combining the parameter changes into one PR makes more sense than fanning out two contemporaneous churns to the same function.

---

## Phase 3 — MCP-shape items (~20-60 minutes each, may need lab host)

### 3A. Item #8 — Verify MCP `program.open(read_only=true, update_analysis=true)` semantics

`SKILL.md` Workflow A documents `read_only=true, update_analysis=true`. Empirically unclear: does the MCP backend persist the analysis DB despite `read_only=true`, or does it discard like the headless `-readOnly` flag does?

**Investigation steps.**
1. On the lab host, open a binary with `read_only=true, update_analysis=true`.
2. Run analysis; close session.
3. Re-open the *same* project; confirm whether function/symbol annotations from the first session persist.
4. If they discard: update `SKILL.md` to document `read_only=false`. If they persist: leave docs alone, but note the contradictory naming in `PATCHES.md` as a candidate upstream improvement.

### 3B. Item #22 — `project.program.open_existing` schema clarity

Tool description implies "reopen a named existing project" but actually requires `program_name` or `program_path`. Schema marks both optional → confusing error.

**Fix.** Choose one path:
- (a) Update the tool description (one-line server.py change in our downstream patch stack).
- (b) Make the tool accept an empty program and return the program list the caller can choose from.

Recommend (a) — smaller patch, ships into `PATCHES.md` as a docstring patch.

---

## Phase 4 — Items deferred or rejected (decision log)

These are tracked here so the next agent doesn't accidentally reopen them.

- **Item #11 — Universal Mach-O auto-slice in `ghidra-scan.sh`.** Documented. Auto-slice not implemented. Decision: keep deferred until a *second* universal-binary target stalls a hunt at this step. Premature implementation risks injecting silent slice selection (the same failure mode the comment warns against).
- **Item #28 — `app.asar` extract location decision.** Now answerable: per `Skills/offensive-macos-electron-surface-pack/SKILL.md` step 2, extract on the workstation (grep velocity). Lab host doesn't need it for static work; if dynamic JS inspection is ever needed, the lab host can extract on demand. Update item status to `shipped — workstation per skill doc` instead of leaving open.
- **HANDOFF.md (c) argv[0] tagging.** Rejected in favor of sidecar-based identification. See PR #8 description for reasoning. Don't reopen unless `lab-health.sh` proves insufficient on a future PASS.
- **Lock auto-cleanup in `lab-health.sh --remove-stale`.** Intentional design choice: only remove stale *sidecars*, never orphan project lockfiles. Lockfile cleanup stays manual so the operator inspects the project before deciding.

---

## Phase 5 — Cross-cutting environment improvements (not in the original SHAKEDOWN table)

These are gaps the 2026-05-11 → 2026-05-13 work surfaced *outside* the numbered backlog.

### 5A. Add new SHAKEDOWN items for the 2026-05-13 surfaces

Append the following to `SHAKEDOWN_NOTES.md` as items #29-#33 (next free numbers):

- **#29 — Universal Mach-O auto-slice scan.** Same as item #11 in spirit but reframed: scanners should default to scanning *both* slices on universal binaries, not silently picking one. Belongs in the universal-binary handling layer of `ghidra-scan.sh`.
- **#30 — `npx @electron/fuses read` at intake for Electron targets.** Fuses surface (ASARIntegrity, RunAsNode, NodeOptions) is currently never inspected. Mandatory step in `offensive-macos-electron-surface-pack` SKILL.md.
- **#31 — Mandatory IPC/contextBridge audit step in electron skill.** PASS-001 audited statically (preload.js read), never dynamically. Add a "for each contextBridge.exposeInMainWorld call, identify the IPC channel + risk" step.
- **#32 — Native `.node` modules enumeration step.** PASS-001 didn't enumerate `**/*.node` modules under `app.asar.unpacked`. Add as a step to electron skill.
- **#33 — Auto-trigger `offensive-macos-hunt-keychain-access-group` on `application-groups` entitlement.** PASS-001 missed this signal at intake.

After appending, write a short skill update wherever each item's "Where" column points.

### 5B. New skills proposed (each its own SKILL.md)

These are *capability gaps*, not item-fixes. Each is a standalone skill addition.

- **`offensive-macos-hunt-electron-version-cve`** — Map Electron version → bundled Chromium version → known Chromium CVEs in that version range. Most Electron apps lag Chromium upstream by months; this is a high-leverage n-day surface.
- **`offensive-macos-hunt-electron-updater-trust`** — Squirrel.Mac / built-in autoUpdater trust model audit. Sparkle is well-covered; Squirrel isn't.
- **`offensive-macos-hunt-recent-patches`** — N-day from public source + changelog. Diff target version against latest, look for security-flavored commit messages, score based on patch density.

### 5C. Snapshot-management story

`LAB_SAFETY.md` says "Operator manages VM snapshots" but the agent has no documented mechanism to take one. As a result, "snapshot before destructive action" is currently a manual operator gate, not an agent-runnable step. Item to investigate: integrate a snapshot tool (tart for Apple Silicon? UTM CLI?) so the agent can self-snapshot on the lab host before destructive moves. Defer until a *destructive PoC* is queued — it's not blocking right now, but will become blocking when PoC harness work begins (item #2 of `2026-05-07-001-feat-macos-os-component-hunting-plan.md`).

### 5D. Disk-reclaim-on-VM-grow procedure

The 2026-05-13 session documented that growing the lab VM's host-side disk doesn't auto-reclaim into the guest because Recovery (`disk0s3`) sits between data (`disk0s2`) and free space. Add a `docs/playbooks/lab-vm-disk-reclaim.md` capturing the diagnosis, the three resolution paths (sacrifice Recovery / reformat-restore / accept smaller container), and the snapshot-before-resize discipline.

### 5E. SSH `~/.ssh/config` host-by-name (not host-by-IP)

PASS-001 follow-up surfaced that `Host NightBlood` pins to `HostName 10.0.0.140`. After a VM reboot/disk-resize, the IPv4 lease can stall while mDNS still resolves. Recommend `HostName szeths-virtual-machine.local` as the durable form. **Defer** until you observe the failure mode again (it didn't reproduce in the 2026-05-13 session after the VM came back up).

### 5F. `install-ghidra-host.sh` auto-applies the patch stack

Currently, `install-ghidra-host.sh` clones upstream `ghidra-headless-mcp` at the pinned commit but does **not** auto-apply our downstream patches (`pyghidra-script-stdout.patch`, `pid-tagging-and-shutdown.patch`). Operator must apply manually. Action: extend the install script to apply every `*.patch` in `Skills/offensive-macos-tooling-ghidra-headless/` after checkout. Idempotent (use `git apply --check` to skip already-applied patches).

**Risk note.** This expands the install script's blast radius. Test on a fresh provisioning, not on the live lab host.

---

## Phase 6 — Maintenance items (low priority, opportunistic)

- **`HANDOFF.md` rotation.** The current `HANDOFF.md` documents the 2026-05-13 state. After Phase 0 + Phase 1 land, regenerate `HANDOFF.md` to reflect the new state. Don't accumulate handoffs; replace.
- **Memory hygiene.** `~/.claude/projects/-Users-bwt-tools-skillz/memory/MEMORY.md` should grow a `pass-001-shutdown-cleanup` entry capturing the sidecar/lab-health pattern, so future sessions don't rediscover it.
- **Skill-discoverability audit.** Several PASS-001 retro entries flagged skills that "should have fired but didn't" (`offensive-macos-foundations-macho`, `offensive-macos-vuln-ontology`, `offensive-macos-watch-static-analysis`, `offensive-macos-maproom-recipes`). Audit each skill's `trigger_phrases` against the actual phrases an operator types. The lab-roster fix (PR #6) added `VM sizing` / `how much RAM` / `Ghidra heap` for exactly this reason.

---

## Sequencing recommendation

Roughly this order, but each phase is optional and can be re-ordered:

1. **Phase 0** (status reconciliation) — first, always.
2. **Phase 1A-1F** (quick wins) — knock out 2-3 in one session.
3. **Phase 5A** (append new SHAKEDOWN items) — formalizes the unnumbered backlog.
4. **Phase 2A-2D** (scan quality) — biggest leverage on the next PASS's signal-to-noise.
5. **Phase 5F** (install-script patch auto-apply) — pays back every fresh-provisioning.
6. **Phase 3A-3B** (MCP shape) — needs lab host, so batch.
7. **Phase 5B** (new skills) + **Phase 2E** (`fast_mode`) — bigger investments, do last.
8. **Phase 5C-5E** (cross-cutting) — opportunistic.

Don't try to ship all of this in one session. The previous session shipped 4 PRs across an arc; aim for 2-4 PRs per session at this granularity.

---

## Branch + PR conventions (carry-over)

- Each phase item gets its own branch: `feat/shakedown-<item-num>-<slug>` or `feat/<scope>-<slug>`.
- One logical PR per item. Don't bundle.
- `SHAKEDOWN_NOTES.md` status update lands in the same commit as the fix, not a separate commit.
- Per global CLAUDE.md: `gh pr merge` requires explicit operator go-ahead each time. Push and open the PR; wait for the operator.
- Per global CLAUDE.md: never `--no-verify`, never amend a published commit.

---

## Appendix — Quick lookup of fixed-vs-open as of 2026-05-13

**Shipped** (closed in PR #5/#6/#7/#8 or earlier):
#1, #2, #3, #4, #5 (partial), #6 (partial), #7 (status-stale), #10a/b, #12 (status-stale), #14, #15 (partial), #17 (status — TBD-confirm), #18-19 (status-TBD), #24, #25, #26 (status-stale), #27.

**Open / verified open as of 2026-05-13**:
#8, #9, #11, #13, #16 (subsumed), #20, #21, #22, #23, #28.

**Open / proposed (this roadmap)**:
#29, #30, #31, #32, #33.

If Phase 0's reconciliation moves any item between columns, update this appendix in the same commit so the roadmap stays current.
