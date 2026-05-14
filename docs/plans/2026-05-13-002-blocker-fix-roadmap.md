---
title: "Reviewer-mode Blocker Fix + Re-review Roadmap"
type: roadmap
status: active
date: 2026-05-13
origin: HANDOFF.md (post-Session-6 reviewer verdict — CONDITIONAL PASS)
---

# Reviewer-mode Blocker Fix + Re-review Roadmap

## Why this exists

Session 6 ran a corporate-style reviewer pass on the station and
returned **CONDITIONAL PASS** scoped to Electron consumer-app PASS-002.
Four blockers were enumerated. This roadmap turns those blockers into a
five-session arc that ends with a *second* reviewer pass — this time
with a def-con-style RE persona scornful of process ceremony, grading
the substrate on its ability to find 0-days rather than on its
documentation cleanliness.

This plan does **not** override
`docs/plans/2026-05-07-001-feat-macos-os-component-hunting-plan.md`.
That plan is about analytical coverage. This one is about getting the
substrate from "merged but inactive" to "actually finding bugs."

**Source of truth for blocker rows:** `HANDOFF.md` post-Session-6
version. Each session below updates that file in place; do not
accumulate handoffs.

## Sequencing rule (carry-over from Sessions 4–6)

- One PR per blocker where a PR applies.
- Status updates land in the same commit as the fix.
- HANDOFF.md regenerated at the end of every session, never bundled
  with a code commit.
- `gh pr merge` is operator-typed only — every session ends by handing
  the merge to the operator and pausing.
- After merge, the *next* session opens by `git fetch && git pull` +
  `lab-health.sh` to confirm state matches HANDOFF before doing any new
  work.

## The arc

| Session | Subject | Closes | Has a PR? | Operator action at end |
|---|---|---|---|---|
| 7 | Pull + install patch stack + cycle PID 1515 + verify | Blocker 1 | No (runtime change, not code) | Operator types `kill -TERM 1515`; agent has nothing to merge |
| 8 | PATCHES.md doc-rot fix + orphan lock cleanup | Blockers 3 + 4 | One PR for #3; lab `rm` for #4 | Operator types `gh pr merge <N>` + the `ssh ... rm` line |
| 9 | Reviewer-prep run: Microsoft Office + CVE-2025-31191 surface mapping | (none — rehearsal) | One PR if substrate tweaks fall out, otherwise none | Operator merges any tweak PR; reviews the dry-run findings repo |
| 10 | Def-con reviewer pass | (verdict only — no code) | No | Operator reads verdict; if FAIL, loop on whatever it surfaced; if PASS, schedule PASS-002 |
| 11+ | PASS-002 (real CVE rediscovery) **or** loop on Session 10 blockers | — | — | — |

Blocker 2 (HANDOFF.md drift) closes implicitly: every session regenerates
HANDOFF, and Session 7 will the first one whose regen reflects post-pull
state. No separate session for it.

## Session 7 — runtime catch-up (Blocker 1)

**Goal.** Get the lab-host MCP runtime to the same state as `origin/main`.
PR #20's universal-Mach-O gate and PR #16's `open_existing` extended
docstring become live. Verify all three observable signals: gate fires,
catalog text updated, sidecar JSON populated.

**Pre-conditions.** Operator has not yet typed `kill -TERM 1515`. Local
working tree is on `main` (one commit behind `origin/main`).

**Steps.**

1. `git fetch origin && git pull --ff-only origin main`. Confirm
   `Skills/offensive-macos-tooling-ghidra-headless/refuse-universal-macho.patch`
   is now tracked.
2. Run `scripts/install-ghidra-host.sh --install`.
   - Watch for `OK applied patch: refuse-universal-macho.patch` and
     `OK applied patch: open-existing-docstring.patch`.
   - If either says "already applied," that's also fine (idempotent).
   - If the script exits 3 ("cannot apply patch — working tree drifted"),
     **stop**, escalate to operator with the diff, do not force.
3. Stop and tell the operator: **"Type `ssh NightBlood 'kill -TERM
   1515'` when you're ready. The next MCP call will bring up a fresh
   process with all 4 patches loaded."**
4. After the operator confirms the kill, exercise three live probes
   from the agent:
   - `program.open` against `/bin/echo` (universal). Expect
     `GhidraBackendError` mentioning `lipo -thin`. Negative result =
     gate works.
   - `tools/list` for `project.program.open_existing`. Expect the
     extended description from PR #16 ("Requires `program_name` or
     `program_path`...").
   - `scripts/lab-health.sh`. Expect "live MCP sessions" section to
     populate with the new PID's sidecar JSON.
5. Regenerate HANDOFF.md with: new `main` HEAD, new lab-host PID,
   patch states all `applied`, blockers 1+2 closed, the Session-8
   opener inline.
6. Tell the operator: **"Session 7 done. No PR to merge. HANDOFF.md
   regenerated. Start Session 8 with the opener at the bottom of
   HANDOFF.md."**

**Risks.**
- PID cycle drops in-flight MCP work. Mitigation: end-of-session timing
  is operator-chosen.
- `install-ghidra-host.sh` could exit 3 if the on-disk editable tree
  diverged from upstream in some way the dual-probe doesn't recognize.
  Mitigation: exit-3 path stops the session, doesn't force.

## Session 8 — doc rot + orphan lock (Blockers 3 + 4)

**Goal.** Land the PATCHES.md doc-rot fix as a small PR. Tell the
operator to `rm` the orphan `wave2-smoke.lock`. Confirm both with
follow-up greps / `lab-health.sh`.

**Pre-conditions.** Session 7 closed; lab-host runtime is patched;
HANDOFF.md reflects post-Session-7 state.

**Steps.**

1. Branch `feat/shakedown-cleanup-patches-md-doc-rot`.
2. Edit `Skills/offensive-macos-tooling-ghidra-headless/PATCHES.md`
   "SSH-fallback wrapper" section:
   - Change `-Xmx12g` → `-Xmx10g`.
   - Replace the "wrapper does not auto-slice" paragraph with a
     one-paragraph summary of PR #14's behavior (lipo-info detect,
     per-slice extract, serial scan, worst-rc-wins, exit code 7).
   - Drop the "Verify with the pinned ghidra-headless-mcp semantics"
     open question; replace with a one-line pointer to SKILL.md
     `## Mutability Semantics`.
3. Verify with grep — these strings should return no hits in
   `PATCHES.md`:
   - `Xmx12g`
   - `does not auto-slice`
   - `Verify with the pinned`
4. Commit with status update; push branch; open PR.
5. Tell the operator: **"Type `ssh NightBlood 'rm -f
   /Users/szeth/ghidra-projects/wave2-smoke.lock
   /Users/szeth/ghidra-projects/wave2-smoke.lock~'` to close Blocker 4.
   Then type `gh pr merge <N> --merge --delete-branch` to land Blocker 3."**
6. Wait for operator confirmation of both.
7. Regenerate HANDOFF.md with all four blockers closed and the
   Session-9 opener inline.

**Risks.** None worth listing; small-PR-shaped changes only.

## Session 9 — reviewer-prep run (Microsoft Office + CVE-2025-31191)

**Goal.** Exercise the substrate end-to-end against a real target with
a known CVE in a class the station claims to cover. Produce a
findings-repo dossier the def-con reviewer in Session 10 can grade.
This is a **rehearsal**, not PASS-002. Time-boxed at 90 minutes of
*active* work; substrate analysis time on top of that.

**Why CVE-2025-31191 / Microsoft Office.**

- Maps to three station ontology classes simultaneously:
  `VULN-SCOPED-BOOKMARKS`, `VULN-FILE-AUTHORITY-TRANSFER`,
  `VULN-SANDBOX-ESCAPE-PRIMITIVE`. If the substrate doesn't put these
  on the candidate list from the entitlement dump, that's a substrate
  failure visible to the reviewer.
- Triggers `offensive-macos-family-tcc-heavy-apps` (security-scoped
  bookmarks is a literal trigger phrase).
- Microsoft Office binaries are universal Mach-O. Exercises PR #20's
  gate live. If the gate misbehaves on a real target, Session 9
  catches it before Session 10's reviewer does.
- Sandbox escape is the holy-grail bug class on macOS. A def-con
  reviewer who watches the substrate fail to even *frame* this bug
  class will write off the station.

**Pre-conditions.** Sessions 7 + 8 closed.

**Steps.**

1. Spin up a fresh findings repo at `~/re/microsoft-office-cve-2025-31191`
   from the `templates/findings-repo/` scaffold (per
   `Skills/offensive-macos-station-topology` "Start A New Project"
   block).
2. Pick one Microsoft Office binary as T-001 (Word, Excel, or
   PowerPoint — Word is the smallest and the most likely entry path
   for the bookmark replay). Do not run intake against the whole
   `Microsoft Office` bundle directory — pick the main exec.
3. Run `scripts/start-target.py` against it. Confirm intake produces:
   - `kind: app` plus the universal-Mach-O detection.
   - Entitlement dump containing `com.apple.security.app-sandbox` and
     security-scoped-bookmark-related strings.
   - `Trigger signals` row routing to keychain-access-group +
     family-tcc-heavy + family-developer-tools as appropriate.
4. Open the binary via `ghidra-mcp`. **Confirm the universal-MachO gate
   fires** (this is the real test of PR #20). Operator pre-slices via
   `lipo -thin arm64` and re-opens.
5. Run one targeted scanner from `ghidra-scripts/` against the
   pre-sliced binary. Suggested: a custom one-off that searches for
   `URLByResolvingBookmarkData` callsites + entitlement-string xrefs.
   If no scanner fits, write a thin one (this is itself a substrate
   exercise — does the agent have the raw materials to write a scanner
   in <30 LOC using `_re_lib`?).
6. Walk the results: do they put bookmark replay or sandbox escape on
   the candidate list? Generate hypotheses via the vuln-ontology
   workflow. Write them up in `findings/analysis/T-001-cve-2025-31191-hypothesis.md`.
7. **Stop before authoring a PoC.** Session 9 is rehearsal, not the
   run. The reviewer should grade what the substrate *surfaced*, not
   what the agent then weaponized.
8. If anything in the substrate misbehaved (a scanner timed out, a
   skill didn't fire when it should have, the universal-MachO gate
   produced a false negative or a confusing message), open a PR fixing
   it. Otherwise no PR.
9. Tell the operator: **"Session 9 done. Findings repo at
   `~/re/microsoft-office-cve-2025-31191`. Session 10's reviewer will
   read it. If you want to merge any substrate-tweak PR before Session
   10, do it now."**

**Hard rules for Session 9.**

- No exploitation, no PoC code beyond static dossier shape. The CVE is
  public and patched but the rule still holds: rehearsal stops at
  candidate creation.
- The findings repo is the operator's; do not commit to `skillz`.
- Per global CLAUDE.md: any destructive action on the workstation
  (e.g., `rm -rf` of stale bundle copies) requires explicit operator
  approval per turn.

**Risks.**

- Office's main exec is large. Substrate analysis time may overflow
  the 90-min active budget. Mitigation: start the import early; do
  prep work (intake, entitlement dump, ontology hypothesis generation)
  in parallel.
- The candidate hypothesis list may *not* surface bookmark replay
  even with the right ontology classes mapped. That itself is a
  substrate finding — record it honestly; don't fabricate. The
  reviewer will value an honest negative more than a padded positive.

## Session 10 — def-con reviewer pass

**Goal.** Re-review the station after Sessions 7–9 closed the
blockers and the substrate had a real run. Persona is intentionally
different from Session 6's corporate reviewer.

**Persona prompt sketch (will be finalized in HANDOFF at Session 9
end).**

> You are an old-school def-con-era reverse engineer who's been
> finding macOS bugs since before TCC existed. You don't care about
> documentation that reads pretty; you care whether this station would
> let you find a 0-day on a Tuesday. Process is ceremony unless it
> demonstrably tightens the loop. Skills that read like compliance
> gates make you suspicious. You don't write fluff in your verdict —
> "yes" or "no" goes first, then a hard reason.

**Inputs to read first.**

- `HANDOFF.md` (current state).
- `Skills/offensive-macos-vuln-ontology/SKILL.md` and
  `docs/ontology/macos-vulnerability-classes.md` — does the ontology
  resemble how a real bug-hunter thinks? Or is it a textbook taxonomy?
- The Session 9 findings repo at
  `~/re/microsoft-office-cve-2025-31191/`. CHRONICLE, CORPUS, hypothesis
  doc. Real evidence of what the substrate surfaces.
- `_re_lib.py` and one or two scanners — do they produce signal a
  human would want to triage, or noise?
- Spot-check: open one binary live via the MCP. Pick something the
  reviewer wants to grep. See if the feedback loop is tight.

**What the reviewer is grading.**

1. **Loop tightness.** Time from "I have an idea" to "I have evidence
   either way." Anything > 5 min for a static question is suspicious.
2. **Signal density.** Per scanner row, what's the false-positive rate
   the reviewer can estimate from a 5-row spot read? PASS-001 found
   24/24 false positives on the TCC regex; what's the equivalent
   today?
3. **Ontology realism.** Does the bug-class list match the reviewer's
   actual mental list of what they'd look for on a new macOS app? Or
   is it abstract?
4. **Pivot ability.** When a hypothesis dies, does the agent have a
   way to pivot or does it loop on the dead lead? `agent-discipline`
   skill should provide it; reviewer judges whether it's real or
   theatrical.
5. **Honest limitations.** Does the station overclaim?
6. **Ceremony tax.** What does the agent have to do that doesn't help
   find bugs? Anything > 0 should have a load-bearing reason.

**Verdict shape.** Same as Session 6: PASS / FAIL / CONDITIONAL PASS.
For FAIL, blockers in priority order with proposed fixes. For
CONDITIONAL PASS, scoped to a target class with the same shape.

If FAIL: loop. The whole point of two reviewers is to catch what one
of them missed. Don't push to PASS-002 with a def-con FAIL on the
table.

If PASS: PASS-002 is unblocked. Next session picks the real CVE
target.

## Session 11+ — PASS-002

Out of scope for this roadmap. Defined in
`docs/plans/2026-05-07-001-feat-macos-os-component-hunting-plan.md`'s
follow-up surface and in HANDOFF when Session 10 lands.

## What this roadmap deliberately does not do

- **Doesn't bundle.** Each session has one focus. Session 7 doesn't
  also "fix the doc rot while we're in there" — that's Session 8.
- **Doesn't preempt the reviewer.** Session 10's verdict isn't
  pre-decided. If the def-con reviewer says "PASS but only against
  developer-tools targets," that's a useful refinement; if they say
  "FAIL, the ontology is corporate slop," that's the most valuable
  finding the substrate could produce. Either is allowed.
- **Doesn't assume Session 9's target lands a finding.** The reviewer
  prep is about exercising the substrate, not about discovering the
  CVE. The CVE is a public reference point.
- **Doesn't add new SHAKEDOWN items speculatively.** New items get
  added during Sessions 7–10 only if real failure modes surface.
