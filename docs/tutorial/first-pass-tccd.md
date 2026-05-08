# First pass: tccd in 30 minutes

This is the calibration run. You'll do one full lap of the loop against `tccd`, the user-side TCC permission broker. It's on every Mac, has real attack surface (XPC, entitlements, identity resolution, the TCC database), and is hardened enough that nothing in this tutorial finds a bug. The exercise is the loop, not the find.

After this you'll have run intake, picked a recipe, run scans that produced navigable anchors, triaged candidates as JSON files with state-machine enforcement, confirmed one anchor in lldb, and closed it with rationale. The same shape applies to every target you'll look at later.

## Before you start

Run the structural smoke. If it fails, fix that first:

```bash
bash scripts/smoke-wave3.sh
```

Then make a project clone for this exercise and open it in your agent:

```bash
mkdir -p ~/re && cd ~/re
git clone <station-repo-url> tutorial-tccd
cd tutorial-tccd
scripts/init-project.sh --name tutorial-tccd
```

Edit `LAB_SAFETY.md` to name your lab host and SIP state. For this tutorial dynamic testing is read-only: lldb attach + read-only inspection. No state changes.

## 1. Intake

```
start a pass on /System/Library/PrivateFrameworks/TCC.framework/Support/tccd. PASS-001.
```

`bundle-intake` runs `scripts/start-target.py` and produces:

- `targets/tccd` — the binary, copied or referenced.
- `findings/analysis/PASS-001-tccd-target-map.json` — structured intake output.
- `findings/analysis/PASS-001-tccd-dossier.json` — surfaces, family labels, Watch fields.
- `CORPUS.md` updated with target inventory and a Watch decision row.
- `SCRIPTORIUM.md` and `CHRONICLE.md` anchored to the intake event.

Open the dossier. The interesting fields:

- `family_labels` should include `os-component`.
- `surfaces` should include `xpc-listener`, `entitlements-bundle`, `private-framework`.
- `watch_decision_support.recommended_recipes` should include `map-xpc-endpoints`.

You handed the agent a path. The agent made the target legible to itself.

## 2. Watch picks the next move

```
what should we look at next
```

`watch-static-analysis` reads the dossier and recommends one artifact. For tccd the recommendation will be an XPC endpoint map. Watch's output looks like:

```
## Watch Recommendation

- Target ID: T-001
- Pass ID: PASS-001
- Dossier: findings/analysis/PASS-001-tccd-dossier.json
- Observed surfaces: xpc-listener, entitlements-bundle, private-framework
- Recommended recipe: map-xpc-endpoints
- First artifact to produce: findings/analysis/PASS-001-tccd-xpc-endpoints.tsv
- Coverage gaps: dynamic confirmation requires snapshot first
- Stop condition: every verified MachService has a should-accept evidence row
```

The stop condition is the half of this you can't get from a checklist. It tells you when this thread is done.

## 3. Sync the binary, run the recipe

Ghidra runs on the lab host, so the binary needs to be there. The agent will normally do this for you. The underlying call:

```bash
MACRE_MACHINE=<lab-host> MACRE_REMOTE_TARGETS=/Users/<remote-user>/Targets \
  bash scripts/rsync-to-vm.sh --record T-001 targets/
```

That writes a `Lab Host Path Mapping` row in `CORPUS.md`. Future Ghidra prompts use that path.

```
run the map-xpc-endpoints recipe
```

The agent uses `ghidra-mcp` to open `tccd` and runs:

- `dump_xpc_listeners.py` — decompiler-verified mach service registrations, ObjC delegate methods, embedded entitlements.
- `scan_xpc_client_validation.py` — anchors for `shouldAcceptNewConnection`, audit-token usage, weak identity checks.

Both write tiered anchor TSVs:

```
target  tier  anchor_kind             name                                                      address      evidence
tccd    A     xpc_registration_callsite  _setup_tccd_listener                                   0x100008abc  api=xpc_connection_create_listener; service=com.apple.tccd
tccd    A     nsxpc_delegate_impl        TCCDXPCConnection.listener:shouldAcceptNewConnection:  0x10000bcd0  selector=listener:shouldAcceptNewConnection:
tccd    B     interesting_entitlement    com.apple.private.tcc.allow                            -            entitlement=com.apple.private.tcc.allow
tccd    C     service_name_string        com.apple.tccd                                         -            service=com.apple.tccd
```

Tier A is decompiler-verified. The address is real. Tier B is Mach-O / ObjC metadata. Tier C is a string heuristic, useful as a navigation starting point.

Saved at `findings/analysis/PASS-001-tccd-xpc-endpoints.tsv`. The agent then runs `scripts/triage.py create` for each tier-A anchor that needs follow-up, and `scripts/triage.py render` so `INDEX.md` shows the new candidates. Scriptorium gets one anchor pointing at the TSV with the binary's sha256 (via the `hash_target` MCP tool) so future evidence stays pinned to the same bytes.

## 4. Triage

```
scripts/triage.py list
```

```
ID       PASS         TARGET     CLASS                  STATUS    SEVERITY  TITLE
C-001    PASS-001     T-001      wrong-door             scan-hit  medium    tccd should-accept-1
C-002    PASS-001     T-001      wrong-door             scan-hit  medium    tccd should-accept-2
```

Look at one directly with `scripts/triage.py show C-001`. Each candidate carries the anchor (tier, kind, address), an evidence list (empty so far), and a history list (one entry: when it was scanned).

Pick C-001:

```
read the decompilation for C-001 and tell me whether the audit token is checked before the request is honored
```

The agent fetches the decompiled function at the anchor address. For tccd the answer for the prominent anchors will be a variant of "yes, the audit token is captured and the requesting subject is resolved against the TCC database before the request is honored." Record that conclusion as evidence and move the candidate forward:

```bash
scripts/triage.py transition C-001 escalated
scripts/triage.py transition C-001 reproducing
```

(Closure happens after lldb confirms.)

If the agent claims something is a bug on the first sweep, stop. Read the decompilation yourself. tccd is well-trodden; first-pass confidence on a hardened Apple component is rarely correct. The exercise is calibrating the agent against your trust.

## 5. Confirm one anchor in lldb

Read-only attach. No state changes.

```
confirm the C-001 anchor in lldb. read-only attach, no state changes.
```

Gatehouse fires:

1. Re-reads `LAB_SAFETY.md` to confirm read-only attach is allowed.
2. Calls `lldb_run_anchors` against tccd with the symbol from C-001.
3. Captures the transcript to `artifacts/PASS-001-tccd-c001.lldb.log`.
4. Calls `hash_target` to get the binary slice's sha256.
5. Runs `scripts/triage.py transition C-001 confirmed --evidence-path artifacts/PASS-001-tccd-c001.lldb.log --evidence-kind lldb_transcript --binary-sha256 <hex>`.

If lldb can't attach (SIP, hardened runtime, codesign restrictions), record `blocked` not `closed`. Cannot-attach is not the same as no-bug.

## 6. Close

```bash
scripts/triage.py transition C-001 closed \
  --reason 'audit token resolved before authorization; expected behavior'
scripts/triage.py render
```

The CLI sets the status to `closed`, records the rationale, appends to history, and refuses further transitions. Then ask the agent to:

- Append a Scriptorium entry naming the closure rationale, decompilation citation, and lldb transcript path with the binary's sha256.
- Increment `METRICS.md` for the pass. Closures are research output and count.
- Update `HANDOFF.md` with the next move (likely "C-002, same procedure").

## What you should have

```
~/re/tutorial-tccd/
├── targets/tccd                                      # local copy or reference
├── findings/analysis/
│   ├── PASS-001-tccd-target-map.json                 # intake
│   ├── PASS-001-tccd-dossier.json                    # surfaces + watch
│   └── PASS-001-tccd-xpc-endpoints.tsv               # tiered anchors
├── findings/candidates/
│   └── C-001.json                                    # closed
├── artifacts/
│   └── PASS-001-tccd-c001.lldb.log                   # lldb transcript
├── CORPUS.md
├── INDEX.md                                          # generated
├── METRICS.md
├── SCRIPTORIUM.md
├── CHRONICLE.md
└── HANDOFF.md
```

## A few rules that show up in every later run

Intake makes the target legible. No magic, just structured facts.

Watch decides one move at a time. The next artifact is named explicitly. There is no "I'll just look around."

Tier-A anchors are the navigation graph. Counts are not evidence; addresses are.

Triage is a state machine, not a feeling. The CLI rejects illegal transitions.

Evidence is hash-pinned. Every Scriptorium entry refers to a sha256 of the binary slice. If the slice changes, the evidence stops counting.

Closures count. A defensible "no story here" is a finding.

## When the loop wants to break

Watch keeps recommending the same recipe — you've already produced that artifact; tell Watch what changed in CORPUS or open a new surface.

The agent is confidently claiming a bug on the first sweep — read the decompilation yourself.

lldb cannot attach — `blocked`, not `closed`. Record the SIP / codesign reason.

You have too many open candidates — spend a session on closures only. That is real work.

## Next steps

Try the same loop on a non-Apple target. Privileged helpers and updaters from third-party vendors are a high-yield first hunt. Look in `/Library/Application Support/<vendor>/`.

Read `Skills/README.md`. You now have the context to know which skills you'll reach for.

When you find a real candidate worth a PoC, read `Skills/offensive-macos-chain-discovery/SKILL.md` and `Skills/offensive-macos-poc-authoring/SKILL.md`. When you find a real bug, `Skills/offensive-macos-submission-packet/SKILL.md` before the report.
