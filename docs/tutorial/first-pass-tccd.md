# First Pass: tccd in 30 minutes

This is your "Hello, agent" run. By the end you will have done one full lap of the loop — intake, Watch, Maproom recipe, Ghidra sweep, candidate triage, lldb confirmation, evidence record, closure — against a real Apple-signed daemon. The target is `tccd`, the user-side TCC permission broker. It is on every Mac, exposes XPC, holds entitlements that matter, is the headline of the wrong-door / TCC bug class anchors, and is **not actually exploitable through anything in this tutorial.** That is the point. The exercise is the loop; the result is "no story here, here is why."

When this tutorial is over you will know:

- What the agent does for you, and what you do for the agent.
- Where each piece of evidence lands in the project clone.
- How to read a tier-A anchor and confirm it in lldb.
- What "closed with rationale" looks like.

## Prerequisites

Before you start, the station should be installed and the lab VM reachable. From the station checkout:

```bash
bash scripts/smoke-wave3.sh
```

Should report all green. If it does not, fix that before continuing — the tutorial assumes a working station.

You also need a Cursor or Claude Code session open in a fresh project clone:

```bash
mkdir -p ~/re && cd ~/re
git clone <station-repo-url> tutorial-tccd
cd tutorial-tccd
scripts/init-project.sh --name tutorial-tccd
```

Edit `LAB_SAFETY.md` to name your lab host and confirm SIP state. For this tutorial **dynamic testing is read-only** — lldb attach and read-only inspection only. No state-changing commands.

Open `~/re/tutorial-tccd` in your agent.

## 0. The shape of the loop

```
intake → watch → recipe → scan → triage → confirm → record
                   ↑                                   │
                   └───────────────── repeat ──────────┘
```

Every step has an artifact. If a step does not produce an artifact, you skipped it.

## 1. Intake (5 min)

In Cursor / Claude Code, type:

```
start a pass on /System/Library/PrivateFrameworks/TCC.framework/Support/tccd. PASS-001.
```

The agent will auto-invoke `bundle-intake` and run:

```bash
python3 scripts/start-target.py "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd" --pass-id PASS-001
```

What you should see when this completes:

- `targets/tccd` — the binary copied or referenced locally.
- `findings/analysis/PASS-001-tccd-target-map.json` — structured intake output.
- `findings/analysis/PASS-001-tccd-dossier.json` — surfaces, family labels, Watch fields.
- `CORPUS.md` updated with target inventory + Watch decision support row.
- `SCRIPTORIUM.md` and `CHRONICLE.md` updated with anchors for the intake event.

Open `findings/analysis/PASS-001-tccd-dossier.json`. The interesting parts are:

- `family_labels`: should include `os-component`.
- `surfaces`: should include `xpc-listener`, `entitlements-bundle`, `private-framework`, possibly `tcc-prompt-broker`.
- `watch_decision_support.recommended_recipes`: should include `map-xpc-endpoints`.

> **What you did:** handed the agent a path. **What the agent did:** made the target legible to itself.

## 2. Watch picks the next move (2 min)

Ask:

```
what should we look at next
```

`watch-static-analysis` fires. The agent reads the dossier and CORPUS, and recommends one artifact to produce next. For tccd, the recommendation will be a map of XPC endpoints — that is the interesting attack surface and it is also where wrong-door bugs live.

Watch's output should look like:

```
## Watch Recommendation

- Target ID: T-001
- Pass ID: PASS-001
- Dossier: findings/analysis/PASS-001-tccd-dossier.json
- Observed surfaces: xpc-listener, entitlements-bundle, private-framework, tcc-prompt-broker
- Recommended recipe: map-xpc-endpoints
- First artifact to produce: findings/analysis/PASS-001-tccd-xpc-endpoints.tsv
- Coverage gaps: dynamic confirmation requires snapshot first
- Stop condition: every verified MachService has a should-accept evidence row
```

> **What you did:** asked one question. **What the agent did:** picked the next move *and* named the stop condition. The stop condition is what tells you when this thread is done.

## 3. Sync the target to the lab VM, run the recipe (8 min)

Ghidra runs on the lab VM, so the binary needs to be there. The agent will normally do this for you; if it asks, say yes. The underlying call:

```bash
MACRE_MACHINE=<lab-host> MACRE_REMOTE_TARGETS=/Users/<remote-user>/Targets \
  bash scripts/rsync-to-vm.sh --record T-001 targets/
```

That writes a `Lab Host Path Mapping` row in `CORPUS.md` so future Ghidra prompts can reference the remote path.

Now ask the agent to run the recipe:

```
run the map-xpc-endpoints recipe
```

The agent will use `ghidra-mcp` to open the remote `tccd`, then run two scripts back-to-back:

- `dump_xpc_listeners.py` — decompiler-verified mach service registrations + ObjC delegate methods + embedded entitlements.
- `scan_xpc_client_validation.py` — anchors for `shouldAcceptNewConnection`-style methods, audit-token usage, weak identity checks.

Both output **tiered anchors** to TSV. Each row carries:

```
target  tier  anchor_kind  name             address      evidence
tccd    A     mach_service com.apple.tccd   0x100008abc  api=xpc_connection_create_mach_service
tccd    A     delegate     -[TCCDelegate listener:shouldAcceptNewConnection:]  0x10000bcd0  selector=listener:shouldAccept...
tccd    B     entitlement  com.apple.private.tcc.allow  -            class=tcc-private-allow
tccd    C     audit_token  xpc_connection_get_audit_token  -          string=xpc_connection_get_audit_token
```

- **Tier A** = decompiler-verified. The address is real. You can hand it to lldb directly.
- **Tier B** = Mach-O / ObjC metadata or embedded plist. Address may be a callsite or a metadata location.
- **Tier C** = string heuristic. A starting point in Ghidra; do not trust the row alone.

The TSV is saved under `findings/analysis/PASS-001-tccd-xpc-endpoints.tsv`. The agent updates `INDEX.md` with one candidate row per tier-A anchor that needs follow-up, and one Scriptorium entry pointing at the TSV with the binary's sha256 so future evidence is pinned to the same bytes.

> **What you did:** asked for the recipe. **What the agent did:** produced navigable evidence. Counts are not evidence; addresses are evidence.

## 4. Triage (5 min)

Open `INDEX.md`. You should see candidate rows like:

```
| C-001 | PASS-001 | tccd should-accept-1 | wrong-door | scan-hit | medium | findings/analysis/PASS-001-tccd-xpc-endpoints.tsv | confirm in lldb |
| C-002 | PASS-001 | tccd should-accept-2 | wrong-door | scan-hit | medium | findings/analysis/PASS-001-tccd-xpc-endpoints.tsv | confirm in lldb |
```

For the tutorial, pick C-001 and ask:

```
read the decompilation for C-001 and tell me whether the audit token is checked before the request is honored
```

The agent will use `ghidra-mcp` to fetch the decompiled function at the anchor address and read it. For tccd, the answer for the most prominent anchors will be a variant of "yes, the audit token is captured and the requesting subject is resolved against the TCC database before the request is honored." The agent should record that conclusion as evidence and update C-001's status — likely to `closed` with rationale `expected behavior; subject is resolved via audit token before authorization`.

If the agent claims something *is* a bug, stop. Verify the decompilation yourself. tccd is well-trodden ground; a confident "this is a bug" from the agent on a first pass is almost certainly wrong, and a confident "this is fine" is what you want to verify the loop is working. The exercise is calibrating the agent to your trust.

> **What you did:** read the agent's reasoning, decided. **What the agent did:** produced reasoning *with citations*. Every claim should point at the decompilation, the address, and the function.

## 5. Confirm one anchor in lldb (5 min)

Pick the most interesting tier-A anchor and confirm it dynamically. Read-only — attach, hit the breakpoint, dump registers, detach.

Ask:

```
confirm the C-001 anchor in lldb. read-only attach, no state changes.
```

Gatehouse fires. The agent will:

1. Re-read `LAB_SAFETY.md` to confirm read-only attach is allowed.
2. Use `lldb_run_anchors` against tccd with the symbol from C-001.
3. Capture the lldb transcript to `artifacts/PASS-001-tccd-c001.lldb.log`.
4. Update C-001's row with the confirmation reference and the SHA256 of the binary slice that was running.

If lldb cannot attach to tccd (SIP, hardened runtime, codesign restrictions), the agent should record that as a *blocker*, not a closure. "Cannot attach" is not the same as "no bug here."

> **What you did:** authorized the dynamic test. **What the agent did:** kept lab safety in the loop and pinned the evidence to a hash.

## 6. Close (3 min)

Tell the agent:

```
close C-001 with rationale based on the decompilation and the lldb transcript
```

The agent will:

- Set C-001's status to `closed` in `INDEX.md`.
- Append a Scriptorium entry naming the closure rationale, decompilation citation, and lldb transcript.
- Increment `METRICS.md` for the pass — closures are research output and should be counted.
- Update `HANDOFF.md` with the next thing to do (probably "C-002, same procedure").

> **What you did:** stated the conclusion. **What the agent did:** wrote it down in three places so the next session can resume cold.

## 7. What you should have at the end

```
~/re/tutorial-tccd/
├── targets/tccd                                      # local copy or reference
├── findings/analysis/
│   ├── PASS-001-tccd-target-map.json                 # intake output
│   ├── PASS-001-tccd-dossier.json                    # surfaces + watch fields
│   └── PASS-001-tccd-xpc-endpoints.tsv               # tiered anchor rows
├── findings/candidates/
│   └── C-001.yaml                                    # candidate state, closed
├── artifacts/
│   └── PASS-001-tccd-c001.lldb.log                   # lldb transcript
├── CORPUS.md                                         # target inventory + watch row
├── INDEX.md                                          # candidate rows
├── METRICS.md                                        # pass metrics
├── SCRIPTORIUM.md                                    # evidence anchors
├── CHRONICLE.md                                      # session timeline
└── HANDOFF.md                                        # next move for the next session
```

## What you learned

1. **Intake makes a target legible.** No magic; just structured facts.
2. **Watch decides one move.** The next artifact is named explicitly. There is no "I'll just look around."
3. **Tiered anchors are the contract.** A scan output is a navigable graph, not a count.
4. **Triage is a state machine.** `scan-hit → escalated | hold | closed | blocked | confirmed → reported`. No `interesting`.
5. **Evidence is hash-pinned.** Every Scriptorium entry refers to a SHA256 of the binary slice. If the slice changes, the evidence stops counting.
6. **Closure is research output.** A defensible "no story here" is a finding.

## When the loop wants to break

- **Watch keeps recommending the same recipe.** You've already produced that artifact; tell Watch what changed in CORPUS or open a new surface.
- **The agent confidently claims a bug on the first sweep.** Read the decompilation yourself. First-pass confidence on a hardened Apple component is rarely correct.
- **The agent cannot attach in lldb.** Mark `blocked`, record the SIP / codesign reason, move to a different candidate.
- **Triage stops converging.** You have too many open candidates. Spend a session on closures only — that is real work.

## Next steps

- Run the same loop on a *non-Apple* target you actually want to look at: pick something from `/Library/Application Support/<vendor>/<helper-name>` — privileged helpers and updaters from third-party vendors are a high-yield first hunt.
- Read `Skills/README.md` once. You now have the context to know which skills you will reach for.
- When you find a real candidate worth a PoC, read `Skills/offensive-macos-chain-discovery/SKILL.md` and `Skills/offensive-macos-poc-authoring/SKILL.md`.
- When you find a real bug, read `Skills/offensive-macos-submission-packet/SKILL.md` before writing the report.
