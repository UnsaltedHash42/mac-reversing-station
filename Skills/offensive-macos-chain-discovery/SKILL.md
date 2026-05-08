---
name: offensive-macos-chain-discovery
description: >-
  Use when corpus state contains two or more candidate primitives that could
  combine into a higher-impact chain - sandbox escape stitched to TCC bypass,
  helper authorization gap stitched to file-write primitive, updater trust
  failure stitched to privileged install, keychain trust slip stitched to
  scoped-bookmark replay. Fires on "chain discovery", "vuln chain",
  "primitive chain", "exploitability ladder", "stitch primitives", and
  "what does this primitive get me".
folder: offensive-macos-chain-discovery
source: skillz-wave5
trigger_phrases:
  - "chain discovery"
  - "vuln chain"
  - "primitive chain"
  - "exploitability ladder"
  - "stitch primitives"
  - "what does this primitive get me"
---

# Chain Discovery

> **Channel boundary:** `REPO_MODE=analysis`. The skill produces chain
> hypotheses, exploitability ratings, and the next experiments needed to
> advance toward a PoC. PoC code, exploit chains, and operational tradecraft
> live in private project clones, not in the reusable template.

## When To Use

- Watch decision support or candidate triage has produced 2+ primitives that may chain.
- A confirmed primitive needs an exploitability rating before the operator decides whether to invest in PoC authoring.
- The operator wants the agent to actively look for chain potential rather than waiting to spot one ad hoc.
- A PoC is stalled because the primitive in hand needs a partner primitive to land impact.

## Lab Topology — Where To Run This

Chain discovery is a static, corpus-driven workflow. It runs entirely on the workstation against project state files; no lab VM action required.

| Step | Where it runs | How |
|------|---------------|-----|
| Read CORPUS state | Workstation | Read `CORPUS.md` Surface Classification, Watch Decision Support, Exploitability And Chainability |
| Read INDEX candidates | Workstation | Read `INDEX.md` candidate rows |
| Read ontology | Workstation | Read `docs/ontology/macos-vulnerability-classes.md` |
| Read submission packet | Workstation | Read `Skills/offensive-macos-submission-packet/SKILL.md` |
| Update Exploitability And Chainability | Workstation | Edit `CORPUS.md` |
| Anchor evidence | Workstation | Append to `SCRIPTORIUM.md`, optionally `CHRONICLE.md` |

If a chain hypothesis later requires dynamic confirmation, hand off to `Skills/offensive-macos-poc-authoring/SKILL.md` and `Skills/offensive-macos-gatehouse-ghidra-lldb/SKILL.md`.

## Workflow

1. Inventory the candidate set:
   - Read CORPUS Surface Classification and Watch Decision Support for every active target.
   - Read CORPUS Exploitability And Chainability for existing chain rows.
   - Read INDEX for candidate primitives with status `scan-hit`, `escalated`, or `confirmed`.
2. Bucket primitives by ontology class using `docs/ontology/macos-vulnerability-classes.md`. Each primitive should map to at least one VULN-* class; primitives without a class are not yet evidence and stay out of chain reasoning.
3. For each pair (or triple) of primitives, ask the bridge questions:
   - Does primitive A produce an attacker-controllable input that primitive B trusts? (file path, message dictionary, bookmark blob, keychain item, helper argument)
   - Does primitive A grant access to a resource primitive B needs? (TCC permission, sandbox extension, file descriptor, audit token, port handle)
   - Does primitive A weaken validation primitive B otherwise prevents? (signing-identity check bypassed, lifecycle operation that re-anchors trust, race window opened by A's write timing)
   - Does primitive B amplify primitive A's impact? (file write becomes privileged execution, prompt-attribution mismatch becomes Full Disk Access, sandboxed-app primitive becomes root via helper)
4. For each plausible chain, record an Exploitability And Chainability row with:
   - **Candidate ID**: stable id assigned at row creation; never renumbered.
   - **Target ID**: lead target the chain stitches against; cross-target chains use the lead and note partners in Reachability.
   - **Exploitability Rating**: see the rating dimensions below.
   - **Chain Hypothesis**: one or two sentences naming the primitives, their roles, and the impact.
   - **Reachability**: where each primitive sits today (UID 501 reachable, sandbox-only, post-grant only, etc.).
   - **Reliability Notes**: race windows, version drift, snapshot-required state, timing dependencies, failure modes.
   - **Next Experiment**: the smallest concrete test (static or dynamic) that advances the chain toward proof.
5. Anchor each promoted chain in Scriptorium with the Candidate ID, the evidence paths for the primitives, and the chain hypothesis as the claim. Append a Chronicle row when the chain is the day's headline.
6. Promote at most one chain per session into PoC authoring. Hand it to `Skills/offensive-macos-poc-authoring/SKILL.md` with the chain row as input.

## Exploitability Rating Dimensions

Rate each chain on the dimensions below; the rating column captures the headline tier (`high`, `medium`, `low`, or `theoretical`) plus inline qualifiers (e.g. `medium / race-bound / requires-snapshot`).

- **Attacker position**: unauthenticated network, local user, sandboxed app, helper client, root-equivalent.
- **Prerequisites**: pre-existing TCC grants, helper installed, target version, OS build, hardware (Intel vs Apple Silicon), entitlement on attacker process.
- **Controllability**: how cleanly the attacker controls the relevant inputs (full, partial, oracle-only, observation-only).
- **Reliability**: race-bound, timing-bound, deterministic, probabilistic; expected hit rate when known.
- **Impact**: privilege escalation, file read/write outside sandbox, TCC inheritance, code execution, persistent authorization, denial of service.
- **Trust boundary crossed**: client-server, sandbox, TCC subject, signing identity, kernel/userspace, network/local.
- **Proof gap**: what is not yet proven (reachability, authorization bypass, impact, root cause).

A chain whose rating is `theoretical` belongs in the table for completeness but should not be promoted to PoC authoring until at least the reachability dimension is observed.

## Output Shape

Each chain becomes one row in CORPUS Exploitability And Chainability:

```
| C-001 | tccd | high / local-user / requires-snapshot | A: prompt-attribution mismatch in tccd; B: bookmark store replay in scoped-bookmark agent; result: Full Disk Access without user prompt | A: UID 501 reachable; B: requires existing scoped bookmark | Race against snapshot restore window | Capture A->B handoff in lab VM with synthetic Documents folder |
```

Cross-link the row to:

- A Scriptorium anchor that names the candidate primitives and links to their analysis files.
- An INDEX row when the chain itself is something the operator will track separately from the constituent primitives.
- A METRICS update if the chain is escalated.

## False-Positive Traps

- Two primitives that share a target are not automatically a chain; they have to actually interact through a controllable input or shared resource.
- A primitive that requires "an attacker who already has root" does not chain into a privilege-escalation story.
- Race windows that nobody has observed in the lab are not chains; they are open coverage gaps.
- Apple-by-design behavior is not a primitive even when it sounds dangerous (broad entitlements, expected helper access, signed updaters).
- Speculative chains across major OS subsystems are easy to write and rarely survive contact with real reachability evidence; rate them `theoretical` and do not promote until reachability lands.

## Pitfalls

- Chain discovery is a calibration loop, not a one-shot. Re-run it whenever a new candidate is confirmed or a primitive's reachability changes.
- Do not invent ontology classes. If a primitive does not fit an existing class, record the gap in Open Questions and continue with the existing classes.
- Do not commit chain artifacts to the template repo; chain hypotheses live in the project clone's `CORPUS.md`, and chain code (when authored) lives under gitignored `pocs/` or `chains/`.
- The Exploitability Rating is for ranking work, not for vendor reporting. Final reporting language belongs in the submission packet.

## See Also

- `docs/playbooks/investigation-recipes.md` (`chain-discovery` recipe)
- `docs/ontology/macos-vulnerability-classes.md`
- `Skills/offensive-macos-vuln-ontology/SKILL.md`
- `Skills/offensive-macos-watch-static-analysis/SKILL.md`
- `Skills/offensive-macos-poc-authoring/SKILL.md`
- `Skills/offensive-macos-scriptorium-evidence/SKILL.md`
- `Skills/offensive-macos-submission-packet/SKILL.md`
