---
name: offensive-macos-poc-authoring
description: >-
  Use when a confirmed candidate or chain-discovery hypothesis is ready for a
  proof-of-concept harness. The skill guides primitive selection, lab-state
  preparation, harness scaffolding, reliability capture, and evidence linking
  back to Scriptorium without losing the discipline that separates a proof
  from a writeup. Fires on "PoC authoring", "write a PoC", "harness this
  primitive", "PoC scaffolding", "stand up a chain harness", and "reliability
  pass".
folder: offensive-macos-poc-authoring
source: skillz-wave5
trigger_phrases:
  - "PoC authoring"
  - "write a PoC"
  - "harness this primitive"
  - "PoC scaffolding"
  - "stand up a chain harness"
  - "reliability pass"
---

# PoC Authoring

> **Channel boundary:** `REPO_MODE=analysis`. PoC code, harnesses, and chain
> artifacts produced by this workflow live exclusively in the project clone's
> gitignored `pocs/` (or `chains/`) tree. They are not committed to the
> reusable station template. Operational tradecraft (persistence, deployment,
> evasion, payload delivery) is out of scope; the deliverable is a
> reproducible proof in a disposable lab VM.

## When To Use

- A candidate has reachability and impact evidence and the operator wants to
  prove it end-to-end.
- A chain-discovery row has graduated past `theoretical` and the next
  experiment is harness work, not more static reading.
- An existing PoC needs a reliability pass — race-window measurement,
  prerequisite recording, or version-drift verification.
- The operator is switching Cursor models for harder generation tasks and
  needs a clean workspace, scaffolded inputs, and clear evidence linkage.

## Lab Topology — Where To Run This

PoC authoring is split between workstation-side scaffolding/text editing and
lab-VM-side harness execution. Workstation actions stay inside the project
clone's gitignored work areas; lab-VM actions are append-logged to
`VM_ACTIONS.md`.

| Step | Where it runs | How |
|------|---------------|-----|
| Select primitive / chain | Workstation | Read CORPUS Exploitability And Chainability + INDEX |
| Pre-flight lab safety | Workstation | Confirm `LAB_SAFETY.md` `lab_disposable: true`; create snapshot if R13 applies |
| Scaffold PoC directory | Workstation | Copy `templates/poc/README.md.template` into `pocs/<target-id>/<id>/README.md`; create harness sub-directories |
| Author harness | Workstation (model selection chosen for the task) | Cursor edits inside `pocs/<target-id>/<id>/` |
| Sync to lab VM | Workstation | `scripts/rsync-to-vm.sh --record <target-id>` (via existing sync script) or operator-driven scp |
| Run harness | Lab VM | Operator-approved command; append a row to `VM_ACTIONS.md` |
| Reliability pass | Lab VM | Multiple harness runs; record hit rate, race window, retry strategy |
| Capture evidence | Workstation | Pull harness output into `findings/analysis/`; link from PoC README |
| Update CORPUS PoC Tracking | Workstation | Edit `CORPUS.md` PoC Tracking row |
| Anchor in Scriptorium | Workstation | Append a Scriptorium row referencing the PoC ID and Candidate / Chain ID |

If dynamic confirmation needs Ghidra-anchored breakpoints, hand off to
`Skills/offensive-macos-gatehouse-ghidra-lldb/SKILL.md` for the LLDB anchor
flow.

## Workflow

1. Pre-flight check:
   - Read `LAB_SAFETY.md`. If `lab_disposable: false`, stop and ask the
     operator for explicit approval before any dynamic action (R14
     standard).
   - Read CORPUS Exploitability And Chainability for the candidate or
     chain row. The Reachability and Reliability Notes columns drive
     harness shape; the Next Experiment column is the entry point.
   - Confirm a snapshot strategy in `LAB_SAFETY.md` and (if practical)
     take a snapshot before any high-disruption action (R13).
2. Assign a stable PoC ID:
   - Format: `POC-<NNN>` zero-padded, sequential within the project.
   - Reserve the ID by adding a row to CORPUS PoC Tracking with
     `Status: scaffolding`.
3. Scaffold the PoC directory:
   - Layout: `pocs/<target-id>/<POC-ID>/` (`pocs/`, `chains/`, and
     `poc/` are gitignored from the station template).
   - Copy `templates/poc/README.md.template` into the directory and
     fill in: target id, candidate / chain id, primitive description,
     prerequisites, lab state required, expected impact, risk.
   - Create `harness/` for the active code, `runs/` for run records,
     and `evidence/` for artifacts the harness produces.
4. Author the harness:
   - Start with the smallest harness that exercises the next experiment
     in the chain row. Avoid stitching the entire chain in the first
     pass.
   - Keep the harness checked-in only in the gitignored `pocs/`
     subtree. The station template never receives PoC code.
   - Document any prerequisite the harness assumes (TCC grants,
     snapshot state, helper installation) in the README.
5. Run on the lab VM:
   - Append a `VM_ACTIONS.md` row before each run with action label
     `mcp-tool` or `other`, the command, the outcome (`succeeded`,
     `failed`, `crashed`, `aborted`), and the `Snapshot Before` value.
   - Capture stdout, stderr, log excerpts, and any artifact in
     `pocs/<target-id>/<POC-ID>/runs/<UTC-timestamp>/`.
6. Reliability pass:
   - Run the harness multiple times. Record hit rate, average latency,
     race-window observations, and failure modes.
   - If reliability is below the threshold the operator cares about,
     update CORPUS Reliability Notes and either iterate or close.
7. Update state:
   - Set CORPUS PoC Tracking `Status` to one of `scaffolding`,
     `harness-built`, `reproducing`, `reliable`, `closed`.
   - Append a Scriptorium row with the PoC ID, Candidate / Chain ID,
     evidence path, and current claim.
   - Append a Chronicle row when the PoC's status changes meaningfully.
8. Close the loop:
   - When the PoC is `reliable`, hand off to
     `Skills/offensive-macos-submission-packet/SKILL.md` for vendor
     disclosure or internal reporting.
   - When the PoC is `closed` (false positive, version-bound, etc.),
     record the rationale in the PoC README and the Chronicle.

## PoC Status Values

- `scaffolding`: directory created, README authored, no harness yet.
- `harness-built`: harness exists, has not been run on the lab VM.
- `reproducing`: harness has run, primitive triggers, reliability not
  yet measured.
- `reliable`: harness reproduces with operator-acceptable reliability.
- `closed`: PoC is no longer worth pursuing; rationale in the README.

These match the values the CORPUS PoC Tracking column expects.

## Evidence Discipline

A PoC counts as "real" only when it carries:

- A target ID and a candidate / chain ID it proves.
- Lab VM identity (OS build, SIP state, arch, snapshot reference).
- The harness code committed in the project clone (gitignored from
  the template).
- At least one reproducing run record under `runs/`.
- A reliability note (single-run, race-bound with measured hit rate,
  deterministic, etc.).
- A Scriptorium anchor and a CORPUS PoC Tracking row.

Without those pieces the PoC stays in `scaffolding` or `harness-built`
status and does not count for reporting.

## False-Positive Traps

- A harness that runs once and produces the expected log line proves
  almost nothing. Reliability is part of the proof.
- A harness that requires post-snapshot state the snapshot does not
  capture is brittle; record the prerequisite explicitly or it will
  not survive the next reset.
- A chain harness that stitches three primitives in one pass usually
  hides which primitive failed. Author each primitive's harness first,
  then a stitcher.
- A PoC whose reliability depends on a specific VM build is still a
  PoC, but the build is part of the proof — record it.
- A "successful" harness without a captured run record is not evidence;
  rerun and capture.

## Pitfalls

- Do not commit PoC code, harnesses, run records, or chain artifacts
  to the station template repo. They live in the project clone's
  gitignored `pocs/<target-id>/<POC-ID>/` directory.
- Do not skip the `VM_ACTIONS.md` append for harness runs even when
  the lab VM is disposable; the audit log is what makes the PoC
  reproducible by another operator.
- Switching Cursor model selection mid-PoC is fine, but do not
  re-author what is already working; treat the current harness as
  authoritative and iterate on it.
- The submission packet is downstream of `reliable`; do not promote a
  `reproducing` PoC to a vendor report until reliability is recorded.

## See Also

- `templates/findings-repo/POC_SCAFFOLDING.md`
- `templates/findings-repo/templates/poc/README.md.template`
- `Skills/offensive-macos-chain-discovery/SKILL.md`
- `Skills/offensive-macos-gatehouse-ghidra-lldb/SKILL.md`
- `Skills/offensive-macos-scriptorium-evidence/SKILL.md`
- `Skills/offensive-macos-submission-packet/SKILL.md`
- `templates/findings-repo/LAB_SAFETY.md`
- `templates/findings-repo/VM_ACTIONS.md`
