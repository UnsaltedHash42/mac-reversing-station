# PoC Scaffolding

Operator-facing description of where PoCs live in this project clone, what each PoC directory carries, and how PoC state links back to corpus and evidence files.

## Directory Layout

```
pocs/
  <target-id>/
    <POC-ID>/
      README.md         # filled from templates/poc/README.md.template
      harness/          # active harness code
      runs/             # one subdirectory per harness run, named by UTC timestamp
        2026-05-08T14-30-00Z/
          stdout.log
          stderr.log
          notes.md
      evidence/         # artifacts the harness produced (logs, dumps, screenshots)
```

`pocs/`, `chains/`, and `poc/` are gitignored from the reusable station template (see the station's root `.gitignore`). They are project-local. If the project clone has its own private remote, the operator decides whether to push these directories to that remote — the station does not assume it.

## PoC IDs

PoC IDs are stable within a project. Format: `POC-<NNN>` zero-padded, sequential within the project clone.

- IDs are reserved by adding a row to `CORPUS.md` PoC Tracking with `Status: scaffolding`.
- IDs are never reused, even for `closed` PoCs. Reuse hides outcomes.
- Multiple PoCs against the same target are allowed; each gets its own ID and subdirectory.

## State Linkage

Each active PoC links into corpus and evidence as follows:

- `CORPUS.md` PoC Tracking carries the index row (PoC ID, Target ID, Candidate / Chain ID, Status, Lab State Required, Artifact Path, Evidence Path).
- `CORPUS.md` Exploitability And Chainability carries the candidate or chain row the PoC proves; the PoC ID is referenced from the chain row's evidence column when the chain has graduated past `theoretical`.
- `SCRIPTORIUM.md` carries an anchor per PoC, with the PoC ID, evidence path, claim, and status.
- `CHRONICLE.md` carries a row when the PoC's status changes meaningfully (scaffolding → harness-built → reproducing → reliable → submission, or closed).
- `VM_ACTIONS.md` carries a row per harness run (lab-safety audit trail).

## PoC README Fields

The per-PoC `README.md` (instantiated from `templates/poc/README.md.template`) records:

- PoC ID, target ID, candidate / chain ID.
- Primitive description and chain hypothesis (when applicable).
- Prerequisites (TCC grants, helper installation, snapshot state, OS build, hardware).
- Lab state required (snapshot label, network isolation, test users).
- Expected impact and trust boundary crossed.
- Risk to the lab VM (panic-prone, kernel-touching, helper-replacement).
- Reliability target (deterministic, race-bound with measured hit rate, etc.).
- Status, with status history dated entries.

## Status Values

The CORPUS PoC Tracking `Status` column uses one of these values, mirrored in the per-PoC README:

- `scaffolding` — directory created, README authored, no harness.
- `harness-built` — harness exists, has not been run on the lab VM.
- `reproducing` — harness runs, primitive triggers, reliability not measured.
- `reliable` — harness reproduces with operator-acceptable reliability; ready for submission packet.
- `closed` — no longer pursued; rationale in the README and Chronicle.

## What Does Not Belong Here

- Operational tradecraft (persistence, deployment, evasion, payload delivery). Out of scope for the station; private project clones must not push such material upstream into the template.
- Real customer or production data. Use synthetic test data.
- Cross-project PoC code. Each PoC lives in the project clone for the target it proves.

## See Also

- `Skills/offensive-macos-poc-authoring/SKILL.md`
- `Skills/offensive-macos-chain-discovery/SKILL.md`
- `Skills/offensive-macos-submission-packet/SKILL.md`
- `templates/findings-repo/CORPUS.md`
- `templates/findings-repo/LAB_SAFETY.md`
- `templates/findings-repo/VM_ACTIONS.md`
- `templates/findings-repo/SCRIPTORIUM.md`
- `templates/findings-repo/CHRONICLE.md`
