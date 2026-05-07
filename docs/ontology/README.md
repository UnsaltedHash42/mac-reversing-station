# macOS Vulnerability Ontology

This directory holds the station-wide vocabulary for macOS vulnerability classes. Playbooks should reference these classes instead of inventing one-off labels.

## How To Use

1. Start from a target-family playbook under `docs/playbooks/`.
2. Map observed surfaces to one or more ontology class IDs in `macos-vulnerability-classes.md`.
3. Use each class's hypothesis prompts to decide what to inspect next.
4. Save target-specific candidates, evidence, and metrics in the copied findings repo, not in `skillz`.

## Entry Shape

Each class uses the same fields:

- **Boundary:** Who trusts whom, and what authority label is supposed to be enforced.
- **Attacker-controlled inputs:** The values, files, messages, processes, or timing windows the low-privilege side may control.
- **Likely impact:** What boundary can be crossed if the class is exploitable.
- **Static signals:** Strings, imports, entitlements, plist keys, or code shapes worth triaging.
- **Dynamic confirmation:** Safe lab checks that distinguish candidates from bugs.
- **False-positive traps:** Signals that commonly look scary but are expected or already gated.
- **Evidence:** What a reviewer needs to understand reachability, impact, and root cause.
- **Hypothesis prompts:** Questions that help generate new-bug hypotheses against unfamiliar targets.

This ontology is intentionally not a vulnerability database. Real target names and finding rows belong in private findings repos.
