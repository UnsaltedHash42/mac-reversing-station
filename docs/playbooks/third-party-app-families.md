# Third-Party App Family Playbooks

Playbooks are views over the shared ontology in `docs/ontology/macos-vulnerability-classes.md`. Start by inventorying the bundle or binary, derive one or more family labels from observed surfaces, then let Scryer route the next move through `docs/playbooks/investigation-recipes.md`.

## Inventory-First Family Routing

Do not choose a family from the app's marketing category. Start with target intake, inspect the bundle surfaces, then assign one or more evidence-derived labels. If the evidence is thin or the app crosses several workflows, use `unknown/mixed` and keep working from the ontology until the pattern clarifies.

| Family | Use When | Primary Playbook |
|--------|----------|------------------|
| Privileged helpers / updaters | App ships root helpers, update frameworks, installers, LaunchDaemons, or privileged XPC services. | `docs/playbooks/privileged-helpers-updaters.md` |
| Enterprise / security agents | App runs endpoint agents, filters, device-management clients, telemetry collectors, or root/system services. | `docs/playbooks/enterprise-security-agents.md` |
| Developer tools | App executes scripts, manages packages, runs build tools, controls VMs, or spawns external commands. | `docs/playbooks/developer-tools.md` |
| TCC-heavy consumer apps | App requests privacy permissions such as Accessibility, Screen Recording, Automation, camera/mic, Desktop/Documents, or Full Disk Access. | `docs/playbooks/tcc-heavy-consumer-apps.md` |
| `unknown/mixed` | Inventory does not clearly fit one family, or several labels apply with equal weight. | Continue with `docs/ontology/macos-vulnerability-classes.md` and record routing notes in `CORPUS.md`. |

## Shared Pass Workflow

1. Confirm authorization as an operator precondition.
2. Confirm lab safety in `LAB_SAFETY.md`.
3. Create or select a pass ID in `CORPUS.md`.
4. Inventory app bundles, helpers, plists, entitlements, XPC services, and data stores.
5. Assign family labels from evidence, allowing multiple labels or `unknown/mixed`.
6. Map surfaces to ontology classes.
7. Pick a Grimoire recipe and run applicable Ghidra or metadata sweeps.
8. Add candidate rows to `INDEX.md`.
9. Update `METRICS.md` with candidates, closures, escalations, confirmed findings, and blockers.
10. Use `REPORTING.md` only after a finding has lab reproduction and root-cause evidence.

## Status Discipline

- `scan-hit` is not proof.
- `closed` is useful when it includes rationale.
- `blocked` should name the blocker type.
- `escalated` means a row deserves focused deep-dive time.
- `confirmed` requires dynamic lab evidence and root-cause understanding.

## Adding Families

See `docs/playbooks/adding-target-families.md` before adding another built-in family. New families should be rare and evidence-driven: repeated targets, distinct workflow value, ontology mapping, clear false-positive traps, and reusable next moves.
