# Third-Party App Family Playbooks

Playbooks are views over the shared ontology in `docs/ontology/macos-vulnerability-classes.md`. Start from the app family to enumerate surfaces, then map those surfaces to ontology classes and record the pass in the copied findings repo.

## Family Routing

| Family | Use When | Primary Playbook |
|--------|----------|------------------|
| Privileged helpers / updaters | App ships root helpers, update frameworks, installers, LaunchDaemons, or privileged XPC services. | `docs/playbooks/privileged-helpers-updaters.md` |
| Enterprise / security agents | App runs endpoint agents, filters, device-management clients, telemetry collectors, or root/system services. | `docs/playbooks/enterprise-security-agents.md` |
| Developer tools | App executes scripts, manages packages, runs build tools, controls VMs, or spawns external commands. | `docs/playbooks/developer-tools.md` |
| TCC-heavy consumer apps | App requests privacy permissions such as Accessibility, Screen Recording, Automation, camera/mic, Desktop/Documents, or Full Disk Access. | `docs/playbooks/tcc-heavy-consumer-apps.md` |

## Shared Pass Workflow

1. Confirm authorization in `AUTHORIZATION.md`.
2. Confirm lab safety in `LAB_SAFETY.md`.
3. Create or select a pass ID in `CORPUS.md`.
4. Inventory app bundles, helpers, plists, entitlements, XPC services, and data stores.
5. Map surfaces to ontology classes.
6. Run applicable Ghidra or metadata sweeps.
7. Add candidate rows to `INDEX.md`.
8. Update `METRICS.md` with candidates, closures, escalations, confirmed findings, and blockers.
9. Use `REPORTING.md` only after a finding has lab reproduction and root-cause evidence.

## Status Discipline

- `scan-hit` is not proof.
- `closed` is useful when it includes rationale.
- `blocked` should name the blocker type.
- `escalated` means a row deserves focused deep-dive time.
- `confirmed` requires dynamic lab evidence and root-cause understanding.
