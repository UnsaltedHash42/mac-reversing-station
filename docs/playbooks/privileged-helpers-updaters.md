# Privileged Helpers And Updaters

Use this playbook for apps that ship privileged helpers, update frameworks, installer tools, LaunchDaemons, or downloader services.

## Common Artifacts

- App bundle `Contents/Library/LaunchServices/` helpers.
- LaunchDaemons and LaunchAgents.
- MachServices and NSXPC services.
- Sparkle or custom updater frameworks.
- Package installers, staged downloads, caches, and helper tools.
- Entitlements and code-signing requirements on app, helper, and updater components.

## Primary Ontology Classes

- `VULN-XPC-CLIENT-VALIDATION`
- `VULN-PRIV-HELPER-AUTHZ`
- `VULN-UPDATER-TRUST`
- `VULN-SYMLINK-RACE`
- `VULN-LAUNCHD-EXPOSURE`
- `VULN-CODESIGN-ENTITLEMENT`
- `VULN-IPC-CONFUSED-DEPUTY`

## First-Pass Checks

- Enumerate helpers and launchd plists.
- Dump Mach service names and XPC listener anchors.
- Compare helper privilege with caller validation.
- Inspect updater configuration, downloader services, signature checks, and staging paths.
- Check whether authorization binds to exact operation, caller, and file.
- Record every candidate under a pass ID in `INDEX.md`.

## False-Positive Traps

- A root helper is not a bug by itself.
- A helper may accept a connection and reject sensitive methods later.
- Updater frameworks may handle signature verification internally.
- Same-team checks can be sufficient for app-private operations when consistently applied.

## Minimum Evidence For Escalation

- Helper or updater component identity and version.
- Caller validation or missing validation path.
- Operation reachable from the lower-privilege actor.
- Impact of the reachable operation.
- Lab proof using harmless inputs.
- Metrics row showing whether this is a candidate, closure, blocker, or confirmed finding.
