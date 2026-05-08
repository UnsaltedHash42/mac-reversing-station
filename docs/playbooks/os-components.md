# Apple OS Components

Use this playbook for Apple-published macOS internals: app bundles under `/System/Applications/` and `/Applications/`, command-line tools, daemons, agents, frameworks, PrivateFrameworks, system extensions, network extensions, Endpoint Security clients, DriverKit/IOKit-adjacent components, and the launchd/MachService surfaces that connect them. The bundle-first project start still applies, but OS-component intake records additional facts (signing authority, dyld shared cache origin, OS build, MachServices) before recipe routing.

## Common Artifacts

- Apple-signed binaries (`Authority=Software Signing`) and `com.apple.*` bundle identifiers.
- Root LaunchDaemons under `/System/Library/LaunchDaemons/` and per-user LaunchAgents under `/System/Library/LaunchAgents/`, with `MachServices`, `Sockets`, `WatchPaths`, and `ProgramArguments`.
- XPC services bundled inside `.app`, `.framework`, or `.systemextension` packages.
- Frameworks under `/System/Library/Frameworks/` and PrivateFrameworks under `/System/Library/PrivateFrameworks/`, often resolved through the dyld shared cache.
- System extensions (`*.systemextension`), network extensions (`*.networkextension`), Endpoint Security clients, and DriverKit extensions (`*.dext`).
- TCC, sharing, file-provider, sandbox, keychain, and authorization-store interfaces.

## Primary Ontology Classes

- `VULN-XPC-CLIENT-VALIDATION`
- `VULN-PRIV-HELPER-AUTHZ`
- `VULN-LAUNCHD-EXPOSURE`
- `VULN-IPC-CONFUSED-DEPUTY`
- `VULN-CODESIGN-ENTITLEMENT`
- `VULN-TCC-ATTRIBUTION`
- `VULN-SANDBOX-ESCAPE-PRIMITIVE`
- `VULN-SCOPED-BOOKMARKS`
- `VULN-KEYCHAIN-TRUST`
- `VULN-FILE-AUTHORITY-TRANSFER`
- `VULN-SYMLINK-RACE`
- `VULN-UPDATER-TRUST`

## Maturity Tiers

OS-component coverage is staged. Each surface intake encounters carries a maturity tier so Watch can be honest about what the station does versus what the operator must drive manually.

- **full-recipe**: launchd jobs, MachServices, XPC services, privileged helpers, frameworks/PrivateFramework dependencies, Apple-signed app bundles. Watch routes a Maproom recipe and supporting Ghidra/MCP work.
- **basic-inventory**: system extensions, network extensions, Endpoint Security clients, DriverKit/IOKit-adjacent components, appex extensions. Intake records the surface; the operator drives the deeper recipe manually until a focused workflow lands.
- **manual-route-needed**: any surface intake recognizes but Watch cannot pair with a recipe. Surfaces in this tier appear in `coverage_gaps` so the next move is operator-led.

## First-Pass Checks

- Capture OS build (`sw_vers`, `system_profiler SPSoftwareDataType`), SIP state (`csrutil status`), and architecture slices for the lab VM that observed the artifact.
- Inventory the bundle or binary before committing to family or subsystem labels; OS-component shapes are recognized at intake by `scripts/start-target.py`.
- Pull Apple-published source from https://opensource.apple.com/releases/ when available and feed it through the source-binary correlation lane.
- Map every launchd plist's `MachServices` to its program path; identify reachability from UID 501.
- Record framework dependencies and dyld shared-cache origins for the main binary so PrivateFramework reach is visible.
- For extensions: read the bundle's Info.plist, entitlements, approval state, and parent app/orchestrator before treating any reachability claim as proof.

## False-Positive Traps

- Apple-signed and `com.apple.*` identifiers are evidence of provenance, not of vulnerability.
- Many Apple frameworks have broad entitlements by design; reachability and trust-boundary failure must be proved separately.
- A privileged MachService that accepts a connection still has to authorize the operation; connection acceptance is not proof of authorization bypass.
- Crash-prone behavior on a lab VM is research signal, not vulnerability evidence.
- Apple often centralizes checks behind a framework; a thin daemon with no obvious gate may be deferring authorization correctly.

## Minimum Evidence For Escalation

- Lab VM identity (OS build, SIP, arch, snapshot reference) and the matching `VM_ACTIONS.md` row when the evidence required dynamic action.
- Static suspicion linked to reachability (UID 501 connection, file-write reach, etc.).
- Trust-boundary or authorization gap mapped to an ontology class with concrete code paths.
- Impact framed for vendor disclosure, internal remediation, or red-team reporting; do not commit Apple-source mirrors or operational tradecraft to the template repo.
- Optional: a chain hypothesis when the primitive is more useful as part of a larger sequence; record this in CORPUS Exploitability And Chainability.
