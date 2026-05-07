# Enterprise And Security Agents

Use this playbook for endpoint agents, EDR-adjacent apps, MDM clients, network filters, telemetry collectors, device-management tools, and always-on enterprise services.

## Common Artifacts

- Root LaunchDaemons, system extensions, network extensions, and privileged helpers.
- Management profiles, policy stores, configuration files, and update channels.
- XPC services that bridge UI agents to root components.
- Log, telemetry, quarantine, file-monitoring, or remediation pipelines.
- Entitlements for Full Disk Access, Endpoint Security, Network Extension, System Extension, Accessibility, or automation.

## Primary Ontology Classes

- `VULN-XPC-CLIENT-VALIDATION`
- `VULN-PRIV-HELPER-AUTHZ`
- `VULN-LAUNCHD-EXPOSURE`
- `VULN-IPC-CONFUSED-DEPUTY`
- `VULN-CODESIGN-ENTITLEMENT`
- `VULN-KEYCHAIN-TRUST`
- `VULN-FILE-AUTHORITY-TRANSFER`

## First-Pass Checks

- Inventory installed agents, daemons, helpers, extensions, and policy stores.
- Map low-privilege UI or user agents to privileged services.
- Identify methods that accept file paths, remediation actions, configuration changes, or policy updates.
- Inspect whether caller identity, policy authority, and operation scope are bound together.
- Keep tests in isolated lab environments and avoid production telemetry or customer data.

## False-Positive Traps

- Security agents often have broad entitlements by design.
- Dangerous-looking remediation operations may be policy-gated correctly.
- Tamper-protection behavior may intentionally reject debugging or instrumentation.
- Some behavior is unsafe to test outside a disposable lab profile.

## Minimum Evidence For Escalation

- Authorized scope reference.
- Lab machine and profile state.
- Privileged operation reachable from a lower-privilege actor or mismatched policy authority.
- Root-cause path showing missing or misplaced enforcement.
- Impact framed for remediation or red-team reporting without deployment tradecraft.
