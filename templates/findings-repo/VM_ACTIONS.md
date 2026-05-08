# VM Actions

Append-only audit log of dynamic research actions taken on the lab VM. Required when `lab_disposable: false` in `LAB_SAFETY.md`; recommended for every dynamic action when the lab is disposable so the operator can reconstruct what changed, what broke, and what evidence was produced.

Add a row after each LLDB attach, DTrace probe, service restart, XPC connection attempt, TCC reset, keychain edit, helper install, snapshot, restore, panic test, or anything else that changes lab state. Keep entries concise; link out to `findings/analysis/` and Scriptorium for full evidence.

| Time UTC | Pass ID | Target ID | Action | Tool / Command | Outcome | Snapshot Before | Evidence Path | Operator |
|----------|---------|-----------|--------|----------------|---------|-----------------|---------------|----------|

## Action Taxonomy

Use one of these action labels to keep the log searchable:

- `lldb-attach`, `lldb-detach`, `lldb-breakpoint-set`
- `dtrace-probe`, `dtrace-script`
- `xpc-connect`, `xpc-send`, `xpc-disconnect`
- `service-load`, `service-unload`, `service-restart`
- `tcc-reset`, `tcc-grant`, `tcc-revoke`
- `keychain-read`, `keychain-write`, `keychain-delete`
- `helper-install`, `helper-uninstall`, `helper-replace`
- `snapshot-create`, `snapshot-restore`, `snapshot-delete`
- `panic-test`, `crash-trigger`
- `network-extension-load`, `system-extension-approve`, `system-extension-uninstall`
- `mcp-tool` (when invoking a `macre-vm-mcp` tool with side effects; record the tool name in the Tool / Command column)
- `other` (with a short description in the Action column)

## Outcome Values

- `succeeded`: the action ran and produced expected output.
- `failed`: the tool ran but reported an error; capture the error in the Outcome column.
- `crashed`: the target or VM crashed; record what was lost.
- `aborted`: the operator interrupted the action before completion.
- `pending`: the action is in flight at the time of writing (rare; append a follow-up row when it resolves).

## Evidence Linking

The Evidence Path column should point to a file under `findings/analysis/`, a Scriptorium anchor in `SCRIPTORIUM.md`, a Chronicle entry in `CHRONICLE.md`, or an explicit `n/a` when the action produced no captured artifact (e.g., a snapshot create with no immediate target observation).
