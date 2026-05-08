# Lab Safety

Use this file to prevent target research from touching credential-bearing profiles or production data.

## Lab Disposability

The station treats the lab VM as disposable for dynamic research actions (R11): debugger attaches, service restarts, XPC traffic, TCC resets, keychain changes, crash-prone behavior. Record the operator's lab disposability decision below before running anything dynamic. When `lab_disposable: false`, treat the lab host like the workstation — destructive dynamic actions then require explicit operator approval (R14 standard).

| Field | Value |
|-------|-------|
| Lab role | (primary / crash-test / shared) |
| `lab_disposable` | (true / false) |
| Snapshot scheme | (e.g., `tart clone` daily, manual VMware snapshot before each pass) |
| Restore expectation | (rollback before next pass / acceptable to lose / never tested) |
| Last verified disposable | (UTC timestamp + operator) |

If `lab_disposable: true`, run the destructive-test checklist below as a heads-up rather than a gate, snapshot before high-disruption actions (R13), and append every dynamic action to `VM_ACTIONS.md` (R12). If `lab_disposable: false`, the destructive-test checklist is a hard precondition and `VM_ACTIONS.md` becomes mandatory.

## Machine Roles

| Role | Alias | OS Build | SIP | Snapshot / Restore Point | Notes |
|------|-------|----------|-----|--------------------------|-------|
| primary | | | | | |
| crash-test | | | | | |
| cross-platform | | | | | |
| intel-baseline | | | | | |

## Test Users

| User | Purpose | Contains Real Data? | Apple ID / iCloud? | Reset Procedure |
|------|---------|---------------------|--------------------|-----------------|
| | | no | no | |

## Privacy And TCC Hygiene

- Use synthetic files, contacts, photos, calendar items, and Desktop/Documents data.
- Record every TCC prompt capture with date, app identity, service, and target resource.
- Do not run TCC prompt-attribution tests against unknowing users.
- Reset or snapshot-restore TCC state after privacy tests when practical.

## Destructive-Test Checklist

Before keychain, bookmark, helper install, updater, panic, or filesystem-race work:

- [ ] Disposable user or disposable VM confirmed.
- [ ] Snapshot or restore path confirmed.
- [ ] No Apple ID / iCloud / personal keychain material present.
- [ ] Target data is synthetic.
- [ ] Abort condition is written down.
- [ ] Cleanup or restore step is written down.

## Untrusted Binary Handling

- Prefer lab VMs or disposable machines for unknown third-party binaries.
- Avoid running target apps on credential-bearing profiles.
- Keep downloaded installers, app bundles, and logs in this private repo or lab storage.
- Treat helper installers and updaters as state-changing until proven otherwise.
