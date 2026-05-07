# Lab Safety

Use this file to prevent target research from touching credential-bearing profiles or production data.

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
