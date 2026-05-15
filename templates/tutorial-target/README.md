# Tutorial target — planted-bug XPC daemon

A small Objective-C XPC daemon with three deliberate vulnerabilities for
practicing the station workflow end to end.

## Contents

- `src/tutorial_daemon.m` — full source (read after you've triaged the binary)
- `src/entitlements.plist` — embedded entitlements (includes a red herring)
- `bin/tutorial_daemon` — **pre-built arm64 binary, ad-hoc signed (tracked in git)**
- `plists/com.tutorial.daemon.privileged.plist` — launchd job definition
- `build.sh` — optional rebuild from source

## Usage

**Default (course):** use `bin/tutorial_daemon` as-is after `git clone` — **no compile step**.

1. Sync the binary to your lab host: `rsync bin/tutorial_daemon NightBlood:~/Targets/`
2. Copy the plist to the lab host if you want to run it under launchd.
3. Follow `docs/tutorial/first-pass-planted.md` for the guided walkthrough.

## Rebuilding

```bash
./build.sh
```

Requires `clang` with Objective-C support and `codesign`. Any Mac with
Xcode or Command Line Tools works. The build script ad-hoc signs the result
so no developer identity is needed.

## Planted bugs

Don't read this until you've completed the tutorial pass:

1. Shared delegate — `shouldAcceptNewConnection:` serves both MachServices identically.
2. Authorization bypass — `authorizeMethodID:connection:` returns YES for methodID 0.
3. Un-gated write — `writeAuditLog:` on the "internal" service has no caller validation.

Plus one red herring: a `com.apple.private.tcc.allow` entitlement that does nothing without Apple platform signing.
