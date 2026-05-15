# Tutorial target 2 — multi-binary `.app` bundle

A small `.app` bundle (`PluginHost.app`) with a host binary, a bundled XPC helper, and a sample dylib. Used as the **extension lab** for the macOS Reversing Station tutorial — it exercises capabilities the bare-binary `tutorial-target` does not (intake of bundles, cross-binary call tracking, `dlopen`-style plugin loading).

## Contents

```
tutorial-target-2/
├── README.md
├── build.sh
├── src/
│   ├── PluginHost.m                    # host binary source
│   ├── PluginHost-entitlements.plist
│   ├── PluginHelper.m                  # bundled XPC helper source
│   ├── PluginHelper-entitlements.plist
│   └── sample_plugin.c                 # legitimate plugin (happy-path demo)
├── plists/
│   ├── PluginHost-Info.plist           # host bundle Info.plist
│   └── PluginHelper-Info.plist         # XPC service Info.plist (XPCService dict)
└── PluginHost.app/                     # produced by build.sh
    └── Contents/
        ├── Info.plist
        ├── MacOS/PluginHost
        ├── Resources/plugins/sample.dylib
        └── XPCServices/PluginHelper.xpc/
            └── Contents/
                ├── Info.plist
                └── MacOS/PluginHelper
```

## Usage

1. Build: `./build.sh` (requires clang + codesign; ad-hoc signed, no developer identity).
2. Sync the bundle (the directory, not just the host binary) to the lab host: `MACRE_MACHINE=<host> MACRE_REMOTE_TARGETS=/Users/<remote-user>/Targets bash ../../scripts/rsync-to-vm.sh --record pluginhost PluginHost.app` (intake will derive the slug `pluginhost` from the bundle name).
3. Run intake against `PluginHost.app` from a per-target project clone: `python3 scripts/start-target.py templates/tutorial-target-2/PluginHost.app --pass-id PASS-NNN`.

Follow the course walkthrough in `LAB_II.md` (socam: `docs/course/ai-re/LAB_II.md`) — separate take-home, not the in-class daemon spine.

## Rebuilding

```bash
./build.sh
```

## Planted bugs

*Don't read this until you've completed the bundle pass:*

1. **Host wrong-door** — `HostDelegate.shouldAcceptNewConnection:` accepts any peer. `requestPluginLoad:` joins the plugin name with the bundle's plugin directory using `stringByAppendingPathComponent:` (string concat, not path resolution), so a name containing `..` traverses out of the bundle before the path reaches the helper.
2. **Helper allowlist bypass** — `PathLooksLikeAllowlistedPlugin` checks `hasSuffix:@".dylib"` and `rangeOfString:@"/plugins/"`. Both pass for paths that escape the bundle (e.g. any `/tmp/.../plugins/x.dylib` directory shape).
3. **No code-signing check on the loaded dylib** — once allowlisted, `dlopen` is called without `SecStaticCodeCheckValidity` / team-id verification. A correct implementation would gate on a designated requirement string before loading.

Plus one red herring: the host's `Info.plist` declares `NSAppleEventsUsageDescription`, which looks like it grants Apple Events automation but is unused — the host never sends any AppleScript.
