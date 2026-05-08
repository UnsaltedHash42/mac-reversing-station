---
name: offensive-macos-hunt-private-framework-hijack
description: >-
  Use when auditing macOS binaries for dynamic-loading paths an attacker
  can influence: weak-linked PrivateFrameworks, dlopen with attacker-
  controlled paths, NSClassFromString / NSSelectorFromString driven by
  user input, Sparkle-style updater dylib resolution, runtime symbol
  resolution that trusts an unsigned dylib. Fires on "private framework
  hijack", "dylib hijack", "weak link bypass", "nsclassfromstring abuse",
  "dynamic symbol resolution audit".
folder: offensive-macos-hunt-private-framework-hijack
source: skillz-wave6
trigger_phrases:
  - "private framework hijack"
  - "dylib hijack"
  - "weak link bypass"
  - "nsclassfromstring abuse"
  - "dynamic symbol resolution audit"
---

# Hunt: private framework / dynamic lookup hijack

> Channel boundary: `REPO_MODE=analysis`. Hijack PoCs and persistence
> shapes live in private project clones, not this template.

## When to use

The target weak-links a PrivateFramework, an `@rpath`-relative dylib, or a path under `/Library/Application Support/<vendor>/`. The target calls `dlopen` with a path built at runtime from configuration, environment, or bundle resources. The target uses `NSClassFromString` / `NSSelectorFromString` with names that come from a user-readable plist, defaults, or remote config. A signed updater (Sparkle-derived or vendor-built) loads helper dylibs by relative path before validating the signature of the loaded bundle.

## Lab topology

| Step | Surface | How |
|---|---|---|
| Static sweep | lab host | `ghidra-mcp` + `~/ghidra-scripts/scan_private_framework_dependency.py` |
| Load commands | workstation | `otool -l <binary> \| grep -A 2 LC_LOAD` |
| Signature inspect | lab host | `macre-vm-mcp codesign_inspect`, `entitlement_dump` |
| Runtime confirmation | crash-test | DTrace on `dlopen`; lldb breakpoint on `dlopen` / `NSClassFromString` |
| Path-control test | crash-test | drop a stub dylib at the candidate path; observe load |
| Evidence | findings repo | TSV + DTrace transcript + lldb log under `artifacts/`, hash-pinned |

## What the bug class is

macOS binaries resolve external code three ways:

Static linker entries: `LC_LOAD_DYLIB` with absolute or `@rpath` paths. Hijack opportunities are `@rpath` ordering, weak links, missing dylibs.

Runtime `dlopen`: argument can be absolute, a leaf name searched via `DYLD_LIBRARY_PATH`-equivalent paths, or a constructed string. Hijack opportunities: attacker-writable directory ahead of the legitimate one in the search order, or attacker-controlled argument string.

Runtime ObjC / Swift name lookup: `NSClassFromString` and `NSSelectorFromString` look up by name in already-loaded images. Hijack opportunity: an attacker who can plant a class with the same name into a loadable bundle the target loads.

The bug class is a privileged process loading a dylib (or resolving a symbol) from a path or name an unprivileged user can influence, and doing so before signature validation.

Three high-yield shapes:

Updater dylib hijack. Sparkle.framework historically allowed an attacker who could write to a `Frameworks/` directory to land a dylib that ran with the updater's privileges.

PrivateFramework substitution. Code expecting `Foo.framework/Foo` from `/System/Library/PrivateFrameworks/` falls back to `@rpath` if the system path is missing, which a user-writable rpath entry resolves to.

NSClassFromString plugin loading. Apps that load a class name from a config file then `[clazz alloc] init]`. If the loader doesn't validate the bundle's signature, the attacker substitutes the class.

## Anchor pattern

Strong: tier-A `dlopen_callsite` with a recovered path arg whose value is relative, `@rpath`-prefixed, or under `/Library/Application Support/`. The `@rpath` ones are especially strong; rpath order matters.

Strong: tier-A `nsclassfromstring_callsite` with a recovered class arg whose value comes from a string read from defaults / config (cross-reference with `scan_defaults_bypass.py` rows).

Medium: tier-A `dlopen_callsite` with a path resolving to an absolute system path. Less interesting unless you can race the path or symlink-swap.

Weak: tier-C `private_framework_path` rows alone. The string exists but isn't necessarily passed to `dlopen`. Navigate to find the actual call.

The reverse: a binary with no tier-A `dlopen_callsite` rows at all but many tier-C `private_framework_path` strings often has its dynamic loading done by a framework dependency. Trace the framework dep.

## Harness

Open the target and run the scan. For each tier-A `dlopen_callsite`, decompile the calling function and identify the source of the path string: literal, bundle resource, defaults, env var, XPC arg. Cross-reference with `procinfo` (codesign + entitlements). Does the loader run with privileges that the loaded dylib should not get?

Inspect load commands:

```bash
otool -l <binary> | grep -A 2 -E 'LC_LOAD|LC_RPATH'
```

## Behavioral confirmation

DTrace `dlopen` to see every dylib loaded at startup:

```bash
sudo dtrace -n 'pid$target::dlopen:entry { trace(copyinstr(arg0)); }' \
  -c '/Applications/<App>.app/Contents/MacOS/<binary>'
```

Look for loads from `@rpath` paths that resolve under user-writable directories, loads from `/Library/Application Support/<vendor>/` or other shared-but-writable paths, loads of leaf names that imply a search-path resolution.

For the Sparkle-style updater pattern, run the updater and watch for it loading helper dylibs *before* it validates the new bundle's signature. The window between `dlopen` and signature check is the bug.

For NSClassFromString, set lldb breakpoints:

```text
breakpoint set --name NSClassFromString
```

Hit the breakpoint and read the registers / stack to recover the string argument.

## Path-control test (crash-test VM only)

If the static path is confirmed user-writable, drop a stub dylib at that path:

```c
__attribute__((constructor)) static void hi(void) {
    fprintf(stderr, "loaded from %s\n", __FILE__);
}
```

Build, sign with an ad-hoc identity, place at the candidate path, re-launch the target. The stub's constructor printing means the hijack is real.

Snapshot the lab VM before this test. Even a benign stub leaves the system in a state where the legitimate dylib is shadowed.

## Triage

Enumerate `dlopen_callsite` and `nsclassfromstring_callsite` rows. Classify each path / name source: literal, bundle_resource, user_writable, xpc_arg, network. Rank by (privilege of loading process) × (writability of source). Confirm one candidate dynamically. Report path: name the loader process, the loaded path, the privilege gap, the moment-of-load relative to signature validation.

## Pitfalls

`@rpath` is plural. A binary can have multiple `LC_RPATH` entries; the first that resolves wins. Inspect order.

Hardened runtime + library validation. Recent macOS apps with hardened runtime + library-validation flags reject unsigned / wrongly-signed dylibs at load time. Check `codesign -dv` flags before claiming the hijack works.

TCC and notarization. A successful library load may not give the loaded code TCC-protected access; the hijack's impact depends on what the target does after loading.

PrivateFrameworks live in the dyld shared cache. A `LC_LOAD_DYLIB` pointing to `/System/Library/PrivateFrameworks/Foo.framework/Foo` won't have a file there to substitute on recent macOS; the dylib is in the shared cache. The hijack story for these requires a different shape (e.g., a fallback path that's filesystem-resolved).

Sparkle has been hardened. Recent Sparkle versions validate signatures earlier in the load sequence. Identify the version before claiming the classic pattern.

## Public anchors

Wojciech Reguła's series on macOS dylib hijacking (objective-see, multiple posts). Patrick Wardle's "Dylib Hijacking on OS X" (Synack, 2015) and follow-up updates. Project Zero on Apple binary loader behavior across releases.

## See also

- `Skills/offensive-macos-foundations-macho/SKILL.md`
- `Skills/offensive-macos-foundations-objc-runtime/SKILL.md`
- `Skills/offensive-macos-tooling-cli-static/SKILL.md`
- `Skills/offensive-macos-tooling-dtrace/SKILL.md`
- `Skills/offensive-macos-poc-authoring/SKILL.md`
- `ghidra-scripts/scan_private_framework_dependency.py`
- `ghidra-scripts/scan_defaults_bypass.py`
