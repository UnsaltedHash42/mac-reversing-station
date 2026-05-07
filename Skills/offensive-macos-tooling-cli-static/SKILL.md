---
name: offensive-macos-tooling-cli-static
description: >-
  Use when a question is answerable by command-line static inspection
  of a Mach-O binary without loading it into Ghidra or running it.
  Covers otool, nm, jtool2, codesign, spctl, strings, class-dump,
  plutil, lipo, dyld_info, and their MCP wrappers. Fires on "what
  dylibs does this link", "is this binary signed", "dump its
  entitlements", "show the class list", "convert this plist", "strip
  the symbol table", "show imports", "list rpaths", "inspect
  universal binary slices".
folder: offensive-macos-tooling-cli-static
source: skillz-wave1
trigger_phrases:
  - "otool"
  - "codesign inspect"
  - "class-dump"
  - "jtool"
  - "spctl"
  - "plutil"
  - "dyld_info"
---

# CLI static tooling — Mach-O from the shell

> **Channel boundary:** `REPO_MODE=analysis`.

## When to use

- You have a Mach-O binary on disk and you want to answer a specific
  factual question about its contents in <30 seconds.
- You want to preprocess a binary before handing it off to Ghidra —
  confirm arch, slice out one arch, check the signature, dump
  entitlements for context.
- You want to script bulk analysis across many targets (an
  `.app` bundle's every binary, all KEXTs in a folder, every XPC
  service inside a framework).

## Lab topology — where to run this

Most tools (`otool`, `nm`, `lipo`, `strings`, `codesign`, `spctl`,
`plutil`, `file`, `class-dump`, `dyld_info`) exist on **both** the
workstation and NightBlood. Default to workstation for speed; use
`macre-vm-mcp` when the binary under analysis only lives on the VM
(e.g. a shared-cache extraction, or a system binary with
version-specific paths).

| Tool | Workstation-local | MCP equivalent on VM |
|------|-------------------|----------------------|
| `otool -h`, `-l`, `-L`, `-tV`, `-Iv` | yes | none yet; SSH directly |
| `nm -m` | yes | SSH directly |
| `lipo -info`, `-thin` | yes | SSH directly |
| `strings` | yes | SSH directly |
| `file` | yes | SSH directly |
| `codesign -dv --entitlements - --requirements -` | yes | `macre-vm-mcp: codesign_inspect` |
| `codesign -d --entitlements :-` | yes | `macre-vm-mcp: entitlement_dump` (parsed) |
| `spctl --assess --verbose=4 --type execute` | yes | `macre-vm-mcp: spctl_assess` |
| `class-dump` | yes (via brew) | SSH directly |
| `plutil -convert xml1 -o - foo.plist` | yes | SSH directly |
| `dyld_info -platform -imports -exports` | yes (macOS 13+) | SSH directly |
| `dyld_shared_cache_util -extract` | no (cache is per-machine) | SSH on VM |

## Theory

### Tool inventory, by question

| You want to know… | Use |
|-------------------|-----|
| Is this a Mach-O? Fat? Thin? What arch? | `file foo` then `lipo -info foo` |
| What does the header look like? | `otool -h foo` |
| What load commands? | `otool -l foo` |
| What dylibs does it link? | `otool -L foo` |
| What are the rpaths? | `otool -l foo \| awk '/LC_RPATH/{f=1} f && /path /{print; f=0}'` |
| What are the exported / imported / local symbols? | `nm -m foo` |
| What does the ARM64 disassembly look like? (quick peek) | `otool -tV foo` or `otool -tV -arch arm64 foo` |
| What are the imports table's resolved addresses? | `otool -Iv foo` |
| What are the chained fixups? | `dyld_info -fixups foo` (macOS 13+) |
| What symbols does `dyld_info` see? | `dyld_info -platform -imports -exports foo` |
| Is it signed? By whom? | `codesign -dv foo` (stderr) |
| What entitlements? | `codesign -d --entitlements :- foo` or `macre-vm-mcp: entitlement_dump` |
| Will Gatekeeper accept it? | `spctl --assess --verbose=4 --type execute foo` |
| What ObjC classes and methods? | `class-dump foo` (first pass; Ghidra for deep) |
| What raw printable strings? | `strings -n 8 foo` |
| Parse a plist? | `plutil -convert xml1 -o - foo.plist` |
| Convert fat to thin? | `lipo -thin arm64 foo -output foo.arm64` |

### `otool` field reference

`otool -h` output fields, left to right:

    magic cputype cpusubtype caps filetype ncmds sizeofcmds flags

Map to `struct mach_header_64` one-to-one; the
[`macho-foundations`](../offensive-macos-foundations-macho/SKILL.md) skill has
the full field meanings. `caps` encodes pointer authentication
capability bits on Apple Silicon — on a standard arm64e binary
you'll see `PTR_AUTH_VERSION USERSPACE 0`.

`otool -l` output is one load command per block. Useful `grep`
patterns:

    otool -l foo | grep -A 4 LC_MAIN         # entry point
    otool -l foo | grep -A 6 LC_BUILD_VERSION  # min/sdk versions
    otool -l foo | grep -A 2 LC_UUID           # build UUID
    otool -l foo | grep -A 2 LC_RPATH          # every rpath

`otool -L` gives you linkage — one line per `LC_LOAD_DYLIB`:

    foo:
        @rpath/libfoo.dylib (compatibility version 1.0.0, current version 1.2.3)
        /usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1345.0.0)
        /System/Library/Frameworks/Foundation.framework/Versions/C/Foundation (…)

`@rpath` entries are the dylib-hijack surface; record every one.

### `nm` — symbols

    nm -m foo

Each line is one symbol with scope/section/name:

    0000000100003f50 (__TEXT,__text) external _main
    0000000100004000 (__TEXT,__stubs) external _printf
                     (undefined) external _objc_msgSend (from libobjc)

Fields: address (or blank for undefined), `(segment,section)`,
scope, name, dylib source (if undefined). Chains:

- **`external`** = defined here, visible to linkers.
- **`non-external`** = defined here but local scope; strip removes
  these.
- **`undefined external`** = import; resolved at load by dyld.
- **`weak`** = a `__weak` symbol; resolver nulls it if the exporter
  is missing.

### `codesign -dv` — read carefully

Every field matters:

    Format=app bundle with Mach-O universal (x86_64 arm64)
    CodeDirectory v=20500 size=75829 flags=0x10000(runtime) hashes=2360+7 ...
    Authority=Apple Distribution: Example Inc (TEAMID)
    Authority=Apple Worldwide Developer Relations Certification Authority
    Authority=Apple Root CA
    TeamIdentifier=TEAMID
    Sealed Resources version=2 rules=13 files=42
    Internal requirements count=1 size=176

Reads to file:

- `flags=0x10000(runtime)` means **hardened runtime** is on. That
  flips on library validation; any dylib injected into this binary
  must have the same Team ID signature. This is the primary defense
  against dylib-hijack that Wave 2 will discuss.
- `flags=0x20002(adhoc,linker-signed)` means no real signature —
  adhoc. Not hardened-runtime-restricted; injectable.
- `TeamIdentifier=...` is the team ID for matching.
- **Missing `flags=...(runtime)`**: not hardened. Check
  entitlements for `get-task-allow` or
  `com.apple.security.cs.allow-dyld-environment-variables` —
  either one gives you debug / inject primitives.

Then on a separate line:

    Entitlements=<?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" ...>
    <plist version="1.0">
    <dict>
        <key>com.apple.security.app-sandbox</key>
        <true/>
        ...

The MCP `entitlement_dump` tool parses this dict for you.

### `class-dump` — when it works, when it doesn't

On an ObjC-centric or ObjC/Swift-bridged binary:

    class-dump ./targets/foo | less

You get every class declaration with methods, properties, and
ivars in a `.h`-like format. For Swift-only, see the
[`swift-abi` skill](../offensive-macos-foundations-swift-abi/SKILL.md).

`class-dump-swift` (community fork) handles Swift metadata but
lags behind Apple; outputs are often partial. Ghidra's Swift view
is more reliable.

### `jtool2` (when macOS-default tools fall short)

`jtool2` (Jonathan Levin's tool) is a superset of `otool` — it
decodes more load commands, understands chained fixups fully,
handles more esoteric Mach-O edge cases, and produces cleaner output.
Install via `brew install jtool2` on the workstation.

Tasks where `jtool2` beats `otool`:

- `jtool2 -l foo` — cleaner load-command dump.
- `jtool2 --sig foo` — pretty-print code signature contents.
- `jtool2 --ent foo` — just the entitlements.
- `jtool2 --dc <shared cache>` — browse the dyld shared cache.

### `dyld_info` (macOS 13+)

Replaces much of `otool -Iv` and the old Apple-internal `DyldInfo`:

    dyld_info -platform foo          # build platform + min OS
    dyld_info -imports foo           # import list, symbol + dylib
    dyld_info -exports foo           # export trie
    dyld_info -fixups foo            # chained-fixups entries
    dyld_info -bindings foo          # legacy bindings

The fixups output is often the fastest way to see every bound
pointer in the binary without loading it.

## Workflow

### A: "first 60 seconds with a new binary"

    cd ~/re/<project>
    ls -la ./targets/foo
    file ./targets/foo
    lipo -info ./targets/foo
    otool -h ./targets/foo
    otool -L ./targets/foo
    otool -l ./targets/foo | grep -A 2 LC_RPATH
    codesign -dv --entitlements - --requirements - ./targets/foo 2>&1 \
      | less
    spctl --assess --verbose=4 --type execute ./targets/foo 2>&1

If `class-dump` is installed and the binary is ObjC-heavy:

    class-dump ./targets/foo | head -200

Then open the binary with `ghidra-mcp` for code-level analysis.

### B: "audit every binary inside an `.app` bundle"

    APP=./targets/SomeApp.app
    find "$APP/Contents" -type f -perm -u+x -exec file {} \; \
      | grep 'Mach-O' \
      | cut -d: -f1 \
      | while read b; do
          echo "=== $b ==="
          codesign -dv "$b" 2>&1 | grep -E 'TeamIdentifier|flags='
          otool -L "$b" | head -4
        done

Surfaces: which binaries are inside, what team signs them, what
common dylibs they depend on, and any `@rpath` / hardened-runtime
outliers.

### C: "dump entitlements of a VM-only binary"

    macre-vm-mcp: entitlement_dump {
      "binary_path": "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd"
    }

Returns a parsed dict you can reason about directly in Cursor. No
stdout parsing required.

### D: "thin a universal for Ghidra"

Some workflows still prefer a single architecture slice:

    lipo -thin arm64 ./targets/foo -output ./targets/foo.arm64
    file ./targets/foo.arm64     # confirms arm64-only

Then open the thin file with `ghidra-mcp` if universal import chooses
the wrong architecture or takes too long.

### E: "find every rpath in every binary under /Applications"

(interactive SSH, not MCP — scans a lot):

    ssh NightBlood '
      find /Applications -type f -perm -u+x 2>/dev/null | while read b; do
        if file "$b" 2>/dev/null | grep -q Mach-O; then
          rpaths=$(otool -l "$b" 2>/dev/null | awk "/LC_RPATH/{f=1} f && /path /{print; f=0}")
          if [ -n "$rpaths" ]; then
            echo "=== $b ==="
            echo "$rpaths"
          fi
        fi
      done
    '

Dylib-hijack surface, enumerated. Wave 2 builds on exactly this.

## Current Bug-Class Anchors

### `spctl` / Gatekeeper

Many Gatekeeper-bypass classes are
discovered by noticing that `spctl --assess` behaved differently
from what Apple claimed. `spctl --assess --verbose=4` output is the
primary way to reproduce each finding locally.

### Entitlement-only attack surface

Most 2024–2026 LPE and sandbox-escape CVEs boil down to "Binary X
holds entitlement Y, Binary X has a bug that lets untrusted input
reach the Y-enabled code path." Enumerating binaries by
entitlement is the hunt primitive. Flow:

1. `macre-vm-mcp: entitlement_dump` across a candidate set.
2. Filter for interesting entitlements
   (`com.apple.private.tcc.allow`, `com.apple.rootless.*`,
   `com.apple.security.cs.disable-library-validation`, etc.).
3. For each hit, feed the binary into the hunt workflow.

Wave 3's TCC-bypass skill uses this pattern as its starting move.

## Pitfalls

- **`otool -L` on a universal shows only one arch by default.** Pass
  `-arch arm64` or split the binary first.
- **`codesign -dv` writes signature info to stderr, not stdout.**
  Capture both: `2>&1 | grep ...`.
- **`class-dump` has multiple forks with different quirks.** The
  original `class-dump` by Steve Nygard is fine for 64-bit ObjC;
  `class-dump-swift` handles Swift metadata (imperfectly); the one
  shipped with tools like `RuntimeBrowser` may differ further. Pin
  a version when you script.
- **`strings` with no `-a` flag skips non-text sections on some
  platforms** — use `strings -a` on macOS to ensure full file scan.
- **`jtool2` is not installed by default.** If a recipe here
  assumes it, add `brew install jtool2` to the operator guide's
  one-time setup.
- **`dyld_info` requires macOS 13+.** On older targets, fall back
  to `otool -Iv` + `dyld_shared_cache_util`.
- **Entitlement XML can contain non-ASCII.** Parse via `plutil` or
  `plistlib` (what `macre-vm-mcp: entitlement_dump` uses), not raw
  text ops.

## Micro-exercise

*Goal:* characterize a binary in ≤60 seconds using only CLI tools.

1. On the workstation, pick `/bin/ls` (universally available).
2. Run this sequence; note the output of each:

        file /bin/ls
        lipo -info /bin/ls
        otool -h /bin/ls
        otool -L /bin/ls
        otool -l /bin/ls | grep -A 2 LC_RPATH   # expect: (no output)
        codesign -dv /bin/ls 2>&1 | head -10
        nm -m /bin/ls | head -5

3. For comparison, on the VM:

        macre-vm-mcp: codesign_inspect {"binary_path": "/bin/ls"}
        macre-vm-mcp: entitlement_dump {"binary_path": "/bin/ls"}

4. Success = you can state:
   - arch (arm64 + possibly x86_64, depending on macOS version)
   - number of load commands
   - linked dylibs (at least libSystem)
   - signing authority (Apple), team identifier
   - no entitlements

## See also

- [`Skills/offensive-macos-foundations-macho/SKILL.md`](../offensive-macos-foundations-macho/SKILL.md) — the meaning of every field these tools print.
- [`Skills/offensive-macos-tooling-ghidra-headless/SKILL.md`](../offensive-macos-tooling-ghidra-headless/SKILL.md) — next step after CLI static.
- [`macre-vm-mcp/src/macre_vm_mcp/tools_codesign.py`](../../macre-vm-mcp/src/macre_vm_mcp/tools_codesign.py) — exact MCP tool implementation.
- Jonathan Levin's `jtool2`: http://www.newosxbook.com/tools/jtool2.html
- Apple developer docs for `codesign(1)`, `spctl(8)`, `otool(1)`, `nm(1)`, `dyld_info(1)`, `plutil(1)`.
