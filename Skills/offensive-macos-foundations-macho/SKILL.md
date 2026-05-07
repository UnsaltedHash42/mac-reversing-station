---
name: offensive-macos-foundations-macho
description: >-
  Use when analyzing a Mach-O binary's file layout — header, load commands,
  segments, sections, symbol tables, chained fixups, code signature,
  entitlements — or when reading the dyld shared cache, fat/universal binaries,
  or any artifact where understanding the Mach-O container itself is the
  prerequisite for the next step. Fires on questions like "what are the load
  commands of this binary", "which dylibs does it link", "is this arm64 or
  universal", "where is the __TEXT segment", "how do chained fixups work in
  macOS 14+", or "extract the dyld shared cache".
folder: offensive-macos-foundations-macho
source: skillz-wave1
trigger_phrases:
  - "mach-o header"
  - "load commands"
  - "universal binary"
  - "dyld shared cache"
  - "chained fixups"
  - "otool"
---

# Mach-O foundations

> **Channel boundary:** This skill operates under `REPO_MODE=analysis`
> (see `cursor/rule-analysis.mdc`). Root-cause analysis, lab reproduction,
> defensive mapping, tooling guidance only. No operational exploit authoring.

## When to use

- A binary just landed in `./targets/` and you need to characterize it
  (arch, linkage, entitlements, signing, suspicious load commands).
- You are tracing a crash or injection bug and need to know exactly
  which `LC_LOAD_DYLIB`, `LC_RPATH`, or `LC_LOAD_DYLINKER` entry sent the
  loader down a given path.
- You are hunting dylib-hijack candidates and need to enumerate `@rpath`,
  `@loader_path`, `@executable_path` references, and weak-loads.
- You opened the binary in Ghidra via MCP and you want to sanity-check
  Ghidra's view against the raw header before you trust its pseudocode.
- A question about the **dyld shared cache** comes up — extracting it,
  resolving symbols inside it, or explaining why a symbol `otool -L`
  shows does not appear in the filesystem.

## Lab topology — where to run this

| Step | Where | How |
|------|-------|-----|
| Raw header + load commands sanity check | Workstation | `otool -h -l ./targets/foo` |
| Verify architecture slice(s) | Workstation | `lipo -info ./targets/foo` |
| Extract one arch from a universal | Workstation | `lipo -thin arm64 ./targets/foo -output foo.arm64` |
| List linked dylibs + rpaths | Workstation | `otool -L` and `otool -l \| grep -A 2 LC_RPATH` |
| Full disassembly + cross-reference | VM (Ghidra) | `ghidra-mcp` tools after opening in Ghidra |
| dyld shared cache extraction | VM | `dyld_shared_cache_util -extract ...` (on VM; cache path differs from workstation) |

See [`Skills/offensive-macos-station-topology/SKILL.md`](../offensive-macos-station-topology/SKILL.md)
for the full routing rationale.

## Theory

### The container, in one sentence

A Mach-O file is a **header** that says "here are N load commands and
this is my CPU type"; followed by **N load commands** that each either
describe a region of the file (segments, symbol table, signature) or
tell the dynamic loader what to do when loading it (link this dylib,
run this entrypoint, set this rpath); followed by the **data** that
those load commands describe.

The canonical source of truth for every field in the format is Apple's
`<mach-o/loader.h>` (shipped in the macOS SDK). This skill is the station
index for the container and points at Apple headers plus practical Ghidra
workflows for deeper reference.

### Universal / fat binaries

Apple Silicon Macs still ship many binaries as **universal** (aka
"fat") — a thin outer wrapper that contains multiple Mach-O slices,
typically arm64 + x86_64. The wrapper is a `fat_header` followed by
N `fat_arch` entries.

| Magic | Meaning |
|-------|---------|
| `0xCAFEBABE` | 32-bit fat header (big-endian on disk) |
| `0xCAFEBABF` | 64-bit fat header (for large slices, e.g. dyld shared cache bits) |
| `0xFEEDFACE` | thin 32-bit Mach-O |
| `0xFEEDFACF` | thin 64-bit Mach-O (everything on arm64 / x86_64) |

Notes:

- The magics are **endian-swapped**: a universal file on disk starts
  `CA FE BA BE`, while the thin Mach-O inside it starts `CF FA ED FE`
  (the runtime reads these as host-endian after swap).
- `lipo -info foo` is the one-liner arch check. `lipo -thin arm64 foo
  -output foo.arm64` gives you a thin file you can feed to tools that
  choke on universal inputs (older Ghidra builds, some analysis
  scripts).
- Apple is slowly dropping `x86_64` slices from system binaries on
  Apple Silicon macOS; a 2024+ system binary that is arm64-only is
  expected, not suspicious.

### The thin Mach-O header

For arm64 (and all modern macOS), the header is `mach_header_64`:

```
struct mach_header_64 {
    uint32_t   magic;        // MH_MAGIC_64 = 0xFEEDFACF
    cpu_type_t cputype;      // CPU_TYPE_ARM64 = 0x0100000C, CPU_TYPE_X86_64 = 0x01000007
    cpu_subtype_t cpusubtype;// CPU_SUBTYPE_ARM64_ALL, or _E / _H for Apple Silicon perf cores
    uint32_t   filetype;     // MH_EXECUTE=2, MH_DYLIB=6, MH_BUNDLE=8, MH_DSYM=0xA, MH_KEXT_BUNDLE=0xB
    uint32_t   ncmds;        // number of load commands that follow
    uint32_t   sizeofcmds;   // total size in bytes of those load commands
    uint32_t   flags;        // MH_NOUNDEFS, MH_DYLDLINK, MH_TWOLEVEL, MH_PIE, MH_HAS_TLV_DESCRIPTORS, ...
    uint32_t   reserved;
};
```

Fields that bite during RE:

- **`filetype`** tells you what *kind* of Mach-O you are looking at.
  Don't assume `MH_EXECUTE`. XPC helpers ship as `MH_EXECUTE` but live
  inside `.app/Contents/XPCServices/*.xpc`; system-extension daemons
  are `MH_EXECUTE`; many Apple binaries that *look* like libraries
  (e.g. the things in `/System/Library/PrivateFrameworks`) are
  `MH_DYLIB`. Kexts are `MH_KEXT_BUNDLE` (relevant for Wave 4).
- **`flags`** includes `MH_PIE` (position-independent, which is the
  default for decades now), `MH_TWOLEVEL` (two-level namespace — means
  every imported symbol is scoped to the specific dylib that exports
  it; has consequences for dylib-hijack attacks covered in Wave 2),
  `MH_WEAK_DEFINES` / `MH_BINDS_TO_WEAK` (weak linkage — relevant for
  cross-version behavior bugs), and `MH_HAS_TLV_DESCRIPTORS` (thread-
  local storage is present; matters for init-order attacks).
- **`ncmds` / `sizeofcmds`** are the only way to know how far to walk
  into the file for the load-command region. Everything after that is
  segment data described *by* the load commands.

Quick check:

    otool -h ./targets/foo

gives the human-readable header. The fields map 1:1.

### Load commands — the RE catalogue

There are ~40 defined load commands. For reversing macOS user-space
binaries you care about these; the rest show up rarely enough to look
up in `<mach-o/loader.h>` when they do.

| Load command | Size/kind | What it says |
|--------------|-----------|--------------|
| `LC_SEGMENT_64` | per segment | Describes a segment (`__TEXT`, `__DATA`, `__LINKEDIT`, `__DATA_CONST`, `__OBJC`, `__DATA_DIRTY`, …). Contains inline array of `section_64` entries. |
| `LC_SYMTAB` | one | Offset + count of the classic symbol table and string table in `__LINKEDIT`. |
| `LC_DYSYMTAB` | one | Tables for local / defined-external / undefined symbols, indirect symbol table. What `nm` and the dynamic linker consult. |
| `LC_LOAD_DYLINKER` | one | Path to the dynamic linker. Always `/usr/lib/dyld` for macOS executables. |
| `LC_UUID` | one | 128-bit identifier for this exact build. dSYM matching and crash symbolication key off this. |
| `LC_VERSION_MIN_MACOSX` / `LC_BUILD_VERSION` | one | Minimum macOS version + SDK. `LC_BUILD_VERSION` is the modern form (12+). |
| `LC_SOURCE_VERSION` | one | Freeform build source version (compiler-provided string). |
| `LC_MAIN` | one (exec only) | File offset of the program entrypoint. Replaced the old `LC_UNIXTHREAD` for standard executables. |
| `LC_LOAD_DYLIB` | per linked lib | A dylib this binary links against. Path + version info. |
| `LC_LOAD_WEAK_DYLIB` | per linked lib | Same, but if the dylib is missing the loader just leaves the symbols null rather than erroring. |
| `LC_REEXPORT_DYLIB` | per linked lib | Re-exports the dylib — anyone linking us gets its symbols as if we defined them. Apple umbrella frameworks do this heavily. |
| `LC_LAZY_LOAD_DYLIB` | per linked lib | Rare. Lazy-loaded. |
| `LC_LOAD_UPWARD_DYLIB` | per linked lib | Cycle-breaker for two dylibs that depend on each other. |
| `LC_RPATH` | per rpath | One entry in the loader's rpath search list — used to resolve `@rpath/...` references in `LC_LOAD_DYLIB` paths. **Every** rpath is an attack-surface entry point for dylib hijacking. |
| `LC_ID_DYLIB` | one (dylib only) | This dylib's own install name (what shows up in `otool -L` of things that link it). |
| `LC_CODE_SIGNATURE` | one (usually) | Offset + size of the code signature blob at the end of `__LINKEDIT`. |
| `LC_FUNCTION_STARTS` | one | Compressed table of function start offsets. How Ghidra/lldb get clean function boundaries without symbols. |
| `LC_DATA_IN_CODE` | one | Ranges that are *data* inside the code segment (jump tables, switch tables) — don't disassemble them. |
| `LC_ENCRYPTION_INFO_64` | one | Indicates an encrypted region. iOS-signed binaries use this; macOS executables almost never do. |
| `LC_DYLD_INFO_ONLY` | one (pre-iOS 15 / macOS 12) | Compressed rebase, bind, weak-bind, lazy-bind, and export trie info. |
| `LC_DYLD_CHAINED_FIXUPS` | one (macOS 12+) | Modern replacement for `LC_DYLD_INFO_ONLY`. See "Chained fixups" below. |
| `LC_DYLD_EXPORTS_TRIE` | one (macOS 12+) | Export trie in its own blob (was embedded in DYLD_INFO). |
| `LC_SEGMENT_SPLIT_INFO` | one | Data that lets dyld merge this binary into the shared cache. Only present in things destined for the shared cache. |

Key mental models:

- **Segments vs sections.** A segment (`__TEXT`) gets one VM mapping
  with one set of permissions. It contains sections (`__TEXT.__text`,
  `__TEXT.__cstring`, `__TEXT.__objc_methname`, …) which are
  informational subdivisions. The kernel mapper only cares about
  segments; Ghidra and lldb care about sections.
- **`__LINKEDIT` is the metadata segment.** Symbol table, string table,
  function starts, chained-fixups data, code signature — everything
  dyld consumes at load time but the program code itself does not
  reference. When you `strip` a binary, you are shrinking its
  `__LINKEDIT`.
- **`__DATA_CONST` is read-only-after-bind.** dyld writes to it during
  load (to resolve pointers) then re-protects it read-only. This is
  why simple `dlsym`+`memcpy` patching of function pointers no longer
  works the way it did on older macOS; the relevant pages are
  re-protected before you get to run.

List them all for your target:

    otool -l ./targets/foo | less

or via Ghidra MCP:

    ghidra-mcp: get_current_assembly    # after opening the binary and Notify Document Loaded

### Chained fixups (the macOS 12+ rebind format)

Starting with macOS Monterey, Apple replaced `LC_DYLD_INFO_ONLY`'s
compressed-bind encoding with **chained fixups** (`LC_DYLD_CHAINED_FIXUPS`).
The idea:

- Pointers in the binary are stored as **packed 64-bit words**, not
  raw VA's.
- Each pointer word contains: the target (for a rebase, a VM offset;
  for a bind, an import-table index), a small next-offset, and a flag
  bit.
- The loader walks the chain — starts at each fixup anchor, reads the
  packed word, patches it into a real address, follows the next-offset
  to the next packed word, repeats until the flag says "end of chain".

Implications for RE:

- **`otool -Iv` and `otool -ldv`** on a chained-fixups binary show
  the fixups in a readable form. The raw bytes look nothing like real
  addresses — don't try to dereference them pre-load.
- The "stubs" section (`__stubs`) still exists, but the indirection
  through it is implemented via chained fixups rather than classic
  lazy binding. See "External C function resolution" in
  [`Skills/offensive-macos-tooling-ghidra-headless/SKILL.md`](../offensive-macos-tooling-ghidra-headless/SKILL.md).
- When writing shellcode that walks pointers in a target binary (see
  [`Skills/offensive-macos-shellcode-arm64/SKILL.md`](../offensive-macos-shellcode-arm64/SKILL.md),
  dyld shared cache walks), remember: the pointer you are reading only has
  its "real" value *after* dyld has resolved that chain. Pre-dyld,
  it's packed metadata.

### Symbol table (`LC_SYMTAB` + `LC_DYSYMTAB`)

- `LC_SYMTAB` gives you `symoff` + `nsyms` + `stroff` + `strsize`.
  The symbol table is an array of `struct nlist_64`; each entry points
  into the string table for its name.
- `LC_DYSYMTAB` partitions that table into three ranges — local
  symbols, externally-defined symbols (exports), undefined symbols
  (imports) — plus the `indirectsymtab` which backs indirect jump
  tables for `__stubs` / `__la_symbol_ptr`.
- `strip` removes the local-symbol range. What you are left with is
  the exported and imported symbols — which is why stripped binaries
  still have readable function names for things like
  `___stack_chk_fail` (imported) or your public functions (exported)
  but lose internal helper names.

`nm -m ./targets/foo` is the right one-liner to read this; it
prints both sides with human-readable scopes.

### Sections that give away semantic info

| Section | Segment | What it holds | How you use it |
|---------|---------|---------------|----------------|
| `__text` | `__TEXT` | Executable code | The thing Ghidra disassembles. |
| `__stubs` | `__TEXT` | Tiny jump stubs to imports (one 12-byte-ish stub per imported function) | Follow a `bl _printf` — it lands here first, then to the real lib. |
| `__cstring` | `__TEXT` | C string literals | `strings ./foo` dumps this + `__objc_methname` + friends. |
| `__objc_methname` | `__TEXT` | Objective-C selector names | Used to reconstruct class/method tables. See `foundations-objc-runtime` skill. |
| `__objc_classname` | `__TEXT` | Objective-C class names | Same. |
| `__objc_classlist` | `__DATA_CONST` | Pointers to every Objective-C class's metadata | Starting point for objc class enumeration in Ghidra. |
| `__objc_protolist` | `__DATA_CONST` | Pointers to every Objective-C protocol | Same. |
| `__got` | `__DATA_CONST` | Global Offset Table — resolved import pointers | After dyld, each entry is the real address of an imported symbol. |
| `__la_symbol_ptr` | `__DATA` | Lazy symbol pointers | Historical; mostly replaced by chained fixups. |
| `__const` | `__DATA_CONST` | C/C++ const globals | Read-only after dyld. |
| `__data` | `__DATA` | Mutable globals | Writable throughout program life. |
| `__bss` | `__DATA` | Zero-initialized mutable globals | Same, but not on-disk. |
| `__swift5_*` | `__TEXT` | Swift metadata (`__swift5_types`, `__swift5_proto`, …) | See `foundations-swift-abi` skill. |

### Code signature and entitlements

`LC_CODE_SIGNATURE` points to a **SuperBlob** at the tail of
`__LINKEDIT`. The SuperBlob contains:

- A **CodeDirectory** (CD) — hash-of-hashes covering every page of
  `__TEXT`, plus the binary's `cdhash`, team ID, signing flags
  (hardened runtime? library-validation? get-task-allow? runtime?),
  and execution restrictions.
- An **entitlements blob** — an XML plist of entitlements the binary
  claims.
- An **entitlements-der blob** — the same entitlements in DER form
  (macOS 12+ requires this for launchd-style checks).
- A **Requirement Set** — the "Designated Requirement" (DR) that
  signed code must satisfy to be considered equivalent to this
  binary. You see these as the `designated =>` lines in `codesign
  -d` output.
- A **CMS signature** — the actual cryptographic signature, signed
  by Apple's root (or adhoc, which means "no signature at all,
  cdhash only").

Two things that matter for RE every single day:

1. **`get-task-allow`** and **`com.apple.security.cs.disable-library-validation`**
   are the two entitlements that make a binary debuggable / injectable
   respectively. An application that wants to be your dylib-hijack
   target must either be adhoc-signed, lack hardened-runtime, *or*
   have one of these. AMFI and hardened runtime behavior decide the full check
   flow; Wave 2's dylib-hijack skill will cite this directly.
2. **Library validation** (on hardened-runtime binaries) means the
   loader will reject any dylib not signed by the same team ID. This
   is what kills most classical DYLD_INSERT_LIBRARIES attacks on
   modern binaries — without `disable-library-validation`, your
   unsigned (or differently-signed) dylib never gets mapped.

Inspect with:

    codesign -dvvv --entitlements - --requirements - ./targets/foo

Or via MCP:

    macre-vm-mcp: codesign_inspect {"binary_path": "/path/on/VM"}
    macre-vm-mcp: entitlement_dump {"binary_path": "/path/on/VM"}

The `entitlement_dump` tool returns the parsed plist as a dict, which
is what you want to feed into subsequent reasoning.

### The dyld shared cache

Starting with macOS 11 (and aggressively ever since), Apple **merges
every system dylib into one giant file** — the dyld shared cache,
stored in
`/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e`
(macOS 26) or similar paths on earlier versions.

Consequences:

- **System dylibs no longer exist as individual files on disk.**
  `/usr/lib/libSystem.B.dylib` does not exist as a file; its symbols
  live inside the shared cache. `otool -L ./targets/foo` still lists
  `libSystem.B.dylib` — the loader knows to resolve it from the
  cache.
- **You cannot run `nm /usr/lib/libSystem.B.dylib` — there is no
  file.** Extract it from the cache first.
- **Symbolication** of crashes and traces requires the cache. tools
  like `atos` and Ghidra handle it transparently.

Extract a dylib from the cache (VM-side, because the cache is
per-machine and uses host-specific paths):

    # Find the cache — path varies by macOS version.
    ls /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/ 2>/dev/null \
      || ls /System/Library/dyld/ 2>/dev/null

    # Extract everything (big; you probably want a specific dylib)
    /usr/bin/dyld_shared_cache_util -extract /tmp/extracted /path/to/dyld_shared_cache_arm64e

On the workstation, pull the extracted files back via `scp` if you
want to disassemble them locally. More commonly: open the cache
directly in Ghidra on the VM — Ghidra understands the format.

For dyld shared cache details, prefer Apple dyld source and local Ghidra observations.

## Workflow

The canonical first-contact flow for a new binary:

1. **Copy it into the project's `targets/` dir on the workstation.**
2. **Sync to the VM:** `bash scripts/rsync-to-vm.sh ./targets/`.
3. **Arch + fat?** Workstation: `lipo -info targets/foo`.
4. **Raw header + load commands:** Workstation: `otool -h -l
   targets/foo | less`. Tag interesting entries.
5. **Linked dylibs + rpaths:** Workstation:
   `otool -L targets/foo` for direct dylibs, then
   `otool -l targets/foo | awk '/LC_RPATH/{found=1} found && /path /{print; found=0}'`
   for rpaths. Record any `@rpath`, `@loader_path`, `@executable_path`
   references (Wave 2 hijack surface).
6. **Code signature + entitlements:** VM via
   `macre-vm-mcp: codesign_inspect` and
   `macre-vm-mcp: entitlement_dump`. Capture: team ID, signing flags
   (hardened runtime? library validation? adhoc?), entitlement plist.
7. **Deep disassembly:** Open in Ghidra on the VM (see
   [`Skills/offensive-macos-tooling-ghidra-headless/SKILL.md`](../offensive-macos-tooling-ghidra-headless/SKILL.md)),
   then drive via `ghidra-mcp` tools from Cursor.

Every later Wave 1 skill (obj-c runtime, Swift ABI, tooling-hopper)
assumes you have already completed steps 1–6 for the target under
analysis.

## Current Bug-Class Anchors

### RemoteViewServices-style sandbox escapes

wh1te4ever's partial-sandbox escape abused an XPC service that loaded
a crafted dylib whose `LC_LOAD_DYLIB` chain and entitlement layout
tricked the victim into running attacker code outside the sandbox.
The fix tightened checks in the loader before honoring certain
`LC_LOAD_WEAK_DYLIB` and `@rpath` references inside XPC-loaded
bundles. The vulnerability is a good example of why the **rpath +
dylib-path combination is a security-relevant attribute of the
Mach-O itself**, not just a loader implementation detail. Upstream
write-up: https://gbhackers.com/macos-sandbox-escape-vulnerability/

### dyld restriction bypasses

Historical write-ups document several bugs where the
interaction between `LC_LOAD_DYLIB`, `LC_RPATH`, and AMFI's
`amfi_check_dyld_policy_self` produced an injectable binary despite
the hardened runtime. Every bug had the same shape: the Mach-O
container said one thing, AMFI interpreted it differently, dyld
honored the Mach-O. Read those sections alongside this skill — they
are the primary reason this skill exists.

## Pitfalls

- **SIP is OFF on NightBlood.** On a SIP-on machine you cannot attach
  a debugger to any Apple-signed binary, you cannot read from
  `__RESTRICT` segments of them, and `dtrace`'s pid provider is
  heavily neutered for Apple code. Every recipe in this skill assumes
  SIP-off. If the station is ever used against a SIP-on host, flag
  this explicitly.
- **`otool` outputs differ across macOS versions.** The modern
  `llvm-otool` (via Xcode Command Line Tools) is more verbose than
  the classic Apple binary and adds a few columns. Pipe through
  `awk`/`grep` rather than parsing fixed-width output.
- **A binary's "armv7" slice is not armv7 on Apple Silicon.**
  Universal slices occasionally have weird cpusubtype values; trust
  `lipo -info`, not naked `cpusubtype` numerics.
- **"No symbols" does not mean "stripped."** Ghidra's pseudocode
  often shows `sub_10000abcd` because the binary was stripped of
  *local* symbols; the exported / imported ones are still there in
  `LC_SYMTAB` and `LC_DYSYMTAB`. `nm -m` shows them.
- **Shared-cache symbols look missing on `nm`.** `nm /usr/lib/libfoo.dylib`
  on modern macOS returns nothing because the file does not exist on
  disk. Extract via `dyld_shared_cache_util -extract` first. See the
  dyld shared cache section above.

## Micro-exercise

*Goal:* characterize a small Mach-O end-to-end using only this skill.

1. Compile a toy Objective-C binary on the workstation:

        cat > /tmp/hello.m <<'EOF'
        #import <Foundation/Foundation.h>
        @interface Greeter : NSObject
        - (void)sayHi;
        @end
        @implementation Greeter
        - (void)sayHi { NSLog(@"hi from %@", [self class]); }
        @end
        int main(int argc, char *argv[]) {
            @autoreleasepool {
                [[Greeter new] sayHi];
            }
            return 0;
        }
        EOF
        clang -fobjc-arc -framework Foundation -o /tmp/hello /tmp/hello.m

2. Run `otool -h /tmp/hello` and note: `cputype`, `filetype`, `ncmds`.
3. Run `otool -L /tmp/hello` and confirm you see
   `/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation`
   (or similar).
4. Sync it to the VM (from an RE project directory that has `/tmp/hello`
   copied into `./targets/`):

        cp /tmp/hello ./targets/hello
        bash scripts/rsync-to-vm.sh ./targets/

5. From Cursor, call `macre-vm-mcp: codesign_inspect` on
   `/Users/szeth/Targets/<project>/hello`. Confirm: adhoc-signed, no
   hardened-runtime flag, no entitlements.
6. Open `/Users/szeth/Targets/<project>/hello` in Ghidra on the VM
   (see [`Skills/offensive-macos-tooling-ghidra-headless/SKILL.md`](../offensive-macos-tooling-ghidra-headless/SKILL.md)).
   From Cursor, call `ghidra-mcp: get_assembly_by_name` with name
   `-[Greeter sayHi]` and confirm you see the `objc_msgSend` call.

Success = every step produces the expected field value without
surprise, and you can explain — from memory — what each field means.

## See also

- [`Skills/offensive-macos-foundations-objc-runtime/SKILL.md`](../offensive-macos-foundations-objc-runtime/SKILL.md) — what the `__objc_*` sections you saw in step 6 actually contain.
- [`Skills/offensive-macos-tooling-ghidra-headless/SKILL.md`](../offensive-macos-tooling-ghidra-headless/SKILL.md) — how to drive the MCP calls in the exercise above.
- [`Skills/offensive-macos-tooling-cli-static/SKILL.md`](../offensive-macos-tooling-cli-static/SKILL.md) — `otool`, `nm`, `jtool2`, `class-dump`, `plutil` in depth.
- Apple `<mach-o/loader.h>` in the macOS SDK — always the final word on any field.
- Apple's open-source `dyld` — https://github.com/apple-oss-distributions/dyld — read `ProcessConfig::Security::Security` for how the loader decides to trust your binary.
