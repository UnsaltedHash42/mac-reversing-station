---
name: offensive-macos-foundations-swift-abi
description: >-
  Use when reversing a Swift-heavy macOS binary and the Objective-C
  runtime view (class-dump, Ghidra's ObjC sidebar) is incomplete or
  shows mangled names. Fires on questions like "demangle this Swift
  symbol", "what's in __swift5_types", "how do I find a Swift method's
  implementation", "why does class-dump fail on this app", "what's a
  value witness table", "how does Swift's reabstraction / partial
  application work", or "is this class @objc or pure Swift". Covers
  Swift 5+ stable ABI; older name mangling (Swift 3/4) is noted as
  legacy.
folder: offensive-macos-foundations-swift-abi
source: skillz-wave1
trigger_phrases:
  - "swift demangle"
  - "swift metadata"
  - "__swift5_types"
  - "swift abi"
  - "@objc swift"
---

# Swift ABI foundations

> **Channel boundary:** `REPO_MODE=analysis`. RCA, lab repro, defensive
> mapping only.

## When to use

- `class-dump ./targets/foo` returned almost nothing but `otool -L`
  shows `libswiftCore.dylib` — the binary is mostly Swift.
- Ghidra symbols look like `$s8MyModule7GreeterC5sayHiyyF` — Swift
  mangled names you need to read.
- You need to call a Swift method at runtime (from an injected
  dylib, an lldb script, or a test harness) and you need the correct
  entry-point symbol and calling convention.
- You are chasing a bug in Swift-native code (no `@objc` bridging)
  and need to find the method implementation.
- You are auditing an XPC service whose exported interface includes
  Swift types.

## Lab topology — where to run this

| Step | Where | How |
|------|-------|-----|
| Demangle a Swift symbol | Workstation | `xcrun swift demangle '$s8MyModule...'` |
| Dump Swift metadata | VM (Ghidra) | Ghidra's Swift view + `ghidra-mcp: get_pseudocode_by_name` using demangled name |
| Call a Swift method via lldb | VM | `macre-vm-mcp: lldb_run` with `-o "po Module.Class.method(args)"` |
| Static inspect `__swift5_*` sections | Workstation | `otool -l ./targets/foo \| grep __swift5` |

## Theory

### Why Swift looks different from ObjC in Ghidra

Swift has **a separate runtime and a separate ABI** from ObjC. While
the Mach-O container is the same, Swift embeds its type and method
metadata in `__swift5_*` sections, its classes use a different layout
from `objc_class`, and its method dispatch is not via
`objc_msgSend` for non-`@objc` methods.

Three world-states to distinguish:

1. **Pure-Swift class** (`class Foo {}`): method dispatch is via
   Swift's vtable (for final or non-@objc methods) or protocol
   witness table (for protocol-dispatched methods). No
   `objc_msgSend`.
2. **`@objc` Swift class inheriting `NSObject`**: exists in **both**
   the ObjC `__objc_classlist` *and* the Swift `__swift5_types`.
   `@objc` methods on it use `objc_msgSend`; non-`@objc` methods use
   Swift dispatch.
3. **Objective-C class imported into Swift**: same ObjC layout as
   always; no Swift metadata.

`class-dump` only sees world 2 and world 3. Pure-Swift (world 1) is
invisible to `class-dump`.

### Name mangling (what the `$s` prefix means)

Swift 5 symbols start with `$s` or `_$s` (the underscore is the
standard C-symbol leading underscore). The rest is a compressed
grammar describing the fully-qualified name, parent contexts,
generic parameters, and type signature.

The best tool is `xcrun swift demangle`. Examples:

    $ xcrun swift demangle '$s8MyModule7GreeterC5sayHiyyF'
    $s8MyModule7GreeterC5sayHiyyF ---> MyModule.Greeter.sayHi() -> ()

    $ xcrun swift demangle '$s8MyModule7GreeterCACycfC'
    $s8MyModule7GreeterCACycfC ---> MyModule.Greeter.__allocating_init() -> MyModule.Greeter

Mangling grammar highlights (from Apple's
`swift/docs/ABI/Mangling.rst`):

| Piece | Meaning |
|-------|---------|
| `$s` | Swift 5+ stable ABI mangled name prefix |
| `8MyModule` | length-prefixed module name |
| `7Greeter` | length-prefixed type name |
| `C` | `class` (vs `V` for struct, `O` for enum, `P` for protocol) |
| `5sayHi` | length-prefixed method name |
| `yyF` | function signature — `F` = function, `y` = empty-tuple args, `y` = empty-tuple return |

You rarely mangle by hand — but you read the demangled form every
day.

### Classes, values, and existentials

Swift types fall into three runtime categories:

- **Reference types (classes)** — heap-allocated, retain-counted, 16-
  byte minimum header (`HeapObject`: isa + refcount). Very similar
  to ObjC instance layout, which is why `@objc` Swift classes mostly
  "just work."
- **Value types (structs, enums)** — inline, no header, no refcount.
  Copied on assignment. Their type metadata lives in
  `__swift5_types`, and their size/copy/destroy operations go
  through a **value witness table** (VWT) referenced from that
  metadata.
- **Existentials (protocols as values)** — 40-byte inline "box"
  containing either the value directly (if ≤3 pointers) or a pointer
  to heap-allocated payload, plus pointers to the type metadata and
  the protocol witness table (PWT). This is the runtime's way of
  implementing `var x: any SomeProtocol`.

### Protocol witness tables

A **protocol witness table** (PWT) is a vtable for "how does *this
specific conforming type* implement *this protocol*". Every
`Struct: Protocol` conformance has one PWT; every
`Class: Protocol` conformance has one PWT; the PWT contents are
function pointers to the witness implementations.

When you see a Ghidra symbol like
`$s8MyModule7GreeterCAA8GreetingAAWP`, that's a PWT: `Greeter`
conforming to `Greeting`. Method dispatch through a protocol-typed
value reads the PWT at a fixed offset.

### `__swift5_*` sections

Swift's metadata lives in multiple `__TEXT` sections; Ghidra
recognizes these and builds the Swift sidebar from them:

| Section | Content |
|---------|---------|
| `__swift5_types` | Pointers to every type's "type descriptor" |
| `__swift5_proto` | Pointers to every protocol declaration |
| `__swift5_protos` | Pointers to every protocol **conformance** |
| `__swift5_fieldmd` | Field metadata (ivar names/types) for each type |
| `__swift5_assocty` | Associated-type metadata |
| `__swift5_typeref` | Interned type references |
| `__swift5_reflstr` | Reflection strings (type/field names) |
| `__swift5_capture` | Closure capture descriptors |
| `__swift5_builtin` | Builtin type descriptors |
| `__swift5_mpenum` | Multi-payload enum descriptors |
| `__swift5_replace` / `__swift5_replac2` | Dynamic-replacement metadata (`@_dynamicReplacement`) |

`class-dump-swift` (a community fork) parses most of these into a
`class-dump`-style listing. Ghidra 5+ does it automatically.

### `@_silgen_name` and demangled entry points

Apple and third-party Swift libraries sometimes annotate entry
points with `@_silgen_name("symbol_name")` to force a C-style symbol
instead of a mangled one. When you see a suspiciously C-named Swift
function in Ghidra (e.g. `swift_allocObject`), it was either
annotated or is part of the runtime itself. These are almost always
interesting surface — audit them.

### Calling conventions and Swift error handling

Swift's ARM64 calling convention is similar to the system one but
not identical:

- Function arguments go in `x0..x7`, `d0..d7` — same as AArch64.
- **`self` is passed in `x20`** (the Swift "context" register), not
  `x0`, for instance-method calls on classes. For structs/enums
  passed by value, `self` goes in the normal arg slots.
- **Returning an error** (`throws` functions) uses `x21` — a thrown
  error object is placed in `x21` with a specific flag pattern, and
  the caller checks it post-return.
- **Indirect returns** (for large values) go through `x8` (the AArch64
  "indirect result location" register, same as C).

When you're reading Ghidra pseudocode for a Swift `throws` function
and see `x20` and `x21` references that look out of place, that's
this ABI in action.

### Interop: `@objc` bridge

The most common Swift-in-macOS shape is a class that inherits from
`NSObject` and is annotated `@objc`. That compiles to:

- A full ObjC `__objc_class` entry in `__objc_classlist`.
- A full Swift type descriptor in `__swift5_types`.
- Every `@objc` method emits two entry points — one with a
  Swift-mangled name, one with the ObjC selector name.

This is why `[MyClass someMethod]` works the same as `MyClass().someMethod()`
on such a class: there are two paths to the same implementation.

Bridging-boundary gotchas:

- `Swift.String` ↔ `NSString` bridging is **not free**. A call that
  crosses that boundary copies. Relevant for performance RE and for
  timing-attack analysis.
- Swift's `Optional<T>` is **not** the same as ObjC's nil-as-object
  convention. A Swift `Optional<NSString>` returned to ObjC becomes
  `NSString?` which is either a pointer or nil; a Swift `Optional<Int>`
  cannot cross the ObjC boundary without boxing.

## Workflow

Canonical "new Swift binary" pass:

1. `otool -L ./targets/foo | grep libswift` — confirm Swift presence.
2. `otool -l ./targets/foo | grep __swift5_` — confirm Swift
   metadata sections exist.
3. Try `class-dump ./targets/foo`. If it fails or shows only ObjC
   shims, skip to step 4.
4. **Open in Ghidra on the VM.** Ghidra's Swift view auto-enumerates
   `__swift5_types` + `__swift5_proto`. Browse the class list in the
   sidebar.
5. For every class of interest:
   - `ghidra-mcp: get_pseudocode_by_name` with the **demangled**
     name (Ghidra accepts both forms; demangled is more readable).
     Example: `MyModule.Greeter.sayHi() -> ()`.
6. For mystery symbols in `bt` output or Ghidra's cross-refs:
   `xcrun swift demangle '<mangled>'` on the workstation.
7. Runtime inspection: `macre-vm-mcp: lldb_run` with a breakpoint on
   the demangled name; use `po` in post-break commands to print
   Swift values. lldb has native Swift support.

## Current Bug-Class Anchors

Swift-only vulnerability write-ups are thinner than ObjC ones because most
macOS attack surface is still ObjC or C. Two flavors that matter:

- **Swift's dynamic-replacement mechanism** (`@_dynamicReplacement(for:)`)
  has been used in legitimate runtime-patching libraries and has
  appeared in at least one malware analysis as an injection primitive.
  Metadata lives in `__swift5_replace` / `__swift5_replac2`; audit
  anything in there that is not a known library.
- **NSXPC + Swift-defined exported interfaces** are the cleanest
  example of why the Swift skill matters for Wave 2 XPC work. If the
  `exportedInterface` whitelists a Swift class, then every
  `NSSecureCoding`-compatible subtype of it is in scope for
  unarchive-side trust bugs. Review ObjC NSXPC and serialization behavior for the
  NSXPC internals; Wave 2's XPC skill will add the Swift-specific
  analysis on top.

## Pitfalls

- **`class-dump` does not fully understand Swift.** Always
  cross-reference with Ghidra's Swift view. Don't conclude "there's
  no interesting class" just because `class-dump` was quiet.
- **Demangling a very long Swift name can span multiple lines in
  terminal output** — always quote the symbol when passing to
  `swift demangle`, and consider piping through `head -1` if your
  shell wraps.
- **Optimized (`-O`) Swift inlines aggressively.** A function you
  see in source may be entirely inlined away at the Swift IL stage.
  Ghidra shows only what made it through to the Mach-O.
- **Swift concurrency (`async`/`await`) generates coroutine-style
  code.** The call sites do not look like a normal `bl` + ret; they
  look like save-context + call + yield + resume. Local Ghidra and LLDB traces
  help you recognize the shape; the Swift ABI's `Async.md` doc in
  apple/swift is the authoritative reference.
- **Stripping a Swift binary is more brutal than stripping an ObjC
  one.** Apple's linker can drop `__swift5_reflstr` in release
  builds, leaving you with type references but no human-readable
  names. Ghidra still works; it just cannot print friendly names
  for everything.

## Micro-exercise

*Goal:* find a Swift method in a binary by name, read its disassembly,
verify it at runtime.

1. On the workstation, build a tiny Swift binary:

        cat > /tmp/swhello.swift <<'EOF'
        class Greeter {
            func sayHi() {
                print("hi from \(type(of: self))")
            }
        }
        Greeter().sayHi()
        EOF
        xcrun swiftc -o /tmp/swhello /tmp/swhello.swift

2. Check metadata:
   `otool -l /tmp/swhello | grep __swift5_` should list several sections.
3. Dump Swift symbols:
   `nm /tmp/swhello | grep -E '\$s' | head`.
4. Demangle one: pick any `$s...` symbol and
   `xcrun swift demangle '<symbol>'`.
5. Sync into project `./targets/` and `bash scripts/rsync-to-vm.sh`.
6. Open `/Users/szeth/Targets/<project>/swhello` in Ghidra on the VM.
7. From Cursor:

        ghidra-mcp: get_pseudocode_by_name {"name": "main.Greeter.sayHi() -> ()"}

   (Ghidra accepts this demangled form.)
8. Confirm: the pseudocode shows the `print`/`Swift.print` call, and
   the method's entry point uses the Swift calling convention (note
   `x20` usage if any, otherwise a plain class method).

Success = you produced a mangled symbol, demangled it, found the same
function in Ghidra by name, and can point to the method's entry
instruction.

## See also

- [`Skills/offensive-macos-foundations-macho/SKILL.md`](../offensive-macos-foundations-macho/SKILL.md) — `__swift5_*` sections are Mach-O sections.
- [`Skills/offensive-macos-foundations-objc-runtime/SKILL.md`](../offensive-macos-foundations-objc-runtime/SKILL.md) — for the `@objc` bridged case.
- [`Skills/offensive-macos-tooling-ghidra-headless/SKILL.md`](../offensive-macos-tooling-ghidra-headless/SKILL.md) — Ghidra's Swift sidebar and demangling UI.
- [`Skills/offensive-macos-tooling-lldb/SKILL.md`](../offensive-macos-tooling-lldb/SKILL.md) — lldb's native Swift expression evaluator (`po`, `expr`).
- Apple's Swift ABI documentation: https://github.com/apple/swift/blob/main/docs/ABI/Mangling.rst
- `xcrun swift demangle` — your daily-driver demangler.
- `class-dump-swift` (community fork) for when you want a one-shot Swift class dump.
