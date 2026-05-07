---
name: offensive-macos-foundations-objc-runtime
description: >-
  Use when reversing an Objective-C binary and you need to recover class
  layout, selector-to-IMP mapping, protocol conformance, property lists,
  or understand how ``objc_msgSend`` dispatches on ARM64. Fires on
  questions like "what classes are in this binary", "where is the
  -[Foo bar:] method", "how does objc_msgSend work on arm64", "dump
  selectors", "find all callers of setObject:forKey:", "what's in
  __objc_classlist", or "how do I call a Swift-bridged Objective-C
  method at runtime". Prerequisite to the ObjC method-swizzling,
  hooking, and XPC-audit skills in Waves 2–3.
folder: offensive-macos-foundations-objc-runtime
source: skillz-wave1
trigger_phrases:
  - "objective-c runtime"
  - "objc_msgSend"
  - "class-dump"
  - "selectors"
  - "method swizzling"
  - "NSXPCListener"
---

# Objective-C runtime foundations

> **Channel boundary:** `REPO_MODE=analysis`. RCA, lab repro, defensive
> mapping only. No operational exploit authoring.

## When to use

- Binary under analysis has `/usr/lib/libobjc.A.dylib` in `otool -L`
  output (≈ every macOS app, menu extra, XPC service, and most
  system daemons).
- You want to enumerate classes, methods, properties, protocols, or
  instance variables of a binary before jumping into Ghidra.
- You are staring at an ARM64 prologue that ends with
  ``bl _objc_msgSend`` and need to figure out which method is about
  to run.
- You are setting up a method swizzle / interposition (Wave 3) and
  need the `SEL`, `IMP`, and class-pair plumbing straight.
- You are auditing an XPC service (Wave 2) and need to know how
  `NSXPCConnection` and `NSXPCListener` expose classes.

## Lab topology — where to run this

| Step | Where | How |
|------|-------|-----|
| Dump class / method listing (quick) | Workstation | `class-dump ./targets/foo` (install: `brew install class-dump`) |
| Dump with modern signatures | Workstation or VM | `class-dump` may fail on Swift-heavy binaries; fall back to Ghidra's ObjC view |
| Deep method-level disassembly | VM (Ghidra) | `ghidra-mcp: get_assembly_by_name` with full selector |
| Runtime observation of message sends | VM | `macre-vm-mcp: dtrace_oneliner` with `objc_msgSend` pid-provider probes |
| Swizzle a method in a live process | VM | Via an injected dylib; covered in Wave 3 hooking skill |

## Theory

### Classes are data; methods are pointers

An Objective-C class is not a C++ vtable. It is a chunk of data at a
fixed address in the binary, laid out roughly like this (simplified
from `<objc/runtime.h>` + `objc-runtime-new.h` in Apple's open-source
`objc4`):

```
struct objc_class {
    Class         isa;          // metaclass (see "isa and metaclasses" below)
    Class         superclass;   // parent class
    cache_t       cache;        // method-lookup cache
    class_data_bits_t bits;     // pointer to class_ro_t, with low bits as flags
};

struct class_ro_t {
    uint32_t         flags;
    uint32_t         instanceStart;
    uint32_t         instanceSize;
    const uint8_t   *ivarLayout;
    const char      *name;            // class name as a C string
    method_list_t   *baseMethodList;  // array of { SEL, types, IMP }
    protocol_list_t *baseProtocols;
    ivar_list_t     *ivars;
    const uint8_t   *weakIvarLayout;
    property_list_t *baseProperties;
};
```

Every class in a Mach-O binary's `__objc_classlist` section is a
pointer to one of these `objc_class` structs in `__DATA_CONST` /
`__DATA`. Ghidra resolves this automatically — if you open a binary
and see classes in the sidebar, Ghidra walked `__objc_classlist` and
followed each pointer.

### Selectors: just strings, with pointer identity

A selector (`SEL`) is the *name* of a method, interned into a
unique-pointer table by the runtime. At compile time every selector
literal `@selector(foo:bar:)` becomes a reference into the
`__objc_selrefs` section; at load time, the runtime walks those refs
and rewrites them to point into the internal selector table.

- **Pointer equality is the whole point.** Two `SEL` values compare
  equal iff their strings are equal — but you compare with `==`, not
  `strcmp`, because the runtime guarantees interning.
- **Method names in `__objc_methname`** are the raw C strings of
  every selector used in this binary. `strings -n 8 ./foo | grep -E
  '^[a-zA-Z_][a-zA-Z0-9_:]+$'` gets you a rough selector list even
  for stripped binaries.

### `objc_msgSend` — the one function you must internalize

Every Objective-C method call compiles to a call to `objc_msgSend`
(or one of its variants: `objc_msgSendSuper` for `[super …]` calls,
`objc_msgSend_stret` for methods that return structs on some
platforms, `objc_msgSendSuper2`). On ARM64 macOS the signature and
calling convention look like this:

```
id objc_msgSend(id self, SEL _cmd, ...);
//              x0        x1        x2, x3, x4, x5, x6, x7, [sp, ...]
//
// return value:   x0 (for id / pointer / small integer returns)
//                 d0 for double return
```

The typical call site pattern Ghidra will show you:

```
; -[Greeter sayHi] calls [self class]
adrp   x8, __objc_classlist@PAGE       ; not usually — class loaded from __objc_data instead
ldr    x0, [sp, #offset_of_self]       ; self into x0
adrp   x1, @selector(class)@PAGE       ; SEL literal
ldr    x1, [x1, @selector(class)@PAGEOFF]
bl     _objc_msgSend                   ; dispatch
```

What this means for RE:

- **The first argument (x0) is always the receiver.** If you can
  determine what class the receiver is at call time, you can compute
  the target method statically.
- **The second argument (x1) is always the selector.** Follow it —
  it points into the selector-refs table, which points into
  `__objc_methname`, which gives you the human name.
- **Variadic args are in x2..x7, then stack.** For ObjC methods
  with N positional args, the Nth arg is in `x[N+1]` (x2 is 1st ObjC
  arg, x3 is 2nd, etc.).
- **Ghidra's pseudocode resolves this automatically** when it can
  determine the receiver's class. When it can't, you get
  ``[r0 someMethod]`` with a type it couldn't resolve — that's a
  hint you need to trace how `r0` got there.

### `isa` and metaclasses

Every Objective-C object has an `isa` pointer as its first field.
`isa` tells the runtime what class this object is.

- For **instances** (`NSString *s = …;`), `isa` points to the class
  (e.g. `NSString`).
- For **classes** themselves (a `Class` is an object too!), `isa`
  points to the **metaclass** — the class that holds the `+class`
  methods. This is how `[Foo classMethod]` works: it sends the
  message to the class object `Foo`, whose isa is the `Foo`
  metaclass, which has `classMethod` in its method list.
- The metaclass's `isa` points to the root metaclass (NSObject's
  metaclass on macOS).

On modern ARM64 macOS, `isa` is **tagged**: the low bits encode
runtime flags (has weak refs, has assoc refs, retain count bits)
rather than all being pointer bits. Code that walks objects in a
live process must mask off these bits — `#define ISA_MASK 0x0000000ffffffff8ULL`
is approximately right, but look up the current value in Apple's
objc4 source before trusting it for Wave 3 swizzling work.

### Method type encodings

Every method carries a **type encoding string** — Apple's compressed
representation of the method's full ObjC-type signature. You see
these in Ghidra next to method names, and in `class-dump` output.

Common characters (from `<objc/message.h>` and runtime docs):

| Char | Type |
|------|------|
| `c` | `char` |
| `i` | `int` |
| `l` | `long` (32-bit on arm64 ABI variants) |
| `q` | `long long` |
| `s` | `short` |
| `C` / `I` / `L` / `Q` / `S` | unsigned variants |
| `f` / `d` | `float` / `double` |
| `B` | `bool` (`_Bool`) |
| `v` | `void` |
| `*` | `char *` (C string) |
| `@` | object (`id` or specific class) |
| `@"NSString"` | object of class `NSString` specifically |
| `#` | `Class` |
| `:` | `SEL` |
| `[...]` | array |
| `{Name=types}` | struct |
| `^type` | pointer to `type` |
| `?` | unknown / block |

A return-type-first encoding like `v24@0:8@16` means: return `void`,
total arg size 24 bytes, arg 0 is `id` (at offset 0), arg 1 is `SEL`
(at offset 8), arg 2 is `id` (at offset 16). Ghidra decodes these
for you in the ObjC view; when it fails, you have this table.

### `__objc_*` Mach-O sections — the parse path

When reversing an ObjC binary from scratch, walk these sections in
order:

1. **`__objc_classlist`** (`__DATA_CONST`) — array of pointers, one
   per class. Start here.
2. For each class pointer, **follow to `__objc_data`** (`__DATA` or
   `__DATA_CONST`). That's where the `class_ro_t` pointer lives
   (`bits` field with low-bit mask).
3. **`class_ro_t`** tells you: class name (in `__objc_classname`),
   method list (in `__objc_const`), ivar list, property list,
   protocol list.
4. **`__objc_methname`** (`__TEXT`) — all selector strings.
5. **`__objc_selrefs`** (`__DATA_CONST`) — pointers *to* selector
   strings; each of these is what the compiler emitted for a
   `@selector(foo)` literal. Cross-reference to find callers of a
   given selector.
6. **`__objc_protolist`** (`__DATA_CONST`) — every declared
   protocol, which methods it requires/provides.
7. **`__objc_catlist`** — categories (Objective-C's "monkey-patch"
   mechanism). Pay attention to these: a category can add methods to
   existing classes, including `NSString`, `NSObject`. Any Wave 3
   swizzling bug hunt should start by listing every category in
   every loaded binary.
8. **`__objc_imageinfo`** — tiny section with ABI version + flags.
   Ghidra uses this to decide which ABI to parse.

A single `class-dump ./targets/foo` on a non-Swift binary does all
of this in one shot. For Swift-heavy binaries, `class-dump` chokes;
use Ghidra's ObjC view plus the `foundations-swift-abi` skill.

### Categories (and why they matter)

Categories let any translation unit add methods to any class — even
Apple's classes — as long as the category's `__objc_catlist` entry
is registered at load time. In a binary's Ghidra sidebar they show
up as something like ``NSObject(MyCategoryName)``.

Attack / audit implications:

- A malicious dylib injected into a hardened-runtime-disabled
  binary can add a category to `NSString` that overrides public
  methods. The new methods win ties.
- Category method lookup happens at `+load` time (if the category
  implements `+load`) or lazily. Two categories that override the
  same method race; order is "undefined" but in practice is link
  order. This is a legitimate source of Heisenbugs.
- When reversing a target, audit every category: they are the most
  common place for third-party code to be inserted into Apple
  classes, and also the most common attack primitive in injection
  bugs.

### Associated objects and weak references

Two runtime features that matter for Wave 3 but not Wave 1, worth
flagging here so the concept is introduced:

- **Associated objects**
  (`objc_setAssociatedObject` / `objc_getAssociatedObject`) let you
  attach arbitrary key/value data to any object instance without
  subclassing. Heavily used by Apple frameworks to add data to Obj-C
  objects they don't own.
- **Weak references** are tracked in a side-table keyed by object
  address. `objc_storeWeak` / `objc_loadWeak` manipulate this table;
  when the underlying object deallocates, every weak ref to it
  clears.

## Workflow

Canonical "new ObjC binary" pass:

1. Verify it's actually ObjC: `otool -L ./targets/foo | grep libobjc`.
   No match ⇒ skip to `foundations-swift-abi` or the C-only path.
2. **Quick class list:**
   `class-dump ./targets/foo | less` (workstation). Gives every
   class, method, property, and ivar in a readable form. For Swift-
   heavy binaries this fails — fall back to step 3.
3. **Ghidra-driven class walk:** via `ghidra-mcp`, call
   `get_current_assembly` after opening the binary, then
   `get_assembly_by_name` for each class you want to read. Ghidra's
   ObjC sidebar enumerates `__objc_classlist` automatically.
4. **Selector-to-caller tracing:** in Ghidra, right-click any
   method to "List References" — Ghidra finds every `bl
   _objc_msgSend` site whose `x1` was set to that selector's ref.
   From Cursor, use `ghidra-mcp: get_pseudocode_by_name` against
   candidate callers.
5. **Runtime observation** (when the binary runs on the VM): attach
   a dtrace oneliner to log every `objc_msgSend` call with its
   selector:

        macre-vm-mcp: dtrace_oneliner {
          "expression":
            "pid$target::objc_msgSend:entry { printf(\"%s %s\", probefunc, copyinstr(arg1)); }",
          "target_pid": <pid>,
          "timeout_sec": 5
        }

   This is **extremely** noisy in a real process; always pair with
   a predicate filter (see
   [`Skills/offensive-macos-tooling-dtrace/SKILL.md`](../offensive-macos-tooling-dtrace/SKILL.md)).
6. **For XPC audits (Wave 2 preview):**
   `class-dump` the target to find the `NSXPCListener` delegate
   class, then grep its methods for `-listener:shouldAcceptNewConnection:`.
   Classes exposed via `setExportedInterface:` are the attack
   surface. Full skill lands in Wave 2.

## Current Bug-Hunting Anchors

### Categories as injection primitive

Objective-C category overrides and method swizzling are a recurring
runtime primitive in both legitimate UI frameworks and malicious code.
Understanding how the runtime's method-list merging picks a winner is
the prerequisite to hunting or defending against this class of bug.

### NSXPC + ObjC runtime trust issues

Many NSXPC-based privilege-escalation bugs rely on the fact that NSXPC
transparently unarchives Objective-C objects across a trust boundary.
The `NSSecureCoding` machinery, the `exportedInterface`
`NSXPCInterface` class whitelist, and the runtime's
`objc_readClassPair`-like plumbing are all ObjC-runtime concepts.
The ObjC runtime skill (this one) is a prerequisite; the XPC-audit
skill is where they become a hunt strategy.

## Pitfalls

- **Swift-bridged ObjC classes confuse `class-dump`.** A Swift class
  with `@objc public class Foo: NSObject` compiles to an ObjC class
  whose Mach-O metadata *plus* Swift metadata disagree on ivars.
  `class-dump` shows the ObjC half; use Ghidra for the Swift half.
- **`objc_msgSend` is sometimes inlined.** In extreme cases the
  compiler can inline ObjC dispatch for `init`-like methods. Rare,
  but it breaks the "every `bl _objc_msgSend` is a method call"
  heuristic.
- **Direct `SEL` references break selector cross-ref.** Binaries
  that pass selectors as data (e.g. a dispatch table of `@selector(foo)`
  stored in a struct) show up as data refs into `__objc_methname`
  with no `objc_msgSend` call site. Ghidra lists them under "String
  References" of the selector string — always check both.
- **`objc_autoreleasePoolPush` / `…Pop` and ARC elision calls (e.g.
  `objc_retainAutoreleaseReturnValue`) clutter pseudocode.** They are
  normal ARC runtime bookkeeping; not bugs.
- **Class-pair trickery (`objc_allocateClassPair`) creates classes
  at runtime.** These are **not** in `__objc_classlist` because they
  don't exist yet at static analysis time. Dynamic-analysis-only.

## Micro-exercise

*Goal:* walk from an `objc_msgSend` call site back to the selector,
then to the method implementation.

1. Use the same `/tmp/hello` binary from the macho skill's exercise
   (or recompile).
2. In Ghidra on the VM (synced from workstation), open `hello`.
3. From Cursor:

        ghidra-mcp: get_pseudocode_by_name {"name": "_main"}

4. In the output, identify the `objc_msgSend` call that dispatches
   `-sayHi`. It will look roughly like:

        rax = [Greeter new];
        [rax sayHi];
        // expanded: x0 = rax; x1 = @selector(sayHi); bl _objc_msgSend

5. From Cursor:

        ghidra-mcp: get_pseudocode_by_name {"name": "-[Greeter sayHi]"}

   Confirm you see the `NSLog` call and the `-[self class]`
   sub-dispatch.
6. *(Optional runtime confirmation — uses dtrace skill from U6.)*
   Run `hello` on the VM while logging every `objc_msgSend`:

        macre-vm-mcp: dtrace_oneliner {
          "expression":
            "pid$target::objc_msgSend:entry { printf(\"%s\", copyinstr(arg1)); }",
          "target_pid": <pid of hello>,
          "timeout_sec": 3
        }

   You should see `class` and `sayHi` in the output.

Success = you can draw the path *binary → class-list entry → method
list entry → IMP → disassembly* without looking anything up, and
you can explain why `objc_msgSend`'s x1 is the selector.

## See also

- [`Skills/offensive-macos-foundations-macho/SKILL.md`](../offensive-macos-foundations-macho/SKILL.md) — the `__objc_*` sections live inside the Mach-O layout described there.
- [`Skills/offensive-macos-foundations-swift-abi/SKILL.md`](../offensive-macos-foundations-swift-abi/SKILL.md) — what happens when the binary is mostly Swift.
- [`Skills/offensive-macos-tooling-ghidra-headless/SKILL.md`](../offensive-macos-tooling-ghidra-headless/SKILL.md) — Ghidra's ObjC view, class references, selector cross-ref.
- [`Skills/offensive-macos-tooling-dtrace/SKILL.md`](../offensive-macos-tooling-dtrace/SKILL.md) — runtime `objc_msgSend` tracing recipes.
- Apple open-source `objc4`: https://github.com/apple-oss-distributions/objc4 — especially `runtime/objc-runtime-new.h` and `runtime/objc-class.mm`.
- `<objc/runtime.h>` and `<objc/message.h>` in the macOS SDK.
