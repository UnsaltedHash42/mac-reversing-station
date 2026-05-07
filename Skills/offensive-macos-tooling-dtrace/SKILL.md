---
name: offensive-macos-tooling-dtrace
description: >-
  Use when you want to observe a macOS binary's runtime behavior at
  scale — syscall traces, ``objc_msgSend`` dispatch volume, file-IO
  patterns, PID-specific function-entry counts — without the per-hit
  overhead of lldb breakpoints. Covers DTrace probes (syscall, pid,
  objc, plockstat), D-language aggregations, action and predicate
  filtering, and the ``macre-vm-mcp`` ``dtrace_script`` / ``dtrace_oneliner``
  tool wrappers. Fires on "trace syscalls", "count objc messages",
  "who opens this file", "stack trace every call to foo",
  "dtrace one-liner for X".
folder: offensive-macos-tooling-dtrace
source: skillz-wave1
trigger_phrases:
  - "dtrace"
  - "dtrace oneliner"
  - "syscall tracing"
  - "objc_msgSend trace"
  - "pid probes"
---

# DTrace — tooling skill

> **Channel boundary:** `REPO_MODE=analysis`.

## When to use

- You want to know **which** syscalls / functions a binary hits and
  **how often**, without wrapping every call in a breakpoint.
- You want the stack trace at every invocation of some function.
- You want to correlate two events (entry + return) to measure
  latency or to capture arguments then return values.
- A bug reproduces only under load; setting lldb breakpoints would
  change timing. DTrace is lower-overhead.

## Lab topology — where to run this

DTrace always runs on NightBlood. `/usr/sbin/dtrace` is standard on
macOS 26. Cursor drives it via `macre-vm-mcp`'s `dtrace_script` (full
D program) and `dtrace_oneliner` (single `-n` expression).

| Step | Surface | How |
|------|---------|-----|
| One-liner (quick counts, simple traces) | Cursor → `macre-vm-mcp` | `dtrace_oneliner` |
| Multi-clause program (aggregations, state machines) | Cursor → `macre-vm-mcp` | `dtrace_script` |
| System-wide tracing | VM | Interactive SSH + `sudo dtrace -n '...'` |
| Long-running continuous capture | VM | SSH + `sudo dtrace -o /tmp/trace.out -s script.d` then `scp` back |

**Important:** `dtrace_script` and `dtrace_oneliner` run as the
invoking user by default. On macOS, most interesting probes require
root. If your probe needs root, either:

- Elevate the MCP tool invocation by running the server under a
  privileged launchd agent (advanced; out of scope for Wave 1),
  **or**
- SSH into the VM as `sudo` and drive interactively; paste the
  trace output back into Cursor.

In practice for Wave 1, `pid$target` probes against a binary you
control work without sudo as long as the target is owned by the
same user. System-wide `syscall:::entry` probes want root.

## Theory

### Probes, actions, and predicates

A D program is one or more clauses:

    <probe>[/<predicate>/] [ { <actions>; } ]

A **probe** is a four-part name `provider:module:function:name`:

| Part | Example | Notes |
|------|---------|-------|
| provider | `syscall`, `pid$target`, `objc$target`, `io`, `proc`, `fbt` | `fbt` (function boundary tracing) needs root and is often restricted; `pid$target` is the safe default for user-space RE |
| module | dylib / framework name, or empty | `pid123::malloc:entry` works; so does `pid$target:libsystem_malloc.dylib:malloc:entry` |
| function | function/method name | For ObjC: `pid$target::objc_msgSend:entry` |
| name | `entry`, `return`, plus provider-specific (`start`, `end`) | Entry fires before the function body; return fires just before `ret` |

**Predicates** `/<expr>/` filter: `/pid == $target/`,
`/execname == "foo"/`, `/arg1 == 0xdeadbeef/`. Probes with a
`false` predicate don't run actions.

**Actions** are D statements in a `{ … }` block. Common ones:

- `printf(fmt, args)` — print to stdout.
- `stack()`, `ustack()` — kernel / user-space stack trace.
- `@agg[keys] = count()` / `sum(arg0)` / `avg(arg0)` / `quantize(arg0)` — aggregations, flushed at script end.
- `printa(fmt, @agg)` — pretty-print an aggregation at an explicit time.
- `copyin(ptr, n)` / `copyinstr(ptr)` — read memory from the traced
  process's address space into DTrace's.
- `exit(n)` — stop tracing.

### Canonical probe providers for macOS RE

| Provider | Scope | Cost | Use for |
|----------|-------|------|---------|
| `syscall` | Every user→kernel transition, system-wide | Low | "What syscalls does PID X make?" |
| `pid$target` | Every function entry/return in process `$target` (when `dtrace -p` or `-c` used) | Medium | Per-function tracing of one user-space binary |
| `objc$target` | Every ObjC method entry/return in process `$target` | High (chatty) | Method-dispatch observation |
| `proc` | Process lifecycle: `create`, `start`, `exec`, `exit`, `signal-send` | Low | Auditing child processes |
| `io` | Disk IO | Medium | File-IO patterns |
| `sched` | Kernel scheduler events | High (kernel-wide) | Performance RE, usually root |
| `fbt` | Kernel function boundary tracing | High | Kernel RE (Wave 4); heavily restricted |
| `plockstat` | pthread locking | Medium | Concurrency RE |

### The `$target` macro

When you run `dtrace -p <pid>` or `dtrace -c <cmd>`, DTrace binds
`$target` to that PID. You then write `pid$target::foo:entry`
instead of hardcoding `pid1234::foo:entry`.

`macre-vm-mcp`'s `dtrace_script` and `dtrace_oneliner` both expose
`target_pid` and `target_command` arguments, which become `-p` and
`-c` respectively. Pass one or neither — not both.

### Aggregations (the thing DTrace does better than anything)

Counting, stratifying, and percentiling are first-class:

    syscall:::entry
    /pid == $target/
    { @[probefunc] = count(); }

At END (or manual `printa`), you get a sorted table of syscall →
count. `@[key]` is implicit-global; key can be any tuple.

    pid$target::malloc:entry
    { @alloc_size[ustack(5)] = quantize(arg0); }

Aggregate by user stack (5 frames) → histogram of malloc sizes.
This is how you find the "who is allocating the biggest things" in
one command.

### Memory reads: `copyin` and `copyinstr`

DTrace's probes run in the kernel; they can't just dereference a
target-process pointer. Use `copyin(ptr, n)` to snapshot N bytes
into DTrace's scratch, or `copyinstr(ptr)` for a NUL-terminated C
string.

    pid$target::open:entry
    { printf("open path=%s flags=%d", copyinstr(arg0), arg1); }

Without `copyinstr`, `arg0` is just the raw pointer value.

### Common pid-probe caveats

- **Not every function is probable.** DTrace's pid provider skips
  functions too small or too weird for it to safely instrument.
  Specifically: some leaf helpers, some arm64 stubs, some Swift
  runtime entry points. If your probe silently misses, try a
  nearby function or use `fbt` (root-only).
- **Probes are per-arch.** An arm64 process gets arm64 probes only.
  No universal weirdness.
- **One probe per clause.** `pid$target::foo:entry, pid$target::bar:entry`
  can be combined as `pid$target::foo,bar:entry` (name is the
  comma-separated part), or with multiple clauses.
- **Return probes don't see the function's arguments.** They see
  `arg1` = return value. Save args at entry, correlate by thread
  or pid at return.

## Workflow

### A: "what syscalls does this binary make?"

    macre-vm-mcp: dtrace_oneliner {
      "expression": "syscall:::entry /pid == $target/ { @[probefunc] = count(); }",
      "target_pid": 4242,
      "timeout_sec": 10
    }

Returns: a sorted count of syscall names over the window. Use this
as the first "what is this binary doing" question every time.

For a one-shot program run (not attach):

    macre-vm-mcp: dtrace_script {
      "script": "syscall:::entry /pid == $target/ { @[probefunc] = count(); } END { printa(@); }",
      "target_command": ["/Users/szeth/Targets/proj/foo", "arg1", "arg2"],
      "timeout_sec": 8
    }

### B: "what's the stack every time this function is called?"

    macre-vm-mcp: dtrace_oneliner {
      "expression": "pid$target::myFunction:entry { ustack(); }",
      "target_pid": 4242,
      "timeout_sec": 5
    }

Every call prints a 20-frame-ish ustack. Pair with a predicate to
narrow it down:

    pid$target::myFunction:entry
    /arg0 == 0x5/
    { ustack(); }

Only prints stacks when `arg0 == 5`.

### C: "trace ObjC method dispatch by selector"

The `objc$target` provider is the cleanest on macOS, but it's chatty
— always filter by class or method. Probes look like:

    objc$target:ClassName::methodName:entry

Example — trace every `-[NSString stringByAppendingString:]` in the
target:

    macre-vm-mcp: dtrace_oneliner {
      "expression":
        "objc$target:NSString::stringByAppendingString?:entry { printf(\"called\"); }",
      "target_pid": 4242,
      "timeout_sec": 5
    }

For generic "trace *every* `objc_msgSend`", use the pid provider
directly:

    pid$target::objc_msgSend:entry
    { printf("%s -> %s", copyinstr(arg1), "msg"); }

(arg0 = self, arg1 = SEL — the same calling convention covered in
the ObjC-runtime foundations skill.)

### D: "who opens this file"

    macre-vm-mcp: dtrace_script {
      "script":
        "syscall::open*:entry\n/copyinstr(arg0) == \"/etc/passwd\"/\n{ printf(\"%s (pid %d)\", execname, pid); ustack(); }",
      "timeout_sec": 15
    }

System-wide, all processes. Typically needs root (run interactively
on the VM). Useful for TCC-bypass investigation — "which process
actually wrote `/Library/Application Support/com.apple.TCC/TCC.db`?"

### E: correlate entry/return for latency or arg↔ret mapping

DTrace thread-local vars: `self->foo`. Classic pattern:

    pid$target::foo:entry
    { self->start = timestamp; self->arg0 = arg0; }

    pid$target::foo:return
    {
        @[self->arg0] = quantize(timestamp - self->start);
        self->start = 0;
        self->arg0 = 0;
    }

Clear the thread-locals on return or they leak memory.

## Current Bug-Class Anchors

### Shellcode analysis

Local shellcode labs use `dtrace -n 'syscall:::entry /pid == $target/
{ printf("%s(%x, %x, %x)", probefunc, arg0, arg1, arg2); }'` to
watch what an execv shellcode actually does at the kernel boundary.
This is the canonical "is my shellcode working?" trace. Every shellcode
micro-exercise in [`Skills/offensive-macos-shellcode-arm64/SKILL.md`](../offensive-macos-shellcode-arm64/SKILL.md)
uses the same dtrace pattern.

### TCC daemon instrumentation

When hunting TCC-bypass bugs, a go-to flow is:

1. `log stream --predicate 'subsystem == "com.apple.tccd"'`
   (via `macre-vm-mcp: log_stream`) to get coarse events.
2. Identify suspicious decision paths.
3. Dtrace `pid$target` probes on `tccd`'s internal C++ methods to
   watch the attribute checks.

This is the same methodology that produced write-ups like wts.dev's
public TCC prompt-attribution research.

## Pitfalls

- **DTrace is easy to crash.** A bad probe on the `fbt` provider can
  panic the kernel on macOS. `pid$target` and `syscall` are safe.
  Stay in those for Wave 1.
- **Probes require root for many providers.** `syscall` system-wide,
  `fbt`, most `sched` probes — all root. `pid$target` against a
  same-user process works without root. If your oneliner returns
  "dtrace: failed to initialize dtrace: DTrace requires additional
  privileges", you need sudo.
- **SIP and DTrace on Apple-signed binaries.** SIP restricts DTrace
  probes into Apple code. Our VM has SIP off — not a concern here,
  but note it for any future SIP-on station.
- **String args need `copyinstr`, not `arg0`.** Raw pointer value
  alone is useless for debugging.
- **Aggregations print at END by default.** If your run is timing
  out before END fires, add `printa(@)` inside a `tick-Ns` probe
  (`profile:::tick-5s { printa(@); trunc(@); }`) for periodic
  snapshots.
- **Return probes never fire** for functions that never return
  (noreturn, tail-called-out). Recent macOS also sometimes misses
  return probes on AppKit classes; not a bug you can work around —
  switch provider or use lldb.

## Micro-exercise

*Goal:* prove you can observe a syscall, a pid probe, and an
aggregation.

1. Use `/tmp/hello` Obj-C binary. Sync to VM.
2. From Cursor, run the binary under dtrace with syscall counting:

        macre-vm-mcp: dtrace_script {
          "script": "syscall:::entry /pid == $target/ { @[probefunc] = count(); } END { printa(@); }",
          "target_command": ["/Users/szeth/Targets/<proj>/hello"],
          "timeout_sec": 5
        }

   Expected: a short aggregation table including `open`, `read`,
   `write`, `close`, `exit`. If no output, check the timeout and
   whether the binary actually ran (it's short).
3. Now trace `objc_msgSend` by selector:

        macre-vm-mcp: dtrace_script {
          "script": "pid$target::objc_msgSend:entry { @[copyinstr(arg1)] = count(); } END { printa(@); }",
          "target_command": ["/Users/szeth/Targets/<proj>/hello"],
          "timeout_sec": 5
        }

   Expected: aggregation keyed by selector string. `sayHi`,
   `class`, `new`, `alloc`, `init`, `autorelease` should appear.

Success = both outputs are non-empty, make sense, and you can
explain why each selector showed up (map back to the source).

## See also

- [`Skills/offensive-macos-tooling-lldb/SKILL.md`](../offensive-macos-tooling-lldb/SKILL.md) — when you need to halt and inspect, not just observe.
- [`Skills/offensive-macos-foundations-objc-runtime/SKILL.md`](../offensive-macos-foundations-objc-runtime/SKILL.md) — why `arg1` of `objc_msgSend` is the selector.
- [`Skills/offensive-macos-shellcode-arm64/SKILL.md`](../offensive-macos-shellcode-arm64/SKILL.md) — the canonical shellcode-dtrace pair.
- [`macre-vm-mcp/src/macre_vm_mcp/tools_dtrace.py`](../../macre-vm-mcp/src/macre_vm_mcp/tools_dtrace.py) — what the MCP wrappers actually invoke.
- Brendan Gregg's DTrace one-liners (still the best cheat sheet): https://www.brendangregg.com/DTrace/dtrace_oneliners.txt
- Apple's DTrace documentation (`dtrace(1)`, `dtrace(7)` man pages).
