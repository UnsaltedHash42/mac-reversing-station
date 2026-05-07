---
name: offensive-macos-tooling-lldb
description: >-
  Use when debugging or dynamically analyzing a macOS binary with lldb.
  Covers non-interactive scripted runs via the macre-vm-mcp ``lldb_run``
  and ``lldb_break_and_inspect`` tools, as well as interactive-style
  debugging patterns expressed as batch scripts. Fires on questions
  like "set a breakpoint on -[Foo bar:]", "dump registers at
  _objc_msgSend", "read 64 bytes at $sp", "patch this instruction
  live", "attach lldb to pid 1234", "what does x16 look like at this
  syscall site". Works against non-Apple-signed binaries freely on
  the configured lab host, with caveats noted for Apple-signed targets.
folder: offensive-macos-tooling-lldb
source: skillz-wave1
trigger_phrases:
  - "lldb breakpoint"
  - "register read"
  - "memory read"
  - "lldb attach"
  - "patch instruction"
---

# LLDB — tooling skill

> **Channel boundary:** `REPO_MODE=analysis`. RCA, lab repro only.

## When to use

- You have a Mach-O binary and you need to observe runtime state —
  argument values, memory contents, control-flow through a branch.
- You have an address from Ghidra and you want to confirm what the
  code actually does (not just what static analysis infers).
- You need to patch a single instruction to unblock further analysis
  — skip a check, nop a call, flip a comparison.
- You want to attach to a running daemon or GUI app and observe
  without killing it.

## Lab topology — where to run this

LLDB runs on the configured lab host. The `/usr/bin/lldb` shipped with the
Xcode Command Line Tools on macOS 26 is sufficient for every Wave 1
workflow. Cursor drives it through `macre-vm-mcp`'s
`lldb_run`, `lldb_break_and_inspect`, and `lldb_run_anchors` tools, which wrap
`/usr/bin/lldb -b -o '<cmd>' -o '<cmd>' ... <binary>`.

| Step | Surface | How |
|------|---------|-----|
| Scripted batch run | Cursor → `macre-vm-mcp` | `lldb_run` or `lldb_break_and_inspect` |
| Ghidra-anchor confirmation | Cursor → `macre-vm-mcp` | `lldb_run_anchors` after slide/slice uncertainty is recorded |
| Live attach to a running PID | VM | `sudo lldb -p <pid>` then iterate via scripted `-o` as needed |
| Quick one-liner | lab host | `ssh <lab-host> 'lldb -b -o "run" -o "register read x0 x1" -o "quit" <binary>'` |
| Apple-signed binary with SIP on | **Not this lab** | Requires entitlement `com.apple.security.cs.debugger` + SIP tweaks; noted for completeness |

## Theory

### Why "batch, not REPL" for MCP-driven work

The cleanest pattern for Cursor-driven lldb is a batch run:

1. Prepare a sequence of commands (set breakpoints, run, dump state
   at each stop, quit).
2. Invoke `lldb -b -o 'cmd1' -o 'cmd2' … <binary>`.
3. Parse the captured output.

This works because `macre-vm-mcp`'s `lldb_run` tool does exactly that
under the hood (see
[`macre-vm-mcp/src/macre_vm_mcp/tools_lldb.py`](../../macre-vm-mcp/src/macre_vm_mcp/tools_lldb.py)).
An interactive REPL would require us to keep a live process on the
VM between MCP calls — which is stateful, error-prone, and not what
FastMCP tools model well. For long stateful sessions, SSH in
manually and drive lldb directly; save the findings back into the
active findings repo.

### Breakpoint syntax (what to put in ``b``)

lldb's `b` / `breakpoint set` accepts many forms; the ones that
matter for macOS RE:

| Form | Meaning |
|------|---------|
| `b _symbol_name` | Break when `_symbol_name` enters. Classic. |
| `b -[NSString length]` | Break on an ObjC method by full selector. lldb parses ObjC selectors natively. |
| `b -n _objc_msgSend` | Name-based. Equivalent to `b _objc_msgSend`. |
| `b -s CoreFoundation.framework/CoreFoundation -n CFRelease` | Name + shared-library filter — useful when the same name exists in multiple dylibs. |
| `b -a 0x10000abcd` | Break at a VM address. Use this for `sub_xxxx` helpers. |
| `b --source <file.c> --line 42` | Source-line (requires debug info — rare in RE targets). |
| `b -r 'objc_msgSend.*'` | Regex across all symbols. |

For Swift:

    b $s8MyModule7GreeterC5sayHiyyF           # raw mangled (may need quoting)
    b -n 'MyModule.Greeter.sayHi() -> ()'     # lldb's Swift plugin accepts demangled form

### Reading state: registers, memory, stack

At a stop:

    register read                    # all GPRs on arm64
    register read x0 x1 x16 x17      # specific registers
    register read -f hex $pc $sp     # specific format

    memory read --count 64 $sp       # 64 bytes at stack pointer
    memory read --count 64 -f x $x0  # 64 bytes at x0, formatted as hex words

    bt 10                            # 10-frame backtrace
    frame variable                   # locals (if debug info)
    image list                       # loaded dylibs and their load addresses

ARM64 quick-reference for macOS ABI:

| Register | Role |
|----------|------|
| `x0..x7` | Integer/pointer args 0..7 |
| `x8` | Indirect return pointer (for large C return values) |
| `x9..x15` | Caller-saved scratch |
| `x16` | IP0 / macOS syscall number (!) |
| `x17` | IP1 |
| `x18` | Platform register (Apple: reserved, do not use) |
| `x19..x28` | Callee-saved |
| `x29` | Frame pointer (FP) |
| `x30` | Link register (LR) — return address |
| `sp` | Stack pointer |
| `pc` | Program counter |
| `d0..d7` | FP/vector args, returns |

**`x16` is the system-call number on macOS.** When you break at
`svc #0x80` (the syscall instruction), `x16` tells you which
syscall is being made. ARM64 shellcode lab work
uses this fact heavily; lldb is how you verify it at runtime.

### Writing: memory, registers, instructions

    register write x0 0                        # nop out arg 0
    memory write 0x10000abcd 0x00 0x00 0x80 0xd2  # patch 4 bytes (arm64 "mov x0, #0")
    expression int $x = (int)0                 # assign via expression
    expression (void)[someObject release]      # call ObjC at runtime

To **nop out an instruction** on arm64: write `0x1f 0x20 0x03 0xd5`
(the `nop` encoding). Ghidra's bytes view gives you the current
bytes to compare before/after.

### Attaching to a live process

    lldb -p <pid>                              # attach by pid
    lldb -n "Safari"                           # attach by process name (first match)

Requires either:
- SIP off on the lab host, or
- The binary was compiled with `get-task-allow`, or
- You are the same-user non-SIP-restricted process owner.

### SIP-off caveats vs SIP-on caveats

On a SIP-off lab host:
- lldb attaches to anything, including Apple-signed daemons.
- You can write memory of Apple-signed processes.
- You can set breakpoints inside the dyld shared cache (lldb
  handles the detach).

On a SIP-on machine (reminded here because Wave 3/4 skills will
reference this):
- `sudo lldb -p <pid of Apple-signed proc>` returns
  "Failed to get reply to handshake packet" — AMFI denies debug
  attach regardless of root.
- Workaround: compile your *own* binary with `get-task-allow` to
  enable attachment; useful for lab targets you authored yourself.
- System binaries need `csrutil disable` + optional
  `csrutil authenticated-root disable` + reboot to be debuggable.

## Workflow

### A: break on a function, dump its arguments

Via MCP:

    macre-vm-mcp: lldb_break_and_inspect {
      "binary_path": "/Users/<remote-user>/Targets/proj/hello",
      "symbol": "-[Greeter sayHi]",
      "dump_registers": true,
      "dump_stack_bytes": 64,
      "timeout_sec": 10
    }

Returns the captured lldb transcript — every register read, memory
read, and backtrace frame, as text. Pipe through your usual
reasoning.

### B: hit a breakpoint, then continue and hit another

`lldb_break_and_inspect` is one-shot. For multi-stop flows use
`lldb_run` directly:

    macre-vm-mcp: lldb_run {
      "binary_path": "/Users/<remote-user>/Targets/proj/hello",
      "breakpoints": ["-[Greeter sayHi]", "-[Greeter someOther]"],
      "post_break_commands": [
        "register read x0 x1",
        "memory read --count 32 $x0",
        "continue"
      ],
      "run_command": "run",
      "timeout_sec": 20
    }

Here `post_break_commands` ending with `continue` causes the run to
hit the second breakpoint too, then quit at program exit.

### C: patch-skip an annoying check

When reversing a binary that aborts early without enough info:

1. In Ghidra, find the address of the check's conditional branch
   (e.g. `b.ne 0x100001234` that jumps past the interesting code).
2. From lldb at that breakpoint, overwrite the branch with a
   `nop`:

        macre-vm-mcp: lldb_run {
          "binary_path": "/path/on/VM/foo",
          "breakpoints": ["0x100001230"],
          "post_break_commands": [
            "memory write 0x100001230 0x1f 0x20 0x03 0xd5",
            "continue"
          ]
        }

3. Observe the now-reachable downstream code via further
   breakpoints.

### D: trace every syscall and its number

    macre-vm-mcp: lldb_run {
      "binary_path": "/path/on/VM/foo",
      "breakpoints": ["svc #0"],
      "post_break_commands": [
        "register read x16 x0 x1",
        "continue"
      ],
      "timeout_sec": 15
    }

Caveat: breaking on every `svc` is slow. For production syscall
tracing use `dtrace` — see
[`Skills/offensive-macos-tooling-dtrace/SKILL.md`](../offensive-macos-tooling-dtrace/SKILL.md).
lldb's `svc` breakpoint is the right tool when you only care about
a specific syscall inside a specific function you already break on.

### E: attach to a running daemon without interrupting it

Interactive (SSH into the lab host manually, not MCP):

    sudo lldb -p $(pgrep -f MyDaemon)
    (lldb) br set -n somefn -G true
    (lldb) continue

`-G true` makes the breakpoint auto-continue after the commands
run — the daemon barely notices. Pair with a `breakpoint command
add` that reads a few registers and continues; you get a poor
man's tracer without halting the daemon.

Batch-ish version via MCP:

    macre-vm-mcp: lldb_run {
      "binary_path": "",                   # attach path unused; we drive via raw commands
      "breakpoints": [],
      "run_command": "process attach --pid <pid>",
      "post_break_commands": [
        "br set -n somefn -G true -C 'register read x0 x1' -C 'continue'",
        "continue"
      ],
      "timeout_sec": 30
    }

(Yes, the `lldb_run` tool's shape is slightly awkward for this;
plan U4 noted the tool list will evolve. For now, prefer
interactive SSH for live-attach work.)

## Current Bug-Class Anchors

### Runtime confirmation of an XPC LPE candidate

Public XPC client-signature-check bugs follow this same debugging shape.
The RE flow includes:

1. Open the privileged XPC helper in Ghidra, locate the
   `-listener:shouldAcceptNewConnection:` method.
2. From lldb, set a breakpoint there and attach to the running
   helper.
3. Trigger a connection from a malicious client; observe the
   register state (`x0 = self`, `x1 = sel`, `x2 = listener`,
   `x3 = newConnection`).
4. Step through the `SecCodeCopyGuestWithAttributes` + requirement
   check flow; confirm exactly what requirement the helper
   validates against.

Every step of the dynamic part lives in this skill. Wave 2's XPC
skill will link here.

### Method-swizzling confirmation

Some runtime-patching exercises use method swizzling, but the confirmation
pass is done in lldb: break on the real method before the swizzle,
observe the password argument, confirm the hook is in the right
place. Pure lldb; no new machinery.

## Pitfalls

- **`lldb_run`'s `run` is the default `run_command`.** For
  `process attach` flows, override `run_command` explicitly (see
  workflow E).
- **`memory write` on write-protected pages silently fails-and-
  reports-success** in some lldb versions. Confirm the write with
  a follow-up `memory read`. If it didn't stick, try
  `expression -- (void *)mprotect(...)` to flip the page, or use
  `mach_vm_protect` if you are patching another process.
- **Breakpoints in the dyld shared cache require `target modules
  add`** in older lldb versions. On macOS 26's lldb-2100.x it mostly
  works out of the box, but for system dylibs you may need
  `target modules add /path/to/extracted/libSystem.B.dylib` first.
- **Attaching to a process that exited between SSH and lldb attach**
  produces a cryptic "Failed to get reply to handshake packet"
  error. Re-check `pgrep -fl` first.
- **SIP-on reminder** — if the station is ever used against a SIP-on
  host, many recipes in this skill will silently fail on
  Apple-signed binaries. Verify with `csrutil status` once per
  session.
- **`breakpoint set` on an inlined function silently no-ops.**
  Release builds inline aggressively. Ghidra may recover a helper
  that lldb cannot resolve by name. Use an address breakpoint if
  name-based does not hit.

## Micro-exercise

*Goal:* confirm a function's argument by live observation, not just
static inference.

1. Use the `/tmp/hello` Obj-C binary. Sync to VM.
2. Pick one `objc_msgSend` call site (from the ObjC-runtime
   exercise). Note that `x1` should be the selector for the called
   method.
3. From Cursor:

        macre-vm-mcp: lldb_run {
          "binary_path": "/Users/<remote-user>/Targets/<proj>/hello",
          "breakpoints": ["_objc_msgSend"],
          "post_break_commands": [
            "register read x0 x1",
            "expression (const char *)sel_getName((void *)$x1)",
            "continue"
          ],
          "timeout_sec": 15
        }

4. In the captured output, confirm that at least one stop shows
   `x1` pointing to a string that resolves to `"class"` or
   `"sayHi"`.

Success = you can state "this `objc_msgSend` at runtime called
selector X" with evidence from lldb's register+`sel_getName` output.

## See also

- [`Skills/offensive-macos-tooling-ghidra-headless/SKILL.md`](../offensive-macos-tooling-ghidra-headless/SKILL.md) — turn addresses observed in lldb into readable Ghidra pseudocode.
- [`Skills/offensive-macos-tooling-dtrace/SKILL.md`](../offensive-macos-tooling-dtrace/SKILL.md) — when lldb's per-breakpoint overhead is too high, switch to dtrace.
- [`Skills/offensive-macos-foundations-objc-runtime/SKILL.md`](../offensive-macos-foundations-objc-runtime/SKILL.md) — why `x0` = self and `x1` = SEL at `objc_msgSend`.
- [`macre-vm-mcp/src/macre_vm_mcp/tools_lldb.py`](../../macre-vm-mcp/src/macre_vm_mcp/tools_lldb.py) — the actual wrapper code; read it to see exactly what `lldb_run` executes.
- Apple's lldb docs: https://lldb.llvm.org/use/tutorial.html
