---
name: offensive-macos-shellcode-arm64
description: >-
  Use when writing, reading, or analyzing ARM64 shellcode on macOS.
  Covers AArch64 calling conventions, macOS syscall numbering
  (``x16`` = syscall number; ``svc #0x80``), execv payloads, bind-shell
  construction, eliminating PC-relative addressing, stub elimination,
  locating libc functions via the dyld shared cache, and the dtrace /
  lldb confirmation loop. Framed as RE-enablement (understanding
  injected payloads during analysis), not operational payload
  authoring for live third-party targets.
folder: offensive-macos-shellcode-arm64
source: skillz-wave1
trigger_phrases:
  - "arm64 shellcode"
  - "macos syscall number"
  - "svc 0x80"
  - "execv shellcode"
  - "bind shell arm64"
  - "position-independent shellcode"
---

# ARM64 shellcode craft (macOS)

> **Channel boundary:** `REPO_MODE=analysis`. This skill exists to help
> the operator **read, reason about, and analyze** ARM64 shellcode that
> shows up in malware samples, public PoCs, or local lab exercises. It is
> **not** a recipe book for operational payload authoring against live
> third-party targets; see `cursor/rule-analysis.mdc`.

## When to use

- You are reading a PoC for a macOS exploit and need to understand
  the injected payload.
- You are doing a local lab-only ARM64 shellcode exercise.
- A malware sample contains suspicious ARM64 code with `svc` / `mov
  x16, #...` patterns and you want to classify what it does.
- You want to confirm your understanding of a shellcode by running
  it in an isolated lab target and observing what it actually does
  via dtrace + lldb.

## Lab topology — where to run this

| Step | Surface | How |
|------|---------|-----|
| Assemble + link on workstation | Workstation | `clang -arch arm64 -o shellcode shellcode.s` |
| Run in lab against a toy target | VM | Copy via `scripts/rsync-to-vm.sh`, then `macre-vm-mcp: lldb_run` |
| Watch syscalls | VM | `macre-vm-mcp: dtrace_script` with `syscall:::entry` |
| Single-step through it | VM | `macre-vm-mcp: lldb_run` with `svc #0` breakpoints |
| Read the raw bytes | Workstation | `otool -tV shellcode`; `xxd` |

## Theory

### ARM64 calling convention on macOS (user-space)

| Register | Role |
|----------|------|
| `x0..x7` | Arg 0..7 (integers, pointers) |
| `x8` | Indirect return pointer (large return values) |
| `x9..x15` | Caller-saved scratch |
| `x16` | `IP0` — **also the syscall number on macOS** |
| `x17` | `IP1` |
| `x18` | Platform reg — **Apple: reserved, do not use** |
| `x19..x28` | Callee-saved |
| `x29` (fp) | Frame pointer |
| `x30` (lr) | Link register — return address |
| `sp` | Stack pointer, must be 16-byte-aligned at call |
| `pc` | Program counter |
| `d0..d7` | FP/vector args + returns |

Key shellcode implication: **x16 is the syscall number**, so every
macOS syscall-issuing shellcode boils down to:

    mov x16, #<syscall_number>   ; set syscall number
    ; set args in x0..x7
    svc #0x80                    ; trigger supervisor call

(`svc #0x80` is traditional on macOS; `svc #0` works too — the
immediate is ignored by the kernel.)

### Syscall numbering

Syscall numbers live in `<sys/syscall.h>` (and
`/System/Library/Sandbox/Profiles`... no, that's something else).
The canonical list also lives in Apple's xnu source
`bsd/kern/syscalls.master`.

Wave 1 relevant numbers:

| # | Name | Signature |
|---|------|-----------|
| 1 | `exit` | `void exit(int rval)` |
| 3 | `read` | `ssize_t read(int fd, void *buf, size_t count)` |
| 4 | `write` | `ssize_t write(int fd, const void *buf, size_t count)` |
| 5 | `open` | `int open(const char *path, int flags, mode_t mode)` |
| 6 | `close` | `int close(int fd)` |
| 23 | `setuid` | `int setuid(uid_t uid)` |
| 24 | `getuid` | `uid_t getuid()` |
| 30 | `accept` | `int accept(int s, struct sockaddr *addr, socklen_t *addrlen)` |
| 59 | `execve` | `int execve(char *fname, char **argp, char **envp)` |
| 90 | `dup2` | `int dup2(int from, int to)` |
| 97 | `socket` | `int socket(int domain, int type, int protocol)` |
| 98 | `connect` | `int connect(int s, struct sockaddr *name, socklen_t namelen)` |
| 104 | `bind` | `int bind(int s, struct sockaddr *name, socklen_t namelen)` |
| 106 | `listen` | `int listen(int s, int backlog)` |

**On macOS BSD syscalls, the numbers above ORed with `0x2000000`**
is what actually goes into x16 historically — but on arm64 macOS
you just put the plain number. The x86_64 class-mask convention
doesn't apply to arm64's `svc`.

### Minimal "exit" shellcode — the smallest correct example

    .section __TEXT,__text
    .globl _main
    .p2align 2
    _main:
        mov     x0, #42        ; exit code
        mov     x16, #1        ; SYS_exit
        svc     #0x80

Assemble and confirm:

    clang -arch arm64 -o miniexit miniexit.s
    ./miniexit ; echo "ret=$?"    # expect ret=42
    otool -tV miniexit | head     # read the raw arm64 bytes

This is the template. Every bigger shellcode is this, plus more
register setup before each `svc`.

### PC-relative addressing and why it matters

ARM64 has no single-instruction absolute `mov x0, #0xffffffff00000000`
for large literals. To load an address you either:

- Use `adr x0, label` — reaches ±1 MB, PC-relative.
- Use `adrp x0, label@PAGE ; add x0, x0, label@PAGEOFF` — reaches
  ±4 GB, PC-relative.
- Chain `mov` / `movk` for a raw 64-bit immediate — the **only**
  form that is **not** PC-relative.

**Consequence for shellcode:** if your payload uses `adr` or `adrp`
to reference its own strings (argv buffers, paths), the resulting
bytes only work at a specific load address. Relocated or copied
elsewhere, they compute wrong targets.

When writing injection-style shellcode, local lab exercises often walk
through eliminating every `adr`/`adrp`. The trick: use
`bl .+4; <data>; <code that reads x30>` so `x30` (the link register)
contains the address **just after** your `bl`, which is wherever
you put your data. Everything downstream is relative to `x30`,
which the CPU computed for you. No PC-relative compile-time magic
needed.

### Stub elimination

Compile a C-based shellcode with `clang -c shellcode.c` and
`otool -tV` the result — you'll see calls to `__stubs` section
entries like `_execv` that resolve indirectly through the GOT. A
raw shellcode blob extracted from the `.text` section won't have
the stubs, so the `bl _execv` will branch into garbage.

Two fixes:

1. **Don't compile C shellcode at all**; write asm directly. Every
   call is a `bl` to a real address you set up.
2. **Locate `execv`'s real address at runtime**, load it into a
   register, and `blr` through that register instead of `bl` to a
   stub. The practical path is: find `dyld`'s
   `_dlsym` via the process's `LC_LOAD_DYLINKER`, then `dlsym(NULL,
   "execv")`, then branch to the returned pointer. That pattern is
   the cornerstone of self-sufficient macOS shellcode.

### Finding symbols via the dyld shared cache

On modern macOS, `execv` lives inside the dyld shared cache, not
a standalone dylib. When you `dlsym(NULL, "execv")` you get the
cache-resident address for your process.

Alternative (for learning / for shellcode that can't call dlsym):
walk the in-process dyld's image list, find the Mach-O header of
`libsystem_c.dylib` (the export dylib for `execv`), walk its
`LC_SYMTAB` to find `_execv`, and compute the address.

Both are valid. `dlsym` is the pragmatic path; the walk-the-cache
path is lab exercise material for people who want to see the loader's
work.

### Avoiding NUL bytes

When shellcode is injected via a string-copying primitive (`strcpy`,
`strcat`), NUL bytes terminate the write — the rest of the payload
is truncated. Clean shellcode avoids them.

Common NUL sources in ARM64 instruction encodings:

- `mov x16, #1` encodes as `20 00 80 d2` — the `00` byte is a NUL.
  Workaround: `mov x16, #2 ; sub x16, x16, #1` or use the syscall
  number OR'd into a register already shaped by earlier ops.
- `mov x0, #0` encodes with NULs. Workaround: `eor x0, x0, x0` (XOR
  with self — `00 00 00 ca`-ish pattern, no NULs).
- Short immediates near zero: use `movn` (move-not) tricks or
  load-from-nearby-non-zero then subtract.

For most RE work you don't care — you're just reading the shellcode,
not injecting it through a string-copy primitive. But recognizing
these tricks helps you identify which shellcode is "string-safe"
vs "blob-only."

## Workflow

### A: read an unknown ARM64 shellcode blob

Given a hex blob from a PoC or malware sample:

1. Save bytes to a file. If the source is a C array like
   `char sc[] = "\xe0\x03\x1f\xaa…"`, use `xxd -r -p` after
   stripping the `\x` prefixes, or assemble a tiny C loader.
2. Disassemble:

        xcrun --sdk macosx llvm-objdump -d --arch=aarch64 shellcode.bin

   or (more convenient) dump the running shellcode from a live
   process via lldb:

        macre-vm-mcp: lldb_run {
          "binary_path": "...",
          "breakpoints": ["_main"],
          "post_break_commands": [
            "disassemble -s 0x100008000 -c 40"
          ]
        }

3. Identify every `svc #0x80` instruction. For each, read backward
   to find what `x16` and arg registers were set to.
4. Map `x16` values to syscall names (table above, or
   `grep -w <n> /usr/include/sys/syscall.h` on workstation).
5. Classify the payload: `execve`-style? `socket`/`bind`/`listen`
   stack? `fork`+`execve`? File write?

### B: write and verify a minimal payload in the lab

The canonical lab shape is to run `/bin/sh -c
"echo hi"` via `execve`:

```
.section __TEXT,__text
.globl _main
.p2align 2
_main:
    // x1 = argv = { &"/bin/sh", &"-c", &"echo hi", NULL }
    // Build argv on the stack so we don't depend on PC-relative
    // loads.

    sub     sp, sp, #48
    adr     x19, sh_path           // cheat for brevity; in real
    adr     x20, dash_c            // shellcode, position-fix these
    adr     x21, cmd
    str     xzr, [sp, #24]
    str     x21, [sp, #16]
    str     x20, [sp, #8]
    str     x19, [sp]

    mov     x0, x19                 // path
    mov     x1, sp                  // argv
    mov     x2, xzr                 // envp
    mov     x16, #59                // SYS_execve
    svc     #0x80

    // fallthrough: exit
    mov     x0, #1
    mov     x16, #1
    svc     #0x80

sh_path: .asciz "/bin/sh"
dash_c:  .asciz "-c"
cmd:     .asciz "echo hi"
```

Build and run on the workstation for a local sanity check:

    clang -arch arm64 -o mini mini.s
    ./mini           # expect "hi"

Sync and run on the VM with dtrace attached:

    cp mini ./targets/
    bash scripts/rsync-to-vm.sh ./targets/

From Cursor:

    macre-vm-mcp: dtrace_script {
      "script":
        "syscall:::entry /pid == $target/ { printf(\"%s(%x, %x, %x)\", probefunc, arg0, arg1, arg2); } END {}",
      "target_command": ["/Users/<remote-user>/Targets/<proj>/mini"],
      "timeout_sec": 5
    }

Expected stdout: an `execve` call logged with the `/bin/sh` path as
arg0, followed by the spawned `sh`'s own syscalls. You'll see
`write` for "hi\n", then `exit`.

### C: step through shellcode in lldb

    macre-vm-mcp: lldb_run {
      "binary_path": "/Users/<remote-user>/Targets/<proj>/mini",
      "breakpoints": ["_main"],
      "post_break_commands": [
        "disassemble -c 30",
        "s", "s", "s", "s", "s",      # step five instructions
        "register read",
        "continue"
      ],
      "timeout_sec": 15
    }

Read the captured transcript — you see the register state at each
step. Perfect for confirming x16 is what you expect at `svc` time.

### D: bind-shell walkthrough

A lab bind shell builds up by composing:

1. `socket(AF_INET=2, SOCK_STREAM=1, 0)` → sockfd in x0.
2. `bind(sockfd, &sockaddr_in{AF_INET, port, 0.0.0.0, 0…}, 16)`.
3. `listen(sockfd, 1)`.
4. `accept(sockfd, NULL, NULL)` → client fd.
5. `dup2(client, 0); dup2(client, 1); dup2(client, 2);`.
6. `execve("/bin/sh", {"/bin/sh", NULL}, NULL)`.

Each step is a `svc` with x16 = the syscall number from the table.
Keep a full assembly listing in the private lab notes; the
learning value is in building it yourself in the lab and verifying
with dtrace that every syscall goes through as expected.

**Ethical framing:** this is lab-only. The point is to understand
how shellcode is *shaped* so that when you find one during RE of
a malware sample, you can read it. Do not run a bind shell on a
publicly-reachable host.

## Current Bug-Class Anchors

### App-injection lab case study

A local lab can walk through injecting `execv` shellcode into
an app process via a specific lab vulnerability. The shellcode used is an
`execve("/usr/bin/open", ["open", "-a", "Calculator"], NULL)`
payload — classic "prove injection worked" proof shape. Keep the assembly
listing in private lab notes; every instruction should map to concepts
introduced here.

### Shellcode in 2024–2026 macOS malware

Multiple recent macOS malware families (Shrouded, HZ Rat variants)
embed ARM64 shellcode loaders. The pattern is consistent:
position-independent payload + dlsym-based symbol resolution +
minimal syscall usage. Wave 1's job is to make that pattern
readable at a glance. Deeper classification (anti-analysis
techniques, unusual cryptographic steps) is Wave 3+ territory.

## Pitfalls

- **`svc #0x80` vs `svc #0`.** Both work. The immediate is ignored
  on arm64 macOS. Don't let a PoC that uses one trick you into
  thinking the other is "wrong."
- **"macOS uses 0x2000000 + syscall on x86_64" is legacy.** Arm64
  uses the bare number in x16. Read assembly accordingly.
- **PC-relative hazards.** A shellcode blob extracted from one
  binary and memcpy'd into another will fail silently if any `adr`
  / `adrp` is in there. Disassemble and audit.
- **Stack alignment.** On arm64, `sp` must be 16-byte aligned at
  every external call (including `svc` in most practical cases). If
  your shellcode decrements `sp` oddly, some syscalls return
  `-EFAULT` or the process SIGBUSes.
- **Signal handlers and `SA_RESTART`.** Shellcode that makes a
  blocking syscall (like `accept`) and gets interrupted by a
  signal returns -EINTR. Robust shellcode retries.
- **Sandbox / entitlements.** If you inject into a sandboxed process,
  your shellcode inherits the sandbox. `socket()` may fail with
  -EPERM even though it "should" work. Check the target's
  entitlements before concluding your shellcode is broken.
- **SIP notes.** Record whether the lab host has SIP on or off, because syscall and tracing behavior changes
  without restriction. On SIP-on systems, `setuid(0)` and related
  are gated by AMFI + codesign flags. Flagged here for
  when-the-station-is-used-elsewhere.

## Micro-exercise

*Goal:* Write a minimal "exit 42" shellcode, run it on the VM,
confirm the syscall with dtrace.

1. On the workstation:

        cat > /tmp/miniexit.s <<'EOF'
        .section __TEXT,__text
        .globl _main
        .p2align 2
        _main:
            mov x0, #42
            mov x16, #1
            svc #0x80
        EOF
        clang -arch arm64 -o /tmp/miniexit /tmp/miniexit.s
        /tmp/miniexit ; echo "ret=$?"   # expect ret=42

2. Sync to VM:

        cp /tmp/miniexit ./targets/
        bash scripts/rsync-to-vm.sh ./targets/

3. From Cursor, trace the syscall:

        macre-vm-mcp: dtrace_script {
          "script": "syscall::exit:entry /pid == $target/ { printf(\"exit(%d)\", arg0); }",
          "target_command": ["/Users/<remote-user>/Targets/<proj>/miniexit"],
          "timeout_sec": 3
        }

   Expected: one `exit(42)` line.
4. Re-disassemble and identify each instruction:

        otool -tV /tmp/miniexit | head -30

   Confirm: `mov x0, #42`, `mov x16, #1`, `svc #0x80`.

Success = everything matches, and you can write out in plain
English "program loaded at address A, executed 3 instructions,
invoked syscall 1 (exit) with argument 42, process terminated."

## See also

- [`Skills/offensive-macos-tooling-dtrace/SKILL.md`](../offensive-macos-tooling-dtrace/SKILL.md) — the primary confirmation tool for shellcode in the lab.
- [`Skills/offensive-macos-tooling-lldb/SKILL.md`](../offensive-macos-tooling-lldb/SKILL.md) — single-step through a payload.
- [`Skills/offensive-macos-foundations-macho/SKILL.md`](../offensive-macos-foundations-macho/SKILL.md) — stubs, chained fixups, and the dyld shared cache (which is where `execve` actually lives on modern macOS).
- `<sys/syscall.h>` + `bsd/kern/syscalls.master` in Apple's xnu source — authoritative syscall numbers.
- Apple ARM64 ABI: https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms
