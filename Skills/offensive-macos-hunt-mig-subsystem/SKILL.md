---
name: offensive-macos-hunt-mig-subsystem
description: >-
  Use when auditing daemons or kernel components that expose a Mach
  Interface Generator (MIG) subsystem: routine numbers dispatched through
  mach_msg, MIG-generated server stubs, mig_server_routine tables, and
  MIG-derived kernel traps. Covers user-space MIG (cfprefsd, lockd,
  bootstrap_server, KernelEventAgent) and kernel MIG (host_priv,
  task_self_trap subsystems). Fires on "mig subsystem", "mig routine",
  "mig server stubs", "mach trap audit", "subsystem audit".
folder: offensive-macos-hunt-mig-subsystem
source: skillz-wave7
trigger_phrases:
  - "mig subsystem"
  - "mig routine"
  - "mig server stubs"
  - "mach trap audit"
  - "subsystem audit"
---

# Hunt: MIG subsystem audit

> Channel boundary: `REPO_MODE=analysis`. Kernel-side PoC code lives in
> private project clones, not this template.

## When to use

The target imports `mach_msg`, exposes a Mach service, or calls into MIG-generated stubs. Headers like `<mach/mig.h>`, function names matching `_X<routine>`, or static `mig_subsystem_t` tables in the binary all flag this. Apple components that historically had MIG bugs include `cfprefsd`, `lockd`, `bootstrap_server`, `KernelEventAgent`, `taskgated`, `coreaudiod`, and the kernel itself (host_priv subsystem, task_self_trap).

## Lab topology

| Step | Surface | How |
|---|---|---|
| Static script sweep | lab host | `ghidra-mcp` + `~/ghidra-scripts/scan_launchd_machservice_topology.py`, `dump_xpc_listeners.py` |
| MIG subsystem table walk | lab host | manual `ghidra-mcp` lookups for `mig_subsystem_t` static structures |
| Routine reachability | lab host | enumerate exported `_X<routine>` functions; check argument validation |
| Reachability probe | crash-test | minimal Mach-port client that calls `mach_msg(MACH_SEND_MSG, ...)` with controlled `msgh_id` |
| Evidence | findings repo | TSVs + decompilation under `findings/analysis/`, hash-pinned |

## What MIG is, briefly

MIG generates server-side stub code that takes a Mach message, demuxes by `msgh_id`, calls a hand-written implementation function, and packs a reply. The user-space MIG framework (`mig` tool against a `.defs` file) emits something like:

```c
mig_routine_t routines[] = {
    /* 0 */ NULL,
    /* 1 */ (mig_routine_t)_X__do_thing,
    /* 2 */ (mig_routine_t)_X__do_other,
    ...
};

boolean_t subsystem_server(...) {
    mig_routine_t routine = subsystem_routine(InHeadP);
    if (routine != NULL) routine(InHeadP, OutHeadP);
}
```

The `_X<name>` thunks decode the message, validate types, and call the human-implemented `<name>(...)`. Bugs land in three places:

The thunk's type validation (NDR records, descriptor counts, complex flag).

The implementation's argument validation (paths, port rights, dictionaries pulled from the message).

The subsystem dispatch table (out-of-range `msgh_id`, missing entries, wrong routine count).

Kernel MIG (the `host_priv`, `task`, `mach_port`, `mach_vm`, `clock` subsystems) follows the same shape but the routines run in kernel and the bugs are kernel LPE.

## Anchor pattern

Strong: a function named `_X<something>` that calls `mig_get_reply_port` or matches the MIG-generated signature `boolean_t routine(mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP)`. These are the entry points.

Strong: a static `mig_subsystem_t` table (Ghidra usually labels it). The table's routine count + start `msgh_id` define the reachable routine range. Out-of-range messages get `MIG_BAD_ID`; routines marked `(mig_routine_t)NULL` get the same. Mismatch between table size and code reality is interesting.

Strong: a daemon listening on a MachService (recovered via `bootstrap_callsite` from `scan_launchd_machservice_topology.py`) whose main message handler is a MIG dispatcher rather than an XPC delegate. These daemons were the first generation of macOS IPC and are often less hardened than NSXPC services.

Medium: function-name regex matches against `_routine`, `_server`, `_subsystem` patterns in the function index. Used to navigate the table.

Weak: tier-C strings mentioning `mig`, `subsystem`, or `MACH_SEND_MSG` alone. Common in any binary that links against Mach.

## Harness

Open the target. Find the subsystem table. Apple typically names it `<service>_subsystem`. In a binary like `/usr/libexec/cfprefsd`, look for a static struct that begins with `mig_impl_routines_t *impl_routines`, has a `mach_msg_id_t start` and `routine_count`, then an array of `mig_routine_descriptor` (one per `msgh_id`).

Once you have the table, enumerate every populated routine. For each:

```text
decomp.function(session_id="<session>", address=<routine_entry>)
```

Read the routine. The MIG-generated thunk (`_X<name>`) does type checking; the implementation (`<name>`) does the actual work. Verify:

- Does the implementation validate every port right it receives? (`mach_port_t` arguments arrive as port descriptors and the receiver inherits a send right.)
- Does it validate the size of every variable-length argument before reading?
- Does it audit-token-check the caller before performing a privileged action? (`audit_token_t` is in the trailer, not the body; the routine has to ask for `MACH_RCV_TRAILER_AUDIT`.)
- Does it free port rights and out-of-line data on every error path? Leaks here are kernel reference-count bugs in some routines.

## Reachability harness

A minimal client that drives one routine. Run only after static review.

```c
#include <mach/mach.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <service> <msgh_id>\n", argv[0]); return 2; }
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t kr = bootstrap_look_up(bootstrap_port, argv[1], &port);
    if (kr != KERN_SUCCESS) { fprintf(stderr, "lookup: 0x%x\n", kr); return 1; }

    struct {
        mach_msg_header_t header;
        // pad to a sane size; real test would carry a typed payload
        char padding[256];
    } msg = {0};
    msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg.header.msgh_remote_port = port;
    msg.header.msgh_local_port = MACH_PORT_NULL;
    msg.header.msgh_id = atoi(argv[2]);
    msg.header.msgh_size = sizeof(msg);

    kr = mach_msg(&msg.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                  msg.header.msgh_size, 0, MACH_PORT_NULL, 1000, MACH_PORT_NULL);
    fprintf(stdout, "service=%s id=%s kr=0x%x\n", argv[1], argv[2], kr);
    return kr == KERN_SUCCESS ? 0 : 1;
}
```

Build with `clang -o mig_probe mig_probe.c`.

This will not actually exercise type-correct routines (the payload is wrong), but it confirms reachability and surfaces logging from the daemon. For real triage, use `mig` against the `.defs` file (when public) or hand-write the matching message.

## Triage

For each routine in the subsystem:

1. Classify by privilege required: unprivileged (any UID), authenticated (audit token check), privileged (entitlement check).
2. Note the inputs that come from the message: paths, ports, dictionaries, fds.
3. Identify validation gaps: missing audit-token check, missing path canonicalization, missing port-right type check, missing size bound on variable-length args.

Promote to `escalated` only when the routine has a clear validation gap *and* the routine is reachable from a low-privilege caller (no entitlement gate, no UID check upstream of the dispatcher).

Confirm reachability with the probe. Do not write a full PoC against a kernel MIG routine on a non-disposable host.

## Pitfalls

Apple has migrated most user-space MIG to NSXPC over the last decade. A daemon may *register* a MachService that's actually used by NSXPC (`xpc_connection_create_mach_service` rather than `mach_msg`); the MIG hunt doesn't apply to those.

Kernel MIG routine numbers are stable across releases and documented in `<mach/mach_traps.h>`. Userland MIG routines are private and may renumber across point releases. Pin the OS build via `os_build_snapshot`.

Trailer-based audit tokens are opt-in. A routine that does not request `MACH_RCV_TRAILER_AUDIT` literally cannot identify its caller. That's not a bug per se but it means any privilege-gated work in that routine has to come from the message body, which is attacker-controlled.

Out-of-line memory descriptors arrive as virtual mappings; reading them without bounds checks is a kernel read primitive.

`mig_subsystem_t` tables can be coalesced with adjacent symbol regions in stripped binaries; Ghidra sometimes mis-types them as byte arrays. Manual structure application is required.

## Public anchors

Ian Beer's series on Mach IPC and MIG bugs (Project Zero, multiple posts). `task_for_pid` and the host_priv subsystem have been documented bug surfaces for over a decade. CVE-2018-4407 (kernel `icmp_input` was parsed via Mach), CVE-2021-30724 (`cfprefsd` MIG validation gap).

## See also

- `Skills/offensive-macos-foundations-macho/SKILL.md`
- `Skills/offensive-macos-tooling-ghidra-headless/SKILL.md`
- `Skills/offensive-macos-tooling-lldb/SKILL.md`
- `Skills/offensive-macos-hunt-iokit-userclient/SKILL.md`
- `Skills/offensive-macos-hunt-wrong-door/SKILL.md`
- `ghidra-scripts/scan_launchd_machservice_topology.py`
- `ghidra-scripts/dump_xpc_listeners.py`
