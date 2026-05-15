# Tutorial: first pass against a planted-bug daemon

This walkthrough uses a purpose-built XPC daemon with three deliberate
vulnerabilities. The goal is to demonstrate the full station workflow: intake,
static scanning, triage of multiple candidates, LLDB confirmation, closure
with rationale, and escalation of the real bug.

The daemon lives at `templates/tutorial-target/`. It ships as a pre-built
ad-hoc-signed arm64 binary so you can start immediately without building
from source. If you want to rebuild it yourself, run `build.sh` in that
directory.

## Target profile

- **Binary:** `tutorial_daemon` (arm64, ad-hoc signed)
- **MachServices:** `com.tutorial.daemon.privileged`, `com.tutorial.daemon.internal`
- **Launchd plist:** `plists/com.tutorial.daemon.privileged.plist`
- **Entitlements:** `com.apple.private.tcc.allow` (kTCCServiceSystemPolicyAllFiles), `com.tutorial.daemon.admin`
- **Protocols:** `PrivilegedOps` (installConfigAtPath:, restartServiceWithID:), `InternalOps` (writeAuditLog:, resetCacheAtPath:)

## Prerequisites

- A working station install (`scripts/smoke-wave3.sh` passes).
- The tutorial binary synced to the lab host under `~/Targets/tutorial_daemon`.
- Ghidra MCP and macre-vm-mcp reachable.

## Step 1: intake

From your project clone:

```bash
python3 scripts/start-target.py templates/tutorial-target/bin/tutorial_daemon \
    --pass-id PASS-TUTORIAL
```

Intake writes:
- Target map under `findings/analysis/`
- Dossier with surface classification
- CORPUS.md entry

Expected Watch classification: **privileged-helper / XPC-service** family.
Watch should recommend the `map-xpc-endpoints` recipe as the first sweep.

## Step 2: static scanning

Open the binary in Ghidra via MCP and run the relevant scans:

```
run scan_xpc_client_validation.py against the tutorial_daemon target.
run scan_wrong_door.py against the tutorial_daemon target.
run dump_xpc_listeners.py against the tutorial_daemon target.
```

Expected output from `scan_wrong_door.py`:
- Finds two MachServices registered in the plist.
- Finds one `shouldAcceptNewConnection:` implementation.
- Notes zero listener-identity branching (the single delegate serves both).

Expected output from `scan_xpc_client_validation.py`:
- Detects `SecTaskCreateWithAuditToken` usage.
- Notes entitlement string `com.tutorial.daemon.admin`.
- Notes no audit-token check in the `InternalOps` path.

Expected output from `dump_xpc_listeners.py`:
- Two verified services, one delegate method, one listener-init site.

## Step 3: triage — three candidates

From the scan output, create three candidates:

### C-001: shared delegate, no listener branching

`shouldAcceptNewConnection:` accepts both listeners with the same exported
interface. A client connecting to `com.tutorial.daemon.privileged` gets
`InternalOps` handlers, and a client connecting to `com.tutorial.daemon.internal`
also gets `InternalOps` handlers. The code never checks which listener
triggered the connection.

Triage state: **escalated**.
Reasoning: this is the root enabler. Without listener branching, the
service-name split is cosmetic. Any process can reach both protocols.

### C-002: audit-token bypass via methodID 0

`authorizeMethodID:connection:` returns `YES` unconditionally when
`methodID == 0`. The privileged handler's `installConfigAtPath:` passes
`methodID:1` and `restartServiceWithID:` passes `methodID:2`, but a
future method or a crafted invocation that routes through ID 0 skips the
entitlement check entirely.

Triage state: **escalated**.
Reasoning: authorization bypass. Even if C-001 didn't exist, a caller
that reaches the privileged handler could bypass the gate.

### C-003: un-gated InternalOps (write + delete)

`InternalHandler` has no caller validation:

- `writeAuditLog:` appends attacker content to `/var/log/tutorial-daemon-audit.log`.
- `resetCacheAtPath:` is `removeItemAtPath:` on an attacker-supplied path — **arbitrary file delete as root** once reached through C-001.

Triage state: **escalated** (severity **critical** for the class chain).
Reasoning: combined with C-001, any process that can open either MachService
gets `InternalOps`. `writeAuditLog:` proves reachability; `resetCacheAtPath:`
is the impact primitive for exploitation demos (e.g. delete a root-owned
sentinel under `/tmp/`).

### Red herring: com.apple.private.tcc.allow entitlement

The embedded entitlement claims `kTCCServiceSystemPolicyAllFiles`. This looks
scary but is inert without Apple's signing identity. Ad-hoc (or third-party)
binaries with private TCC entitlements are ignored by `tccd`. This is expected
behavior, not a bug.

Triage state: **closed**.
Rationale: private TCC entitlements require Apple platform signing to be
honored. Ad-hoc or third-party signatures get these claims silently stripped
at evaluation time.

## Step 4: LLDB confirmation for C-001

Attach to the running daemon (read-only) and confirm the delegate behavior:

```
break set -n "-[DaemonDelegate listener:shouldAcceptNewConnection:]"
```

Connect a test client to `com.tutorial.daemon.privileged`:

```objc
NSXPCConnection *conn = [[NSXPCConnection alloc]
    initWithMachServiceName:@"com.tutorial.daemon.privileged"
                    options:0];
conn.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(InternalOps)];
[conn resume];
[[conn remoteObjectProxy] writeAuditLog:@"hello from privileged port" withReply:^(BOOL ok) {
    NSLog(@"got reply: %d", ok);
}];
```

Expected: the breakpoint hits, the connection is accepted, and
`writeAuditLog:` executes successfully despite connecting to the
"privileged" service name. This confirms the delegate does not branch.

Record the LLDB transcript under `artifacts/`.

## Step 5: closure and escalation

Update `INDEX.md`:

| ID    | State    | Class                        | Summary                                  |
|-------|----------|------------------------------|------------------------------------------|
| C-001 | escalated | wrong-door / shared-delegate | No listener branching; both ports identical |
| C-002 | escalated | authorization-bypass         | methodID 0 skips entitlement check       |
| C-003 | escalated | un-gated-write               | writeAuditLog + resetCacheAtPath (root delete) |
| C-004 | closed   | n/a (red herring)            | Private TCC entitlement inert without Apple sig |

The real finding to report is C-001 + C-003 combined: any caller that reaches
`InternalOps` can delete arbitrary paths as root via `resetCacheAtPath:`
(wrong door on either MachService). `writeAuditLog:` proves unprivileged
reachability.

C-002 is a separate class (authorization bypass) that compounds the issue
if the privileged handler is ever reached.

## Step 6: Unprivileged reachability PoC

Connect to `com.tutorial.daemon.internal` with **no**
`NSXPCConnectionPrivileged` flag and call `writeAuditLog:` — proves UID 501
reachability without `sudo`.

## Step 7: Chain — root file delete

Connect to either Mach name (internal recommended for unprivileged callers),
call `resetCacheAtPath:` on a root-owned sentinel you planted (e.g.
`/tmp/tutorial-chain-sentinel`), verify the lab user could not delete it and
the XPC call removed it.

## Appendix: writeAuditLog PoC snippet

A minimal PoC connects to `com.tutorial.daemon.internal` (or `.privileged`,
since the delegate doesn't care) and calls `writeAuditLog:` with a crafted
payload:

```objc
#import <Foundation/Foundation.h>

@protocol InternalOps <NSObject>
- (void)writeAuditLog:(NSString *)message withReply:(void (^)(BOOL))reply;
@end

int main(void) {
    NSXPCConnection *conn = [[NSXPCConnection alloc]
        initWithMachServiceName:@"com.tutorial.daemon.internal"
                        options:0];
    conn.remoteObjectInterface =
        [NSXPCInterface interfaceWithProtocol:@protocol(InternalOps)];
    [conn resume];

    id proxy = [conn remoteObjectProxyWithErrorHandler:^(NSError *err) {
        NSLog(@"error: %@", err);
    }];
    [proxy writeAuditLog:@"INJECTED CONTENT" withReply:^(BOOL ok) {
        NSLog(@"write succeeded: %d", ok);
        exit(0);
    }];

    [[NSRunLoop currentRunLoop] run];
    return 0;
}
```

## What this tutorial demonstrates

1. **Scan selectivity.** The scans surface multiple signals; you triage them, not the tool.
2. **Closure discipline.** The TCC entitlement looks alarming but is inert. Closing it with rationale is as important as escalating the real bugs.
3. **Composition.** C-001 alone is a design flaw. C-003 alone is a missing auth check. Together they're an exploitable privilege boundary violation.
4. **The workflow.** Intake → scan → triage → confirm → close/escalate → unprivileged PoC → chain to root impact. Every step produces a durable artifact.

## Next steps after the tutorial

- Try running `export_lldb_anchors.py` to get ranked breakpoints for the daemon.
- Run the `hunt-wrong-door` skill against a real target and compare the triage experience.
- Rebuild the daemon from source (`build.sh`) and introduce a fourth bug to practice the cycle again.
