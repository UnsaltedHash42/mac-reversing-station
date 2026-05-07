---
name: offensive-macos-hunt-wrong-door
description: >-
  Use when auditing macOS daemons for "entitlement on the wrong door" bugs:
  multiple XPC MachServices, privileged/internal service names, missing or
  inconsistent `shouldAcceptNewConnection:` gates, post-connection entitlement
  checks, or unprivileged UID 501 reachability. Fires on "wrong-door",
  "entitlement on wrong interface", "audit this daemon for XPC gates", and
  "run the wrong-door scan".
folder: offensive-macos-hunt-wrong-door
source: skillz-wave2
trigger_phrases:
  - "wrong-door"
  - "entitlement on the wrong door"
  - "audit this daemon for XPC gates"
  - "run the wrong-door scan"
---

# Hunt: Entitlement On The Wrong Door

> **Channel boundary:** `REPO_MODE=analysis`. Root-cause analysis, lab reproduction,
> defensive mapping, and tooling guidance only. No operational exploit authoring
> against live third-party targets.

## When To Use

- A daemon exposes two or more MachServices and only some appear to be entitlement-gated.
- A service name contains `privileged`, `internal`, `private`, `driver`, `registry`, or similar but accepts a low-privilege XPC connection.
- Static analysis finds entitlement checks, but they appear to happen after connection acceptance or only in one listener delegate.

## Lab Topology — Where To Run This

| Step | Surface | How |
|------|---------|-----|
| Static script sweep | lab host via Cursor | `ghidra-mcp` + `/Users/<remote-user>/ghidra-scripts/scan_wrong_door.py` |
| Entitlement and launchd metadata | lab host | `macre-vm-mcp` entitlement/codesign/launchd tools |
| UID 501 reachability probe | crash-test or primary | Build/run a small ObjC XPC harness as unprivileged user |
| Decompile delegate logic | lab host via Cursor | `function.by_name`, `decomp.function`, `ghidra.script` |
| Writeup state | Findings repo | Save TSV and candidate notes under `findings/analysis/` |

Full topology: `Skills/offensive-macos-station-topology/SKILL.md`.

## Vulnerability Class Definition

The wrong-door pattern happens when a daemon has multiple doors into the same privileged process, but the gate is attached to the wrong door. One XPC listener checks a private entitlement, another listener exposes equivalent or adjacent power with no equivalent check, or all connections are accepted and authorization is deferred until later operations where coverage is inconsistent.

The signal is not "a service accepts a connection." Many services accept and then reject method calls. The signal is a mismatch:

- More listener surfaces than entitlement checks.
- Service names that imply privilege but share a permissive delegate.
- `shouldAcceptNewConnection:` exists but does not branch by listener identity.
- Entitlement checks appear per-operation, not per-connection.
- UID 501 can connect to a service that claims to be privileged, internal, or registry/control-plane oriented.

## Anchor Pattern

The useful shape is: enumerate every MachService for one daemon, count static entitlement evidence, count listener delegates, then test reachability from UID 501. Rank targets where `listeners > entitlement_refs`, where multiple services share one permissive delegate, or where privileged service names return `ACCEPTED`/`REPLIED`.

Known pattern sources included daemons with multi-listener splits, post-connection checks, and service names such as privileged app/tool, driver, registry, simulation, internal, and classic/control endpoints. Those names are triage hints, not proof.

## Harness Invocation

1. Open the target binary with `ghidra-mcp`:

   ```text
   program.open(path="/path/to/daemon", project_location="/Users/<remote-user>/ghidra-projects", project_name="wrong-door-<target>", read_only=true, update_analysis=true)
   ```

2. Run:

   ```text
   ghidra.script(session_id="<session>", path="/Users/<remote-user>/ghidra-scripts/scan_wrong_door.py", script_args=[])
   ```

3. Save TSV stdout:

   ```text
   daemon	listeners	ent_refs	should_accept_impls	audit_token_uses	evidence
   /path/to/daemon	3	1	1	0	listeners=...
   ```

4. Rank rows:

   - Tier 1: `listeners >= 2`, privileged/internal service names, `ent_refs == 0` or fewer entitlement refs than listener surfaces, UID 501 `ACCEPTED` or `REPLIED`.
   - Tier 2: entitlement strings exist but appear post-connection; delegate logic unclear.
   - Tier 3: generic listener evidence but no privileged naming or dynamic reachability.

## UID 501 XPC Reachability Probe

Use this shape to classify a service before writing a PoC. Fill in the service name and protocol only after static analysis identifies the remote interface.

```objective-c
#import <Foundation/Foundation.h>

@protocol ProbeProtocol
- (void)pingWithReply:(void (^)(id reply))reply;
@end

int main(int argc, const char **argv) {
    @autoreleasepool {
        if (argc != 2) {
            fprintf(stderr, "usage: %s <mach-service-name>\n", argv[0]);
            return 2;
        }

        NSString *service = [NSString stringWithUTF8String:argv[1]];
        NSXPCConnection *conn = [[NSXPCConnection alloc]
            initWithMachServiceName:service
                            options:0];
        conn.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(ProbeProtocol)];

        __block int result = 3; // TIMEOUT
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        conn.interruptionHandler = ^{
            result = 2; // REJECTED / interrupted
            dispatch_semaphore_signal(sem);
        };
        conn.invalidationHandler = ^{
            result = 2;
            dispatch_semaphore_signal(sem);
        };
        [conn resume];

        id proxy = [conn remoteObjectProxyWithErrorHandler:^(NSError *err) {
            fprintf(stdout, "REJECTED\t%s\t%s\n", service.UTF8String, err.localizedDescription.UTF8String);
            result = 2;
            dispatch_semaphore_signal(sem);
        }];

        if (proxy) {
            fprintf(stdout, "ACCEPTED\t%s\n", service.UTF8String);
            result = 0;
            dispatch_semaphore_signal(sem);
        }

        dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC));
        [conn invalidate];
        if (result == 3) {
            fprintf(stdout, "TIMEOUT\t%s\n", service.UTF8String);
        }
        return result == 0 ? 0 : 1;
    }
}
```

Build:

```bash
clang -framework Foundation -fobjc-arc -o xpc_reachability_probe xpc_reachability_probe.m
```

Classify results:

- `ACCEPTED`: connection object established. Continue to interface-specific method probes.
- `REPLIED`: a real method call returned data. This is stronger than accepted.
- `REJECTED`: error handler or invalidation fired before usable interaction.
- `TIMEOUT`: ambiguous; retry once, then inspect logs.

## Triage Workflow

1. Build the service inventory from launchd plists and static strings.
2. Run `scan_wrong_door.py` for every candidate daemon and concatenate TSV rows.
3. Pick top candidates where listener count, service naming, and entitlement evidence do not line up.
4. Use the reachability probe from UID 501 against every service name for that daemon.
5. Decompile the delegate(s). Look for listener-specific branching, audit-token extraction, entitlement lookup, and whether the same code path serves all listeners.
6. If a method-level probe is needed, define only the minimum protocol methods required to prove reachability or authorization mismatch.
7. Close candidates aggressively when connection acceptance is followed by complete per-method authorization.

## Micro-Hunt

1. Choose three multi-service daemons from `/System/Library/LaunchDaemons` or `/usr/libexec`.
2. For each binary, run `scan_wrong_door.py` and save rows to `findings/analysis/<date>-wrong-door.tsv`.
3. For the highest-ranked row, test every MachService with the UID 501 reachability probe.
4. Decompile the listener delegate and write one paragraph: "gate before connection", "gate after connection", "no gate found", or "closed as false positive."

## Pitfalls

- XPC connection acceptance is not enough. The bug needs reachable privileged behavior, missing authorization, sensitive read/write, crash/DoS, or confused-deputy impact.
- Some daemons centralize checks in frameworks. If the thin daemon has low evidence, follow framework imports before closing.
- A service may intentionally accept low-privilege clients. Privileged naming raises priority but does not prove security intent.
- Crash-test anything panic-prone or daemon-crashing outside the primary machine when the lab roster has that role available.

## Attribution

Pattern adapted from dmaynor/AVR-INTERNAL, 2026 (see https://github.com/dmaynor/AVR-INTERNAL). This station imports the methodology and taxonomy; it does not claim AVR-INTERNAL's specific findings as ours.

## See Also

- `Skills/offensive-macos-tooling-ghidra-headless/SKILL.md`
- `Skills/offensive-macos-tooling-lldb/SKILL.md`
- `Skills/offensive-macos-agent-discipline/SKILL.md`
- `ghidra-scripts/scan_wrong_door.py`
