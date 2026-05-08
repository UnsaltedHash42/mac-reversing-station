---
name: offensive-macos-hunt-iokit-userclient
description: >-
  Use when auditing macOS user-mode binaries that talk to a kernel driver via
  IOKit user clients: EDR drivers, GPU userspace stacks, USB / HID stacks,
  vendor kexts and DriverKit dexts, and any helper binary that calls
  IOServiceOpen + IOConnectCallMethod. Fires on "iokit user client",
  "ioconnect call", "external method", "iokit selector hunt", and "kernel
  driver user surface".
folder: offensive-macos-hunt-iokit-userclient
source: skillz-wave6
trigger_phrases:
  - "iokit user client"
  - "ioconnect call"
  - "external method"
  - "iokit selector hunt"
  - "kernel driver user surface"
---

# Hunt: IOKit User Client Selector Surface

> **Channel boundary:** `REPO_MODE=analysis`. Root-cause analysis, lab
> reproduction, defensive mapping, and reporting guidance only. No
> operational kernel exploitation against live third-party targets;
> kernel work happens in private project clones.

## When To Use

- The target imports `IOKit.framework` and calls `IOServiceOpen` plus one or more `IOConnectCall*` variants.
- A vendor binary talks to a kext (`/System/Library/Extensions/<vendor>.kext`) or DriverKit dext.
- An EDR or AV product has a kernel-mode component and a user-mode helper that drives it.
- A bug-class signal points at "the user-mode side calls method index N with these scalars" and you need to enumerate N.

## Lab Topology — Where To Run This

| Step | Surface | How |
|------|---------|-----|
| Static script sweep | lab host via Cursor | `ghidra-mcp` + `~/ghidra-scripts/scan_iokit_user_clients.py` |
| Driver-side correlation | lab host via Cursor | open the matching `.kext` / `.dext` in Ghidra; find `getTargetAndMethodForIndex` / `externalMethod` |
| Driver enumeration | lab host | `kextstat` / `systemextensionsctl list` / `ioreg -l` |
| Reachability harness | crash-test only | minimal C program that opens the user client and calls the candidate selector with controlled scalars |
| Evidence record | findings repo | TSVs + driver decompilation under `findings/analysis/`; **never run kernel-fuzzing harnesses on the primary lab VM** |

This hunt is high-impact and high-blast-radius. Kernel panics will reboot the lab VM and may corrupt the disk. Use a snapshotted crash-test VM.

## Vulnerability Class Definition

An IOKit user client exposes a callable surface that runs in the kernel. The kernel side dispatches each `IOConnectCallMethod(connect, selector, ...)` through a fixed table or virtual method like `IOUserClient::getTargetAndMethodForIndex` / `IOUserClient::externalMethod`. The bugs come from:

1. **Insufficient selector validation.** The driver does not check the selector index range, lets it select an out-of-table function pointer, or dispatches to a method that should be privileged-only.
2. **Insufficient scalar / struct validation.** The selected method trusts user-provided sizes, type tags, or pointer fields. Classic IOKit bugs land here (every other IOSurface / IOSurfaceClient bug).
3. **Insufficient client-class gating.** A user client class meant for one privileged path is openable from a sandboxed or unprivileged caller.
4. **Async vs sync confusion.** The async variant (`IOConnectCallAsyncMethod`) takes a port; mishandling that port has produced multiple kernel-LPE chains.

The user-mode side of this hunt is what `scan_iokit_user_clients.py` recovers. The kernel-mode side is where the bug actually lives — but the user-mode binary tells you exactly which selectors and scalars are reachable from userspace, which constrains the kernel-side fuzzing space dramatically.

## Anchor Pattern

From `scan_iokit_user_clients.py`:

- **Strong**: tier-A `ioservice_matching_callsite` with a recovered class name (`com.apple.driver.AppleAVE2`, `IOSurfaceRoot`, vendor classes) **plus** multiple tier-A `ioconnect_call_method_callsite` rows with recovered selectors. You now have a complete (driver class, selector list) tuple. Take it to the kernel side.
- **Strong**: tier-A `ioconnect_call_async_method_callsite` rows. Async paths are historically the highest-yield bug class.
- **Medium**: tier-A `ioservice_open_callsite` with no recovered class name. Driver class is dynamic; navigate the caller to find where it is computed.
- **Weak**: tier-C `io_kit_string` rows alone. The binary references IOKit but may only consume sysctl / IORegistry, not actually open user clients.

## Harness Invocation

1. Open the user-mode binary:
   ```text
   program.open(path="/Library/Application Support/<Vendor>/<helper>",
                project_location="/Users/<remote-user>/ghidra-projects",
                project_name="iokit-<vendor>", read_only=true, update_analysis=true)
   ```

2. Run the scan:
   ```text
   ghidra.script(session_id="<session>",
                 path="/Users/<remote-user>/ghidra-scripts/scan_iokit_user_clients.py",
                 script_args=[])
   ```

3. Build the (class, selector) inventory from tier-A rows:
   ```
   class=com.apple.driver.AppleAVE2:
     selector=0x05  caller=_ave2_init
     selector=0x12  caller=_ave2_submit_frame
     selector=0x21  caller=_ave2_set_qp
   ```

4. Open the driver in Ghidra:
   ```text
   program.open(path="/System/Library/Extensions/<vendor>.kext/Contents/MacOS/<binary>",
                project_location="/Users/<remote-user>/ghidra-projects",
                project_name="iokit-<vendor>-driver", read_only=true, update_analysis=true)
   ```

5. Find `getTargetAndMethodForIndex` or the static `IOExternalMethodDispatch` / `IOExternalMethodDispatch2022` table. Map each selector index to its kernel-side method. The resulting (selector, kernel_method, scalar_count, struct_input_size) table is the fuzz surface.

## Reachability Harness

Build a minimal C user-client opener. Run **only on the crash-test VM**.

```c
#include <IOKit/IOKitLib.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <driver-class-name> <selector-decimal>\n", argv[0]);
        return 2;
    }
    io_service_t svc = IOServiceGetMatchingService(
        kIOMainPortDefault, IOServiceMatching(argv[1]));
    if (!svc) { fprintf(stderr, "no matching service\n"); return 1; }

    io_connect_t conn = 0;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
    IOObjectRelease(svc);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "IOServiceOpen failed: 0x%x\n", kr);
        return 1;
    }

    uint32_t selector = (uint32_t)atoi(argv[2]);
    uint64_t scalars[8] = {0};
    uint32_t out_count = 8;
    uint64_t out_scalars[8] = {0};

    kr = IOConnectCallScalarMethod(conn, selector, scalars, 8,
                                   out_scalars, &out_count);
    fprintf(stdout, "selector=%u kr=0x%x out_count=%u\n",
            selector, kr, out_count);

    IOServiceClose(conn);
    return kr == KERN_SUCCESS ? 0 : 1;
}
```

Build:
```bash
clang -framework IOKit -o ioconnect_probe ioconnect_probe.c
```

Use this **only** to confirm reachability of one selector you've already statically reviewed. Do not loop over selector ranges blindly; that is fuzzing on a non-disposable host.

## Triage Workflow

1. Enumerate selectors via `scan_iokit_user_clients.py`.
2. Pull the driver-side dispatch table.
3. For each selector that the user-mode binary actually calls, classify:
   - The kernel method's scalar count and struct sizes.
   - Whether selector validation gates by user vs root.
   - Whether the method touches user-provided pointers in kernel.
4. Promote to `escalated` only when the kernel method has user-controlled inputs that affect kernel pointer arithmetic, allocation size, or capability checks.
5. Confirm with a single-selector reachability run on the crash-test VM.
6. PoC authoring lives in private project clones (`Skills/offensive-macos-poc-authoring/SKILL.md`).

## Pitfalls

- **Driver class names are not always strings.** Some binaries compute the matching dictionary via `CFDictionaryCreate` and `CFSTR("IOProviderClass")` keys; the class name may not show up as a tier-A recovery. Inspect the dictionary builder.
- **DriverKit dext dispatch is in user space.** The kernel-side selector table for a dext lives in the dext binary itself, not in the kernel. Scan the dext.
- **System Integrity Protection vs kernel work.** SIP being on does not protect against IOKit selector bugs in vendor drivers; vendor drivers run privileged regardless. Lab safety is about the panic risk, not SIP.
- **Apple Silicon kernel exclusion.** PAC and PPL block several historical exploitation strategies but not the bug surface itself. Static analysis still applies.
- **Async ports leak.** Test harnesses that open and never close user clients with async ports will eventually exhaust port tables and panic.

## Known Public Anchors

- Project Zero's series on IOSurface / AGX / AppleAVD selectors (multiple write-ups across 2019-2024).
- `IOMobileFramebuffer` selector validation bugs (2021-2023).
- Vendor driver bugs in EDR products (multiple disclosures via vendor advisories).

## See Also

- `Skills/offensive-macos-foundations-macho/SKILL.md`
- `Skills/offensive-macos-foundations-objc-runtime/SKILL.md`
- `Skills/offensive-macos-tooling-ghidra-headless/SKILL.md`
- `Skills/offensive-macos-tooling-lldb/SKILL.md`
- `Skills/offensive-macos-poc-authoring/SKILL.md`
- `ghidra-scripts/scan_iokit_user_clients.py`
- `ghidra-scripts/scan_private_framework_dependency.py`
