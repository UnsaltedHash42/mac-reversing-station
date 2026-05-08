---
name: offensive-macos-hunt-iokit-userclient
description: >-
  Use when auditing user-mode binaries that drive a kernel driver via
  IOKit user clients: EDR drivers, GPU userspace stacks, USB/HID stacks,
  vendor kexts, DriverKit dexts, helper binaries that call IOServiceOpen
  + IOConnectCallMethod. Fires on "iokit user client", "ioconnect call",
  "external method", "iokit selector hunt", "kernel driver user surface".
folder: offensive-macos-hunt-iokit-userclient
source: skillz-wave6
trigger_phrases:
  - "iokit user client"
  - "ioconnect call"
  - "external method"
  - "iokit selector hunt"
  - "kernel driver user surface"
---

# Hunt: IOKit user-client selector surface

> Channel boundary: `REPO_MODE=analysis`. RCA, lab reproduction, defensive
> mapping, reporting only. Kernel-side PoC code lives in private project
> clones, not this template.

## When to use

The target imports `IOKit.framework` and calls `IOServiceOpen` plus one or more `IOConnectCall*` variants. A vendor binary talks to a kext (`/System/Library/Extensions/<vendor>.kext`) or DriverKit dext. An EDR has a kernel-mode component and a user-mode helper. You need the (driver class, selector list) inventory before going kernel-side.

## Lab topology

| Step | Surface | How |
|---|---|---|
| Static sweep | lab host | `ghidra-mcp` + `~/ghidra-scripts/scan_iokit_user_clients.py` |
| Driver-side correlation | lab host | open the matching kext / dext in Ghidra; find `getTargetAndMethodForIndex` or `IOExternalMethodDispatch` table |
| Driver enumeration | lab host | `kextstat`, `systemextensionsctl list`, `ioreg -l` |
| Reachability harness | crash-test only | minimal C program calling one selector with controlled scalars |
| Evidence | findings repo | TSV + driver decompilation under `findings/analysis/`. Don't run kernel fuzzers on the primary lab VM. |

This hunt has a high blast radius. Kernel panics will reboot the lab VM and may corrupt the disk. Use a snapshotted crash-test VM.

## What the bug class is

A user client exposes a callable surface that runs in the kernel. The kernel side dispatches each `IOConnectCallMethod(connect, selector, ...)` through a fixed table (`IOExternalMethodDispatch[2022]`) or a virtual method (`IOUserClient::getTargetAndMethodForIndex`, `IOUserClient::externalMethod`). Bugs come from:

Insufficient selector validation. The driver does not check the selector index range, lets it select an out-of-table function pointer, or dispatches to a method that should be privileged-only.

Insufficient scalar / struct validation. The selected method trusts user-provided sizes, type tags, or pointer fields. Most IOSurface / IOSurfaceClient bugs land here.

Insufficient client-class gating. A user client class meant for one privileged path is openable from a sandboxed or unprivileged caller.

Async vs sync confusion. `IOConnectCallAsyncMethod` takes a Mach port for replies; mishandling that port has produced multiple kernel LPE chains.

The user-mode side is what `scan_iokit_user_clients.py` recovers. The kernel-mode side is where the bug actually lives. The user-mode binary tells you exactly which selectors and scalars are reachable from userspace, which constrains the kernel-side surface dramatically.

## Anchor pattern

Strong signals are tier-A `ioservice_matching_callsite` with a recovered class name (`com.apple.driver.AppleAVE2`, `IOSurfaceRoot`, vendor classes) plus multiple tier-A `ioconnect_call_method_callsite` rows with recovered selector constants. You now have a complete (driver class, selector list) tuple. Take it to the kernel side.

Also strong: tier-A `ioconnect_call_async_method_callsite` rows. Async paths are historically the highest-yield bug class.

Medium: tier-A `ioservice_open_callsite` with no recovered class name. Driver class is dynamic; navigate the caller to find where it's computed.

Weak: tier-C `io_kit_string` rows alone. The binary references IOKit but may only consume sysctl / IORegistry, not actually open user clients.

## Harness

Open the user-mode binary:

```text
program.open(path="/Library/Application Support/<Vendor>/<helper>",
             project_location="/Users/<remote-user>/ghidra-projects",
             project_name="iokit-<vendor>", read_only=true, update_analysis=true)
```

Run the scan:

```text
ghidra.script(session_id="<session>",
              path="/Users/<remote-user>/ghidra-scripts/scan_iokit_user_clients.py",
              script_args=[])
```

Build the (class, selector) inventory from tier-A rows:

```
class=com.apple.driver.AppleAVE2:
  selector=0x05  caller=_ave2_init
  selector=0x12  caller=_ave2_submit_frame
  selector=0x21  caller=_ave2_set_qp
```

Open the driver in Ghidra:

```text
program.open(path="/System/Library/Extensions/<vendor>.kext/Contents/MacOS/<binary>",
             project_location="/Users/<remote-user>/ghidra-projects",
             project_name="iokit-<vendor>-driver", read_only=true, update_analysis=true)
```

Find `getTargetAndMethodForIndex` or the static `IOExternalMethodDispatch` / `IOExternalMethodDispatch2022` table. Map each selector to its kernel-side method. The resulting (selector, kernel_method, scalar_count, struct_input_size) table is the fuzz surface.

## Reachability harness

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

Build with `clang -framework IOKit -o ioconnect_probe ioconnect_probe.c`.

Use this only to confirm reachability of one selector you already statically reviewed. Don't loop over selector ranges blindly; that is fuzzing on a non-disposable host.

## Triage

Enumerate selectors via `scan_iokit_user_clients.py`. Pull the driver-side dispatch table. For each selector the user-mode binary actually calls, classify the kernel method's scalar count, struct sizes, whether selector validation gates by user vs root, and whether the method touches user-provided pointers in kernel.

Promote to `escalated` only when the kernel method has user-controlled inputs that affect kernel pointer arithmetic, allocation size, or capability checks.

Confirm with a single-selector reachability run on the crash-test VM. PoC authoring lives in private project clones (`Skills/offensive-macos-poc-authoring/SKILL.md`).

## Pitfalls

Driver class names aren't always strings. Some binaries compute the matching dictionary via `CFDictionaryCreate` and `CFSTR("IOProviderClass")`. The class name may not show up as a tier-A recovery; inspect the dictionary builder.

DriverKit dext dispatch is in user space. The kernel-side selector table for a dext lives in the dext binary itself, not in the kernel. Scan the dext.

SIP doesn't protect against IOKit selector bugs in vendor drivers; vendor drivers run privileged regardless. Lab safety here is about panic risk, not SIP.

Apple Silicon kernel exclusion. PAC and PPL block several historical exploitation strategies but not the bug surface itself. Static analysis still applies.

Async ports leak. Test harnesses that open and never close user clients with async ports will eventually exhaust port tables and panic.

## Public anchors

Project Zero's series on IOSurface / AGX / AppleAVD selectors (multiple write-ups across 2019–2024). `IOMobileFramebuffer` selector validation bugs (2021–2023). Vendor driver bugs in EDR products (multiple disclosures via vendor advisories).

## See also

- `Skills/offensive-macos-foundations-macho/SKILL.md`
- `Skills/offensive-macos-foundations-objc-runtime/SKILL.md`
- `Skills/offensive-macos-tooling-ghidra-headless/SKILL.md`
- `Skills/offensive-macos-tooling-lldb/SKILL.md`
- `Skills/offensive-macos-poc-authoring/SKILL.md`
- `ghidra-scripts/scan_iokit_user_clients.py`
- `ghidra-scripts/scan_private_framework_dependency.py`
