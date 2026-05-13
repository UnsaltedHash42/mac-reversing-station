# Ghidra script: extract verified XPC listener / service anchors from a Mach-O.
#
# Strategy (high precision, low recall by design):
#   1. Find callsites of XPC registration APIs and recover the literal
#      Mach service-name argument via the decompiler. These are ground
#      truth and emit as tier A.
#   2. Walk Objective-C metadata to find NSXPCListenerDelegate method
#      implementations by selector, not function name. Catches methods
#      that have no direct XREFs because they're dispatched through
#      objc_msgSend.
#   3. Extract the embedded entitlements plist from __TEXT,__entitlements.
#      Tier B rows.
#   4. Fall back to string heuristics only as supplementary evidence,
#      labeled tier C.
#
# Toggles (edit FAST_MODE below):
#   FAST_MODE = True  -> skip decompiler, fall back to instruction-walk
#                        for string args. ~10x faster, lower precision.
#   FAST_MODE = False -> use DecompInterface. Slower, higher precision.
#
# @category Mach-O.XPC
# @runtime PyGhidra

import re
import plistlib

from _re_lib import (
    AnchorWriter, DecompCache, format_addr, recover_call_string_arg,
    recover_call_arg_fast, callers_of, find_external,
)


FAST_MODE = False
MAX_EVIDENCE_ITEMS = 12

# Service-name registration APIs. Each maps to (arg_index_for_service_name).
XPC_REGISTRATION_APIS = (
    ("xpc_connection_create_mach_service", 0),
    ("xpc_connection_create_listener", 0),
)

# Objective-C selectors registered as XPC listener entry points. Matched
# against the *selector*, not the function name, so name mangling and
# Ghidra's auto-generated names are irrelevant.
NSXPC_DELEGATE_SELECTORS = {
    "listener:shouldAcceptNewConnection:",
    "listener:shouldAcceptConnection:",  # older variant seen in the wild
}

NSXPC_LISTENER_INIT_SELECTORS = {
    "initWithMachServiceName:",
    "serviceListener",
    "anonymousListener",
}

SERVICE_NAME_RE = re.compile(r"^([A-Za-z0-9_-]+\.){2,}[A-Za-z0-9_.-]+$")


# --------------------------------------------------------------------------
# 1. Callsite-anchored Mach service recovery
# --------------------------------------------------------------------------

def find_xpc_registration_callsites(decomp):
    """Yield (api_name, function_name, callsite_addr, service_name_or_None)."""
    for api_name, arg_idx in XPC_REGISTRATION_APIS:
        fn = find_external(api_name)
        if fn is None:
            continue
        for caller, site in callers_of(fn):
            if caller is None:
                continue
            container_name = caller.getName()
            arg = None
            if decomp is not None:
                arg = recover_call_string_arg(decomp, site, arg_idx)
            if arg is None:
                arg = recover_call_arg_fast(site, arg_idx)
            yield api_name, container_name, site, arg


# --------------------------------------------------------------------------
# 2. Objective-C metadata walk for delegate methods
# --------------------------------------------------------------------------

def walk_objc_methods():
    """Yield (class_name, selector, entry_address) for ObjC methods."""
    fm = currentProgram.getFunctionManager()
    for fn in fm.getFunctions(True):
        try:
            parent = fn.getParentNamespace()
        except Exception:
            continue
        if parent is None:
            continue
        parent_name = parent.getName()
        if parent_name in (None, "", "Global"):
            continue
        if " " in parent_name:
            continue
        try:
            yield (parent_name, fn.getName(), fn.getEntryPoint())
        except Exception:
            continue


def find_nsxpc_delegate_impls():
    return [(cls, sel, addr) for cls, sel, addr in walk_objc_methods()
            if sel in NSXPC_DELEGATE_SELECTORS]


def find_nsxpc_listener_init_callsites():
    """Find references to NSXPCListener init selectors."""
    hits = []
    sm = currentProgram.getSymbolTable()
    for selector in NSXPC_LISTENER_INIT_SELECTORS:
        for variant in (selector, "_" + selector,
                        "sel_" + selector.replace(":", "_")):
            for sym in sm.getSymbols(variant):
                try:
                    refs = getReferencesTo(sym.getAddress())
                except Exception:
                    continue
                for ref in refs:
                    try:
                        rt = ref.getReferenceType()
                    except Exception:
                        continue
                    if rt.isData() or rt.isCall():
                        hits.append((selector, ref.getFromAddress()))
    return hits


# --------------------------------------------------------------------------
# 3. Entitlements extraction
# --------------------------------------------------------------------------

def extract_entitlements():
    """Pull the embedded entitlements plist from __TEXT,__entitlements."""
    mem = currentProgram.getMemory()
    candidate_block = None
    for block in mem.getBlocks():
        name = block.getName() or ""
        if "entitlement" in name.lower():
            candidate_block = block
            break
    if candidate_block is None:
        return None
    try:
        size = int(candidate_block.getSize())
    except Exception:
        return None
    if size <= 0 or size > 1024 * 1024:
        return None
    try:
        buf = bytearray(size)
        candidate_block.getBytes(candidate_block.getStart(), buf)
        return plistlib.loads(bytes(buf))
    except Exception:
        return None


def interesting_entitlements(plist):
    """Return entitlement keys we care about for XPC triage."""
    if not plist:
        return []
    keep = []
    for k in plist.keys():
        kl = k.lower()
        if any(needle in kl for needle in (
            "mach-lookup", "mach-register", "privileged",
            "application-groups", "smprivilegedexecutables",
            "temporary-exception",
        )):
            keep.append(k)
    return sorted(keep)


# --------------------------------------------------------------------------
# 4. Supplementary string heuristics
# --------------------------------------------------------------------------

def heuristic_service_strings(verified_set):
    """Strings shaped like reverse-DNS service names, minus the verified ones."""
    out = set()
    listing = currentProgram.getListing()
    for data in listing.getDefinedData(True):
        try:
            val = data.getValue()
        except Exception:
            continue
        if not isinstance(val, str) or len(val) < 5:
            continue
        if not SERVICE_NAME_RE.search(val):
            continue
        if val in verified_set:
            continue
        out.add(val)
    return sorted(out)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    cache = DecompCache(fast_mode=FAST_MODE)
    try:
        decomp = cache.open()
        callsite_findings = list(find_xpc_registration_callsites(decomp))
    finally:
        cache.dispose()

    delegate_impls = find_nsxpc_delegate_impls()
    listener_inits = find_nsxpc_listener_init_callsites()
    plist = extract_entitlements()
    ent_keys = interesting_entitlements(plist) if plist else []

    verified_services = sorted({arg for (_a, _f, _addr, arg) in callsite_findings if arg})
    unverified_services = heuristic_service_strings(set(verified_services))

    writer = AnchorWriter("dump_xpc_listeners")

    for api, fn_name, addr, arg in callsite_findings:
        evid = "api=%s; service=%s" % (api, arg if arg else "<unresolved>")
        writer.add("A", "xpc_registration_callsite", fn_name,
                   format_addr(addr), evid)

    for cls, sel, addr in delegate_impls:
        writer.add("A", "nsxpc_delegate_impl", "%s.%s" % (cls, sel),
                   format_addr(addr), "selector=%s" % sel)

    for sel, addr in listener_inits:
        writer.add("A", "nsxpc_listener_init", sel,
                   format_addr(addr), "selector=%s" % sel)

    for key in ent_keys:
        writer.add("B", "interesting_entitlement", key, "-",
                   "entitlement=%s" % key)

    for service in unverified_services[:MAX_EVIDENCE_ITEMS * 4]:
        writer.add("C", "service_name_string", service, "-",
                   "service=%s" % service)

    if FAST_MODE:
        writer.warn("fast_mode")

    writer.flush()


main()
