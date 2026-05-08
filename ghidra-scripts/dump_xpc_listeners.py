# Ghidra script: extract verified XPC listener/service anchors from a Mach-O.
#
# Strategy (high precision, low recall by design):
#   1. Find callsites of XPC registration APIs and recover the literal Mach
#      service-name argument via the decompiler. These are ground truth.
#   2. Walk Objective-C metadata to find NSXPCListenerDelegate method
#      implementations by selector, not function name. Catches methods that
#      have no direct XREFs because they're dispatched through objc_msgSend.
#   3. Extract the embedded entitlements plist from __TEXT,__entitlements.
#   4. Fall back to string/symbol heuristics only as supplementary evidence,
#      clearly labeled as unverified.
#
# Output: TSV with one row per binary. The `evidence` column is structured
# key=value pairs separated by `; ` so it survives `cut -f` pipelines.
#
# Toggles (edit FAST_MODE below):
#   FAST_MODE = True  -> skip decompiler, fall back to simple backward scan
#                        for string args. ~10x faster, lower precision.
#   FAST_MODE = False -> use DecompInterface. Slower, higher precision.
#
# @category Mach-O.XPC
# @runtime Jython

import re
import plistlib

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.program.model.symbol import RefType, SourceType
from ghidra.program.model.pcode import PcodeOp
from ghidra.util.task import ConsoleTaskMonitor

FAST_MODE = False
MAX_EVIDENCE_ITEMS = 12
DECOMPILE_TIMEOUT_SEC = 30

# APIs whose first/named string argument is a Mach service name.
# (api_name, arg_index_zero_based) -- arg_index is the position of the
# service-name string in the call's pcode inputs (after the function ptr).
XPC_REGISTRATION_APIS = {
    "_xpc_connection_create_mach_service": 0,
    "xpc_connection_create_mach_service": 0,
    "_xpc_connection_create_listener": 0,
    "xpc_connection_create_listener": 0,
}

# Objective-C selectors registered as XPC listener entry points.
# Matched against the *selector*, not the function name, so name mangling
# and Ghidra's auto-generated names (e.g. _objc_msgSend dispatch stubs) are
# irrelevant.
NSXPC_DELEGATE_SELECTORS = {
    "listener:shouldAcceptNewConnection:",
    "listener:shouldAcceptConnection:",  # older variant seen in the wild
}

NSXPC_LISTENER_INIT_SELECTORS = {
    "initWithMachServiceName:",
    "serviceListener",
    "anonymousListener",
}

# Supplementary heuristics (clearly labeled as such in output).
SERVICE_NAME_RE = re.compile(r"^([A-Za-z0-9_-]+\.){2,}[A-Za-z0-9_.-]+$")


def emit(line):
    try:
        println(line)
    except NameError:
        print(line)


def warn(msg):
    # Surface to console without polluting the TSV row.
    try:
        printerr("[xpc] %s" % msg)
    except NameError:
        import sys
        sys.stderr.write("[xpc] %s\n" % msg)


def program_name():
    try:
        path = currentProgram.getExecutablePath()
        if path:
            return path.replace("\t", " ")
    except Exception as exc:
        warn("getExecutablePath failed: %s" % exc)
    try:
        return currentProgram.getName().replace("\t", " ")
    except Exception:
        return "<unknown>"


# --------------------------------------------------------------------------
# 1. Callsite-anchored Mach service recovery
# --------------------------------------------------------------------------

def find_external_function(name):
    """Resolve an external symbol name to its Function object, if present."""
    sm = currentProgram.getSymbolTable()
    # Try a few namespaces: external, global, leading-underscore variants.
    candidates = [name]
    if name.startswith("_"):
        candidates.append(name[1:])
    else:
        candidates.append("_" + name)
    for cand in candidates:
        for sym in sm.getSymbols(cand):
            obj = sym.getObject()
            # External function reference or thunk both count.
            try:
                from ghidra.program.model.listing import Function
                if isinstance(obj, Function):
                    return obj
            except Exception:
                pass
            # Sometimes the symbol points at the thunk address; resolve it.
            fm = currentProgram.getFunctionManager()
            fn = fm.getFunctionAt(sym.getAddress())
            if fn is not None:
                return fn
    return None


def get_decompiler():
    if FAST_MODE:
        return None
    iface = DecompInterface()
    opts = DecompileOptions()
    iface.setOptions(opts)
    iface.openProgram(currentProgram)
    return iface


def recover_string_at(address):
    """Return the C string at `address`, or None."""
    if address is None:
        return None
    data = getDataAt(address)
    if data is not None:
        try:
            val = data.getValue()
            if isinstance(val, str):
                return val
            if val is not None:
                s = str(val)
                if s:
                    return s
        except Exception:
            pass
    # Manual byte read: Ghidra may not have promoted this to defined data.
    try:
        mem = currentProgram.getMemory()
        out = bytearray()
        addr = address
        for _ in range(512):
            b = mem.getByte(addr) & 0xFF
            if b == 0:
                break
            out.append(b)
            addr = addr.add(1)
        if out:
            return bytes(out).decode("utf-8", errors="replace")
    except Exception:
        return None
    return None


def recover_arg_via_decomp(decomp, callsite_addr, arg_index):
    """Use the decompiler to find the literal address passed at arg_index."""
    fm = currentProgram.getFunctionManager()
    containing = fm.getFunctionContaining(callsite_addr)
    if containing is None:
        return None
    monitor = ConsoleTaskMonitor()
    res = decomp.decompileFunction(containing, DECOMPILE_TIMEOUT_SEC, monitor)
    if res is None or not res.decompileCompleted():
        return None
    high = res.getHighFunction()
    if high is None:
        return None
    op_iter = high.getPcodeOps(callsite_addr)
    while op_iter.hasNext():
        op = op_iter.next()
        opcode = op.getOpcode()
        if opcode != PcodeOp.CALL and opcode != PcodeOp.CALLIND:
            continue
        # inputs[0] is the call target; arg N is inputs[arg_index + 1].
        idx = arg_index + 1
        if op.getNumInputs() <= idx:
            continue
        vn = op.getInput(idx)
        if vn is None:
            continue
        if vn.isConstant() or vn.isAddress():
            try:
                addr_space = currentProgram.getAddressFactory().getDefaultAddressSpace()
                target = addr_space.getAddress(vn.getOffset())
                s = recover_string_at(target)
                if s:
                    return s
            except Exception:
                pass
        # Walk one level back through a COPY/CAST if the constant is hidden.
        defn = vn.getDef()
        if defn is not None and defn.getOpcode() in (PcodeOp.COPY, PcodeOp.CAST):
            src = defn.getInput(0)
            if src is not None and (src.isConstant() or src.isAddress()):
                try:
                    addr_space = currentProgram.getAddressFactory().getDefaultAddressSpace()
                    target = addr_space.getAddress(src.getOffset())
                    s = recover_string_at(target)
                    if s:
                        return s
                except Exception:
                    pass
    return None


def recover_arg_fast(callsite_addr, arg_index):
    """Cheap fallback: scan a few instructions back for an LEA/ADRP to a string."""
    listing = currentProgram.getListing()
    instr = listing.getInstructionAt(callsite_addr)
    if instr is None:
        return None
    # Walk backwards up to 12 instructions looking for any reference whose
    # target resolves to a string. This is best-effort and will pick the
    # wrong arg in calls with multiple string operands -- accepted tradeoff
    # for FAST_MODE.
    cur = instr
    for _ in range(12):
        cur = cur.getPrevious()
        if cur is None:
            break
        for ref in cur.getReferencesFrom():
            if not ref.getReferenceType().isData():
                continue
            s = recover_string_at(ref.getToAddress())
            if s and len(s) >= 3:
                return s
    return None


def find_xpc_registration_callsites(decomp):
    """
    Returns list of (api_name, function_name, callsite_addr, service_name_or_None).
    """
    findings = []
    fm = currentProgram.getFunctionManager()
    for api_name, arg_idx in XPC_REGISTRATION_APIS.items():
        fn = find_external_function(api_name)
        if fn is None:
            continue
        refs = getReferencesTo(fn.getEntryPoint())
        for ref in refs:
            ref_type = ref.getReferenceType()
            if not (ref_type.isCall() or ref_type.isJump()):
                continue
            from_addr = ref.getFromAddress()
            container = fm.getFunctionContaining(from_addr)
            container_name = container.getName() if container else "<orphan>"
            if FAST_MODE or decomp is None:
                arg = recover_arg_fast(from_addr, arg_idx)
            else:
                arg = recover_arg_via_decomp(decomp, from_addr, arg_idx)
            findings.append((api_name, container_name, from_addr, arg))
    return findings


# --------------------------------------------------------------------------
# 2. Objective-C metadata walk for delegate methods
# --------------------------------------------------------------------------

def walk_objc_methods():
    """
    Yield (class_name, selector, method_addr) for every Objective-C method
    Ghidra has identified. Relies on the ObjectiveC2 analyzer having run.
    """
    sm = currentProgram.getSymbolTable()
    # Ghidra represents ObjC methods as functions whose namespace is the class
    # and whose name is the selector. Iterate all functions and check.
    fm = currentProgram.getFunctionManager()
    for fn in fm.getFunctions(True):
        parent = fn.getParentNamespace()
        if parent is None:
            continue
        parent_name = parent.getName()
        # ObjC class namespaces typically aren't the global namespace and
        # have a non-empty name. Filter out C functions.
        if parent_name in (None, "", "Global"):
            continue
        selector = fn.getName()
        # Selectors with colons are dead giveaways; selectors without colons
        # also valid (zero-arg messages). Use namespace as the discriminator.
        # Cheap sanity check: ObjC class names rarely contain spaces.
        if " " in parent_name:
            continue
        yield (parent_name, selector, fn.getEntryPoint())


def find_nsxpc_delegate_impls():
    """Return list of (class_name, selector, addr) for delegate methods."""
    hits = []
    for class_name, selector, addr in walk_objc_methods():
        if selector in NSXPC_DELEGATE_SELECTORS:
            hits.append((class_name, selector, addr))
    return hits


def find_nsxpc_listener_init_callsites():
    """
    Find callsites of NSXPCListener init selectors. These are objc_msgSend
    calls, so we look for references to the selector strings in __objc_methname
    or to the NSXPCListener class.
    """
    hits = []
    listing = currentProgram.getListing()
    # Find selector references via the symbol table -- ObjC analyzer creates
    # symbols like `objc::initWithMachServiceName:` or selref entries.
    sm = currentProgram.getSymbolTable()
    for selector in NSXPC_LISTENER_INIT_SELECTORS:
        # Try a few symbol name variants the ObjC analyzer produces.
        for variant in (selector, "_" + selector, "sel_" + selector.replace(":", "_")):
            for sym in sm.getSymbols(variant):
                refs = getReferencesTo(sym.getAddress())
                for ref in refs:
                    if ref.getReferenceType().isData() or ref.getReferenceType().isCall():
                        hits.append((selector, ref.getFromAddress()))
    return hits


# --------------------------------------------------------------------------
# 3. Entitlements extraction
# --------------------------------------------------------------------------

def extract_entitlements():
    """
    Pull the entitlements plist from the Mach-O. Ghidra exposes the
    __TEXT,__entitlements section as a memory block named "__entitlements"
    (or similar) when the loader recognizes it. Returns dict or None.
    """
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
        if size <= 0 or size > 1024 * 1024:  # sanity cap at 1 MiB
            return None
        buf = bytearray(size)
        candidate_block.getBytes(candidate_block.getStart(), buf)
        # Plist may be XML or binary.
        try:
            if hasattr(plistlib, "loads"):
                return plistlib.loads(bytes(buf))
            else:
                # Jython 2.7 fallback: only XML plists supported.
                from StringIO import StringIO
                return plistlib.readPlist(StringIO(bytes(buf)))
        except Exception as exc:
            warn("entitlements parse failed: %s" % exc)
            return None
    except Exception as exc:
        warn("entitlements read failed: %s" % exc)
        return None


def interesting_entitlements(plist):
    """Return sorted list of entitlement keys we care about for XPC triage."""
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
# 4. Supplementary heuristic strings (labeled as unverified)
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
    decomp = get_decompiler()
    try:
        callsite_findings = find_xpc_registration_callsites(decomp)
    finally:
        if decomp is not None:
            decomp.dispose()

    delegate_impls = find_nsxpc_delegate_impls()
    listener_inits = find_nsxpc_listener_init_callsites()
    plist = extract_entitlements()
    ent_keys = interesting_entitlements(plist) if plist else []

    verified_services = sorted({
        arg for (_api, _fn, _addr, arg) in callsite_findings if arg
    })
    unverified_services = heuristic_service_strings(set(verified_services))

    # Build evidence string. Order matters: highest-confidence first.
    evidence = []

    if callsite_findings:
        parts = []
        for api, fn, addr, arg in callsite_findings[:MAX_EVIDENCE_ITEMS]:
            arg_repr = arg if arg else "<unresolved>"
            parts.append("%s@%s->%s(%s)" % (fn, addr, api, arg_repr))
        evidence.append("registrations=%s" % "|".join(parts))

    if delegate_impls:
        parts = ["%s.%s" % (cls, sel)
                 for (cls, sel, _addr) in delegate_impls[:MAX_EVIDENCE_ITEMS]]
        evidence.append("delegates=%s" % "|".join(parts))

    if listener_inits:
        parts = ["%s@%s" % (sel, addr)
                 for (sel, addr) in listener_inits[:MAX_EVIDENCE_ITEMS]]
        evidence.append("listener_inits=%s" % "|".join(parts))

    if ent_keys:
        evidence.append("entitlements=%s" % "|".join(ent_keys[:MAX_EVIDENCE_ITEMS]))

    if unverified_services:
        evidence.append("unverified_service_strings=%s" %
                        "|".join(unverified_services[:MAX_EVIDENCE_ITEMS]))

    # Emit anchor rows in the standard tiered contract (see _re_lib.py).
    from _re_lib import AnchorWriter, format_addr

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

    for service in unverified_services:
        writer.add("C", "service_name_string", service, "-",
                   "service=%s" % service)

    if FAST_MODE:
        writer.warn("fast_mode")

    writer.flush()


main()