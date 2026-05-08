# Ghidra script: export prioritized function anchors for LLDB follow-up.
#
# Goal: produce a ranked list of breakpoint-worthy functions in the loaded
# Mach-O, plus a sidecar `.lldb` file with ready-to-source breakpoint commands.
# Designed for the static-to-dynamic handoff: triage in Ghidra, flip to LLDB
# with a single `command source <file>.lldb`.
#
# Anchor sources (each with a confidence weight that drives ranking):
#   1. Exported symbols                              (weight 5)
#   2. Mach-O entry points: main, start, mod_init    (weight 5)
#   3. Callers of sensitive APIs                     (weight 4 per API)
#   4. Non-system Objective-C methods                (weight 3)
#   5. High in-degree functions (top N percentile)   (weight 2)
#
# A function picking up multiple sources accumulates score; ties broken by
# in-degree, then name.
#
# Output:
#   stdout TSV: one row per anchor with stable columns.
#   sidecar:    `<binary>.anchors.lldb` written next to the program file
#               (or /tmp if path unavailable). Contains `breakpoint set`
#               commands keyed by symbol when available, falling back to
#               address. ASLR slide is left to LLDB to resolve via symbol.
#
# Toggles:
#   MAX_ANCHORS         -- cap on output rows (default 200)
#   MIN_SCORE           -- drop anchors scoring below this (default 2)
#   IN_DEGREE_PERCENTILE-- top N% by callers gets the high-fanin signal
#   SIDECAR_DIR         -- override output dir for the .lldb file
#
# @category Mach-O.Anchors
# @runtime Jython

import os
import re

from ghidra.program.model.symbol import SourceType, SymbolType
from ghidra.program.model.listing import Function

MAX_ANCHORS = 200
MIN_SCORE = 2
IN_DEGREE_PERCENTILE = 0.95
SIDECAR_DIR = None  # None -> auto

# Sensitive APIs grouped by capability. Score weight per group is uniform but
# the group label gets carried into the evidence so you can filter the TSV.
SENSITIVE_APIS = {
    "xpc": [
        "xpc_connection_create_mach_service",
        "xpc_connection_create_listener",
        "xpc_connection_create",
        "xpc_connection_send_message",
        "xpc_connection_send_message_with_reply_sync",
    ],
    "auth": [
        "AuthorizationCreate",
        "AuthorizationExecuteWithPrivileges",
        "AuthorizationCopyRights",
        "SMJobBless",
    ],
    "keychain": [
        "SecKeychainAddGenericPassword",
        "SecKeychainFindGenericPassword",
        "SecItemAdd",
        "SecItemCopyMatching",
        "SecItemUpdate",
    ],
    "exec": [
        "system",
        "popen",
        "execve",
        "execvp",
        "posix_spawn",
        "posix_spawnp",
        "NSTask",  # class ref, handled separately but kept for completeness
    ],
    "dylib": [
        "dlopen",
        "dlsym",
        "NSCreateObjectFileImageFromFile",
        "NSLinkModule",
    ],
    "iokit": [
        "IOConnectCallMethod",
        "IOConnectCallScalarMethod",
        "IOConnectCallStructMethod",
        "IOServiceOpen",
    ],
    "code_inject": [
        "task_for_pid",
        "mach_vm_write",
        "mach_vm_protect",
        "thread_create_running",
    ],
}

ENTRY_POINT_NAMES = {"main", "_main", "start", "_start", "NSApplicationMain", "_NSApplicationMain"}

# Objective-C class namespace prefixes we treat as "system" and skip.
SYSTEM_CLASS_PREFIXES = (
    "NS", "_NS", "CF", "_CF", "OS_", "__NS", "_OS", "CA", "CG", "CT",
    "UI", "AV", "MK", "MP", "SK", "WK", "GK", "PK", "EK",
)


def emit(line):
    try:
        println(line)
    except NameError:
        print(line)


def warn(msg):
    try:
        printerr("[anchors] %s" % msg)
    except NameError:
        import sys
        sys.stderr.write("[anchors] %s\n" % msg)


def program_path():
    try:
        return currentProgram.getExecutablePath() or currentProgram.getName()
    except Exception:
        return currentProgram.getName()


def safe_target_field():
    return program_path().replace("\t", " ")


# --------------------------------------------------------------------------
# Anchor record + scoring
# --------------------------------------------------------------------------

class Anchor(object):
    __slots__ = ("function", "score", "sources", "in_degree")

    def __init__(self, function):
        self.function = function
        self.score = 0
        self.sources = []   # list of (source_label, weight, detail)
        self.in_degree = 0

    def add_source(self, label, weight, detail=""):
        self.score += weight
        self.sources.append((label, weight, detail))

    @property
    def name(self):
        try:
            return self.function.getName()
        except Exception:
            return "<unknown>"

    @property
    def address(self):
        try:
            return self.function.getEntryPoint()
        except Exception:
            return None

    @property
    def namespace(self):
        try:
            ns = self.function.getParentNamespace()
            return ns.getName() if ns else ""
        except Exception:
            return ""

    def evidence_str(self):
        parts = []
        for label, weight, detail in self.sources:
            if detail:
                parts.append("%s:%s" % (label, detail))
            else:
                parts.append(label)
        return ",".join(parts)


# --------------------------------------------------------------------------
# Source 1: exported symbols
# --------------------------------------------------------------------------

def collect_exports(anchor_map):
    sm = currentProgram.getSymbolTable()
    fm = currentProgram.getFunctionManager()
    count = 0
    for sym in sm.getSymbolIterator():
        try:
            if not sym.isExternalEntryPoint() and not sym.isPrimary():
                continue
            if sym.getSymbolType() != SymbolType.FUNCTION:
                continue
            # External-entry-point flag is the strongest signal that this
            # symbol is genuinely exported (vs. just primary on a function).
            if not sym.isExternalEntryPoint():
                continue
            fn = fm.getFunctionAt(sym.getAddress())
            if fn is None:
                continue
            anchor = anchor_map.setdefault(fn.getEntryPoint(), Anchor(fn))
            anchor.add_source("export", 5, sym.getName())
            count += 1
        except Exception as exc:
            warn("export iter failed: %s" % exc)
            continue
    return count


# --------------------------------------------------------------------------
# Source 2: entry points (main / start / mod_init)
# --------------------------------------------------------------------------

def collect_entry_points(anchor_map):
    fm = currentProgram.getFunctionManager()
    sm = currentProgram.getSymbolTable()
    count = 0

    # Named entry points.
    for name in ENTRY_POINT_NAMES:
        for sym in sm.getSymbols(name):
            fn = fm.getFunctionAt(sym.getAddress())
            if fn is None:
                continue
            anchor = anchor_map.setdefault(fn.getEntryPoint(), Anchor(fn))
            anchor.add_source("entrypoint", 5, sym.getName())
            count += 1

    # __mod_init_func: array of function pointers run before main.
    mem = currentProgram.getMemory()
    for block in mem.getBlocks():
        bn = block.getName() or ""
        if bn not in ("__mod_init_func", "__init_func", "__mod_init"):
            continue
        try:
            ptr_size = currentProgram.getDefaultPointerSize()
            addr_factory = currentProgram.getAddressFactory()
            default_space = addr_factory.getDefaultAddressSpace()
            cur = block.getStart()
            end = block.getEnd()
            while cur is not None and cur.compareTo(end) <= 0:
                # Read pointer-sized little-endian value.
                val = 0
                for i in range(ptr_size):
                    b = block.getByte(cur.add(i)) & 0xFF
                    val |= b << (8 * i)
                if val != 0:
                    target = default_space.getAddress(val)
                    fn = fm.getFunctionAt(target)
                    if fn is None:
                        fn = fm.getFunctionContaining(target)
                    if fn is not None:
                        anchor = anchor_map.setdefault(fn.getEntryPoint(), Anchor(fn))
                        anchor.add_source("mod_init", 5, str(target))
                        count += 1
                cur = cur.add(ptr_size)
        except Exception as exc:
            warn("__mod_init_func walk failed: %s" % exc)

    return count


# --------------------------------------------------------------------------
# Source 3: callers of sensitive APIs
# --------------------------------------------------------------------------

def find_external(name):
    sm = currentProgram.getSymbolTable()
    fm = currentProgram.getFunctionManager()
    candidates = [name, "_" + name] if not name.startswith("_") else [name, name[1:]]
    for cand in candidates:
        for sym in sm.getSymbols(cand):
            fn = fm.getFunctionAt(sym.getAddress())
            if fn is not None:
                return fn
            # Some externals show up only as labels; resolve to thunk.
            obj = sym.getObject()
            if isinstance(obj, Function):
                return obj
    return None


def collect_sensitive_callers(anchor_map):
    fm = currentProgram.getFunctionManager()
    total = 0
    for group, apis in SENSITIVE_APIS.items():
        for api in apis:
            target = find_external(api)
            if target is None:
                continue
            for ref in getReferencesTo(target.getEntryPoint()):
                rt = ref.getReferenceType()
                if not (rt.isCall() or rt.isJump()):
                    continue
                caller = fm.getFunctionContaining(ref.getFromAddress())
                if caller is None:
                    continue
                anchor = anchor_map.setdefault(caller.getEntryPoint(), Anchor(caller))
                anchor.add_source("api/%s" % group, 4, api)
                total += 1
    return total


# --------------------------------------------------------------------------
# Source 4: non-system Objective-C methods
# --------------------------------------------------------------------------

def is_system_class(class_name):
    if not class_name or class_name in ("Global", ""):
        return True
    for prefix in SYSTEM_CLASS_PREFIXES:
        if class_name.startswith(prefix):
            return True
    return False


def collect_objc_methods(anchor_map):
    fm = currentProgram.getFunctionManager()
    count = 0
    for fn in fm.getFunctions(True):
        try:
            ns = fn.getParentNamespace()
            if ns is None:
                continue
            class_name = ns.getName()
            if not class_name or class_name == "Global":
                continue
            # ObjC class names don't contain spaces; this filters out C++
            # nested namespaces and other false positives.
            if " " in class_name:
                continue
            if is_system_class(class_name):
                continue
            anchor = anchor_map.setdefault(fn.getEntryPoint(), Anchor(fn))
            anchor.add_source("objc_method", 3, "%s.%s" % (class_name, fn.getName()))
            count += 1
        except Exception:
            continue
    return count


# --------------------------------------------------------------------------
# Source 5: high in-degree functions
# --------------------------------------------------------------------------

def collect_high_in_degree(anchor_map):
    """Compute in-degree for every function; flag the top percentile."""
    fm = currentProgram.getFunctionManager()
    in_degree = {}
    funcs = list(fm.getFunctions(True))
    for fn in funcs:
        try:
            in_degree[fn.getEntryPoint()] = fn.getCallingFunctions(None).size()
        except Exception:
            in_degree[fn.getEntryPoint()] = 0

    # Annotate every existing anchor with its in-degree (used for tiebreaking).
    for addr, anchor in anchor_map.items():
        anchor.in_degree = in_degree.get(addr, 0)

    if not in_degree:
        return 0

    # Find the percentile cutoff.
    values = sorted(in_degree.values())
    if not values:
        return 0
    cutoff_idx = int(len(values) * IN_DEGREE_PERCENTILE)
    if cutoff_idx >= len(values):
        cutoff_idx = len(values) - 1
    cutoff = values[cutoff_idx]
    if cutoff < 3:  # don't flag unless it's actually meaningful fanin
        cutoff = 3

    count = 0
    for fn in funcs:
        deg = in_degree.get(fn.getEntryPoint(), 0)
        if deg < cutoff:
            continue
        # Skip thunks and trivially small functions -- they're rarely the
        # right place for a breakpoint even with high fanin.
        try:
            if fn.isThunk():
                continue
            body_len = fn.getBody().getNumAddresses()
            if body_len < 8:
                continue
        except Exception:
            pass
        anchor = anchor_map.setdefault(fn.getEntryPoint(), Anchor(fn))
        anchor.add_source("high_fanin", 2, "callers=%d" % deg)
        anchor.in_degree = deg
        count += 1
    return count


# --------------------------------------------------------------------------
# Output: TSV + LLDB sidecar
# --------------------------------------------------------------------------

def lldb_breakpoint_command(anchor):
    """
    Prefer symbol-based breakpoints (survive ASLR + library reloads). Fall
    back to address with a comment noting the slide problem.
    """
    name = anchor.name
    addr = anchor.address
    # Ghidra synthesizes names like FUN_100001234 for unnamed functions; those
    # aren't real symbols so use the address.
    if name and not name.startswith("FUN_") and not name.startswith("LAB_"):
        # Quote names with colons (ObjC selectors) and special chars.
        if ":" in name or " " in name:
            return 'breakpoint set --name "%s"' % name.replace('"', '\\"')
        return "breakpoint set --name %s" % name
    return "breakpoint set --address 0x%s  # unnamed; ASLR slide applies" % str(addr)


def write_sidecar(anchors, target):
    """Write LLDB commands to a sidecar file. Returns path, or None on failure."""
    if SIDECAR_DIR:
        out_dir = SIDECAR_DIR
    else:
        try:
            out_dir = os.path.dirname(target) or "/tmp"
            if not os.path.isdir(out_dir) or not os.access(out_dir, os.W_OK):
                out_dir = "/tmp"
        except Exception:
            out_dir = "/tmp"

    base = os.path.basename(target) or "program"
    # Sanitize for filesystem.
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)
    out_path = os.path.join(out_dir, "%s.anchors.lldb" % base)

    try:
        with open(out_path, "w") as fh:
            fh.write("# Generated anchor breakpoints for %s\n" % target)
            fh.write("# Source this from LLDB: command source %s\n" % out_path)
            fh.write("# Disable all at once: breakpoint disable\n\n")
            for i, anchor in enumerate(anchors, start=1):
                fh.write("# [%d] score=%d sources=%s\n" %
                         (i, anchor.score, anchor.evidence_str()))
                fh.write(lldb_breakpoint_command(anchor) + "\n\n")
        return out_path
    except Exception as exc:
        warn("sidecar write failed: %s" % exc)
        return None


def main():
    anchor_map = {}

    n_export = collect_exports(anchor_map)
    n_entry = collect_entry_points(anchor_map)
    n_api = collect_sensitive_callers(anchor_map)
    n_objc = collect_objc_methods(anchor_map)
    n_fanin = collect_high_in_degree(anchor_map)

    # Filter and rank.
    anchors = [a for a in anchor_map.values() if a.score >= MIN_SCORE]
    anchors.sort(key=lambda a: (-a.score, -a.in_degree, a.name))
    anchors = anchors[:MAX_ANCHORS]

    target = safe_target_field()
    sidecar_path = write_sidecar(anchors, program_path())

    # TSV header.
    emit("\t".join([
        "target", "rank", "score", "in_degree", "name", "address",
        "namespace", "sources",
    ]))
    for i, anchor in enumerate(anchors, start=1):
        emit("\t".join([
            target,
            str(i),
            str(anchor.score),
            str(anchor.in_degree),
            (anchor.name or "").replace("\t", " "),
            str(anchor.address),
            (anchor.namespace or "").replace("\t", " "),
            anchor.evidence_str().replace("\t", " "),
        ]))

    # Summary line on stderr so it doesn't pollute the TSV.
    warn(
        "anchors=%d (export=%d entrypoint=%d api=%d objc=%d fanin=%d) sidecar=%s"
        % (len(anchors), n_export, n_entry, n_api, n_objc, n_fanin,
           sidecar_path or "<none>")
    )


main()