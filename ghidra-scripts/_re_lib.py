# Shared helpers for the Ghidra hunt scripts.
#
# Every script in this directory emits the same TSV contract:
#
#   target  tier  anchor_kind  name  address  evidence
#
# Tiers carry the trust level of each row:
#
#   A  decompiler- or callsite-verified. The address points at real code.
#      Hand to lldb directly.
#   B  Mach-O / ObjC metadata, embedded plists, exported symbols. Address
#      is meaningful (callsite, function, metadata location) but the row
#      reflects metadata rather than recovered semantics.
#   C  string heuristic. A starting point for Ghidra navigation; do not
#      trust the row alone.
#
# A scan that has nothing to report emits the header row and zero anchor
# rows. Per-scan summary statistics go to stderr so they do not pollute
# the TSV.
#
# This module is imported by every scan script. Ghidra puts the script
# directory on sys.path, so `from _re_lib import ...` works under both
# Jython 2.7 and PyGhidra (Python 3).
#
# @runtime PyGhidra

import os
import re
import sys


ANCHOR_HEADER = ("target", "tier", "anchor_kind", "name", "address", "evidence")

# Hard cap on the per-scan string index. Hitting this is recorded in the
# stderr summary and surfaced via AnchorWriter.summary() so the agent can
# notice when a row count is bounded by the cap rather than by reality.
# Override via env: MACRE_MAX_STRINGS=50000
DEFAULT_MAX_STRINGS = int(os.environ.get("MACRE_MAX_STRINGS", "20000"))

# Hard cap on the per-scan function-name iteration. Same rationale.
# Override via env: MACRE_MAX_FUNCTIONS=100000
DEFAULT_MAX_FUNCTIONS = int(os.environ.get("MACRE_MAX_FUNCTIONS", "50000"))


# --------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------

def emit(line):
    """Write a TSV row to stdout via Ghidra's println, falling back to print."""
    try:
        println(line)  # Ghidra's globals
    except NameError:
        print(line)


def warn(msg):
    """Write a status line to stderr via Ghidra's printerr, falling back to sys.stderr."""
    try:
        printerr(msg)  # Ghidra's globals
    except NameError:
        sys.stderr.write(msg + "\n")


def program_path():
    """Best-effort path of the loaded program. Falls back to its name."""
    _bind_ghidra_globals_from_caller()
    try:
        path = currentProgram.getExecutablePath()
        if path:
            return path
    except Exception:
        pass
    try:
        return currentProgram.getName()
    except Exception:
        return "<unknown>"


def safe_field(value):
    """Strip tabs and newlines so a value never breaks the TSV."""
    if value is None:
        return ""
    if not isinstance(value, str):
        try:
            value = str(value)
        except Exception:
            return ""
    return value.replace("\t", " ").replace("\n", " ").replace("\r", " ")


# --------------------------------------------------------------------------
# PyGhidra compatibility: bind Ghidra runtime globals into this module
# --------------------------------------------------------------------------
#
# Under PyGhidra (Python 3), Ghidra-injected names like currentProgram,
# println, printerr, monitor, state are resolved via the script's
# PyGhidraScript dict-subclass `__missing__` hook. They are only visible from
# the script's top-level frame, NOT from imported modules. Helpers in this
# file reference `currentProgram` directly — under PyGhidra that raises
# NameError as soon as e.g. StringIndex._load() runs.
#
# Under Jython (the original target runtime) these names propagated to
# imported modules; the scan scripts work unchanged.
#
# Workaround: walk the call stack at each public entry point to find a frame
# whose globals can resolve currentProgram, and copy the relevant names into
# this module's __dict__. Subsequent LOAD_GLOBAL lookups inside _re_lib
# resolve normally. Called by `run_string_scan` and the other public entry
# points.

_GHIDRA_RUNTIME_NAMES = (
    # State / monitor / current selection
    "currentProgram", "currentAddress", "currentSelection",
    "currentHighlight", "currentLocation",
    "monitor", "state",
    # I/O
    "println", "printerr",
    # GhidraScript flat-API helpers that this library calls bare
    "getReferencesTo", "getDataAt", "getFunctionAt", "getFunctionContaining",
    "getInstructionAt", "getSymbol", "getSymbolAt", "getNamespace",
    "toAddr", "getMemoryBlock",
)


def _bind_ghidra_globals_from_caller():
    """Copy Ghidra runtime names from a caller's globals into this module's globals.

    Required under PyGhidra; a no-op under Jython (names are already global).
    Returns True if a caller frame carrying `currentProgram` was found.
    Safe to call from every public entry point — rebinds each call because
    `_re_lib` is cached across Ghidra script runs but `currentProgram` is not.
    """
    import inspect
    self_globals = sys.modules[__name__].__dict__
    frame = inspect.currentframe()
    if frame is not None:
        frame = frame.f_back  # skip this fn
    while frame is not None:
        g = frame.f_globals
        if g is self_globals:
            frame = frame.f_back
            continue
        try:
            g["currentProgram"]  # triggers PyGhidraScript.__missing__ if applicable
        except (KeyError, NameError, AttributeError):
            frame = frame.f_back
            continue
        for name in _GHIDRA_RUNTIME_NAMES:
            try:
                self_globals[name] = g[name]
            except (KeyError, NameError, AttributeError):
                self_globals.pop(name, None)
        return True
    return False


# --------------------------------------------------------------------------
# String + function indices (lazy, capped, truncation-aware)
# --------------------------------------------------------------------------

class StringIndex(object):
    """Snapshot of defined-data strings in the current program.

    The index walks `getDefinedData(True)` once, captures the textual
    value plus its address, and reports whether the cap was hit. Scans
    share one index per run rather than each script re-walking the
    listing.
    """

    __slots__ = ("max_strings", "_items", "_truncated")

    def __init__(self, max_strings=DEFAULT_MAX_STRINGS):
        self.max_strings = max_strings
        self._items = None
        self._truncated = False

    def _load(self):
        if self._items is not None:
            return
        _bind_ghidra_globals_from_caller()
        items = []
        listing = currentProgram.getListing()
        seen = 0
        truncated = False
        for data in listing.getDefinedData(True):
            if seen >= self.max_strings:
                truncated = True
                break
            try:
                value = data.getValue()
            except Exception:
                continue
            if isinstance(value, str):
                text = value
            elif value is None:
                continue
            else:
                try:
                    text = str(value)
                except Exception:
                    continue
            if len(text) < 3:
                continue
            try:
                addr = data.getAddress()
            except Exception:
                addr = None
            items.append((text, addr))
            seen += 1
        self._items = items
        self._truncated = truncated

    @property
    def items(self):
        """List of (text, ghidra_address_or_none) tuples."""
        self._load()
        return self._items

    @property
    def truncated(self):
        self._load()
        return self._truncated

    def matching(self, regex):
        """Yield (text, address) for strings whose value matches `regex`."""
        for text, addr in self.items:
            if regex.search(text):
                yield text, addr


class FunctionIndex(object):
    """Snapshot of (name, entry-point) pairs for every function in the program."""

    __slots__ = ("max_functions", "_items", "_truncated")

    def __init__(self, max_functions=DEFAULT_MAX_FUNCTIONS):
        self.max_functions = max_functions
        self._items = None
        self._truncated = False

    def _load(self):
        if self._items is not None:
            return
        _bind_ghidra_globals_from_caller()
        items = []
        truncated = False
        try:
            fm = currentProgram.getFunctionManager()
        except Exception:
            self._items = items
            return
        seen = 0
        for fn in fm.getFunctions(True):
            if seen >= self.max_functions:
                truncated = True
                break
            try:
                name = fn.getName()
                addr = fn.getEntryPoint()
            except Exception:
                continue
            items.append((name, addr, fn))
            seen += 1
        self._items = items
        self._truncated = truncated

    @property
    def items(self):
        """List of (name, entry_address, function_object) tuples."""
        self._load()
        return self._items

    @property
    def truncated(self):
        self._load()
        return self._truncated

    def matching(self, regex):
        for name, addr, fn in self.items:
            if regex.search(name):
                yield name, addr, fn


# --------------------------------------------------------------------------
# Symbol resolution
# --------------------------------------------------------------------------

def find_external(name):
    """Resolve an external symbol name to its Function object, if present.

    Tries both the bare name and a leading-underscore variant; some
    externals appear only as labels resolved through thunks.
    """
    _bind_ghidra_globals_from_caller()
    try:
        from ghidra.program.model.listing import Function
    except Exception:
        Function = None

    sm = currentProgram.getSymbolTable()
    fm = currentProgram.getFunctionManager()
    if name.startswith("_"):
        candidates = [name, name[1:]]
    else:
        candidates = [name, "_" + name]
    for cand in candidates:
        for sym in sm.getSymbols(cand):
            try:
                obj = sym.getObject()
            except Exception:
                obj = None
            if Function is not None and isinstance(obj, Function):
                return obj
            try:
                fn = fm.getFunctionAt(sym.getAddress())
            except Exception:
                fn = None
            if fn is not None:
                return fn
    return None


def callers_of(function):
    """Yield (caller_function, callsite_address) for callers of `function`.

    Skips data references; only call/jump xrefs count as a callsite.
    """
    if function is None:
        return
    _bind_ghidra_globals_from_caller()
    fm = currentProgram.getFunctionManager()
    try:
        refs = list(getReferencesTo(function.getEntryPoint()))
    except Exception:
        return
    target_entry = None
    target_name = None
    try:
        target_entry = function.getEntryPoint()
        target_name = function.getName()
    except Exception:
        pass
    for ref in refs:
        try:
            rt = ref.getReferenceType()
        except Exception:
            continue
        if not (rt.isCall() or rt.isJump()):
            continue
        try:
            site = ref.getFromAddress()
        except Exception:
            continue
        # Skip the import-thunk self-reference. PASS-001 saw rows whose
        # "caller" was the external symbol itself (e.g. a row claiming
        # _SecTaskCopyValueForEntitlement calls _SecTaskCopyValueForEntitlement)
        # because the thunk's entry counts as a call xref to itself.
        if target_entry is not None and site == target_entry:
            continue
        try:
            caller = fm.getFunctionContaining(site)
        except Exception:
            caller = None
        if caller is not None and target_name is not None:
            try:
                if caller.getName() == target_name:
                    continue
            except Exception:
                pass
        yield caller, site


# --------------------------------------------------------------------------
# Decompiler-driven argument recovery
# --------------------------------------------------------------------------
#
# Recovering literal arguments (strings, constants, symbol refs) at each
# callsite is what lifts a tier-A row from "there is a call" to "there
# is a call passing this exact value." The agent can then triage by
# arg, e.g. "which AuthorizationCopyRights calls request com.apple.SUFP".
#
# The Ghidra imports for decompilation are heavy, so they are loaded
# lazily by DecompCache.open(). Scripts that never enrich pay nothing.

class DecompCache(object):
    """Lazy wrapper around Ghidra's DecompInterface.

    Use as:

        cache = DecompCache()
        try:
            value = recover_call_string_arg(cache.open(), callsite, idx)
        finally:
            cache.dispose()

    `open()` returns None if `fast_mode=True` was passed at construction
    time. Scripts that opt out of the decompiler share the same callsite
    interface via the fast-path fallback.
    """

    __slots__ = ("_iface", "_fast", "_disposed")

    def __init__(self, fast_mode=False):
        self._iface = None
        self._fast = bool(fast_mode)
        self._disposed = False

    @property
    def fast(self):
        return self._fast

    def open(self):
        if self._fast or self._disposed:
            return None
        if self._iface is not None:
            return self._iface
        _bind_ghidra_globals_from_caller()
        try:
            from ghidra.app.decompiler import DecompInterface, DecompileOptions
        except Exception:
            return None
        iface = DecompInterface()
        try:
            iface.setOptions(DecompileOptions())
            iface.openProgram(currentProgram)
        except Exception:
            return None
        self._iface = iface
        return iface

    def dispose(self):
        if self._iface is not None and not self._disposed:
            try:
                self._iface.dispose()
            except Exception:
                pass
        self._disposed = True


DECOMPILE_TIMEOUT_SEC = int(os.environ.get("MACRE_DECOMPILE_TIMEOUT", "30"))

# Layout of a CFConstantString on 64-bit macOS:
#   isa     : 8 bytes
#   flags   : 8 bytes  (4 + 4 padding)
#   str ptr : 8 bytes  <-- this is what we want
#   length  : 8 bytes
_CFSTRING_STR_OFFSET = 0x10


def _read_pointer(address, ptr_size=8):
    """Read a little-endian pointer of ``ptr_size`` bytes at ``address``."""
    if address is None:
        return None
    try:
        mem = currentProgram.getMemory()
        value = 0
        for i in range(ptr_size):
            b = mem.getByte(address.add(i)) & 0xFF
            value |= b << (8 * i)
        return value
    except Exception:
        return None


def _block_name_at(address):
    """Return the memory block name containing ``address``, or ''. """
    try:
        mem = currentProgram.getMemory()
        block = mem.getBlock(address)
        if block is None:
            return ""
        return block.getName() or ""
    except Exception:
        return ""


def _read_cstring(address, max_len=512):
    """Raw NUL-terminated read at ``address``, or None."""
    if address is None:
        return None
    try:
        mem = currentProgram.getMemory()
        out = bytearray()
        addr = address
        for _ in range(max_len):
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


def recover_string_at(address):
    """Return the C string at ``address``, or None.

    Resolves four common cases:
      1. Ghidra-defined string data at the address (most precise).
      2. A pointer in __objc_selrefs / __got that dereferences to a C string.
      3. A CFConstantString in __cfstring (read the str ptr at +0x10).
      4. A raw NUL-terminated byte sequence at the address.
    """
    if address is None:
        return None
    _bind_ghidra_globals_from_caller()

    # 1. Defined data Ghidra already understands.
    try:
        data = getDataAt(address)
    except Exception:
        data = None
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

    # 2/3. CFString or selref-style indirection: the address sits in a
    # section that holds pointers, not chars. Heuristic: if the address
    # is in __cfstring, dereference at +0x10. If it's in __objc_selrefs
    # or __got, dereference at offset 0.
    block_name = _block_name_at(address).lower()
    addr_space = currentProgram.getAddressFactory().getDefaultAddressSpace()

    if "cfstring" in block_name:
        ptr = _read_pointer(address.add(_CFSTRING_STR_OFFSET))
        if ptr:
            try:
                target = addr_space.getAddress(ptr)
            except Exception:
                target = None
            s = _read_cstring(target)
            if s:
                return s

    if "selref" in block_name or "got" in block_name or "auth_ptr" in block_name:
        ptr = _read_pointer(address)
        if ptr:
            try:
                target = addr_space.getAddress(ptr)
            except Exception:
                target = None
            s = _read_cstring(target)
            if s:
                return s

    # 4. Raw NUL-terminated read at the address.
    s = _read_cstring(address)
    if s:
        return s

    # Last-resort: maybe the address is a CFString but in a block whose
    # name we did not recognize; try the +0x10 dereference unconditionally.
    ptr = _read_pointer(address.add(_CFSTRING_STR_OFFSET))
    if ptr:
        try:
            target = addr_space.getAddress(ptr)
        except Exception:
            target = None
        s = _read_cstring(target)
        if s:
            return s
    return None


def recover_objc_selector(decomp_iface, callsite_addr):
    """Recover the selector string at an objc_msgSend-style callsite.

    Reads arg 1 (the SEL) of the call. The varnode there is typically a
    pointer into __objc_selrefs whose contents point into __objc_methname.
    Returns the selector string, or None.
    """
    return recover_call_string_arg(decomp_iface, callsite_addr, 1)


def _pcode_inputs_at(decomp_iface, callsite_addr):
    """Yield Varnode inputs of the call pcode op at ``callsite_addr``.

    Yields nothing if decompilation fails or the address is not a call.
    """
    if decomp_iface is None:
        return
    try:
        from ghidra.program.model.pcode import PcodeOp
        from ghidra.util.task import ConsoleTaskMonitor
    except Exception:
        return
    fm = currentProgram.getFunctionManager()
    try:
        containing = fm.getFunctionContaining(callsite_addr)
    except Exception:
        containing = None
    if containing is None:
        return
    try:
        res = decomp_iface.decompileFunction(containing, DECOMPILE_TIMEOUT_SEC,
                                             ConsoleTaskMonitor())
    except Exception:
        return
    if res is None or not res.decompileCompleted():
        return
    high = res.getHighFunction()
    if high is None:
        return
    try:
        op_iter = high.getPcodeOps(callsite_addr)
    except Exception:
        return
    while op_iter.hasNext():
        op = op_iter.next()
        try:
            opcode = op.getOpcode()
        except Exception:
            continue
        if opcode not in (PcodeOp.CALL, PcodeOp.CALLIND):
            continue
        for i in range(op.getNumInputs()):
            yield op.getInput(i)


def recover_call_string_arg(decomp_iface, callsite_addr, arg_index):
    """Recover the literal string at ``arg_index`` of the call at ``callsite_addr``.

    arg_index is 0-based across function arguments (input 0 in pcode is
    the call target, so arg N maps to pcode input N+1).
    """
    _bind_ghidra_globals_from_caller()
    target_idx = arg_index + 1
    inputs = list(_pcode_inputs_at(decomp_iface, callsite_addr))
    if len(inputs) <= target_idx:
        return None
    vn = inputs[target_idx]
    if vn is None:
        return None
    return _resolve_varnode_to_string(vn)


def recover_call_const_arg(decomp_iface, callsite_addr, arg_index):
    """Recover the integer constant at ``arg_index`` of the call.

    Returns an int or None.
    """
    _bind_ghidra_globals_from_caller()
    target_idx = arg_index + 1
    inputs = list(_pcode_inputs_at(decomp_iface, callsite_addr))
    if len(inputs) <= target_idx:
        return None
    vn = inputs[target_idx]
    if vn is None:
        return None
    return _resolve_varnode_to_int(vn)


def _resolve_varnode_to_string(vn):
    """Resolve a Varnode to a C string at the constant address it carries."""
    try:
        from ghidra.program.model.pcode import PcodeOp
    except Exception:
        return None
    addr_space = currentProgram.getAddressFactory().getDefaultAddressSpace()

    def addr_from(value):
        try:
            return addr_space.getAddress(value)
        except Exception:
            return None

    if vn.isConstant() or vn.isAddress():
        s = recover_string_at(addr_from(vn.getOffset()))
        if s:
            return s
    defn = vn.getDef()
    if defn is None:
        return None
    if defn.getOpcode() in (PcodeOp.COPY, PcodeOp.CAST, PcodeOp.PTRSUB):
        for i in range(defn.getNumInputs()):
            src = defn.getInput(i)
            if src is None:
                continue
            if src.isConstant() or src.isAddress():
                s = recover_string_at(addr_from(src.getOffset()))
                if s:
                    return s
    return None


def _resolve_varnode_to_int(vn, depth=0):
    """Resolve a Varnode to an integer constant, folding simple expressions.

    Handles direct constants, COPY/CAST chains, and INT_OR / INT_AND /
    INT_LEFT / INT_RIGHT / INT_XOR when both operands fold to constants.
    Modern macOS APIs take flag args built as `RTLD_LAZY | RTLD_LOCAL`
    or `kSecMatchLimitOne | kCFNumberSInt32Type` and the previous
    "isConstant only" path returned None for those.
    """
    if vn is None or depth > 8:
        return None
    try:
        from ghidra.program.model.pcode import PcodeOp
    except Exception:
        return None
    if vn.isConstant():
        try:
            return int(vn.getOffset())
        except Exception:
            return None
    defn = vn.getDef()
    if defn is None:
        return None
    op = defn.getOpcode()
    if op in (PcodeOp.COPY, PcodeOp.CAST):
        return _resolve_varnode_to_int(defn.getInput(0), depth + 1)
    if defn.getNumInputs() < 2:
        return None
    a = _resolve_varnode_to_int(defn.getInput(0), depth + 1)
    b = _resolve_varnode_to_int(defn.getInput(1), depth + 1)
    if a is None or b is None:
        return None
    a &= (1 << 64) - 1
    b &= (1 << 64) - 1
    try:
        if op == PcodeOp.INT_OR:
            return a | b
        if op == PcodeOp.INT_AND:
            return a & b
        if op == PcodeOp.INT_XOR:
            return a ^ b
        if op == PcodeOp.INT_LEFT:
            return (a << b) & ((1 << 64) - 1)
        if op == PcodeOp.INT_RIGHT:
            return a >> b
        if op == PcodeOp.INT_ADD:
            return (a + b) & ((1 << 64) - 1)
        if op == PcodeOp.INT_SUB:
            return (a - b) & ((1 << 64) - 1)
        if op == PcodeOp.INT_MULT:
            return (a * b) & ((1 << 64) - 1)
    except Exception:
        return None
    return None


def recover_call_arg_fast(callsite_addr, arg_index=0):
    """Best-effort fallback: scan back ~12 instructions for a data ref.

    Used when the decompiler is disabled or fails. ``arg_index`` is
    advisory; the fast path picks the *first* string-shaped data ref
    it sees and returns it. Calls with multiple string operands will
    pick the wrong arg under FAST_MODE -- accepted tradeoff.
    """
    _bind_ghidra_globals_from_caller()
    try:
        listing = currentProgram.getListing()
        instr = listing.getInstructionAt(callsite_addr)
    except Exception:
        return None
    if instr is None:
        return None
    cur = instr
    for _ in range(12):
        cur = cur.getPrevious()
        if cur is None:
            break
        try:
            refs = cur.getReferencesFrom()
        except Exception:
            continue
        for ref in refs:
            try:
                if not ref.getReferenceType().isData():
                    continue
                s = recover_string_at(ref.getToAddress())
            except Exception:
                continue
            if s and len(s) >= 3:
                return s
    return None


# --------------------------------------------------------------------------
# Declarative API enrichment
# --------------------------------------------------------------------------

_APPLE_FRAMEWORK_PREFIXES = (
    "_CF", "CF", "_NS", "NS", "_OS_", "_OBJC_", "OBJC_",
    "_dispatch_", "dispatch_", "_pthread_", "pthread_",
    "_xpc_", "xpc_", "__Z", "__Block",
)


def is_apple_framework_function(name):
    """Heuristic: True if ``name`` looks like an Apple framework symbol.

    Used to silence tier-B function-name regex matches against framework
    thunks that have nothing to do with the target's own logic.
    """
    if not name:
        return False
    for prefix in _APPLE_FRAMEWORK_PREFIXES:
        if name.startswith(prefix):
            return True
    return False


class ObjCSelectorSpec(object):
    """Declarative spec for matching objc_msgSend callsites by selector.

    selector         the selector string to match at arg 1
    anchor_kind      tier-A anchor_kind for matching rows
    evidence_label   key= label for the recovered selector (default: 'selector')
    """

    __slots__ = ("selector", "anchor_kind", "evidence_label")

    def __init__(self, selector, anchor_kind=None, evidence_label="selector"):
        self.selector = selector
        self.anchor_kind = anchor_kind or ("objc_msg_" +
                                           selector.replace(":", "_").replace(" ", "_"))
        self.evidence_label = evidence_label


DEFAULT_MAX_PER_SELECTOR = int(os.environ.get("MACRE_MAX_PER_SELECTOR", "64"))


def enrich_objc_msgsend(writer, selector_specs, decomp_cache=None,
                        max_per_selector=DEFAULT_MAX_PER_SELECTOR):
    """For each selector spec, walk objc_msgSend callsites whose recovered
    arg-1 matches the selector, and emit a tier-A row per callsite.

    objc_msgSend is invoked through several symbols depending on linkage
    and ARC. We enumerate all of them and recover the selector at each
    callsite, then bucket by selector spec.
    """
    _bind_ghidra_globals_from_caller()
    own_cache = decomp_cache is None
    if own_cache:
        decomp_cache = DecompCache()
    try:
        decomp = decomp_cache.open()
        # Build a quick selector -> spec map.
        wanted = {s.selector: s for s in selector_specs}
        per_selector_count = {s.selector: 0 for s in selector_specs}
        total_processed = 0

        for msgsend_name in ("_objc_msgSend", "objc_msgSend",
                             "_objc_msgSendSuper2", "objc_msgSendSuper2",
                             "_objc_msgSend_stret", "objc_msgSend_stret"):
            fn = find_external(msgsend_name)
            if fn is None:
                continue
            for caller, site in callers_of(fn):
                if caller is None:
                    continue
                total_processed += 1
                if total_processed % HEARTBEAT_EVERY == 0:
                    selector_hits = sum(per_selector_count.values())
                    warn("[enrich_objc_msgsend] processed=%d msgsend=%s hits=%d" %
                         (total_processed, msgsend_name, selector_hits))
                sel = recover_objc_selector(decomp, site) if decomp else None
                if not sel:
                    continue
                spec = wanted.get(sel)
                if spec is None:
                    continue
                if per_selector_count[sel] >= max_per_selector:
                    continue
                evidence = "msgsend=%s; site=%s; %s=%s" % (
                    msgsend_name.lstrip("_"), format_addr(site),
                    spec.evidence_label, sel,
                )
                writer.add("A", spec.anchor_kind, caller.getName(),
                           format_addr(site), evidence)
                per_selector_count[sel] += 1
        return per_selector_count
    finally:
        if own_cache:
            decomp_cache.dispose()


class APISpec(object):
    """Declarative spec for one API to enrich at every callsite.

    name             C symbol (matched with and without leading underscore)
    arg_index        0-based; the arg whose value we want
    recover_kind     "string" (resolve to C string) or
                     "const" (resolve to int constant) or
                     "none" (record callsite without arg recovery)
    anchor_kind      tier-A anchor_kind for matching rows
    evidence_label   key= label for the recovered value in the evidence column
    """

    __slots__ = ("name", "arg_index", "recover_kind", "anchor_kind", "evidence_label")

    def __init__(self, name, arg_index=0, recover_kind="none",
                 anchor_kind=None, evidence_label=None):
        if recover_kind not in ("string", "const", "none"):
            raise ValueError("recover_kind must be string|const|none")
        self.name = name
        self.arg_index = int(arg_index)
        self.recover_kind = recover_kind
        self.anchor_kind = anchor_kind or "%s_callsite" % name
        self.evidence_label = evidence_label or recover_kind


DEFAULT_MAX_PER_API = int(os.environ.get("MACRE_MAX_PER_API", "64"))

# Emit a stderr heartbeat every N callsites in enrich phases. Visible to
# ghidra-watch.sh and to operators tailing stderr during long scans.
HEARTBEAT_EVERY = int(os.environ.get("MACRE_HEARTBEAT_EVERY", "100"))


def enrich_callsite_args(writer, api_specs, decomp_cache=None,
                         max_per_api=DEFAULT_MAX_PER_API):
    """For each API spec, walk callers and emit one tier-A row per callsite.

    The tier-A row's `name` is the calling function. The `address` is
    the callsite. The `evidence` column carries `api=<name>; site=<addr>`
    plus, when recovery succeeds, `<evidence_label>=<recovered>`.

    Recovery uses the decompiler if `decomp_cache` is provided and not
    in fast mode; otherwise falls back to the instruction-walk path.

    Returns a dict of {api_name: callsite_count} for stderr summary.
    """
    _bind_ghidra_globals_from_caller()
    own_cache = decomp_cache is None
    if own_cache:
        decomp_cache = DecompCache()
    try:
        decomp_iface = decomp_cache.open()
        counts = {}
        total_processed = 0
        for spec in api_specs:
            fn = find_external(spec.name)
            if fn is None:
                counts[spec.name] = 0
                continue
            count = 0
            for caller, site in callers_of(fn):
                if count >= max_per_api:
                    writer.warn("max_per_api_hit=%s" % spec.name)
                    break
                if caller is None:
                    continue
                total_processed += 1
                if total_processed % HEARTBEAT_EVERY == 0:
                    warn("[enrich_callsite_args] processed=%d api=%s hits=%d" %
                         (total_processed, spec.name, count))
                evidence = "api=%s; site=%s" % (spec.name, format_addr(site))
                if spec.recover_kind == "string":
                    val = None
                    if decomp_iface is not None:
                        val = recover_call_string_arg(decomp_iface, site, spec.arg_index)
                    if val is None:
                        val = recover_call_arg_fast(site, spec.arg_index)
                    if val:
                        evidence += "; %s=%s" % (spec.evidence_label, safe_field(val)[:160])
                elif spec.recover_kind == "const" and decomp_iface is not None:
                    val = recover_call_const_arg(decomp_iface, site, spec.arg_index)
                    if val is not None:
                        evidence += "; %s=0x%x" % (spec.evidence_label, val & ((1 << 64) - 1))
                writer.add("A", spec.anchor_kind, caller.getName(),
                           format_addr(site), evidence)
                count += 1
            counts[spec.name] = count
        return counts
    finally:
        if own_cache:
            decomp_cache.dispose()


# --------------------------------------------------------------------------
# Anchor writer
# --------------------------------------------------------------------------

class AnchorWriter(object):
    """Buffer anchor rows, emit header + rows on flush, summary to stderr."""

    __slots__ = ("scan_name", "_rows", "_kinds", "_warnings")

    def __init__(self, scan_name):
        self.scan_name = scan_name
        self._rows = []
        self._kinds = {}
        self._warnings = []

    def add(self, tier, kind, name, address="-", evidence=""):
        """Buffer one anchor row.

        tier      one of "A", "B", "C"
        kind      short slug, e.g. "xpc_listener", "audit_token_use"
        name      symbol / selector / string / class.method
        address  hex string, or "-" if not applicable
        evidence  free-form, structured `key=value` pairs joined by `; `
        """
        if tier not in ("A", "B", "C"):
            raise ValueError("tier must be A/B/C, got %r" % tier)
        addr_str = address if isinstance(address, str) else format_addr(address)
        self._rows.append((tier, kind, safe_field(name), addr_str, safe_field(evidence)))
        self._kinds.setdefault(tier, 0)
        self._kinds[tier] += 1

    def warn(self, msg):
        self._warnings.append(msg)

    def flush(self, target=None):
        target_str = safe_field(target if target is not None else program_path())
        emit("\t".join(ANCHOR_HEADER))
        # Stable sort: tier (A < B < C), then kind, then name.
        ordered = sorted(self._rows, key=lambda r: (r[0], r[1], r[2]))
        for tier, kind, name, addr, evid in ordered:
            emit("\t".join([target_str, tier, kind, name, addr, evid]))

        a = self._kinds.get("A", 0)
        b = self._kinds.get("B", 0)
        c = self._kinds.get("C", 0)
        warn("[%s] anchors=%d (A=%d B=%d C=%d)%s" % (
            self.scan_name, a + b + c, a, b, c,
            (" warnings=" + "|".join(self._warnings)) if self._warnings else "",
        ))


def format_addr(value):
    if value is None:
        return "-"
    try:
        return str(value)
    except Exception:
        return "-"


# --------------------------------------------------------------------------
# Declarative string-scan helper
# --------------------------------------------------------------------------

class StringRule(object):
    """One regex bucket fed into the declarative scan helper.

    tier            "A" / "B" / "C"
    kind            short slug for the anchor row
    regex           compiled regex applied to each string value
    max_anchors     cap on rows emitted from this rule (default 20)
    accept          optional callable(text) -> bool to filter further
    evidence_label  optional string used as the evidence's key= prefix
    """

    __slots__ = ("tier", "kind", "regex", "max_anchors", "accept", "evidence_label")

    def __init__(self, tier, kind, regex, max_anchors=20, accept=None, evidence_label=None):
        self.tier = tier
        self.kind = kind
        self.regex = re.compile(regex, re.I) if isinstance(regex, str) else regex
        self.max_anchors = max_anchors
        self.accept = accept
        self.evidence_label = evidence_label or kind


def run_string_scan(scan_name, rules, string_index=None, function_rules=None,
                    function_index=None, enrich=None, api_specs=None,
                    objc_specs=None, fast_mode=False, apple_filter=True):
    """Convenience runner for the simpler regex-bag scripts.

    Walks the string index once per rule (cheap; index is cached) and
    emits one anchor per matching string, capped per rule. If
    `function_rules` is provided, each rule is also matched against
    function names with the same anchor shape.

    If `enrich` is provided, it is called as `enrich(writer)` after the
    rule passes complete and before the writer flushes. Use this hook
    to add tier-A rows (callsite-verified anchors) recovered through
    `find_external` + `callers_of`.

    Returns the AnchorWriter after flush so callers can read counters
    for further reporting.
    """
    _bind_ghidra_globals_from_caller()
    if string_index is None:
        string_index = StringIndex()
    writer = AnchorWriter(scan_name)

    for rule in rules:
        emitted = 0
        seen = set()
        for text, addr in string_index.matching(rule.regex):
            if rule.accept is not None and not rule.accept(text):
                continue
            if text in seen:
                continue
            seen.add(text)
            if emitted >= rule.max_anchors:
                break
            # Cap the name and evidence columns. PASS-001 hit a 800 KB
            # single TSV row when an Electron Framework PEM cert matched
            # a string rule and the full PEM body landed in the name
            # column.
            name_field = safe_field(text)[:160]
            evidence = "%s=%s" % (rule.evidence_label, safe_field(text)[:120])
            writer.add(rule.tier, rule.kind, name_field, format_addr(addr), evidence)
            emitted += 1

    if function_rules:
        if function_index is None:
            function_index = FunctionIndex()
        for rule in function_rules:
            emitted = 0
            seen = set()
            for name, addr, _fn in function_index.matching(rule.regex):
                if apple_filter and is_apple_framework_function(name):
                    continue
                if rule.accept is not None and not rule.accept(name):
                    continue
                if name in seen:
                    continue
                seen.add(name)
                if emitted >= rule.max_anchors:
                    break
                evidence = "%s=%s" % (rule.evidence_label, safe_field(name)[:120])
                writer.add(rule.tier, rule.kind, name, format_addr(addr), evidence)
                emitted += 1

    if string_index.truncated:
        writer.warn("string_index_truncated_at_%d" % string_index.max_strings)
    if function_rules and function_index is not None and function_index.truncated:
        writer.warn("function_index_truncated_at_%d" % function_index.max_functions)

    if api_specs or objc_specs:
        cache = DecompCache(fast_mode=fast_mode)
        try:
            if api_specs:
                counts = enrich_callsite_args(writer, api_specs, decomp_cache=cache)
                covered = sum(1 for v in counts.values() if v > 0)
                writer.warn("api_callsites=%d/%d apis"
                            % (sum(counts.values()), len(counts)))
                if covered == 0:
                    writer.warn("no_api_callsites_resolved")
            if objc_specs:
                obj_counts = enrich_objc_msgsend(writer, objc_specs,
                                                 decomp_cache=cache)
                writer.warn("objc_msgsend_callsites=%d/%d selectors"
                            % (sum(obj_counts.values()), len(obj_counts)))
        finally:
            cache.dispose()

    if enrich is not None:
        try:
            enrich(writer)
        except Exception as exc:
            writer.warn("enrich_failed=%s" % exc)

    writer.flush()
    return writer
