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
# @runtime Jython

import re
import sys


ANCHOR_HEADER = ("target", "tier", "anchor_kind", "name", "address", "evidence")

# Hard cap on the per-scan string index. Hitting this is recorded in the
# stderr summary and surfaced via AnchorWriter.summary() so the agent can
# notice when a row count is bounded by the cap rather than by reality.
DEFAULT_MAX_STRINGS = 20000

# Hard cap on the per-scan function-name iteration. Same rationale.
DEFAULT_MAX_FUNCTIONS = 50000


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
    fm = currentProgram.getFunctionManager()
    try:
        refs = list(getReferencesTo(function.getEntryPoint()))
    except Exception:
        return
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
        try:
            caller = fm.getFunctionContaining(site)
        except Exception:
            caller = None
        yield caller, site


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
                    function_index=None, enrich=None):
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
            evidence = "%s=%s" % (rule.evidence_label, safe_field(text)[:120])
            writer.add(rule.tier, rule.kind, text, format_addr(addr), evidence)
            emitted += 1

    if function_rules:
        if function_index is None:
            function_index = FunctionIndex()
        for rule in function_rules:
            emitted = 0
            seen = set()
            for name, addr, _fn in function_index.matching(rule.regex):
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

    if enrich is not None:
        try:
            enrich(writer)
        except Exception as exc:
            writer.warn("enrich_failed=%s" % exc)

    writer.flush()
    return writer
