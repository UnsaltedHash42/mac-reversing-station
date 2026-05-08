# Ghidra script: scan one loaded program for "wrong door" XPC entitlement patterns.
#
# Emits the standard tiered anchor TSV. See `_re_lib.py` for the contract.
#
# Tier B (function-name match):
#   should_accept_impl   -[*Delegate listener:shouldAcceptNewConnection:] etc.
#   audit_token_user     functions whose name references audit token / SecTask
#
# Tier C (string heuristic):
#   listener_string      mach/xpc/listener vocabulary
#   ent_string           entitlement / com.apple.private / SecTaskCopyValueForEntitlement
#   audit_token_string   audit_token / responsible / effectiveUserIdentifier strings
#
# For decompiler-verified callsite recovery of XPC service registrations,
# use `dump_xpc_listeners.py` instead. This script is the lightweight
# string-pass companion.
#
# @category Mach-O.XPC
# @runtime Jython

from _re_lib import (
    AnchorWriter, FunctionIndex, StringIndex, StringRule, run_string_scan,
)

run_string_scan(
    scan_name="scan_wrong_door",
    rules=[
        StringRule("C", "listener_string",
                   r"(mach|xpc|listener|service|com\.apple\.)",
                   max_anchors=24, evidence_label="listener_string"),
        StringRule("C", "ent_string",
                   r"(entitlement|com\.apple\.private|SecTaskCopyValueForEntitlement)",
                   max_anchors=20, evidence_label="ent_string"),
        StringRule("C", "audit_token_string",
                   r"(audit[_-]?token|SecTask|responsible|effectiveUserIdentifier)",
                   max_anchors=16, evidence_label="audit_string"),
    ],
    function_rules=[
        StringRule("B", "should_accept_impl",
                   r"(shouldAcceptNewConnection|listener:shouldAccept|acceptNewConnection)",
                   max_anchors=16, evidence_label="selector"),
        StringRule("B", "audit_token_user",
                   r"(audit[_-]?token|SecTask|effectiveUserIdentifier)",
                   max_anchors=16, evidence_label="function"),
    ],
)
