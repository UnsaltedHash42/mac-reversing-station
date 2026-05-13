# Ghidra script: scan one loaded program for "wrong door" XPC entitlement patterns.
#
# Tier A (decompiler-recovered callsite + literal arg):
#   xpc_listener_callsite               service name (arg 0)
#   sectaskvalueforentitlement_callsite entitlement key (arg 1)
#
# The wrong-door bug class wants you to compare the *number of listeners*
# (one tier-A xpc_listener_callsite per registered service) against the
# *number of entitlement checks* (one tier-A sectaskvalueforentitlement
# per check). When listeners outnumber entitlement checks, you have a
# wrong-door candidate.
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
# For decompiler-recovered service names + ObjC delegate impl walking
# + entitlements-blob extraction, run `dump_xpc_listeners.py` alongside
# this script.
#
# @category Mach-O.XPC
# @runtime PyGhidra

from _re_lib import APISpec, StringRule, run_string_scan


API_SPECS = [
    APISpec("xpc_connection_create_listener", arg_index=0, recover_kind="string",
            anchor_kind="xpc_listener_callsite", evidence_label="service"),
    APISpec("xpc_connection_create_mach_service", arg_index=0, recover_kind="string",
            anchor_kind="xpc_mach_service_callsite", evidence_label="service"),
    APISpec("SecTaskCopyValueForEntitlement", arg_index=1, recover_kind="string",
            anchor_kind="sectask_entitlement_callsite", evidence_label="entitlement"),
]


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
    api_specs=API_SPECS,
)
