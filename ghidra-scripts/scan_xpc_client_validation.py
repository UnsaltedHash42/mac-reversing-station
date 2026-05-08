# Ghidra script: scan one loaded program for XPC client-validation signals.
#
# Tier A (callsite-verified):
#   xpc_listener_callsite       callers of xpc_connection_create_listener /
#                               xpc_connection_create_mach_service
#
# Tier B (function-name match):
#   should_accept_impl          *shouldAcceptNewConnection / acceptNewConnection
#   audit_token_user            functions referencing audit token / SecTask
#   weak_identity_check         functions referencing pid / bundleIdentifier /
#                               processIdentifier / executablePath
#
# Tier C (string heuristic):
#   mach_service_string         MachServices / NSXPC / com.apple.* names
#   team_id_string              TeamIdentifier / SecCode / SecRequirement
#
# For decompiler-verified service-name recovery, see `dump_xpc_listeners.py`.
#
# @category Mach-O.XPC
# @runtime Jython

from _re_lib import (
    StringRule, format_addr, callers_of, find_external, run_string_scan,
)


XPC_LISTENER_APIS = (
    "xpc_connection_create_listener",
    "xpc_connection_create_mach_service",
    "_xpc_main",
)


def add_listener_callsites(writer):
    for api in XPC_LISTENER_APIS:
        target = find_external(api)
        if target is None:
            continue
        for caller, site in callers_of(target):
            if caller is None:
                continue
            writer.add(
                "A", "xpc_listener_callsite",
                caller.getName(),
                format_addr(site),
                "api=%s; site=%s" % (api, format_addr(site)),
            )


run_string_scan(
    scan_name="scan_xpc_client_validation",
    rules=[
        StringRule("C", "mach_service_string",
                   r"(MachServices|NSXPC|xpc_|com\.[A-Za-z0-9_.-]+)",
                   max_anchors=30, evidence_label="string"),
        StringRule("C", "team_id_string",
                   r"(TeamIdentifier|teamid|SecCode|SecRequirement|anchor apple)",
                   max_anchors=12, evidence_label="string"),
    ],
    function_rules=[
        StringRule("B", "should_accept_impl",
                   r"(shouldAcceptNewConnection|listener:shouldAccept|acceptNewConnection)",
                   max_anchors=16, evidence_label="selector"),
        StringRule("B", "audit_token_user",
                   r"(audit[_-]?token|xpc_connection_get_audit_token|SecTask)",
                   max_anchors=20, evidence_label="function"),
        StringRule("B", "weak_identity_check",
                   r"(processIdentifier|bundleIdentifier|executablePath|target_path|target_identifier)",
                   max_anchors=20, evidence_label="function"),
    ],
    enrich=add_listener_callsites,
)
