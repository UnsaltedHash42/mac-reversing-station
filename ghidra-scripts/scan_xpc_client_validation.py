# Ghidra script: scan one loaded program for XPC client-validation signals.
#
# Tier A (decompiler-recovered callsite + literal arg):
#   xpc_listener_callsite       service name (arg 0, char*)
#                               of xpc_connection_create_listener /
#                               xpc_connection_create_mach_service
#   xpc_dictionary_get_value    key being read (arg 1, char*)
#   sectaskvalueforentitlement  entitlement name (arg 1, CFStringRef)
#
# For decompiler-verified service-name recovery + ObjC delegate walking
# + entitlements-blob extraction, see `dump_xpc_listeners.py`. This
# script is the lighter sweep; the dump script is the heavyweight.
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
# @category Mach-O.XPC
# @runtime PyGhidra

from _re_lib import APISpec, StringRule, run_string_scan


API_SPECS = [
    APISpec("xpc_connection_create_listener", arg_index=0, recover_kind="string",
            anchor_kind="xpc_listener_callsite", evidence_label="service"),
    APISpec("xpc_connection_create_mach_service", arg_index=0, recover_kind="string",
            anchor_kind="xpc_mach_service_callsite", evidence_label="service"),
    APISpec("xpc_connection_create", arg_index=0, recover_kind="string",
            anchor_kind="xpc_connection_create_callsite", evidence_label="service"),
    APISpec("xpc_dictionary_get_string", arg_index=1, recover_kind="string",
            anchor_kind="xpc_dict_read_callsite", evidence_label="key"),
    APISpec("xpc_dictionary_get_value", arg_index=1, recover_kind="string",
            anchor_kind="xpc_dict_read_callsite", evidence_label="key"),
    APISpec("xpc_connection_get_audit_token", arg_index=0, recover_kind="none",
            anchor_kind="xpc_get_audit_token_callsite"),
    APISpec("SecTaskCopyValueForEntitlement", arg_index=1, recover_kind="string",
            anchor_kind="sectask_entitlement_callsite", evidence_label="entitlement"),
]


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
    api_specs=API_SPECS,
)
