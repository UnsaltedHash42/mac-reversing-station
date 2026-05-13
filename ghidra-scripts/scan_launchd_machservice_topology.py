# Ghidra script: scan one loaded program for launchd / MachService topology.
#
# Tier A (decompiler-recovered callsite + literal arg):
#   bootstrap_check_in_callsite         service name (arg 0, char*)
#   bootstrap_register_callsite         service name (arg 1)
#   xpc_create_mach_service_callsite    service name (arg 0)
#   xpc_create_listener_callsite        endpoint name (arg 0)
#   xpc_lookup_callsite                 service name (arg 0)
#
# A recovered service name from a callsite is the strongest evidence
# you can have without launchd plists. Pair with the launchctl print
# output captured by macre-vm-mcp.
#
# Tier B (function-name match):
#   listener_setup_impl         functions named *resume / *registerForXPC /
#                               *initWithMachServiceName / *startListening
#
# Tier C (string heuristic):
#   mach_service_string         reverse-DNS strings co-occurring with com.apple
#                               or xpc/mach vocabulary (likely service names)
#   listener_api_string         NSXPCListener / xpc_connection_create_mach_service /
#                               bootstrap_*
#   entitlement_string          com.apple.security / entitlement /
#                               SecTaskCopyValueForEntitlement
#
# @category Mach-O.Launchd
# @runtime PyGhidra

import re

from _re_lib import APISpec, StringRule, run_string_scan


API_SPECS = [
    APISpec("bootstrap_check_in", arg_index=1, recover_kind="string",
            anchor_kind="bootstrap_check_in_callsite", evidence_label="service"),
    APISpec("bootstrap_register", arg_index=1, recover_kind="string",
            anchor_kind="bootstrap_register_callsite", evidence_label="service"),
    APISpec("bootstrap_look_up", arg_index=1, recover_kind="string",
            anchor_kind="bootstrap_look_up_callsite", evidence_label="service"),
    APISpec("xpc_connection_create_mach_service", arg_index=0, recover_kind="string",
            anchor_kind="xpc_create_mach_service_callsite", evidence_label="service"),
    APISpec("xpc_connection_create_listener", arg_index=0, recover_kind="string",
            anchor_kind="xpc_create_listener_callsite", evidence_label="endpoint"),
    APISpec("xpc_connection_create", arg_index=0, recover_kind="string",
            anchor_kind="xpc_connection_create_callsite", evidence_label="service"),
]


_REV_DNS = re.compile(r"^([A-Za-z0-9_-]+\.){2,}[A-Za-z0-9_.-]+$")


def _looks_like_service_name(text):
    if not _REV_DNS.match(text):
        return False
    if "/" in text or " " in text:
        return False
    if len(text) > 96:
        return False
    return ("com.apple" in text or "mach" in text.lower() or "xpc" in text.lower()
            or text.count(".") <= 5)


run_string_scan(
    scan_name="scan_launchd_machservice_topology",
    rules=[
        StringRule("C", "mach_service_string", r".",
                   max_anchors=24, evidence_label="service",
                   accept=_looks_like_service_name),
        StringRule("C", "listener_api_string",
                   r"(NSXPCListener|xpc_connection_create_mach_service|launchctl|MachServices|bootstrap_)",
                   max_anchors=16, evidence_label="api"),
        StringRule("C", "entitlement_string",
                   r"(com\.apple\.security|entitlement|SecTaskCopyValueForEntitlement)",
                   max_anchors=16, evidence_label="string"),
    ],
    function_rules=[
        StringRule("B", "listener_setup_impl",
                   r"(NSXPCListener|initWithMachServiceName|registerForXPC|startListening|setupListener|listener.{0,20}resume)",
                   max_anchors=12, evidence_label="function"),
    ],
    api_specs=API_SPECS,
)
