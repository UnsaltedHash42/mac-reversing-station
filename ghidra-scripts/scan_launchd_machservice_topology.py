# Ghidra script: scan one loaded program for launchd / MachService topology.
#
# Tier A (callsite-verified):
#   bootstrap_callsite          callers of bootstrap_check_in /
#                               bootstrap_register / xpc_connection_create_mach_service
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
# @runtime Jython

import re

from _re_lib import (
    StringRule, format_addr, callers_of, find_external, run_string_scan,
)


BOOTSTRAP_APIS = (
    "bootstrap_check_in",
    "bootstrap_register",
    "xpc_connection_create_mach_service",
    "xpc_connection_create_listener",
)


def add_bootstrap_callsites(writer):
    for api in BOOTSTRAP_APIS:
        fn = find_external(api)
        if fn is None:
            continue
        for caller, site in callers_of(fn):
            if caller is None:
                continue
            writer.add("A", "bootstrap_callsite", caller.getName(),
                       format_addr(site),
                       "api=%s; site=%s" % (api, format_addr(site)))


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
    enrich=add_bootstrap_callsites,
)
