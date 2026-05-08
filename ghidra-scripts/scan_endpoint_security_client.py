# Ghidra script: scan one loaded program for Endpoint Security client surface.
#
# Tier A (callsite-verified):
#   es_client_callsite          callers of es_new_client / es_subscribe /
#                               es_respond_auth_result / es_delete_client
#
# Tier B (function-name match):
#   es_handler_impl             functions named *handler / *callback / *event
#                               that mention es / endpoint / event_message
#   policy_decision_impl        functions named *policy / *decision / *verdict
#
# Tier C (string heuristic):
#   es_client_string            EndpointSecurity / es_new_client / es_subscribe
#   es_event_string             ES_EVENT_TYPE_* / AUTH_ / NOTIFY_ / es_event_
#   cache_string                cache / policy_cache / decision / mute / unmute
#   policy_string               allow / deny / block / authorize / quarantine
#
# @category Mach-O.EndpointSecurity
# @runtime Jython

from _re_lib import (
    StringRule, format_addr, callers_of, find_external, run_string_scan,
)


ES_APIS = (
    "es_new_client",
    "es_delete_client",
    "es_subscribe",
    "es_unsubscribe",
    "es_respond_auth_result",
    "es_respond_flags_result",
    "es_mute_path",
)


def add_es_callsites(writer):
    for api in ES_APIS:
        fn = find_external(api)
        if fn is None:
            continue
        for caller, site in callers_of(fn):
            if caller is None:
                continue
            writer.add("A", "es_client_callsite", caller.getName(),
                       format_addr(site),
                       "api=%s; site=%s" % (api, format_addr(site)))


run_string_scan(
    scan_name="scan_endpoint_security_client",
    rules=[
        StringRule("C", "es_client_string",
                   r"(EndpointSecurity|es_new_client|es_delete_client|es_subscribe|es_unsubscribe|es_respond_)",
                   max_anchors=20, evidence_label="string"),
        StringRule("C", "es_event_string",
                   r"(ES_EVENT_TYPE_[A-Z0-9_]+|ES_AUTH_RESULT|ES_NEW_CLIENT_RESULT|es_event_)",
                   max_anchors=24, evidence_label="string"),
        StringRule("C", "cache_string",
                   r"(policy_cache|decision_cache|mute_path|unmute_path|verdict_cache)",
                   max_anchors=12, evidence_label="string"),
        StringRule("C", "policy_string",
                   r"(allow|deny|block|authorize|quarantine|remediate|trust)",
                   max_anchors=12, evidence_label="string",
                   accept=lambda s: " " not in s and len(s) <= 96),
    ],
    function_rules=[
        StringRule("B", "es_handler_impl",
                   r"(es_event|es_handler|es_callback|endpoint.{0,10}(handler|event))",
                   max_anchors=12, evidence_label="function"),
        StringRule("B", "policy_decision_impl",
                   r"(policy|verdict|decision|authorize|quarantine).{0,30}(handler|callback|impl)",
                   max_anchors=12, evidence_label="function"),
    ],
    enrich=add_es_callsites,
)
