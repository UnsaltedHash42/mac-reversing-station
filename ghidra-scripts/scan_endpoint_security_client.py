# Ghidra script: scan one loaded program for Endpoint Security client surface.
#
# Tier A (decompiler-recovered callsite + literal arg):
#   es_new_client_callsite          callsite (handler block at arg 1; record site)
#   es_subscribe_callsite           events count (arg 2, size_t)
#   es_unsubscribe_callsite         events count (arg 2)
#   es_respond_auth_callsite        decision constant (arg 2, ES_AUTH_RESULT)
#   es_mute_path_callsite           path being muted (arg 1, char*)
#   es_unmute_path_callsite         path being unmuted (arg 1)
#
# The mute_path / unmute_path arg recovery is the high-leverage one:
# whether an EDR is muting `/tmp/known_attacker_path` versus
# `/private/var/db/com.vendor.legitimate` shows up here directly.
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
# @runtime PyGhidra

from _re_lib import APISpec, StringRule, run_string_scan


API_SPECS = [
    APISpec("es_new_client", arg_index=0, recover_kind="none",
            anchor_kind="es_new_client_callsite"),
    APISpec("es_delete_client", arg_index=0, recover_kind="none",
            anchor_kind="es_delete_client_callsite"),
    APISpec("es_subscribe", arg_index=2, recover_kind="const",
            anchor_kind="es_subscribe_callsite", evidence_label="event_count"),
    APISpec("es_unsubscribe", arg_index=2, recover_kind="const",
            anchor_kind="es_unsubscribe_callsite", evidence_label="event_count"),
    APISpec("es_respond_auth_result", arg_index=2, recover_kind="const",
            anchor_kind="es_respond_auth_callsite", evidence_label="decision"),
    APISpec("es_respond_flags_result", arg_index=2, recover_kind="const",
            anchor_kind="es_respond_flags_callsite", evidence_label="decision"),
    APISpec("es_mute_path", arg_index=1, recover_kind="string",
            anchor_kind="es_mute_path_callsite", evidence_label="path"),
    APISpec("es_unmute_path", arg_index=1, recover_kind="string",
            anchor_kind="es_unmute_path_callsite", evidence_label="path"),
    APISpec("es_mute_process", arg_index=1, recover_kind="none",
            anchor_kind="es_mute_process_callsite"),
]


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
    api_specs=API_SPECS,
)
