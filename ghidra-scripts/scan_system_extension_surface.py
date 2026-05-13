# Ghidra script: scan one loaded program for system/network extension surface.
#
# Tier B (function-name match):
#   extension_lifecycle_impl    *willActivate / *didActivate / *willTerminate /
#                               *requestActivation
#   ne_provider_impl            functions whose name references NEProvider /
#                               NETunnelProvider / NEFilterDataProvider
#
# Tier C (string heuristic):
#   extension_string            systemextension / networkextension / DriverKit /
#                               dext / appex / OSSystemExtension
#   es_string                   EndpointSecurity / es_new_client / es_subscribe
#   ext_entitlement_string      com.apple.developer.system-extension /
#                               com.apple.developer.networking.networkextension /
#                               com.apple.developer.endpoint-security
#   approval_string             approval / activated / systemextensionsctl /
#                               NEProvider
#
# @category Mach-O.SystemExtensions
# @runtime PyGhidra

from _re_lib import StringRule, run_string_scan


run_string_scan(
    scan_name="scan_system_extension_surface",
    rules=[
        StringRule("C", "extension_string",
                   r"(systemextension|networkextension|DriverKit|dext|appex|OSSystemExtension)",
                   max_anchors=16, evidence_label="string"),
        StringRule("C", "es_string",
                   r"(EndpointSecurity|es_new_client|es_subscribe|es_event_|ES_EVENT_TYPE)",
                   max_anchors=16, evidence_label="string"),
        StringRule("C", "ext_entitlement_string",
                   r"com\.apple\.developer\.(system-extension|networking\.networkextension|endpoint-security|driverkit)",
                   max_anchors=16, evidence_label="entitlement"),
        StringRule("C", "approval_string",
                   r"(approval|required|activated|systemextensionsctl|NEProvider|NEFilter)",
                   max_anchors=12, evidence_label="string"),
    ],
    function_rules=[
        StringRule("B", "extension_lifecycle_impl",
                   r"(willActivate|didActivate|willTerminate|requestActivation|activationRequest)",
                   max_anchors=12, evidence_label="function"),
        StringRule("B", "ne_provider_impl",
                   r"(NEProvider|NETunnelProvider|NEFilterDataProvider|NEPacketTunnelProvider|NEAppProxyProvider)",
                   max_anchors=12, evidence_label="function"),
    ],
)
