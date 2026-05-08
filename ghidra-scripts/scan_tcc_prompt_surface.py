# Ghidra script: scan one loaded program for TCC prompt-attribution / privacy surface.
#
# Tier A (decompiler-recovered callsite + literal arg):
#   tccaccessrequest_callsite          kTCCService string (arg 0)
#   tccaccesspreflight_callsite        kTCCService string (arg 0)
#   sectaskcopyentitlement_callsite    entitlement key (arg 1)
#   sectaskcopyident_callsite          callsite address (no string arg)
#
# The wrong-prompt-attribution bug class is: a daemon mediates a TCC
# prompt for a *different* requesting subject than the one whose UI
# the user sees, so consent is laundered through the wrong identity.
# The literal kTCCService recovered here tells the agent which service
# the daemon is gating, which is half of the attribution question.
#
# Tier B (function-name match):
#   prompt_handler              functions named *prompt* / *consent* / *permission*
#   identity_resolver           functions named *bundleIdentifier* / *executablePath*
#                               / *target_identifier* / *responsible*
#
# Tier C (string heuristic):
#   tcc_string                  TCC / kTCCService / com.apple.TCC / tccd
#   apple_event_string          AppleEvent / kTCCServiceAppleEvents / NSAppleEventsUsageDescription
#   privacy_service_string      Accessibility / ScreenCapture / Camera / Microphone /
#                               FullDisk / DocumentsFolder etc.
#   identity_string             bundleIdentifier / executablePath / SecRequirement / csreq
#
# @category Mach-O.TCC
# @runtime Jython

from _re_lib import APISpec, StringRule, run_string_scan


API_SPECS = [
    APISpec("TCCAccessRequest", arg_index=0, recover_kind="string",
            anchor_kind="tccaccessrequest_callsite", evidence_label="service"),
    APISpec("TCCAccessPreflight", arg_index=0, recover_kind="string",
            anchor_kind="tccaccesspreflight_callsite", evidence_label="service"),
    APISpec("TCCAccessRequestForSelf", arg_index=0, recover_kind="string",
            anchor_kind="tccaccessrequestforself_callsite", evidence_label="service"),
    APISpec("SecTaskCopyValueForEntitlement", arg_index=1, recover_kind="string",
            anchor_kind="sectaskcopyentitlement_callsite", evidence_label="entitlement"),
    APISpec("SecTaskCopySigningIdentifier", arg_index=0, recover_kind="none",
            anchor_kind="sectaskcopyident_callsite"),
]


run_string_scan(
    scan_name="scan_tcc_prompt_surface",
    rules=[
        StringRule("C", "tcc_string",
                   r"(TCC|TCCAccessRequest|kTCCService|com\.apple\.TCC|tccd)",
                   max_anchors=24, evidence_label="string"),
        StringRule("C", "apple_event_string",
                   r"(AppleEvent|Apple Events|kTCCServiceAppleEvents|NSAppleEventsUsageDescription|AEDesc)",
                   max_anchors=12, evidence_label="string"),
        StringRule("C", "privacy_service_string",
                   r"(Accessibility|ScreenCapture|ScreenRecording|Camera|Microphone|DesktopFolder|DocumentsFolder|DownloadsFolder|FullDisk|ListenEvent|PostEvent)",
                   max_anchors=20, evidence_label="string"),
        StringRule("C", "identity_string",
                   r"(bundleIdentifier|executablePath|target_identifier|target_path|SecRequirement|csreq)",
                   max_anchors=20, evidence_label="string"),
    ],
    function_rules=[
        StringRule("B", "prompt_handler",
                   r"(prompt|consent|permission|displayName|localizedName)",
                   max_anchors=16, evidence_label="function"),
        StringRule("B", "identity_resolver",
                   r"(bundleIdentifier|executablePath|target_identifier|responsible|effectiveUserIdentifier)",
                   max_anchors=16, evidence_label="function"),
    ],
    api_specs=API_SPECS,
)
