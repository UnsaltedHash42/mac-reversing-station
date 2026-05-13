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
# @runtime PyGhidra

from _re_lib import APISpec, ObjCSelectorSpec, StringRule, run_string_scan


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

# AVFoundation / Photos / EventKit prompts go through ObjC dispatch.
OBJC_SPECS = [
    ObjCSelectorSpec("requestAccessForMediaType:completionHandler:",
                     anchor_kind="avfoundation_request_access_callsite"),
    ObjCSelectorSpec("requestAccessWithCompletionHandler:",
                     anchor_kind="objc_request_access_callsite"),
    ObjCSelectorSpec("requestAuthorizationForAccessLevel:handler:",
                     anchor_kind="photos_request_authorization_callsite"),
    ObjCSelectorSpec("requestAuthorizationWithCompletionHandler:",
                     anchor_kind="objc_request_authorization_callsite"),
    ObjCSelectorSpec("authorizationStatusForMediaType:",
                     anchor_kind="avfoundation_auth_status_callsite"),
    ObjCSelectorSpec("authorizationStatus",
                     anchor_kind="objc_auth_status_callsite"),
]


run_string_scan(
    scan_name="scan_tcc_prompt_surface",
    rules=[
        # Bare 'TCC' was dropped 2026-05-13 — re.I matched 'TCC' inside base64
        # PEM root-cert blobs, producing 24/24 false positives on Electron
        # Framework. The four specific forms below are precise enough.
        StringRule("C", "tcc_string",
                   r"(TCCAccessRequest|kTCCService|com\.apple\.TCC|tccd)",
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
    objc_specs=OBJC_SPECS,
)
