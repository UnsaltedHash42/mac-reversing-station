# Ghidra script: scan one loaded program for TCC prompt-attribution / privacy surface.
#
# Tier A (callsite-verified):
#   tcc_callsite                callers of TCCAccessRequest / TCCAccessPreflight /
#                               SecTaskCopyValueForEntitlement
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

from _re_lib import (
    StringRule, format_addr, callers_of, find_external, run_string_scan,
)


TCC_APIS = (
    "TCCAccessRequest",
    "TCCAccessPreflight",
    "TCCAccessRequestForSelf",
    "SecTaskCopyValueForEntitlement",
    "SecTaskCopySigningIdentifier",
)


def add_tcc_callsites(writer):
    for api in TCC_APIS:
        fn = find_external(api)
        if fn is None:
            continue
        for caller, site in callers_of(fn):
            if caller is None:
                continue
            writer.add("A", "tcc_callsite", caller.getName(),
                       format_addr(site),
                       "api=%s; site=%s" % (api, format_addr(site)))


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
    enrich=add_tcc_callsites,
)
