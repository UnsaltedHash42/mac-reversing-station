# Ghidra script: scan for Catalyst / iOS-on-Mac platform-conditional bypasses.
#
# Tier B (function-name match):
#   platform_branch             functions named *isCatalyst* / *targetEnvironment* /
#                               *isMac* / *iOSAppOnMac*
#
# Tier C (string heuristic):
#   catalyst_string             catalyst / MacCatalyst / isiOSAppOnMac
#   platform_string             targetEnvironment / macos / iphone / ipad / ios
#   ent_string                  entitlement / com.apple.private / SecTaskCopyValueForEntitlement
#   bypass_string               bypass / skip / non-macos / exempt / legacy / compat
#
# @category Mach-O.CatalystPortingGap
# @runtime PyGhidra

from _re_lib import StringRule, run_string_scan


run_string_scan(
    scan_name="scan_catalyst_porting_gap",
    rules=[
        StringRule("C", "catalyst_string",
                   r"(catalyst|MacCatalyst|is-catalyst-binary|isiOSAppOnMac)",
                   max_anchors=16, evidence_label="string"),
        StringRule("C", "platform_string",
                   r"(targetEnvironment|isMac|iphone|ipad|isiOS|isMacCatalyst|UIDevice)",
                   max_anchors=16, evidence_label="string"),
        StringRule("C", "ent_string",
                   r"(entitlement|com\.apple\.private|SecTaskCopyValueForEntitlement)",
                   max_anchors=16, evidence_label="string"),
        StringRule("C", "bypass_string",
                   r"(bypass|skip|non.?macos|exempt|legacy|compat)",
                   max_anchors=12, evidence_label="string"),
    ],
    function_rules=[
        StringRule("B", "platform_branch",
                   r"(isCatalyst|isMac|isiOSAppOnMac|targetEnvironment)",
                   max_anchors=12, evidence_label="function"),
    ],
)
