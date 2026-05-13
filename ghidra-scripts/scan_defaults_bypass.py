# Ghidra script: scan one loaded program for user-defaults-gated security checks.
#
# Tier A (decompiler-recovered callsite + literal arg):
#   cfprefs_copyappvalue_callsite       defaults key (arg 0, CFStringRef)
#   cfprefs_copyvalue_callsite          defaults key (arg 0)
#   cfprefs_getbool_callsite            defaults key (arg 0)
#   cfprefs_getint_callsite             defaults key (arg 0)
#   cfprefs_setvalue_callsite           defaults key being set (arg 0)
#
# Recovering the key turns a vague "this binary reads defaults" into
# "this binary reads `disable-amfi-dyld-trust` from `com.apple.foo`" --
# direct triage signal for the bypass-gate hunt.
#
# Tier B (function-name match):
#   bypass_gate_impl            functions named *disable* / *bypass* / *override*
#                               / *force* (internal toggles often live in
#                               functions that read defaults).
#
# Tier C (string heuristic):
#   defaults_api_string         NSUserDefaults / CFPreferences / standardUserDefaults
#   defaults_key_candidate      bypass-shaped keys (short, no spaces, no slashes)
#                               matching disable/bypass/skip/allow/override/internal
#                               /debug/development/test/force/ignore vocabulary
#   defaults_domain             reverse-DNS strings that look like preference domains
#
# @category Mach-O.DefaultsBypass
# @runtime PyGhidra

import re

from _re_lib import APISpec, ObjCSelectorSpec, StringRule, run_string_scan


API_SPECS = [
    APISpec("CFPreferencesCopyAppValue", arg_index=0, recover_kind="string",
            anchor_kind="cfprefs_copyappvalue_callsite", evidence_label="key"),
    APISpec("CFPreferencesCopyValue", arg_index=0, recover_kind="string",
            anchor_kind="cfprefs_copyvalue_callsite", evidence_label="key"),
    APISpec("CFPreferencesGetAppBooleanValue", arg_index=0, recover_kind="string",
            anchor_kind="cfprefs_getbool_callsite", evidence_label="key"),
    APISpec("CFPreferencesGetAppIntegerValue", arg_index=0, recover_kind="string",
            anchor_kind="cfprefs_getint_callsite", evidence_label="key"),
    APISpec("CFPreferencesSetAppValue", arg_index=0, recover_kind="string",
            anchor_kind="cfprefs_setappvalue_callsite", evidence_label="key"),
    APISpec("CFPreferencesSetValue", arg_index=0, recover_kind="string",
            anchor_kind="cfprefs_setvalue_callsite", evidence_label="key"),
]

# NSUserDefaults uses ObjC dispatch. Recover the key from objc_msgSend.
OBJC_SPECS = [
    ObjCSelectorSpec("boolForKey:",
                     anchor_kind="nsuserdefaults_boolforkey_callsite",
                     evidence_label="key"),
    ObjCSelectorSpec("integerForKey:",
                     anchor_kind="nsuserdefaults_integerforkey_callsite",
                     evidence_label="key"),
    ObjCSelectorSpec("stringForKey:",
                     anchor_kind="nsuserdefaults_stringforkey_callsite",
                     evidence_label="key"),
    ObjCSelectorSpec("objectForKey:",
                     anchor_kind="nsuserdefaults_objectforkey_callsite",
                     evidence_label="key"),
    ObjCSelectorSpec("setBool:forKey:",
                     anchor_kind="nsuserdefaults_setboolforkey_callsite",
                     evidence_label="key"),
    ObjCSelectorSpec("setObject:forKey:",
                     anchor_kind="nsuserdefaults_setobjectforkey_callsite",
                     evidence_label="key"),
]


_BYPASS_TOKEN = re.compile(
    r"(disable|bypass|skip|allow|override|internal|debug|development|test|force|ignore)",
    re.I,
)
_DOMAIN = re.compile(r"^([A-Za-z0-9_-]+\.){2,}[A-Za-z0-9_-]+$")


def _is_bypass_key(text):
    if " " in text or "/" in text:
        return False
    if len(text) > 96 or len(text) < 4:
        return False
    return bool(_BYPASS_TOKEN.search(text))


def _is_domain(text):
    return bool(_DOMAIN.match(text))


run_string_scan(
    scan_name="scan_defaults_bypass",
    rules=[
        StringRule("C", "defaults_api_string",
                   r"(NSUserDefaults|CFPreferences|standardUserDefaults|UserDefaults|defaults\s+write)",
                   max_anchors=16, evidence_label="api"),
        StringRule("C", "defaults_key_candidate",
                   r".",
                   max_anchors=24, evidence_label="key",
                   accept=_is_bypass_key),
        StringRule("C", "defaults_domain",
                   r".",
                   max_anchors=12, evidence_label="domain",
                   accept=_is_domain),
    ],
    function_rules=[
        StringRule("B", "bypass_gate_impl",
                   r"(disable|bypass|override|force|skip|allow).{0,40}(check|validation|gate|signing|amfi|sip|enforce)",
                   max_anchors=12, evidence_label="function"),
    ],
    api_specs=API_SPECS,
    objc_specs=OBJC_SPECS,
)
