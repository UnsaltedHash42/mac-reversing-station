# Ghidra script: scan one loaded program for user-defaults-gated security checks.
#
# Tier A (callsite-verified):
#   defaults_callsite           callers of CFPreferencesCopyAppValue /
#                               NSUserDefaults boolForKey: / standardUserDefaults
#                               (resolved via name; NS selectors live in
#                               objc metadata so coverage varies by binary)
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
# @runtime Jython

import re

from _re_lib import (
    StringRule, format_addr, callers_of, find_external, run_string_scan,
)


DEFAULTS_APIS = (
    "CFPreferencesCopyAppValue",
    "CFPreferencesCopyValue",
    "CFPreferencesGetAppBooleanValue",
    "CFPreferencesGetAppIntegerValue",
)


def add_defaults_callsites(writer):
    for api in DEFAULTS_APIS:
        fn = find_external(api)
        if fn is None:
            continue
        for caller, site in callers_of(fn):
            if caller is None:
                continue
            writer.add("A", "defaults_callsite", caller.getName(),
                       format_addr(site),
                       "api=%s; site=%s" % (api, format_addr(site)))


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
                   r".",  # accept all; filter handles selectivity
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
    enrich=add_defaults_callsites,
)
