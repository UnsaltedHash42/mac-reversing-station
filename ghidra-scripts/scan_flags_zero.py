# Ghidra script: identify code-signing-flag and AMFI references that may
# correspond to "flags == 0" gating decisions.
#
# Tier A (callsite-verified):
#   csops_callsite              callers of csops / csops_audittoken
#
# Tier B (function-name match):
#   code_sign_check_impl        functions named *codesign* / *SecCode* /
#                               *CodeDirectory*
#   flag_check_impl             functions named *flag* / *CS_VALID* /
#                               *CS_PLATFORM_BINARY*
#
# Tier C (string heuristic):
#   code_sign_string            codesign / SecCode / CodeDirectory / csops / CS_OPS
#   flags_string                flag / CS_VALID / CS_RUNTIME / CS_PLATFORM_BINARY
#   amfi_string                 AMFI / AppleMobileFileIntegrity / MISValidate
#
# @category Mach-O.CodeSigning
# @runtime Jython

from _re_lib import (
    StringRule, format_addr, callers_of, find_external, run_string_scan,
)


CSOPS_APIS = (
    "csops",
    "csops_audittoken",
)


def add_csops_callsites(writer):
    for api in CSOPS_APIS:
        fn = find_external(api)
        if fn is None:
            continue
        for caller, site in callers_of(fn):
            if caller is None:
                continue
            writer.add("A", "csops_callsite", caller.getName(),
                       format_addr(site),
                       "api=%s; site=%s" % (api, format_addr(site)))


run_string_scan(
    scan_name="scan_flags_zero",
    rules=[
        StringRule("C", "code_sign_string",
                   r"(codesign|code.?sign|SecCode|SecStaticCode|CodeDirectory|csops|CS_OPS)",
                   max_anchors=20, evidence_label="string"),
        StringRule("C", "flags_string",
                   r"(CS_VALID|CS_RUNTIME|CS_PLATFORM_BINARY|CS_HARD|CS_KILL|flags?\s*[=:]\s*0x?0)",
                   max_anchors=16, evidence_label="string"),
        StringRule("C", "amfi_string",
                   r"(amfi|AppleMobileFileIntegrity|MISValidate|MobileFileIntegrity)",
                   max_anchors=12, evidence_label="string"),
    ],
    function_rules=[
        StringRule("B", "code_sign_check_impl",
                   r"(codesign|SecCode|CodeDirectory|signingIdentity|signedRequirement)",
                   max_anchors=12, evidence_label="function"),
        StringRule("B", "flag_check_impl",
                   r"(CS_VALID|CS_PLATFORM_BINARY|cs_flags|csflags)",
                   max_anchors=12, evidence_label="function"),
    ],
    enrich=add_csops_callsites,
)
