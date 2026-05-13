# Ghidra script: identify code-signing-flag and AMFI references that may
# correspond to "flags == 0" gating decisions.
#
# Tier A (decompiler-recovered callsite + literal arg):
#   csops_callsite                operation constant (arg 1, CS_OPS_*)
#   csops_audittoken_callsite     operation constant (arg 0)
#   sec_static_code_callsite      callsite address (arg is dict; record path)
#   sec_code_check_validity       flags arg (const)
#
# Recovering the csops *operation* tells the agent whether the call
# is asking for CS_OPS_STATUS, CS_OPS_ENTITLEMENTS_BLOB, etc., which
# determines whether a returned-zero flags decision is meaningful.
#
# Tier B (function-name match):
#   code_sign_check_impl    functions named *codesign* / *SecCode* /
#                           *CodeDirectory*
#   flag_check_impl         functions named *flag* / *CS_VALID* /
#                           *CS_PLATFORM_BINARY*
#
# Tier C (string heuristic):
#   code_sign_string        codesign / SecCode / CodeDirectory / csops / CS_OPS
#   flags_string            flag / CS_VALID / CS_RUNTIME / CS_PLATFORM_BINARY
#   amfi_string             AMFI / AppleMobileFileIntegrity / MISValidate
#
# @category Mach-O.CodeSigning
# @runtime PyGhidra

from _re_lib import APISpec, StringRule, run_string_scan


API_SPECS = [
    APISpec("csops", arg_index=1, recover_kind="const",
            anchor_kind="csops_callsite", evidence_label="ops"),
    APISpec("csops_audittoken", arg_index=1, recover_kind="const",
            anchor_kind="csops_audittoken_callsite", evidence_label="ops"),
    APISpec("SecStaticCodeCheckValidity", arg_index=1, recover_kind="const",
            anchor_kind="sec_static_code_check_callsite", evidence_label="flags"),
    APISpec("SecStaticCodeCheckValidityWithErrors", arg_index=1, recover_kind="const",
            anchor_kind="sec_static_code_check_callsite", evidence_label="flags"),
    APISpec("SecCodeCheckValidity", arg_index=1, recover_kind="const",
            anchor_kind="sec_code_check_callsite", evidence_label="flags"),
    APISpec("SecCodeCopyStaticCode", arg_index=1, recover_kind="const",
            anchor_kind="sec_code_copy_static_callsite", evidence_label="flags"),
]


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
    api_specs=API_SPECS,
)
