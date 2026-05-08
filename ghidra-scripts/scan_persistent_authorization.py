# Ghidra script: scan one loaded program for persistent authorization /
# bookmark / keychain / sandbox-extension surface.
#
# Tier A (decompiler-recovered callsite + literal arg):
#   secitemadd_callsite                 callsite (arg 0 is CFDictionary; record site)
#   secitemcopymatching_callsite        callsite (arg 0 is CFDictionary)
#   seckeychainaddgenericpassword       service name (arg 1, char*)
#                                       account name (arg 3, char*) -- recover service only
#   seckeychainfindgenericpassword      service name (arg 1)
#   urlbookmarkdata_callsite            options (arg 1, const)
#   sandbox_extension_consume_callsite  extension token (arg 0, char*)
#   sandbox_extension_issue_file        path (arg 0, char*) and class (arg 1)
#
# The string args here name the *named resource* the binary is asking
# about (keychain service, sandbox-extension path) -- exactly what
# the persistent-authorization hunt cares about.
#
# Tier B (function-name match):
#   bookmark_handler            functions named *bookmark* / *startAccessing*
#   sandbox_extension_handler   functions named *extension* / *consume* / *issue*
#
# Tier C (string heuristic):
#   bookmark_string             security-scoped / ScopedBookmark / bookmark tokens
#   keychain_string             SecItem / kSecClass / Keychain / kSecAttr*
#   sandbox_string              com.apple.security.app-sandbox / extension / consume
#   container_string            Group Containers / Application Scripts / Application Support
#
# @category Mach-O.PersistentAuthorization
# @runtime Jython

from _re_lib import APISpec, StringRule, run_string_scan


API_SPECS = [
    APISpec("SecItemAdd", arg_index=0, recover_kind="none",
            anchor_kind="secitemadd_callsite"),
    APISpec("SecItemCopyMatching", arg_index=0, recover_kind="none",
            anchor_kind="secitemcopymatching_callsite"),
    APISpec("SecItemUpdate", arg_index=0, recover_kind="none",
            anchor_kind="secitemupdate_callsite"),
    APISpec("SecKeychainAddGenericPassword", arg_index=1, recover_kind="string",
            anchor_kind="seckeychainadd_callsite", evidence_label="service"),
    APISpec("SecKeychainFindGenericPassword", arg_index=1, recover_kind="string",
            anchor_kind="seckeychainfind_callsite", evidence_label="service"),
    APISpec("CFURLCreateBookmarkData", arg_index=2, recover_kind="const",
            anchor_kind="bookmark_create_callsite", evidence_label="options"),
    APISpec("CFURLCreateByResolvingBookmarkData", arg_index=2, recover_kind="const",
            anchor_kind="bookmark_resolve_callsite", evidence_label="options"),
    APISpec("sandbox_extension_consume", arg_index=0, recover_kind="string",
            anchor_kind="sandbox_extension_consume_callsite", evidence_label="token"),
    APISpec("sandbox_extension_issue_file", arg_index=0, recover_kind="string",
            anchor_kind="sandbox_extension_issue_callsite", evidence_label="path"),
    APISpec("sandbox_extension_release", arg_index=0, recover_kind="const",
            anchor_kind="sandbox_extension_release_callsite", evidence_label="handle"),
]


run_string_scan(
    scan_name="scan_persistent_authorization",
    rules=[
        StringRule("C", "bookmark_string",
                   r"(bookmark|security.?scoped|startAccessingSecurityScopedResource|ScopedBookmark)",
                   max_anchors=16, evidence_label="string"),
        StringRule("C", "keychain_string",
                   r"(SecItem|kSecClass|Keychain|kSecAttrAccessGroup|kSecAttrService|ACL)",
                   max_anchors=16, evidence_label="string"),
        StringRule("C", "sandbox_string",
                   r"(sandbox|com\.apple\.security\.app-sandbox|consume|issue_extension)",
                   max_anchors=16, evidence_label="string"),
        StringRule("C", "container_string",
                   r"(Group Containers|Application Scripts|Application Support|NSUserDefaults|CFPreferences)",
                   max_anchors=12, evidence_label="string"),
    ],
    function_rules=[
        StringRule("B", "bookmark_handler",
                   r"(bookmark|startAccessing|stopAccessing|resolveBookmark)",
                   max_anchors=12, evidence_label="function"),
        StringRule("B", "sandbox_extension_handler",
                   r"(extension|consume|issue_extension|sandbox_extension)",
                   max_anchors=12, evidence_label="function"),
    ],
    api_specs=API_SPECS,
)
