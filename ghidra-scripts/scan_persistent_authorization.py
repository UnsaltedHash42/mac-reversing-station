# Ghidra script: scan one loaded program for persistent authorization /
# bookmark / keychain / sandbox-extension surface.
#
# Tier A (callsite-verified):
#   keychain_callsite           callers of SecItemAdd / SecItemCopyMatching /
#                               SecKeychainAddGenericPassword
#   bookmark_callsite           callers of CFURLCreateBookmarkData /
#                               URLByResolvingBookmarkData
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

from _re_lib import (
    StringRule, format_addr, callers_of, find_external, run_string_scan,
)


KEYCHAIN_APIS = (
    "SecItemAdd",
    "SecItemCopyMatching",
    "SecItemUpdate",
    "SecKeychainAddGenericPassword",
    "SecKeychainFindGenericPassword",
)

BOOKMARK_APIS = (
    "CFURLCreateBookmarkData",
    "CFURLCreateByResolvingBookmarkData",
    "URLByResolvingBookmarkData",
    "bookmarkDataWithOptions",
)


def add_callsites(writer):
    for api in KEYCHAIN_APIS:
        fn = find_external(api)
        if fn is None:
            continue
        for caller, site in callers_of(fn):
            if caller is None:
                continue
            writer.add("A", "keychain_callsite", caller.getName(),
                       format_addr(site),
                       "api=%s; site=%s" % (api, format_addr(site)))
    for api in BOOKMARK_APIS:
        fn = find_external(api)
        if fn is None:
            continue
        for caller, site in callers_of(fn):
            if caller is None:
                continue
            writer.add("A", "bookmark_callsite", caller.getName(),
                       format_addr(site),
                       "api=%s; site=%s" % (api, format_addr(site)))


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
    enrich=add_callsites,
)
