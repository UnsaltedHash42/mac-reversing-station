# Ghidra script: scan one loaded program for custom URL scheme registration
# and inbound URL handling.
#
# Custom URL schemes are a classic macOS / iOS attack surface. A bundle
# claims a scheme in its Info.plist, the system routes external URLs to
# that bundle, and the bundle's `application:openURL:` (or AppKit
# `application:openURLs:`) dispatcher decides what to do with the URL.
# Bugs here come from:
#   - dispatchers that trust the URL's host or query without validation
#   - schemes that overlap with well-known iOS or Apple schemes
#   - registration via LSSetDefaultHandlerForURLScheme without prompting
#
# Tier A (decompiler-recovered callsite + literal arg):
#   ls_register_url_callsite          callsite (registers handler bundle)
#   ls_set_default_handler_callsite   scheme being claimed (arg 0, CFStringRef)
#   ls_copy_default_handler_callsite  scheme being looked up (arg 0)
#   url_with_string_callsite          URL string when constant (arg 0)
#
# Tier B (function-name match):
#   open_url_handler_impl       application:openURL: / application:openURLs: /
#                               handleURL: / handleURLEvent:
#   url_validator_impl          *validateURL / *isAllowedURL / *parseScheme
#
# Tier C (string heuristic):
#   url_scheme_string           reverse-DNS-shaped or short tokens followed
#                               by `://` in defined data
#   cfbundle_url_key_string     CFBundleURLSchemes / CFBundleURLTypes /
#                               LSHandlerContentType
#   nsappletevent_url_string    NSAppleEventManager / kAEGetURL /
#                               kInternetEventClass
#
# @category Mach-O.URLSchemes
# @runtime Jython

import re

from _re_lib import APISpec, ObjCSelectorSpec, StringRule, run_string_scan


API_SPECS = [
    APISpec("LSRegisterURL", arg_index=0, recover_kind="none",
            anchor_kind="ls_register_url_callsite"),
    APISpec("LSSetDefaultHandlerForURLScheme", arg_index=0, recover_kind="string",
            anchor_kind="ls_set_default_handler_callsite", evidence_label="scheme"),
    APISpec("LSCopyDefaultHandlerForURLScheme", arg_index=0, recover_kind="string",
            anchor_kind="ls_copy_default_handler_callsite", evidence_label="scheme"),
    APISpec("LSCopyAllHandlersForURLScheme", arg_index=0, recover_kind="string",
            anchor_kind="ls_copy_all_handlers_callsite", evidence_label="scheme"),
    APISpec("CFURLCreateWithString", arg_index=1, recover_kind="string",
            anchor_kind="cfurl_create_with_string_callsite", evidence_label="url"),
    APISpec("CFURLCreateWithBytes", arg_index=1, recover_kind="none",
            anchor_kind="cfurl_create_with_bytes_callsite"),
]

# Most URL-handler dispatch goes through ObjC. Recover the selector at
# the callsite to find every entry point and every place the bundle
# itself opens a URL.
OBJC_SPECS = [
    ObjCSelectorSpec("application:openURL:",
                     anchor_kind="application_openurl_callsite"),
    ObjCSelectorSpec("application:openURLs:",
                     anchor_kind="application_openurls_callsite"),
    ObjCSelectorSpec("application:openFile:",
                     anchor_kind="application_openfile_callsite"),
    ObjCSelectorSpec("handleURL:",
                     anchor_kind="handle_url_callsite"),
    ObjCSelectorSpec("getUrl:withReplyEvent:",
                     anchor_kind="apple_event_geturl_callsite"),
    ObjCSelectorSpec("openURL:",
                     anchor_kind="objc_openurl_callsite"),
    ObjCSelectorSpec("openURL:configuration:completionHandler:",
                     anchor_kind="workspace_openurl_callsite"),
    ObjCSelectorSpec("setEventHandler:andSelector:forEventClass:andEventID:",
                     anchor_kind="appleeventmanager_seteventhandler_callsite"),
]


_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]{1,32}://")


def _is_url_with_scheme(text):
    return bool(_SCHEME.match(text))


run_string_scan(
    scan_name="scan_url_scheme_handlers",
    rules=[
        StringRule("C", "url_scheme_string", r".",
                   max_anchors=24, evidence_label="url",
                   accept=_is_url_with_scheme),
        StringRule("C", "cfbundle_url_key_string",
                   r"(CFBundleURLSchemes|CFBundleURLTypes|CFBundleURLName|LSHandlerContentType|LSHandlerURLScheme|LSHandlerRoleAll)",
                   max_anchors=12, evidence_label="key"),
        StringRule("C", "nsappletevent_url_string",
                   r"(NSAppleEventManager|kAEGetURL|kInternetEventClass|GURLGURL|kCoreEventClass)",
                   max_anchors=12, evidence_label="string"),
    ],
    function_rules=[
        StringRule("B", "open_url_handler_impl",
                   r"(application:openURL|application:openURLs|application_openURL|handleURL:|handleURLEvent:|getUrl:withReplyEvent:)",
                   max_anchors=16, evidence_label="selector"),
        StringRule("B", "url_validator_impl",
                   r"(validateURL|isAllowedURL|parseScheme|allowedSchemes|whitelistedURL|sanitizeURL)",
                   max_anchors=12, evidence_label="function"),
    ],
    api_specs=API_SPECS,
    objc_specs=OBJC_SPECS,
)
