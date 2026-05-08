# Ghidra script: dump implementations of named ObjC selectors / protocols.
#
# Walks ObjC class metadata, finds methods whose selector matches one of a
# set of selectors of interest, and emits one tier-A row per implementation.
# Optionally also finds objc_msgSend callsites for those selectors so you
# get both the implementor side and every caller.
#
# Edit SELECTORS / SELECTOR_GROUPS below to match the protocol you care
# about. The defaults cover the high-yield selectors in macOS RE:
#
#   - NSXPCListenerDelegate's accept methods
#   - URL-handler entry points (NSApplicationDelegate openURL family,
#     getUrl:withReplyEvent: for Apple Events)
#   - Sandbox extension consume / issue selectors
#   - Common authorization-prompt UI selectors
#
# @category Mach-O.ObjC
# @runtime Jython

from _re_lib import (
    AnchorWriter, DecompCache, ObjCSelectorSpec, format_addr,
    enrich_objc_msgsend, recover_string_at,
)


SELECTOR_GROUPS = {
    "xpc_delegate": [
        "listener:shouldAcceptNewConnection:",
        "listener:shouldAcceptConnection:",
        "connection:shouldAcceptConnection:",
    ],
    "url_handler": [
        "application:openURL:",
        "application:openURLs:",
        "application:openFile:",
        "application:openFiles:",
        "handleURL:",
        "handleURLEvent:",
        "getUrl:withReplyEvent:",
    ],
    "url_lookup": [
        "openURL:",
        "openURL:configuration:completionHandler:",
        "openURLs:withApplicationAtURL:configuration:completionHandler:",
    ],
    "auth_prompt": [
        "authorize:",
        "authorizeWithRights:flags:environment:authorizedRights:",
        "evaluateWithError:reply:",
        "evaluatePolicy:localizedReason:reply:",
    ],
    "sandbox_extension": [
        "consumeExtension:",
        "issueExtensionForFile:",
        "issueExtensionForURL:options:",
    ],
    "tcc_prompt": [
        "requestAccessForMediaType:completionHandler:",
        "requestAccessWithCompletionHandler:",
    ],
}

# Flatten into one selector list. Edit this script's source to focus on
# a subset for big binaries.
SELECTORS = [s for group in SELECTOR_GROUPS.values() for s in group]


def walk_objc_methods():
    """Yield (class_name, selector, entry_address) for every ObjC method."""
    fm = currentProgram.getFunctionManager()
    for fn in fm.getFunctions(True):
        try:
            parent = fn.getParentNamespace()
        except Exception:
            continue
        if parent is None:
            continue
        parent_name = parent.getName()
        if parent_name in (None, "", "Global"):
            continue
        if " " in parent_name:
            continue
        try:
            yield (parent_name, fn.getName(), fn.getEntryPoint())
        except Exception:
            continue


def group_for_selector(sel):
    for name, members in SELECTOR_GROUPS.items():
        if sel in members:
            return name
    return "other"


def main():
    writer = AnchorWriter("dump_objc_protocols")

    # Implementor side: classes that implement these selectors.
    selector_set = set(SELECTORS)
    impl_count = 0
    for cls, sel, addr in walk_objc_methods():
        if sel in selector_set:
            writer.add(
                "A", "objc_method_impl",
                "%s.%s" % (cls, sel),
                format_addr(addr),
                "selector=%s; group=%s; class=%s"
                % (sel, group_for_selector(sel), cls),
            )
            impl_count += 1

    # Caller side: objc_msgSend callsites that pass these selectors.
    cache = DecompCache()
    try:
        specs = [ObjCSelectorSpec(sel,
                                  anchor_kind="objc_msgsend_caller",
                                  evidence_label="selector")
                 for sel in SELECTORS]
        enrich_objc_msgsend(writer, specs, decomp_cache=cache)
    finally:
        cache.dispose()

    writer.warn("implementations=%d selectors=%d" % (impl_count, len(SELECTORS)))
    writer.flush()


main()
