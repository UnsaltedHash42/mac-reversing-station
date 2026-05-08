# Ghidra script: scan one loaded program for PrivateFramework / dyld-cache dependency signals.
#
# Tier A (callsite-verified):
#   dlopen_callsite             callers of dlopen / dlsym / NSLinkModule /
#                               NSCreateObjectFileImageFromFile (dynamic lookup
#                               into shared cache or PrivateFramework)
#
# Tier B (function-name match):
#   dynamic_resolver_impl       functions named *load_*Framework / *resolve* /
#                               *dlopen / *dlsym
#
# Tier C (string heuristic):
#   private_framework_path      /System/Library/PrivateFrameworks/* paths
#   public_framework_path       /System/Library/Frameworks/* paths
#   dyld_token                  dyld shared cache / dyld_shared_cache / LC_LOAD_*
#   weak_link_token             weak link / LC_LOAD_WEAK_DYLIB / NSClassFromString
#
# @category Mach-O.PrivateFramework
# @runtime Jython

from _re_lib import (
    StringRule, format_addr, callers_of, find_external, run_string_scan,
)


DYNAMIC_LOOKUP_APIS = (
    "dlopen",
    "dlsym",
    "NSLinkModule",
    "NSCreateObjectFileImageFromFile",
    "NSLookupAndBindSymbol",
)


def add_dlopen_callsites(writer):
    for api in DYNAMIC_LOOKUP_APIS:
        fn = find_external(api)
        if fn is None:
            continue
        for caller, site in callers_of(fn):
            if caller is None:
                continue
            writer.add("A", "dlopen_callsite", caller.getName(),
                       format_addr(site),
                       "api=%s; site=%s" % (api, format_addr(site)))


run_string_scan(
    scan_name="scan_private_framework_dependency",
    rules=[
        StringRule("C", "private_framework_path",
                   r"/System/Library/PrivateFrameworks/[A-Za-z0-9_./-]+",
                   max_anchors=24, evidence_label="path"),
        StringRule("C", "public_framework_path",
                   r"/System/Library/Frameworks/[A-Za-z0-9_./-]+\.framework",
                   max_anchors=20, evidence_label="path"),
        StringRule("C", "dyld_token",
                   r"(dyld shared cache|dyld_shared_cache|LC_LOAD_DYLIB|LC_LOAD_WEAK_DYLIB)",
                   max_anchors=12, evidence_label="string"),
        StringRule("C", "weak_link_token",
                   r"(weak[_ -]?link|NSClassFromString|NSSelectorFromString)",
                   max_anchors=12, evidence_label="string"),
    ],
    function_rules=[
        StringRule("B", "dynamic_resolver_impl",
                   r"(load.{0,20}Framework|resolveSymbol|dlopen|dlsym|symbolByName)",
                   max_anchors=12, evidence_label="function"),
    ],
    enrich=add_dlopen_callsites,
)
