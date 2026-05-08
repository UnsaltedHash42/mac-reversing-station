# Ghidra script: scan one loaded program for PrivateFramework / dyld-cache dependency signals.
#
# Tier A (decompiler-recovered callsite + literal arg):
#   dlopen_callsite                 path or framework name (arg 0)
#   dlsym_callsite                  symbol name (arg 1)
#   nsclassfromstring_callsite      class name (arg 0)
#   nsselectorfromstring_callsite   selector (arg 0)
#   nslinkmodule_callsite           file path (arg 0)
#
# Recovering the dlopen path tells the agent whether this is a clean
# weak link to a public framework, or a runtime lookup into a Private-
# Framework / @rpath-relative path that an attacker might be able to
# influence (the dylib-hijack story).
#
# Tier B (function-name match):
#   dynamic_resolver_impl   functions named *load_*Framework / *resolve* /
#                           *dlopen / *dlsym
#
# Tier C (string heuristic):
#   private_framework_path  /System/Library/PrivateFrameworks/* paths
#   public_framework_path   /System/Library/Frameworks/* paths
#   dyld_token              dyld shared cache / dyld_shared_cache / LC_LOAD_*
#   weak_link_token         weak link / LC_LOAD_WEAK_DYLIB / NSClassFromString
#
# @category Mach-O.PrivateFramework
# @runtime Jython

from _re_lib import APISpec, StringRule, run_string_scan


API_SPECS = [
    APISpec("dlopen", arg_index=0, recover_kind="string",
            anchor_kind="dlopen_callsite", evidence_label="path"),
    APISpec("dlopen_preflight", arg_index=0, recover_kind="string",
            anchor_kind="dlopen_preflight_callsite", evidence_label="path"),
    APISpec("dlsym", arg_index=1, recover_kind="string",
            anchor_kind="dlsym_callsite", evidence_label="symbol"),
    APISpec("NSClassFromString", arg_index=0, recover_kind="string",
            anchor_kind="nsclassfromstring_callsite", evidence_label="class"),
    APISpec("NSSelectorFromString", arg_index=0, recover_kind="string",
            anchor_kind="nsselectorfromstring_callsite", evidence_label="selector"),
    APISpec("NSLinkModule", arg_index=0, recover_kind="string",
            anchor_kind="nslinkmodule_callsite", evidence_label="path"),
    APISpec("NSCreateObjectFileImageFromFile", arg_index=0, recover_kind="string",
            anchor_kind="nscreateofifromfile_callsite", evidence_label="path"),
]


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
    api_specs=API_SPECS,
)
