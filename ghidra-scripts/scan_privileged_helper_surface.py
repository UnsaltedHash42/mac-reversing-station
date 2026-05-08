# Ghidra script: scan one loaded program for privileged-helper / updater surface.
#
# Tier A (callsite-verified):
#   authorization_callsite      callers of AuthorizationCreate /
#                               AuthorizationCopyRights /
#                               AuthorizationExecuteWithPrivileges / SMJobBless
#   exec_callsite               callers of system / popen / posix_spawn /
#                               execve / execvp
#
# Tier B (function-name match):
#   helper_install_impl         install/upgrade/bless * helper/service/daemon
#   privileged_op_impl          *privileged / *elevate / *withPrivileges / setuid
#
# Tier C (string heuristic):
#   helper_string               com.apple.SMJobBless.* / *PrivilegedHelperTools / *.helper
#   launchd_string              LaunchDaemons / LaunchAgents / launchctl
#   authz_string                authorization right / com.apple.* right names
#   install_string              install / update / patch / bless tokens
#
# @category Mach-O.PrivilegedHelpers
# @runtime Jython

from _re_lib import (
    StringRule, format_addr, callers_of, find_external, run_string_scan,
)


AUTHORIZATION_APIS = (
    "AuthorizationCreate",
    "AuthorizationCopyRights",
    "AuthorizationExecuteWithPrivileges",
    "AuthorizationRightSet",
    "SMJobBless",
    "SMJobSubmit",
)

EXEC_APIS = (
    "system",
    "popen",
    "execve",
    "execvp",
    "execv",
    "posix_spawn",
    "posix_spawnp",
)


def add_callsites(writer):
    for api in AUTHORIZATION_APIS:
        fn = find_external(api)
        if fn is None:
            continue
        for caller, site in callers_of(fn):
            if caller is None:
                continue
            writer.add("A", "authorization_callsite", caller.getName(),
                       format_addr(site),
                       "api=%s; site=%s" % (api, format_addr(site)))
    for api in EXEC_APIS:
        fn = find_external(api)
        if fn is None:
            continue
        for caller, site in callers_of(fn):
            if caller is None:
                continue
            writer.add("A", "exec_callsite", caller.getName(),
                       format_addr(site),
                       "api=%s; site=%s" % (api, format_addr(site)))


run_string_scan(
    scan_name="scan_privileged_helper_surface",
    rules=[
        StringRule("C", "helper_string",
                   r"(com\.apple\.SMJobBless|PrivilegedHelperTools|\.helper$|HelperTool)",
                   max_anchors=20, evidence_label="string"),
        StringRule("C", "launchd_string",
                   r"(LaunchDaemons|LaunchAgents|launchctl|launchd\.plist|MachServices|KeepAlive|ProgramArguments)",
                   max_anchors=16, evidence_label="string"),
        StringRule("C", "authz_string",
                   r"(authorization right|com\.apple\.[A-Za-z0-9_.-]+\.right|SecAuthorization|rightName)",
                   max_anchors=16, evidence_label="string"),
        StringRule("C", "install_string",
                   r"(install|update|upgrade|patch|bless|Sparkle|SUUpdater)",
                   max_anchors=12, evidence_label="string",
                   accept=lambda s: " " not in s and len(s) <= 96),
    ],
    function_rules=[
        StringRule("B", "helper_install_impl",
                   r"(install|upgrade|update|bless|register).{0,40}(helper|service|plist|daemon|agent)",
                   max_anchors=12, evidence_label="function"),
        StringRule("B", "privileged_op_impl",
                   r"(privileged|elevate|asRoot|withPrivileges|setuid|setgid|chown|chmod)",
                   max_anchors=12, evidence_label="function"),
    ],
    enrich=add_callsites,
)
