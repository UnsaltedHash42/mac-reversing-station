# Ghidra script: scan one loaded program for privileged-helper / updater surface.
#
# Tier A (decompiler-recovered callsite + literal arg):
#   AuthorizationCopyRights_callsite     right name (arg 1, AuthorizationItemSet*)
#                                        not directly recoverable; we capture
#                                        the callsite and the rights-set address
#   AuthorizationCreate_callsite         flags arg
#   AuthorizationExecuteWithPrivileges_  exec'd path (arg 1)
#   SMJobBless_callsite                  service label (arg 1, CFStringRef)
#   SMJobSubmit_callsite                 job label (arg 2 dict; we record callsite)
#   posix_spawn_callsite                 path (arg 1, char*)
#   execve_callsite                      path (arg 0, char*)
#   system_callsite                      command (arg 0, char*)
#   popen_callsite                       command (arg 0, char*)
#
# Tier B (function-name match):
#   helper_install_impl     install/upgrade/bless * helper/service/daemon
#   privileged_op_impl      *privileged / *elevate / *withPrivileges / setuid
#
# Tier C (string heuristic):
#   helper_string           com.apple.SMJobBless.* / *PrivilegedHelperTools / *.helper
#   launchd_string          LaunchDaemons / LaunchAgents / launchctl
#   authz_string            authorization right / com.apple.* right names
#   install_string          install / update / patch / bless tokens
#
# @category Mach-O.PrivilegedHelpers
# @runtime Jython

from _re_lib import APISpec, StringRule, run_string_scan


API_SPECS = [
    APISpec("SMJobBless", arg_index=1, recover_kind="string",
            anchor_kind="smjobbless_callsite", evidence_label="label"),
    APISpec("SMJobSubmit", arg_index=2, recover_kind="none",
            anchor_kind="smjobsubmit_callsite"),
    APISpec("AuthorizationCreate", arg_index=2, recover_kind="const",
            anchor_kind="authcreate_callsite", evidence_label="flags"),
    APISpec("AuthorizationCopyRights", arg_index=2, recover_kind="const",
            anchor_kind="authcopyrights_callsite", evidence_label="flags"),
    APISpec("AuthorizationExecuteWithPrivileges", arg_index=1, recover_kind="string",
            anchor_kind="authexec_callsite", evidence_label="path"),
    APISpec("AuthorizationRightSet", arg_index=1, recover_kind="string",
            anchor_kind="rightset_callsite", evidence_label="right"),
    APISpec("system", arg_index=0, recover_kind="string",
            anchor_kind="exec_system_callsite", evidence_label="cmd"),
    APISpec("popen", arg_index=0, recover_kind="string",
            anchor_kind="exec_popen_callsite", evidence_label="cmd"),
    APISpec("execve", arg_index=0, recover_kind="string",
            anchor_kind="exec_execve_callsite", evidence_label="path"),
    APISpec("execvp", arg_index=0, recover_kind="string",
            anchor_kind="exec_execvp_callsite", evidence_label="path"),
    APISpec("posix_spawn", arg_index=1, recover_kind="string",
            anchor_kind="exec_posix_spawn_callsite", evidence_label="path"),
    APISpec("posix_spawnp", arg_index=1, recover_kind="string",
            anchor_kind="exec_posix_spawnp_callsite", evidence_label="path"),
]


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
    api_specs=API_SPECS,
)
