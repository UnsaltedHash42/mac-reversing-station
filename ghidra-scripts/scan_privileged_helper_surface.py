# Ghidra script: scan one loaded program for privileged helper/updater surface signals.
# Output TSV:
# target	helpers	launchd_refs	authz_refs	install_refs	privileged_ops	confidence	evidence

import re


def emit(line):
    try:
        println(line)
    except NameError:
        print(line)


def program_name():
    try:
        return currentProgram.getExecutablePath() or currentProgram.getName()
    except Exception:
        return currentProgram.getName()


def iter_strings(limit=8000):
    listing = currentProgram.getListing()
    seen = 0
    for data in listing.getDefinedData(True):
        if seen >= limit:
            break
        try:
            value = data.getValue()
        except Exception:
            continue
        text = value if isinstance(value, str) else (str(value) if value is not None else "")
        if len(text) < 3:
            continue
        seen += 1
        yield text


helper_re = re.compile(r"(helper|privileged|daemon|LaunchServices|SMJobBless|com\.[A-Za-z0-9_.-]+\.helper)", re.I)
launchd_re = re.compile(r"(LaunchDaemon|LaunchAgent|MachServices|KeepAlive|ProgramArguments)", re.I)
authz_re = re.compile(r"(AuthorizationCreate|AuthorizationCopyRights|AuthorizationExecute|SecAuthorization|rightName)", re.I)
install_re = re.compile(r"(install|installer|pkg|package|update|Sparkle|SUUpdater|Autoupdate|download)", re.I)
privop_re = re.compile(r"(chown|chmod|setuid|root|sudo|removeItem|copyItem|moveItem|NSTask|posix_spawn|launchctl)", re.I)

strings = list(iter_strings())

helpers = sorted({s for s in strings if helper_re.search(s)})
launchd = sorted({s for s in strings if launchd_re.search(s)})
authz = sorted({s for s in strings if authz_re.search(s)})
install = sorted({s for s in strings if install_re.search(s)})
privops = sorted({s for s in strings if privop_re.search(s)})

score = 0
score += 2 if helpers else 0
score += 2 if launchd else 0
score += 2 if authz else 0
score += 1 if install else 0
score += 1 if privops else 0
confidence = "high" if score >= 6 else ("medium" if score >= 3 else ("low" if score else "none"))

evidence = []
for label, values in (
    ("helpers", helpers[:4]),
    ("launchd", launchd[:3]),
    ("authz", authz[:3]),
    ("install", install[:4]),
    ("privops", privops[:4]),
):
    if values:
        evidence.append("%s=%s" % (label, "|".join(values).replace("\t", " ")))

emit("target\thelpers\tlaunchd_refs\tauthz_refs\tinstall_refs\tprivileged_ops\tconfidence\tevidence")
emit(
    "%s\t%d\t%d\t%d\t%d\t%d\t%s\t%s"
    % (
        program_name(),
        len(helpers),
        len(launchd),
        len(authz),
        len(install),
        len(privops),
        confidence,
        "; ".join(evidence),
    )
)
