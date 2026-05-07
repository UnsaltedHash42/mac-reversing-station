# Ghidra script: scan one loaded program for XPC client-validation signals.
# Output TSV:
# target	mach_services	should_accept_refs	audit_token_refs	weak_identity_refs	team_id_refs	confidence	evidence

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


def iter_function_names():
    fm = currentProgram.getFunctionManager()
    for function in fm.getFunctions(True):
        try:
            yield function.getName()
        except Exception:
            continue


mach_re = re.compile(r"(MachServices|NSXPC|xpc_|com\.[A-Za-z0-9_.-]+)", re.I)
accept_re = re.compile(r"(shouldAcceptNewConnection|listener:shouldAccept|acceptNewConnection)", re.I)
audit_re = re.compile(r"(audit[_-]?token|xpc_connection_get_audit_token|SecTask)", re.I)
weak_re = re.compile(r"(processIdentifier|pid|bundleIdentifier|executablePath|target_path|target_identifier)", re.I)
team_re = re.compile(r"(TeamIdentifier|teamid|SecCode|SecRequirement|codesign|anchor apple)", re.I)

strings = list(iter_strings())
functions = list(iter_function_names())
combined = strings + functions

mach_services = sorted({s for s in strings if mach_re.search(s)})
accept_refs = sorted({item for item in combined if accept_re.search(item)})
audit_refs = sorted({item for item in combined if audit_re.search(item)})
weak_refs = sorted({item for item in combined if weak_re.search(item)})
team_refs = sorted({item for item in combined if team_re.search(item)})

score = 0
score += 2 if mach_services else 0
score += 2 if accept_refs else 0
score += 2 if weak_refs else 0
score += 1 if audit_refs else 0
score += 1 if team_refs else 0
confidence = "high" if score >= 6 else ("medium" if score >= 3 else ("low" if score else "none"))

evidence = []
for label, values in (
    ("mach", mach_services[:4]),
    ("accept", accept_refs[:3]),
    ("audit", audit_refs[:3]),
    ("weak_identity", weak_refs[:4]),
    ("team", team_refs[:3]),
):
    if values:
        evidence.append("%s=%s" % (label, "|".join(values).replace("\t", " ")))

emit("target\tmach_services\tshould_accept_refs\taudit_token_refs\tweak_identity_refs\tteam_id_refs\tconfidence\tevidence")
emit(
    "%s\t%d\t%d\t%d\t%d\t%d\t%s\t%s"
    % (
        program_name(),
        len(mach_services),
        len(accept_refs),
        len(audit_refs),
        len(weak_refs),
        len(team_refs),
        confidence,
        "; ".join(evidence),
    )
)
