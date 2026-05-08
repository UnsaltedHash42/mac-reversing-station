# Ghidra script: scan one loaded program for launchd/MachService topology signals.
# Output TSV:
# target	listeners	mach_services	entitlement_refs	audit_token_uses	evidence

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
        try:
            return currentProgram.getName()
        except Exception:
            return "stub"


def iter_strings(limit=8000):
    try:
        listing = currentProgram.getListing()
    except Exception:
        return
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
    try:
        functions = currentProgram.getFunctionManager().getFunctions(True)
    except Exception:
        return
    for function in functions:
        try:
            yield function.getName()
        except Exception:
            continue


service_re = re.compile(r"([A-Za-z0-9_-]+\.){2,}[A-Za-z0-9_.-]+")
listener_re = re.compile(r"(NSXPCListener|xpc_connection_create_mach_service|launchctl|MachServices|bootstrap_)", re.I)
entitlement_re = re.compile(r"(com\.apple\.security|entitlement|SecTaskCopyValueForEntitlement)", re.I)
audit_re = re.compile(r"(audit[_-]?token|xpc_connection_get_audit_token|SecTask)", re.I)

strings = list(iter_strings())
functions = list(iter_function_names())
combined = strings + functions

mach_services = sorted({s for s in strings if service_re.search(s) and ("com.apple" in s or "mach" in s.lower() or "xpc" in s.lower())})
listeners = sorted({item for item in combined if listener_re.search(item)})
entitlements = sorted({item for item in combined if entitlement_re.search(item)})
audit_uses = sorted({item for item in combined if audit_re.search(item)})

evidence = []
for label, values in (
    ("services", mach_services[:6]),
    ("listeners", listeners[:5]),
    ("entitlements", entitlements[:5]),
    ("audit", audit_uses[:5]),
):
    if values:
        evidence.append("%s=%s" % (label, "|".join(values).replace("\t", " ")))

emit("target\tlisteners\tmach_services\tentitlement_refs\taudit_token_uses\tevidence")
emit(
    "%s\t%d\t%d\t%d\t%d\t%s"
    % (
        program_name(),
        len(listeners),
        len(mach_services),
        len(entitlements),
        len(audit_uses),
        "; ".join(evidence),
    )
)
