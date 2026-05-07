# Ghidra script: scan one loaded program for wrong-door XPC entitlement patterns.
# Output TSV:
# daemon	listeners	ent_refs	should_accept_impls	audit_token_uses	evidence

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


def iter_strings(limit=5000):
    listing = currentProgram.getListing()
    seen = 0
    for data in listing.getDefinedData(True):
        if seen >= limit:
            break
        try:
            value = data.getValue()
        except Exception:
            continue
        if isinstance(value, str):
            text = value
        else:
            text = str(value) if value is not None else ""
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


listener_re = re.compile(r"(mach|xpc|listener|service|com\.apple\.)", re.I)
ent_re = re.compile(r"(entitlement|com\.apple\.private|audit[_-]?token|SecTaskCopyValueForEntitlement)", re.I)
accept_re = re.compile(r"(shouldAcceptNewConnection|listener:shouldAccept|acceptNewConnection)", re.I)
audit_re = re.compile(r"(audit[_-]?token|SecTask|responsible|effectiveUserIdentifier)", re.I)

strings = list(iter_strings())
functions = list(iter_function_names())

listeners = sorted({s for s in strings if listener_re.search(s)})
ent_refs = sorted({s for s in strings if ent_re.search(s)})
accept_impls = sorted({f for f in functions if accept_re.search(f)})
audit_uses = sorted({item for item in strings + functions if audit_re.search(item)})

evidence = []
for label, values in (
    ("listeners", listeners[:3]),
    ("ent_refs", ent_refs[:3]),
    ("accept_impls", accept_impls[:3]),
    ("audit_uses", audit_uses[:3]),
):
    if values:
        evidence.append("%s=%s" % (label, "|".join(values).replace("\t", " ")))

emit("daemon\tlisteners\tent_refs\tshould_accept_impls\taudit_token_uses\tevidence")
emit(
    "%s\t%d\t%d\t%d\t%d\t%s"
    % (
        program_name(),
        len(listeners),
        len(ent_refs),
        len(accept_impls),
        len(audit_uses),
        "; ".join(evidence),
    )
)
