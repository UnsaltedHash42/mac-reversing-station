# Ghidra script: scan one loaded program for system/network extension surface signals.
# Output TSV:
# target	system_extension	es_subsystems	entitlement_refs	approval_strings	evidence

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


extension_re = re.compile(r"(systemextension|networkextension|DriverKit|dext|appex|OSSystemExtension)", re.I)
es_re = re.compile(r"(EndpointSecurity|es_new_client|es_subscribe|es_event_|ES_EVENT_TYPE)", re.I)
entitlement_re = re.compile(r"(com\.apple\.developer\.(system-extension|networking\.networkextension|endpoint-security)|entitlement)", re.I)
approval_re = re.compile(r"(approval|required|allowed|activated|enabled|systemextensionsctl|NEProvider)", re.I)

strings = list(iter_strings())
functions = list(iter_function_names())
combined = strings + functions

extension_refs = sorted({item for item in combined if extension_re.search(item)})
es_refs = sorted({item for item in combined if es_re.search(item)})
entitlements = sorted({item for item in combined if entitlement_re.search(item)})
approval = sorted({item for item in combined if approval_re.search(item)})

evidence = []
for label, values in (
    ("extension", extension_refs[:5]),
    ("endpoint_security", es_refs[:5]),
    ("entitlements", entitlements[:5]),
    ("approval", approval[:5]),
):
    if values:
        evidence.append("%s=%s" % (label, "|".join(values).replace("\t", " ")))

emit("target\tsystem_extension\tes_subsystems\tentitlement_refs\tapproval_strings\tevidence")
emit(
    "%s\t%d\t%d\t%d\t%d\t%s"
    % (
        program_name(),
        len(extension_refs),
        len(es_refs),
        len(entitlements),
        len(approval),
        "; ".join(evidence),
    )
)
