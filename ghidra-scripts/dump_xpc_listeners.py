# Ghidra script: dump likely XPC listener/service anchors from one loaded program.
# Output TSV:
# target	mach_services	listener_delegate_impls	xpc_strings	evidence

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


def iter_strings(limit=7000):
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


service_re = re.compile(r"^([A-Za-z0-9_-]+\.){2,}[A-Za-z0-9_.-]+$")
xpc_re = re.compile(r"(NSXPC|xpc_|XPC|mach service|MachServices|listener)", re.I)
delegate_re = re.compile(r"(shouldAcceptNewConnection|NSXPCListenerDelegate|listener:shouldAccept)", re.I)

strings = list(iter_strings())
functions = list(iter_function_names())

mach_services = sorted({s for s in strings if service_re.search(s) and ("xpc" in s.lower() or "com.apple" in s)})
xpc_strings = sorted({s for s in strings if xpc_re.search(s)})
delegate_impls = sorted({f for f in functions if delegate_re.search(f)})

evidence = []
if mach_services:
    evidence.append("mach_services=%s" % "|".join(mach_services[:8]).replace("\t", " "))
if delegate_impls:
    evidence.append("delegates=%s" % "|".join(delegate_impls[:8]).replace("\t", " "))
if xpc_strings:
    evidence.append("xpc_strings=%s" % "|".join(xpc_strings[:8]).replace("\t", " "))

emit("target\tmach_services\tlistener_delegate_impls\txpc_strings\tevidence")
emit(
    "%s\t%d\t%d\t%d\t%s"
    % (
        program_name(),
        len(mach_services),
        len(delegate_impls),
        len(xpc_strings),
        "; ".join(evidence),
    )
)
