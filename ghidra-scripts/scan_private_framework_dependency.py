# Ghidra script: scan one loaded program for PrivateFramework and dyld-cache dependency signals.
# Output TSV:
# target	framework_deps	private_framework_refs	dyld_cache_origin	weak_links	evidence

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


def iter_strings(limit=9000):
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


framework_re = re.compile(r"(/System/Library/(?:Private)?Frameworks/[^ \t\n]+\.framework[^ \t\n]*)", re.I)
private_re = re.compile(r"/System/Library/PrivateFrameworks/[^ \t\n]+", re.I)
dyld_re = re.compile(r"(dyld shared cache|dyld_shared_cache|__TEXT|LC_LOAD_DYLIB|LC_LOAD_WEAK_DYLIB)", re.I)
weak_re = re.compile(r"(weak[_ -]?link|LC_LOAD_WEAK_DYLIB|NSClassFromString|dlsym|dlopen)", re.I)

strings = list(iter_strings())
functions = list(iter_function_names())
combined = strings + functions

frameworks = sorted({match.group(1) for item in strings for match in framework_re.finditer(item)})
private_refs = sorted({item for item in strings if private_re.search(item)})
dyld_refs = sorted({item for item in combined if dyld_re.search(item)})
weak_links = sorted({item for item in combined if weak_re.search(item)})

evidence = []
for label, values in (
    ("frameworks", frameworks[:6]),
    ("private", private_refs[:6]),
    ("dyld", dyld_refs[:5]),
    ("weak", weak_links[:5]),
):
    if values:
        evidence.append("%s=%s" % (label, "|".join(values).replace("\t", " ")))

emit("target\tframework_deps\tprivate_framework_refs\tdyld_cache_origin\tweak_links\tevidence")
emit(
    "%s\t%d\t%d\t%d\t%d\t%s"
    % (
        program_name(),
        len(frameworks),
        len(private_refs),
        len(dyld_refs),
        len(weak_links),
        "; ".join(evidence),
    )
)
