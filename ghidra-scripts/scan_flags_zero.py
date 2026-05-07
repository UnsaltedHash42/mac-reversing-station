# Ghidra script: identify likely Mach-O code-signing flag references and zero-flag checks.
# Output TSV:
# target	code_sign_refs	flags_zero_refs	amfi_refs	confidence	evidence

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


code_sign_re = re.compile(r"(codesign|code.?sign|SecCode|SecStaticCode|CodeDirectory|csops|CS_OPS)", re.I)
zero_re = re.compile(r"(flags?\s*[=:]\s*0x?0|CS_VALID|CS_RUNTIME|CS_PLATFORM_BINARY|flag)", re.I)
amfi_re = re.compile(r"(amfi|AppleMobileFileIntegrity|MISValidate|MobileFileIntegrity)", re.I)

items = list(iter_strings()) + list(iter_function_names())
code_sign = sorted({item for item in items if code_sign_re.search(item)})
flags_zero = sorted({item for item in items if zero_re.search(item)})
amfi = sorted({item for item in items if amfi_re.search(item)})

score = 0
score += 2 if code_sign else 0
score += 2 if flags_zero else 0
score += 1 if amfi else 0
confidence = "high" if score >= 4 else ("medium" if score >= 2 else ("low" if score else "none"))

evidence = []
for label, values in (
    ("code_sign", code_sign[:5]),
    ("flags_zero", flags_zero[:5]),
    ("amfi", amfi[:5]),
):
    if values:
        evidence.append("%s=%s" % (label, "|".join(values).replace("\t", " ")))

emit("target\tcode_sign_refs\tflags_zero_refs\tamfi_refs\tconfidence\tevidence")
emit(
    "%s\t%d\t%d\t%d\t%s\t%s"
    % (
        program_name(),
        len(code_sign),
        len(flags_zero),
        len(amfi),
        confidence,
        "; ".join(evidence),
    )
)
