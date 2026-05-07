# Ghidra script: scan one loaded program for Catalyst/platform-conditional bypass strings.
# Output TSV:
# target	catalyst_refs	platform_checks	entitlement_refs	bypass_refs	confidence	evidence

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


catalyst_re = re.compile(r"(catalyst|MacCatalyst|is-catalyst-binary|isiOSAppOnMac)", re.I)
platform_re = re.compile(r"(platform|targetEnvironment|macos|iphone|ipad|ios|non macos|isMac)", re.I)
ent_re = re.compile(r"(entitlement|com\.apple\.private|SecTaskCopyValueForEntitlement)", re.I)
bypass_re = re.compile(r"(bypass|skip|allow.*catalyst|non macos|exempt|legacy|compat)", re.I)

strings = list(iter_strings())
catalyst = sorted({s for s in strings if catalyst_re.search(s)})
platform = sorted({s for s in strings if platform_re.search(s)})
entitlements = sorted({s for s in strings if ent_re.search(s)})
bypasses = sorted({s for s in strings if bypass_re.search(s)})

score = 0
score += 2 if catalyst else 0
score += 1 if platform else 0
score += 2 if entitlements else 0
score += 1 if bypasses else 0
confidence = "high" if score >= 5 else ("medium" if score >= 3 else ("low" if score else "none"))

evidence = []
for label, values in (
    ("catalyst", catalyst[:4]),
    ("platform", platform[:4]),
    ("entitlements", entitlements[:4]),
    ("bypasses", bypasses[:4]),
):
    if values:
        evidence.append("%s=%s" % (label, "|".join(values).replace("\t", " ")))

emit("target\tcatalyst_refs\tplatform_checks\tentitlement_refs\tbypass_refs\tconfidence\tevidence")
emit(
    "%s\t%d\t%d\t%d\t%d\t%s\t%s"
    % (
        program_name(),
        len(catalyst),
        len(platform),
        len(entitlements),
        len(bypasses),
        confidence,
        "; ".join(evidence),
    )
)
