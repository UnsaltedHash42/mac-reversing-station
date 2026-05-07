# Ghidra script: scan one loaded program for user-defaults-gated security checks.
# Output TSV:
# target	type	domains	keys	bypass_strings	confidence	evidence

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


def classify_target(name):
    lowered = name.lower()
    if "launchagents" in lowered or lowered.endswith(".app"):
        return "launchagent-or-user-context"
    if "launchdaemons" in lowered or "/sbin/" in lowered or "/usr/libexec/" in lowered:
        return "launchdaemon-or-system-context"
    return "unknown"


domain_re = re.compile(r"([A-Za-z0-9_-]+\.){2,}[A-Za-z0-9_-]+")
defaults_re = re.compile(r"(NSUserDefaults|CFPreferences|defaults\s+write|standardUserDefaults|UserDefaults)", re.I)
bypass_re = re.compile(
    r"(disable|bypass|skip|allow|override|internal|debug|development|test|force|ignore)",
    re.I,
)

strings = list(iter_strings())
default_strings = [s for s in strings if defaults_re.search(s)]
bypass_strings = [s for s in strings if bypass_re.search(s)]
domains = sorted({m.group(0) for s in strings for m in domain_re.finditer(s)})
keys = sorted(
    {
        s
        for s in strings
        if bypass_re.search(s) and len(s) <= 96 and " " not in s and "/" not in s
    }
)

score = 0
score += 2 if default_strings else 0
score += 2 if keys else 0
score += 1 if domains else 0
score += 1 if bypass_strings else 0
confidence = "high" if score >= 5 else ("medium" if score >= 3 else ("low" if score else "none"))

evidence = []
if default_strings:
    evidence.append("defaults_api=%s" % "|".join(default_strings[:3]).replace("\t", " "))
if keys:
    evidence.append("keys=%s" % "|".join(keys[:5]).replace("\t", " "))
if bypass_strings:
    evidence.append("bypass=%s" % "|".join(bypass_strings[:5]).replace("\t", " "))

name = program_name()
emit("target\ttype\tdomains\tkeys\tbypass_strings\tconfidence\tevidence")
emit(
    "%s\t%s\t%d\t%d\t%d\t%s\t%s"
    % (
        name,
        classify_target(name),
        len(domains),
        len(keys),
        len(bypass_strings),
        confidence,
        "; ".join(evidence),
    )
)
