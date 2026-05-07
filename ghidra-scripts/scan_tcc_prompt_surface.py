# Ghidra script: scan one loaded program for TCC prompt-attribution and privacy surface signals.
# Output TSV:
# target	tcc_refs	prompt_refs	bundle_identity_refs	apple_event_refs	privacy_services	confidence	evidence

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


def iter_strings(limit=9000):
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


tcc_re = re.compile(r"(TCC|TCCAccessRequest|kTCCService|com\.apple\.TCC|tccd)", re.I)
prompt_re = re.compile(r"(prompt|consent|permission|displayName|localizedName|target_prompt)", re.I)
identity_re = re.compile(r"(bundleIdentifier|executablePath|target_identifier|target_path|SecRequirement|csreq)", re.I)
apple_event_re = re.compile(r"(AppleEvent|Apple Events|kTCCServiceAppleEvents|NSAppleEventsUsageDescription|AEDesc)", re.I)
privacy_re = re.compile(
    r"(Accessibility|ScreenCapture|ScreenRecording|Camera|Microphone|DesktopFolder|DocumentsFolder|DownloadsFolder|FullDisk|ListenEvent|PostEvent)",
    re.I,
)

strings = list(iter_strings())

tcc_refs = sorted({s for s in strings if tcc_re.search(s)})
prompt_refs = sorted({s for s in strings if prompt_re.search(s)})
identity_refs = sorted({s for s in strings if identity_re.search(s)})
apple_event_refs = sorted({s for s in strings if apple_event_re.search(s)})
privacy_services = sorted({s for s in strings if privacy_re.search(s)})

score = 0
score += 2 if tcc_refs else 0
score += 2 if prompt_refs else 0
score += 2 if identity_refs else 0
score += 1 if apple_event_refs else 0
score += 1 if privacy_services else 0
confidence = "high" if score >= 6 else ("medium" if score >= 3 else ("low" if score else "none"))

evidence = []
for label, values in (
    ("tcc", tcc_refs[:4]),
    ("prompt", prompt_refs[:4]),
    ("identity", identity_refs[:4]),
    ("apple_events", apple_event_refs[:3]),
    ("privacy", privacy_services[:4]),
):
    if values:
        evidence.append("%s=%s" % (label, "|".join(values).replace("\t", " ")))

emit("target\ttcc_refs\tprompt_refs\tbundle_identity_refs\tapple_event_refs\tprivacy_services\tconfidence\tevidence")
emit(
    "%s\t%d\t%d\t%d\t%d\t%d\t%s\t%s"
    % (
        program_name(),
        len(tcc_refs),
        len(prompt_refs),
        len(identity_refs),
        len(apple_event_refs),
        len(privacy_services),
        confidence,
        "; ".join(evidence),
    )
)
