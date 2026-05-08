# Ghidra script: scan one loaded program for Endpoint Security client signals.
# Output TSV:
# target	es_client_calls	es_event_subscriptions	cache_handlers	policy_strings	evidence

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


client_re = re.compile(r"(EndpointSecurity|es_new_client|es_delete_client|es_subscribe|es_unsubscribe|es_respond_)", re.I)
event_re = re.compile(r"(ES_EVENT_TYPE_[A-Z0-9_]+|AUTH_|NOTIFY_|es_event_)", re.I)
cache_re = re.compile(r"(cache|memo|policy_cache|decision|verdict|mute|unmute)", re.I)
policy_re = re.compile(r"(policy|allow|deny|block|authorize|quarantine|remediate|trust)", re.I)

strings = list(iter_strings())
functions = list(iter_function_names())
combined = strings + functions

client_calls = sorted({item for item in combined if client_re.search(item)})
events = sorted({item for item in combined if event_re.search(item)})
cache_handlers = sorted({item for item in combined if cache_re.search(item)})
policy_strings = sorted({item for item in combined if policy_re.search(item)})

evidence = []
for label, values in (
    ("client", client_calls[:5]),
    ("events", events[:7]),
    ("cache", cache_handlers[:5]),
    ("policy", policy_strings[:5]),
):
    if values:
        evidence.append("%s=%s" % (label, "|".join(values).replace("\t", " ")))

emit("target\tes_client_calls\tes_event_subscriptions\tcache_handlers\tpolicy_strings\tevidence")
emit(
    "%s\t%d\t%d\t%d\t%d\t%s"
    % (
        program_name(),
        len(client_calls),
        len(events),
        len(cache_handlers),
        len(policy_strings),
        "; ".join(evidence),
    )
)
