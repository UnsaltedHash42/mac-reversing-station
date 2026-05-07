# Ghidra script: scan one loaded program for persistent authorization and bookmark signals.
# Output TSV:
# target	bookmark_refs	keychain_refs	container_store_refs	sandbox_refs	file_access_refs	confidence	evidence

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


bookmark_re = re.compile(r"(bookmark|security.?scoped|startAccessingSecurityScopedResource|ScopedBookmark)", re.I)
keychain_re = re.compile(r"(SecItem|kSecClass|Keychain|kSecAttrAccessGroup|kSecAttrService|ACL)", re.I)
container_re = re.compile(r"(Container|Application Scripts|Group Containers|Application Support|\.plist|NSUserDefaults|CFPreferences)", re.I)
sandbox_re = re.compile(r"(sandbox|extension|com\.apple\.security\.app-sandbox|consume|issue_extension)", re.I)
file_re = re.compile(r"(NSOpenPanel|NSSavePanel|fileURL|URLByResolvingBookmarkData|read|write|copyItem|moveItem)", re.I)

strings = list(iter_strings())

bookmarks = sorted({s for s in strings if bookmark_re.search(s)})
keychain = sorted({s for s in strings if keychain_re.search(s)})
containers = sorted({s for s in strings if container_re.search(s)})
sandbox = sorted({s for s in strings if sandbox_re.search(s)})
file_access = sorted({s for s in strings if file_re.search(s)})

score = 0
score += 2 if bookmarks else 0
score += 2 if keychain else 0
score += 1 if containers else 0
score += 1 if sandbox else 0
score += 1 if file_access else 0
confidence = "high" if score >= 5 else ("medium" if score >= 3 else ("low" if score else "none"))

evidence = []
for label, values in (
    ("bookmarks", bookmarks[:4]),
    ("keychain", keychain[:4]),
    ("containers", containers[:4]),
    ("sandbox", sandbox[:4]),
    ("file", file_access[:4]),
):
    if values:
        evidence.append("%s=%s" % (label, "|".join(values).replace("\t", " ")))

emit("target\tbookmark_refs\tkeychain_refs\tcontainer_store_refs\tsandbox_refs\tfile_access_refs\tconfidence\tevidence")
emit(
    "%s\t%d\t%d\t%d\t%d\t%d\t%s\t%s"
    % (
        program_name(),
        len(bookmarks),
        len(keychain),
        len(containers),
        len(sandbox),
        len(file_access),
        confidence,
        "; ".join(evidence),
    )
)
