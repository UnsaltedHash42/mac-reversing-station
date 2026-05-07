# Ghidra script: export lightweight function anchors for LLDB follow-up.
# Output TSV:
# target	functions	entry_points	evidence


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


anchors = []
try:
    fm = currentProgram.getFunctionManager()
    for function in fm.getFunctions(True):
        if len(anchors) >= 50:
            break
        try:
            name = function.getName()
            entry = function.getEntryPoint()
        except Exception:
            continue
        anchors.append("%s@%s" % (name, entry))
except Exception:
    anchors = []

emit("target\tfunctions\tentry_points\tevidence")
emit(
    "%s\t%d\t%d\t%s"
    % (
        program_name(),
        len(anchors),
        len(anchors),
        "|".join(anchors[:20]).replace("\t", " "),
    )
)
