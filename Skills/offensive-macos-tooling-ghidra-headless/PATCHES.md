# Downstream patches to `ghidra-headless-mcp`

Patches the station carries on top of the upstream pin
(`mrphrazer/ghidra-headless-mcp @ b9c491a6383dbc68c581e7fed16341ac47e7faba`).
Each patch has a short problem statement, the fix, and where the live copy
runs so an operator can decide whether to keep carrying it or upstream it.

---

## `pyghidra-script-stdout.patch`

**Problem.** When a PyGhidra script calls `print()` or `println()` from
inside the top-level script file, Ghidra wraps those calls via the
`PyGhidraScript` globals dict and the Java `ScriptControls` captures the
output. That captured text is what `ghidra_script`'s `stdout_text` /
`stderr_text` returns to the MCP client.

`print()` from an **imported module** does not go through that wrapper —
it writes to the real `sys.stdout` of the backend process, and the MCP
client sees empty `stdout_text`.

This shows up any time a helper library (the station's `_re_lib.emit`
falls back to a bare `print(line)` when Ghidra's `println` is not
bound into the module) emits the scan's primary output. The MCP client
reports "empty TSV" even though the scan ran correctly and wrote to
the real stdout.

**Fix.** Wrap the `ghidra_script` call in `redirect_stdout` /
`redirect_stderr`, then concatenate the captured Python output onto
Ghidra's `stdout_text` / `stderr_text` before returning.

**Where it lives.** Lab host editable install at
`/Users/<remote-user>/tools/ghidra-headless-mcp/ghidra_headless_mcp/backend.py`.
The patch is `pyghidra-script-stdout.patch` in this directory (unified
diff rooted at the `ghidra-headless-mcp` repo — `patch -p1 < ...`).

**Applies against.** Pinned commit `b9c491a6383dbc68c581e7fed16341ac47e7faba`.
Touches ~30 lines inside the `ghidra_script` method of the
`GhidraBackend` class. Required imports (`io`, `redirect_stdout`,
`redirect_stderr`) are already present upstream; the patch does not
add new imports.

**Operator actions.**
1. Reapply on any new lab host after `scripts/install-ghidra-host.sh`
   clones the upstream pin.
2. Candidate for upstreaming to `mrphrazer/ghidra-headless-mcp` — the
   fix is generic and not station-specific.
3. If upstreamed, remove this patch and bump the commit pin in
   `scripts/install-ghidra-host.sh`.

**Interaction with `_re_lib`.** This backend patch is one half of the
fix for empty-TSV scans; the other half is the
`_bind_ghidra_globals_from_caller()` call stack walker in
`ghidra-scripts/_re_lib.py`. Without the `_re_lib` fix, imported
modules raise `NameError` on `currentProgram` under PyGhidra. Without
the backend patch, even a `_re_lib` that correctly writes through
`println` is safe, but any imported-module fallback to bare `print`
still gets lost. Carry both together.

---

## `pid-tagging-and-shutdown.patch`

**Problem.** PASS-001 stopped because a prior Claude Code session crashed
while its `ghidra-headless-mcp` subprocess held an exclusive `.lock` on a
Ghidra project. The zombie MCP process kept the lock; the next session's
`project.program.open_existing` failed with `LockException` even with
`read_only=true`. Worse, when the operator tried to clean up, both live
and zombie MCPs looked identical in `ps` output and the wrong PID got
killed, disconnecting the active MCP mid-session. Closes
SHAKEDOWN_NOTES.md items #24/#25.

**Fix.** Three additions to `GhidraBackend`:

1. A **shutdown method** that closes every open session (releasing each
   project's Ghidra lock via existing `session_close` semantics) and
   tears down the executor. Wired to `atexit` and (via
   `_install_signal_handlers`) to `SIGTERM`/`SIGINT`. The signal handler
   re-raises the default after cleanup so the process actually exits.
2. A **sidecar JSON file** at `~/.ghidra-headless-mcp/sessions/<pid>.json`
   updated on backend init, every session open, and every session close.
   Schema:

   ```json
   {
     "pid": 12345,
     "started_at": 1715616000.0,
     "claude_code_session_id": "<from CLAUDE_CODE_SESSION_ID env>",
     "ghidra_install_dir": "/Users/szeth/Applications/ghidra_12.0.4_PUBLIC",
     "open_projects": [
       {
         "session_id": "...",
         "project_location": "/Users/szeth/ghidra-projects",
         "project_name": "rocket-chat-analysis",
         "lockfile": "/Users/szeth/ghidra-projects/rocket-chat-analysis.lock",
         "program_name": "Electron Framework"
       }
     ]
   }
   ```

3. A **`cli.main` hook** that calls `backend._install_signal_handlers()`
   right after `build_backend(args)` so the cleanup runs on `kill -TERM`
   or Ctrl-C, not just on clean exits.

The reader half is `scripts/lab-health.sh`. It walks the sidecar dir,
cross-references each PID with `kill -0`, surfaces stale sidecars, and
flags orphan `.lock` files in `~/ghidra-projects/` that no live sidecar
claims (the PASS-001 stop condition).

**Where it lives.** Same place as the stdout patch: lab host editable
install at `/Users/<remote-user>/tools/ghidra-headless-mcp/`. Apply with
`patch -p1 < pid-tagging-and-shutdown.patch` after the upstream pin is
checked out. Touches +84 LOC in `backend.py` and +5 LOC in `cli.py`.

**Applies against.** Pinned commit
`b9c491a6383dbc68c581e7fed16341ac47e7faba`. Stacks cleanly on top of
`pyghidra-script-stdout.patch` (different code regions). Required
imports (`atexit`, `signal`) are added by the patch.

**Operator actions.**
1. Reapply on any new lab host after `scripts/install-ghidra-host.sh`
   clones the upstream pin, alongside the stdout patch.
2. Verify by running `scripts/lab-health.sh` from the workstation; the
   "live MCP sessions" section should populate with PID + open
   projects.
3. Test the shutdown path: with one MCP session open, send SIGTERM to
   the MCP PID; the lockfile and sidecar should both disappear.
4. Carrying-our-own-version policy: this patch is not slated for
   upstream. The downstream stack is the station's source of truth.

**Interaction with `pyghidra-script-stdout.patch`.** The two patches
touch disjoint regions (`__init__`, end-of-class, and `cli.main` for
this one; the `ghidra_script` method for the stdout one). Apply order
is irrelevant; either can be applied first.

**Why `_install_signal_handlers` is name-private.** The MCP server
introspects `GhidraBackend`'s public methods at startup (in
`server._build_backend_tool_specs`) and refuses to start if any public
method is missing from `_BACKEND_TOOL_NAME_MAP`. A public
`install_signal_handlers` would crash the server. The leading
underscore tells the introspector to skip it; `cli.py` calls it
through `getattr(backend, "_install_signal_handlers", None)` for
backwards-compatibility with unpatched backends.

**Verification.** End-to-end SIGTERM cycle was exercised on the lab
host (snapshot taken first, per LAB_SAFETY.md):

1. Apply both patches on a clean upstream tree (verified with
   `git apply --check`).
2. Start MCP via `~/bin/ghidra-mcp-launch` with stdin held open via a
   FIFO (so the stdio loop doesn't EOF-exit).
3. Confirm sidecar appears at `~/.ghidra-headless-mcp/sessions/<pid>.json`
   with PID, started_at, claude_code_session_id (if env set), and an
   empty open_projects list.
4. Run `scripts/lab-health.sh` from the workstation; "live MCP sessions"
   section populates.
5. Send `kill -TERM <pid>`; sidecar disappears within ~1 second; PID
   gone.
6. Run `lab-health.sh` again; clean state, no stale entries.

---

## `open-existing-docstring.patch`

**Problem.** The `project.program.open_existing` MCP tool's description
(`server.py:283`) reads "Open a program from a named existing Ghidra
project and return a new session." The implementation in
`backend.session_open_existing` accepts `program_name` and `program_path`
as keyword arguments with default `None` (so the tool's input schema
marks both *optional*), but the impl raises
`GhidraBackendError("program_name or program_path is required")` at
runtime if neither is set. From the client's side this looks like two
optional fields that are nonetheless mandatory in some hidden way; the
only signal is the runtime error after the call has already been
issued. Closes SHAKEDOWN_NOTES.md item #22.

**Fix.** Extend the description string to state the constraint
explicitly: "Open a program from a named existing Ghidra project and
return a new session. Requires `program_name` or `program_path` to
identify which program inside the project to open; both are listed as
optional in the schema but exactly one must be supplied." One-line
edit; no impl changes. The runtime error remains — the patch only
closes the documentation gap so the MCP client's tool catalog conveys
the constraint before the call.

**Where it lives.** Same place as the other patches: lab host editable
install at `/Users/<remote-user>/tools/ghidra-headless-mcp/`. Apply
with `git apply <patch>` after the upstream pin is checked out.
Touches one line in `ghidra_headless_mcp/server.py`.

**Applies against.** Pinned commit
`b9c491a6383dbc68c581e7fed16341ac47e7faba`. Stacks cleanly on top of
`pyghidra-script-stdout.patch` and `pid-tagging-and-shutdown.patch`
(disjoint files: those touch `backend.py` and `cli.py`; this touches
`server.py`). Apply order is irrelevant.

**Operator actions.**
1. Auto-applied by `scripts/install-ghidra-host.sh --install` via the
   patch-stack rsync + dual-probe apply loop (PR #13). No manual step
   on a fresh provisioning.
2. Candidate for upstreaming to `mrphrazer/ghidra-headless-mcp` — the
   schema/description mismatch is generic and not station-specific.
   The fully correct upstream fix is to express
   "exactly one of `program_name` / `program_path`" in the input
   schema (e.g. via Pydantic discriminator or oneOf) so the MCP client
   can validate before the call — but that's a larger change to the
   server's tool-spec generator. The docstring patch is the minimum
   fix that closes the immediate confusion.
3. If upstreamed, remove this patch and bump the commit pin in
   `scripts/install-ghidra-host.sh`.

**Verification.** After apply, the MCP client's tool catalog for
`project.program.open_existing` should show the extended description
on the next handshake. No runtime behavior change — the impl still
raises the same error if both arguments are omitted. The patch's value
is purely in the discoverability of the constraint.

---

## `refuse-universal-macho.patch`

**Problem.** When the MCP path opens a universal Mach-O, Ghidra's loader
silently picks one slice and the caller has no signal that the other
slices weren't scanned. PR #14 fixed this for the SSH path
(`scripts/ghidra-scan.sh` auto-iterates slices); the MCP path had no
equivalent. The SHAKEDOWN #8 probe confirmed: `program.open` against
`/bin/echo` (universal `x86_64+arm64e`) returned
`language_id: x86:LE:64:default` with no warning. An x86_64-only or
arm64-only bug in the unscanned slice slips through. Closes
SHAKEDOWN_NOTES.md item #35.

**Fix.** Detect Mach-O fat magic (`0xCAFEBABE` for 32-bit fat,
`0xCAFEBABF` for 64-bit fat) at the earliest unambiguous point in both
`session_open` (path-based) and `session_open_bytes` (uploaded blob).
Raise `GhidraBackendError` with a message that names the path and
suggests the resolution: pre-slice with `lipo -thin <arch> <in> <out>`
and pass the slice path, or use `scripts/ghidra-scan.sh` which
auto-iterates slices. Same heuristic `lipo -info` uses (first 4 bytes
in big-endian).

**Where it lives.** Lab host editable install at
`/Users/<remote-user>/tools/ghidra-headless-mcp/`. Apply with
`git apply <patch>` after the upstream pin is checked out. Touches
~9 lines in `session_open` (after `_ensure_started()` + path-existence
check) and ~5 lines in `session_open_bytes` (after base64 decode).

**Applies against.** Pinned commit
`b9c491a6383dbc68c581e7fed16341ac47e7faba`. Stacks cleanly on top of
the other three patches (`pyghidra-script-stdout.patch`,
`pid-tagging-and-shutdown.patch`, `open-existing-docstring.patch`) —
disjoint regions in `backend.py` and a different file (`server.py`)
for the docstring patch.

**Operator actions.**
1. Auto-applied by `scripts/install-ghidra-host.sh --install` via the
   patch-stack rsync + dual-probe apply loop (PR #13). No manual step
   on a fresh provisioning.
2. **Restart any long-lived MCP processes** after install — the
   editable install only re-reads `backend.py` on process start; PIDs
   running before the install keep the unpatched code cached. Kill
   stale MCP PIDs and let the operator's MCP transport reconnect.
3. Carrying-our-own-version policy: this patch is candidate for
   upstreaming to `mrphrazer/ghidra-headless-mcp` — the silent-slice
   behavior is a generic problem, not station-specific. The fully
   correct upstream design is to detect fat Mach-Os and either iterate
   (returning multiple session ids) or accept an `arch` parameter; the
   downstream fix is the minimum-viable refuse-loudly variant.

**Why refuse instead of auto-iterate.** The tool returns a single
`session_id`. Auto-iteration would change the return shape (list of
session ids) and ripple through every caller's expectations. Refuse
keeps the schema unchanged and pushes the slice choice to the caller —
who may want only one slice anyway (e.g. `arm64e` on Apple Silicon for
modern-binary work). The error message names both escape hatches.

**Why magic-byte read instead of shellout to `lipo`.** No host-tool
dependency; works on any platform; no fork overhead. Mach-O fat magic
is `0xCAFEBABE` (32-bit) or `0xCAFEBABF` (64-bit) in big-endian on
disk. Same heuristic `lipo -info` uses internally.

**Java-class-magic collision note.** `0xCAFEBABE` also collides with
Java `.class` file magic. Defensive implementations sanity-check
`nfat_arch < 32` to disambiguate. The lab tools collectively will not
see this collision in practice — Ghidra's macOS-target workflow is
the only consumer, and a `.class` file routed through a Mach-O loader
is already a misuse the loader would reject for unrelated reasons.
The patch does not add the sanity-check, matching `lipo -info`'s
behavior of declaring fat on bare magic match.

**Verification.** Runtime probed against the patched lab-host backend
(probe sequence in `~/.venvs/ghidra-headless-mcp/bin/python` with
`GHIDRA_INSTALL_DIR` + `JAVA_HOME` exported, then `cli.build_backend`
on the patched module):

1. `session_open("/bin/echo")` (real universal Mach-O on macOS) →
   raises with the expected message including the path.
2. `session_open_bytes(<base64 of 0xCAFEBABE + zeros>)` → raises with
   the bytes-variant message. Same for `0xCAFEBABF`.
3. `session_open_bytes(<base64 of 0xCFFAEDFE + zeros>)` (thin 64-bit
   Mach-O magic) → gate lets it past; downstream Ghidra raises
   `LoadException: No load spec found` (expected — the rest of the
   header is zeros). Negative control proves the gate is selective.

After successful application, restart the MCP process so the in-memory
Python module picks up the patched function bodies.

---

## SSH-fallback wrapper: `scripts/ghidra-scan.sh`

Not a patch to `ghidra-headless-mcp` itself, but a companion helper for
when the MCP tools aren't available in-session (fresh Claude Code
session whose deferred-tool list was snapshotted before SSH recovered,
or any out-of-band usage). Drives `pyghidra_launcher.py -H` directly
against the same binary the MCP would have opened.

**Key design decisions:**

- **No `-readOnly`.** First-scan analysis on a large binary (e.g. an
  Electron Framework at 177 MB arm64 slice) can take 30+ minutes.
  Persisting the DB means subsequent scripts against the same binary
  cost seconds, not hours. The disposable lab host has no reason to
  throw the DB away at exit.
- **Persistent project naming:** `~/ghidra-projects/<project>/<target-id>.gpr`.
  Callers pass `--project <name> --target-id <id>` so the mapping is
  explicit. First call uses `-import`; subsequent calls detect the
  existing `.gpr` and use `-process <binary> -noanalysis`.
- **JVM heap default `-Xmx12g`** (overridable via `MACRE_GHIDRA_HEAP`).
  Ghidra's decompiler is heap-hungry; the conservative default lets
  large binaries finish without OOM.
- **Pre-slice universal Mach-Os.** `analyzeHeadless` has no flag for
  slice selection on universal binaries; the caller must
  `lipo -thin <arch>` first. The wrapper does not auto-slice — too
  much implicit behavior.

**Interaction with `read_only=true` in MCP Workflow A.** The SKILL.md
examples (`read_only=true, update_analysis=true` on `program.open`)
pass `read_only=true` to the MCP tool. Verify with the pinned
`ghidra-headless-mcp` semantics whether that blocks DB commits;
if it does, the MCP path is NOT persistent and an equivalent
adjustment is needed upstream. For the SSH-fallback path,
`-readOnly` unambiguously discards the DB — so the wrapper omits it.
