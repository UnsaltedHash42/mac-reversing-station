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
   `install_signal_handlers`) to `SIGTERM`/`SIGINT`. The signal handler
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

3. A **`cli.main` hook** that calls `backend.install_signal_handlers()`
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
