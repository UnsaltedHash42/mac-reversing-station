"""DTrace tools — run D-scripts against a target binary or PID.

Note on SIP: if the configured lab host has SIP disabled, DTrace can
instrument system binaries freely. On a SIP-on machine, DTrace providers
for Apple-signed binaries are restricted; the skill docs call this out.
"""

from __future__ import annotations

import shlex
import tempfile
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from ._proc import run


def register(mcp: FastMCP) -> None:
    @mcp.tool
    def dtrace_script(
        script: str,
        target_command: list[str] | None = None,
        target_pid: int | None = None,
        timeout_sec: float = 15.0,
        extra_args: list[str] | None = None,
    ) -> dict[str, Any]:
        """Run a full D-script and capture the trace output.

        Exactly one of ``target_command`` (spawn a child) or
        ``target_pid`` (attach to a running process) may be set.
        If both are None the script runs in probe-anywhere mode.
        """
        if target_command and target_pid is not None:
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": "Specify only one of target_command or target_pid.",
                "timed_out": False,
            }

        extra_args = extra_args or []

        with tempfile.NamedTemporaryFile(
            "w", suffix=".d", delete=False, encoding="utf-8"
        ) as scriptfile:
            scriptfile.write(script)
            script_path = Path(scriptfile.name)

        try:
            argv: list[str] = ["/usr/sbin/dtrace", "-q", "-s", str(script_path)]
            argv.extend(extra_args)
            if target_pid is not None:
                argv.extend(["-p", str(int(target_pid))])
            if target_command:
                # `dtrace -c <cmd>` runs <cmd> through /bin/sh, so caller
                # arguments need shell-quoting to survive spaces and
                # metacharacters. shlex.join builds a string sh will
                # re-tokenize the way the caller intended.
                argv.extend(["-c", shlex.join(target_command)])
            return run(argv, timeout=timeout_sec).to_dict()
        finally:
            try:
                script_path.unlink()
            except OSError:
                pass

    @mcp.tool
    def dtrace_oneliner(
        expression: str,
        target_pid: int | None = None,
        timeout_sec: float = 10.0,
    ) -> dict[str, Any]:
        """Run a single-line D expression like ``syscall:::entry /pid == $target/ { @[probefunc] = count(); }``.

        Thin wrapper around ``dtrace -n <expr>``. Use ``dtrace_script``
        for multi-clause programs.
        """
        argv: list[str] = ["/usr/sbin/dtrace", "-q", "-n", expression]
        if target_pid is not None:
            argv.extend(["-p", str(int(target_pid))])
        return run(argv, timeout=timeout_sec).to_dict()
