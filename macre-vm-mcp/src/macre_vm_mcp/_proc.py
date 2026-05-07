"""Shared subprocess helpers for macre-vm-mcp tool modules."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, asdict
from typing import Any


@dataclass
class ProcResult:
    """Uniform wrapper for subprocess results returned to MCP callers."""

    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def run(
    argv: list[str],
    *,
    timeout: float = 30.0,
    input_text: str | None = None,
    env: dict[str, str] | None = None,
) -> ProcResult:
    """Run a command, capture stdout/stderr, enforce a timeout.

    Never raises on subprocess failure — returns a ProcResult with the
    error fields populated so MCP responses stay structured.
    """
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        return ProcResult(
            returncode=-1,
            stdout=exc.stdout or "",
            stderr=f"TIMEOUT after {timeout}s\n{exc.stderr or ''}",
            timed_out=True,
        )
    except FileNotFoundError as exc:
        return ProcResult(returncode=127, stdout="", stderr=f"not found: {exc}")
    except OSError as exc:
        return ProcResult(returncode=-1, stdout="", stderr=f"OSError: {exc}")

    return ProcResult(
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
    )
