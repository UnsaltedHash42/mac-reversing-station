"""lldb tools — scripted batch runs via ``lldb -b -o``."""

from __future__ import annotations

import re
from typing import Any

from fastmcp import FastMCP

from ._proc import run


def register(mcp: FastMCP) -> None:
    @mcp.tool
    def lldb_run(
        binary_path: str,
        args: list[str] | None = None,
        breakpoints: list[str] | None = None,
        post_break_commands: list[str] | None = None,
        run_command: str = "run",
        timeout_sec: float = 30.0,
    ) -> dict[str, Any]:
        """Run a binary under lldb in batch mode and return captured output.

        ``breakpoints`` are symbol names or ``file:line`` forms passed to
        ``b`` one at a time. ``post_break_commands`` runs after each stop
        (e.g. ``register read``, ``memory read --count 64 $sp``).

        Returns the uniform ProcResult dict {returncode, stdout, stderr,
        timed_out}. Never raises on subprocess failure.
        """
        args = args or []
        breakpoints = breakpoints or []
        post_break_commands = post_break_commands or ["bt 5", "register read"]

        cmds: list[str] = ["settings set target.run-args " + " ".join(args)] if args else []
        for bp in breakpoints:
            cmds.append(f"b {bp}")
        cmds.append(run_command)
        for cmd in post_break_commands:
            cmds.append(cmd)
        cmds.append("quit")

        argv = ["/usr/bin/lldb", "-b"]
        for cmd in cmds:
            argv.extend(["-o", cmd])
        argv.append(binary_path)

        return run(argv, timeout=timeout_sec).to_dict()

    @mcp.tool
    def lldb_break_and_inspect(
        binary_path: str,
        symbol: str,
        args: list[str] | None = None,
        dump_registers: bool = True,
        dump_stack_bytes: int = 64,
        timeout_sec: float = 30.0,
    ) -> dict[str, Any]:
        """Break on ``symbol``, dump registers plus stack, and return.

        Convenience wrapper for the extremely common "hit this function,
        show me the state" workflow. For more complex orchestration use
        ``lldb_run`` directly.
        """
        post: list[str] = []
        if dump_registers:
            post.append("register read")
        if dump_stack_bytes > 0:
            post.append(f"memory read --count {int(dump_stack_bytes)} $sp")
        post.append("bt 5")
        return lldb_run(
            binary_path=binary_path,
            args=args,
            breakpoints=[symbol],
            post_break_commands=post,
            timeout_sec=timeout_sec,
        )

    @mcp.tool
    def lldb_run_anchors(
        binary_path: str,
        anchors: list[dict[str, str]],
        args: list[str] | None = None,
        extra_post_commands: list[str] | None = None,
        timeout_sec: float = 30.0,
    ) -> dict[str, Any]:
        """Run LLDB from Ghidra-derived anchors and return the batch transcript.

        Each anchor should provide either ``symbol`` or ``address``. Addresses
        are passed to LLDB as-is, so callers must account for image slide and
        architecture slice before relying on an address stop.
        """
        breakpoints = []
        skipped = []
        for anchor in anchors:
            breakpoint = anchor_breakpoint(anchor)
            if breakpoint:
                breakpoints.append(breakpoint)
            else:
                skipped.append(anchor)

        post = ["image list", "bt 10", "register read"]
        post.extend(cmd for cmd in (extra_post_commands or []) if safe_lldb_command(cmd))
        result = lldb_run(
            binary_path=binary_path,
            args=args,
            breakpoints=breakpoints,
            post_break_commands=post,
            timeout_sec=timeout_sec,
        )
        return {
            "anchors_requested": anchors,
            "breakpoints": breakpoints,
            "skipped_anchors": skipped,
            "slide_warning": "Address anchors require caller-verified image slide and architecture slice.",
            "result": result,
        }


def anchor_breakpoint(anchor: dict[str, str]) -> str:
    symbol = anchor.get("symbol", "").strip()
    if symbol and safe_lldb_command(symbol):
        return symbol
    address = anchor.get("address", "").strip()
    if address and re.fullmatch(r"(0x[0-9A-Fa-f]+|[0-9]+)", address):
        return f"-a {address}"
    return ""


def safe_lldb_command(value: str) -> bool:
    return "\n" not in value and "\r" not in value and ";" not in value
