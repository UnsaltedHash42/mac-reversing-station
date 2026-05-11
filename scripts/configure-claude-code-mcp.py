#!/usr/bin/env python3
"""Register Claude Code MCP entries for the Keep via `claude mcp add-json`.

Previously this script wrote to `~/.claude/settings.json` under a top-level
`mcpServers` key. Claude Code does NOT read MCP servers from that file —
the CLI-managed registry lives in `~/.claude.json` (user/local scope) or in
a project-root `.mcp.json` (project scope). The supported way to register
stdio servers is the `claude mcp add-json` CLI; this script shells out to it.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from typing import Any


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--host",
        default=os.environ.get("MACRE_MACHINE", "lab-host"),
        help="SSH alias for lab host",
    )
    parser.add_argument(
        "--remote-home",
        default=os.environ.get("MACRE_REMOTE_HOME", "/Users/<remote-user>"),
        help="Remote user's home directory",
    )
    parser.add_argument(
        "--scope",
        choices=("local", "user", "project"),
        default="user",
        help="Claude Code MCP config scope (default: user)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the `claude mcp add-json` invocations without running them",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    if not args.dry_run and shutil.which("claude") is None:
        print(
            "ERROR: `claude` CLI not on PATH; install Claude Code first or run with --dry-run",
            file=sys.stderr,
        )
        return 2

    servers: dict[str, dict[str, Any]] = {
        "ghidra-mcp": ghidra_server(args.host, args.remote_home),
        "macre-vm-mcp": macre_server(args.host, args.remote_home),
    }

    for name, spec in servers.items():
        spec_json = json.dumps(spec)
        cmd = ["claude", "mcp", "add-json", "-s", args.scope, name, spec_json]
        if args.dry_run:
            print("DRY-RUN:", " ".join(shell_quote(c) for c in cmd))
            continue
        result = subprocess.run(cmd, check=False)
        if result.returncode != 0:
            print(
                f"ERROR: `claude mcp add-json` failed for {name} (exit {result.returncode})",
                file=sys.stderr,
            )
            return result.returncode
        print(f"OK - registered {name} at scope={args.scope}")

    if not args.dry_run:
        print("Restart Claude Code so the deferred-tool list refreshes.")
        print("Verify with: claude mcp list")
    return 0


def ghidra_server(host: str, remote_home: str) -> dict[str, Any]:
    return {
        "command": "ssh",
        "args": [
            "-o",
            "BatchMode=yes",
            "-o",
            "ServerAliveInterval=30",
            host,
            f"{remote_home}/bin/ghidra-mcp-launch",
        ],
    }


def macre_server(host: str, remote_home: str) -> dict[str, Any]:
    return {
        "command": "ssh",
        "args": [
            "-o",
            "BatchMode=yes",
            "-o",
            "ServerAliveInterval=30",
            host,
            f"{remote_home}/.venvs/macre-vm-mcp/bin/python",
            "-m",
            "macre_vm_mcp",
        ],
    }


def shell_quote(value: str) -> str:
    if not value or any(c in value for c in " '\"\\$`{}[]<>|&;*?#~"):
        return "'" + value.replace("'", "'\\''") + "'"
    return value


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
