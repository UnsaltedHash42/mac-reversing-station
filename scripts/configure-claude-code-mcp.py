#!/usr/bin/env python3
"""Write or update Claude Code MCP entries for the Keep."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.environ.get("MACRE_MACHINE", "lab-host"), help="SSH alias for lab host")
    parser.add_argument(
        "--remote-home",
        default=os.environ.get("MACRE_REMOTE_HOME", "/Users/<remote-user>"),
        help="Remote user's home directory",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path.home() / ".claude/settings.json",
        help="Claude Code settings path",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print merged config without writing it",
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Do not write a .bak copy before changing an existing config",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    config = load_config(args.config)
    config.setdefault("mcpServers", {})
    config["mcpServers"]["ghidra-mcp"] = ghidra_server(args.host, args.remote_home)
    config["mcpServers"]["macre-vm-mcp"] = macre_server(args.host, args.remote_home)

    rendered = json.dumps(config, indent=2, sort_keys=True) + "\n"
    if args.dry_run:
        print(rendered, end="")
        return 0

    current = args.config.read_text(encoding="utf-8") if args.config.is_file() else ""
    if current == rendered:
        print(f"OK - Claude Code MCP config already up to date: {args.config}")
        return 0

    args.config.parent.mkdir(parents=True, exist_ok=True)
    if current and not args.no_backup:
        backup = args.config.with_suffix(args.config.suffix + ".bak")
        backup.write_text(current, encoding="utf-8")
        print(f"OK - wrote backup: {backup}")
    write_atomic(args.config, rendered)
    print(f"OK - wrote Claude Code MCP config: {args.config}")
    print("Restart Claude Code so the MCP server list refreshes.")
    return 0


def load_config(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"ERROR: invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"ERROR: {path} must contain a JSON object")
    return data


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


def write_atomic(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
