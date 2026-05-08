#!/usr/bin/env python3
"""Validate the Wave 4 investigation recipe registry."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


REQUIRED_RECIPE_IDS = {
    "bundle-dossier",
    "map-xpc-endpoints",
    "inspect-privileged-helper-or-updater",
    "review-tcc-and-persistent-authorization",
    "review-electron-ipc-and-packaging",
    "correlate-source-to-binary",
    "gatehouse-ghidra-lldb-confirmation",
    "inventory-first-manual-routing",
    "os-component-inventory",
    "inspect-launchd-machservice-topology",
    "inspect-system-or-network-extension",
    "inspect-endpoint-security-client",
    "private-framework-dependency-map",
    "apple-signed-build-drift-check",
    "vm-snapshot-and-action-log",
    "chain-discovery",
    "poc-authoring",
    "apple-source-correlation",
}


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Repository root")
    parser.add_argument(
        "--doc",
        default="docs/playbooks/investigation-recipes.md",
        help="Recipe registry path relative to root",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    root = args.root.resolve()
    doc_path = root / args.doc
    if not doc_path.is_file():
        print(f"ERROR: missing recipe registry: {args.doc}", file=sys.stderr)
        return 1

    text = doc_path.read_text(encoding="utf-8")
    ids = set(re.findall(r"^Recipe ID: `([^`]+)`", text, flags=re.MULTILINE))
    missing = sorted(REQUIRED_RECIPE_IDS - ids)
    broken_refs = broken_backtick_paths(root, text)

    for recipe_id in missing:
        print(f"ERROR: missing recipe id: {recipe_id}", file=sys.stderr)
    for ref in broken_refs:
        print(f"ERROR: recipe references missing path: {ref}", file=sys.stderr)

    return 1 if missing or broken_refs else 0


def broken_backtick_paths(root: Path, text: str) -> list[str]:
    broken = []
    for ref in sorted(set(re.findall(r"`((?:Skills|docs|ghidra-scripts|scripts|macre-vm-mcp)/[^`]+)`", text))):
        if not (root / ref).exists():
            broken.append(ref)
    return broken


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
