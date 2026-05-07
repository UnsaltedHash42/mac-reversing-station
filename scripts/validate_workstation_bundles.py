#!/usr/bin/env python3
"""Validate Skill directory paths referenced in docs/workstation/skill-bundles.md."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


_INLINE_SKILLS_PATH = re.compile(r"`(Skills/offensive-[a-z0-9-]+)`")


def extract_paths(markdown_text: str) -> list[str]:
    return sorted({_normalize_path(match) for match in _INLINE_SKILLS_PATH.findall(markdown_text)})


def _normalize_path(raw: str) -> str:
    # Future: allow optional trailing slashes or Windows separators by normalizing here.
    return raw


def validate(root: Path, doc: Path, markdown_text: str) -> list[str]:
    errors: list[str] = []
    paths = extract_paths(markdown_text)
    if not paths:
        errors.append(
            "No Skills/offensive-* references found via inline-code `Skills/...` markers in "
            f"{doc}."
        )
        return errors

    for rel in paths:
        target = root / rel
        if not target.is_dir():
            errors.append(f"{rel} is not an existing directory (repo root={root}).")
            continue
        skill_file = target / "SKILL.md"
        if not skill_file.is_file():
            errors.append(f"{rel}/SKILL.md is missing.")

    return errors


def parse_args(argv: list[str]) -> argparse.Namespace:
    default_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=default_root,
        help=f"repository root holding Skills/ tree (default: {default_root})",
    )
    parser.add_argument(
        "--doc",
        type=Path,
        default=default_root / "docs/workstation/skill-bundles.md",
        help="Markdown file containing inline-code `Skills/...` paths",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    root = args.root.resolve()
    doc = args.doc.resolve()

    if not doc.is_file():
        print(f"Document not found: {doc}", file=sys.stderr)
        return 2

    markdown_text = doc.read_text(encoding="utf-8")
    errors = validate(root=root, doc=doc, markdown_text=markdown_text)
    if errors:
        print("Workstation bundle validation failed:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    count = len(extract_paths(markdown_text))
    print(f"OK — {count} unique `Skills/offensive-*` directories referenced in {doc.name}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
