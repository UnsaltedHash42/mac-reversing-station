"""Pure helpers used across the package."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit


def dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def slugify(value: str) -> str:
    return re.sub(r"(^-|-$)", "", re.sub(r"[^a-z0-9]+", "-", value.lower()))


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def is_privacy_usage_key(key: str) -> bool:
    return key.startswith("NS") and key.endswith("UsageDescription")


def is_executable(path: Path) -> bool:
    return os.access(path, os.X_OK)


def should_skip_executable(path: Path) -> bool:
    return path.suffix in {".plist", ".strings", ".json", ".nib", ".storyboardc"}


def is_inside_bundle(path: Path, suffix: str) -> bool:
    return any(parent.suffix == suffix for parent in path.parents)


def is_inside_any_bundle(path: Path, suffixes: tuple[str, ...]) -> bool:
    return any(parent.suffix in suffixes for parent in path.parents)


def is_within_root(path: Path, root_resolved: Path) -> bool:
    try:
        path.resolve().relative_to(root_resolved)
        return True
    except (OSError, ValueError):
        return False


def sha256_file(path: Path) -> str:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return ""


def redact_url(value: str) -> str:
    parts = urlsplit(value)
    if not parts.username and not parts.password:
        return value
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    return urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))


def version_string(bundle: dict[str, str]) -> str:
    short = bundle.get("short_version", "")
    build = bundle.get("bundle_version", "")
    if short and build:
        return f"{short} ({build})"
    return short or build or "unknown"


def relative_paths(root: Path, paths) -> list[str]:
    results = []
    root_resolved = root.resolve()
    for path in sorted(paths):
        if path.is_symlink() or not is_within_root(path, root_resolved):
            continue
        try:
            results.append(str(path.relative_to(root)))
        except ValueError:
            results.append(str(path))
    return results
