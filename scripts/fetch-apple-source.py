#!/usr/bin/env python3
"""Fetch Apple-published component source for the source-binary correlation lane.

Resolves a component name and release identifier into a canonical archive URL,
downloads the tarball into a workstation-local gitignored cache, and prints
arguments suitable for `scripts/start-target.py --source-root --source-ref --source-url`.

Apple migrated current releases to https://github.com/apple-oss-distributions/, with
the opensource.apple.com/releases/ page acting as the discovery surface. The fetcher
defaults to the GitHub archive URL but supports the legacy opensource.apple.com path
as a fallback.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tarfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


DEFAULT_CACHE_DIR = Path.cwd() / "sources/apple"
GITHUB_URL_TEMPLATE = (
    "https://github.com/apple-oss-distributions/{component}/archive/refs/tags/"
    "{component}-{release}.tar.gz"
)
LEGACY_URL_TEMPLATE = (
    "https://opensource.apple.com/source/{component}/{component}-{release}.tar.gz"
)
COMPONENT_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")
RELEASE_PATTERN = re.compile(r"^[A-Za-z0-9._+-]+$")


class FetchError(Exception):
    """Raised when fetch-apple-source cannot complete safely."""


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("component", help="Apple component name, e.g. dyld, xnu, Security, Heimdal")
    parser.add_argument("--release", required=True, help="Release identifier, e.g. 1042.1")
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=DEFAULT_CACHE_DIR,
        help="Workstation-local cache directory (default: ./sources/apple, gitignored)",
    )
    parser.add_argument(
        "--source",
        choices=("github", "opensource"),
        default="github",
        help="Archive source. github: apple-oss-distributions on GitHub (default). "
        "opensource: legacy opensource.apple.com/source path.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Resolve and print the URL/cache layout without downloading.",
    )
    parser.add_argument(
        "--no-extract",
        action="store_true",
        help="Download the tarball but do not extract it.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Per-request HTTP timeout in seconds (default 60).",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        result = fetch_apple_source(
            component=args.component,
            release=args.release,
            cache_dir=args.cache_dir,
            source=args.source,
            dry_run=args.dry_run,
            extract=not args.no_extract,
            timeout=args.timeout,
        )
    except FetchError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(result, indent=2))
    return 0


def fetch_apple_source(
    component: str,
    release: str,
    cache_dir: Path,
    source: str = "github",
    dry_run: bool = False,
    extract: bool = True,
    timeout: int = 60,
    url_opener=None,
) -> dict[str, Any]:
    """Resolve, fetch, and unpack an Apple component release.

    `url_opener` is an injection seam for tests; it must accept (url, timeout)
    and return a binary file-like object. Defaults to urllib.request.urlopen.
    """
    if not COMPONENT_PATTERN.match(component):
        raise FetchError(f"invalid component name: {component!r}")
    if not RELEASE_PATTERN.match(release):
        raise FetchError(f"invalid release: {release!r}")
    if source not in {"github", "opensource"}:
        raise FetchError(f"invalid source: {source!r}")

    url = resolve_url(component, release, source)
    cache_dir = cache_dir.expanduser().resolve()
    component_dir = cache_dir / component / release
    archive_path = component_dir / f"{component}-{release}.tar.gz"
    extracted_marker = component_dir / ".extracted"

    if dry_run:
        return {
            "component": component,
            "release": release,
            "source": source,
            "url": url,
            "cache_dir": str(cache_dir),
            "component_dir": str(component_dir),
            "archive_path": str(archive_path),
            "status": "dry-run",
            "start_target_args": start_target_args(component_dir, release, url),
        }

    if extracted_marker.exists():
        return {
            "component": component,
            "release": release,
            "source": source,
            "url": url,
            "cache_dir": str(cache_dir),
            "component_dir": str(component_dir),
            "archive_path": str(archive_path),
            "status": "cache-hit",
            "start_target_args": start_target_args(component_dir, release, url),
        }

    component_dir.mkdir(parents=True, exist_ok=True)

    if not archive_path.is_file() or archive_path.stat().st_size == 0:
        download_archive(url, archive_path, timeout=timeout, url_opener=url_opener)

    if extract:
        extract_archive(archive_path, component_dir)
        extracted_marker.touch()
        status = "fetched-and-extracted"
    else:
        status = "fetched"

    return {
        "component": component,
        "release": release,
        "source": source,
        "url": url,
        "cache_dir": str(cache_dir),
        "component_dir": str(component_dir),
        "archive_path": str(archive_path),
        "status": status,
        "start_target_args": start_target_args(component_dir, release, url),
    }


def resolve_url(component: str, release: str, source: str) -> str:
    if source == "github":
        return GITHUB_URL_TEMPLATE.format(component=component, release=release)
    return LEGACY_URL_TEMPLATE.format(component=component, release=release)


def download_archive(url: str, target: Path, timeout: int, url_opener=None) -> None:
    opener = url_opener or _default_url_opener
    try:
        response = opener(url, timeout)
    except urllib.error.HTTPError as exc:
        raise FetchError(f"HTTP {exc.code} fetching {url}") from exc
    except urllib.error.URLError as exc:
        raise FetchError(f"network error fetching {url}: {exc.reason}") from exc
    except OSError as exc:
        raise FetchError(f"network error fetching {url}: {exc}") from exc

    try:
        with target.open("wb") as fh:
            while True:
                chunk = response.read(64 * 1024)
                if not chunk:
                    break
                fh.write(chunk)
    finally:
        try:
            response.close()
        except Exception:  # noqa: BLE001
            pass

    if not target.is_file() or target.stat().st_size == 0:
        raise FetchError(f"downloaded archive is empty: {target}")


def _default_url_opener(url: str, timeout: int):
    return urllib.request.urlopen(url, timeout=timeout)  # noqa: S310 - URL is operator-supplied


def extract_archive(archive_path: Path, target_dir: Path) -> None:
    try:
        with tarfile.open(archive_path, "r:gz") as tar:
            members = [m for m in tar.getmembers() if is_safe_member(m, target_dir)]
            tar.extractall(target_dir, members=members)
    except (OSError, tarfile.TarError) as exc:
        raise FetchError(f"failed to extract {archive_path}: {exc}") from exc


def is_safe_member(member: tarfile.TarInfo, target_dir: Path) -> bool:
    """Reject absolute paths and traversal to keep extraction inside target_dir."""
    name = member.name
    if name.startswith("/") or ".." in Path(name).parts:
        return False
    if member.issym() or member.islnk():
        link_target = Path(member.linkname or "")
        if link_target.is_absolute() or ".." in link_target.parts:
            return False
    return True


def start_target_args(component_dir: Path, release: str, url: str) -> dict[str, str]:
    return {
        "--source-root": str(component_dir),
        "--source-ref": release,
        "--source-url": url,
    }


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
