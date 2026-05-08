"""Codesign + dyld inspection helpers.

`detect_apple_signing` and `detect_dyld_dependencies` shell out to
`codesign` and `otool`. The pure parsers (`apply_codesign_evidence`,
`parse_dyld_dependencies`) are exported for unit tests.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any


def codesign_target(local_path: Path) -> Path | None:
    if local_path.is_file() or local_path.is_dir():
        return local_path
    return None


def run_codesign(local_path: Path) -> str:
    target = codesign_target(local_path)
    if target is None:
        return ""
    try:
        proc = subprocess.run(
            ["codesign", "-dv", "--", str(target)],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""
    return (proc.stderr or "") + (proc.stdout or "")


def apply_codesign_evidence(info: dict[str, Any], codesign_output: str) -> dict[str, Any]:
    if not codesign_output:
        return info
    authority = ""
    authority_match = re.search(r"^Authority=(.+)$", codesign_output, re.MULTILINE)
    if authority_match:
        authority = authority_match.group(1).strip()
    team_match = re.search(r"^TeamIdentifier=(\S+)$", codesign_output, re.MULTILINE)
    if team_match:
        info["team_id"] = team_match.group(1).strip()
    if authority and ("Software Signing" in authority
                      or "Apple Code Signing Certification Authority" in authority):
        info["apple_signed"] = True
        info["authority"] = authority
        info["evidence"] = f"codesign Authority={authority}"
    elif authority and not info["apple_signed"]:
        info["authority"] = authority
        info["evidence"] = f"codesign Authority={authority}"
    return info


def detect_apple_signing(local_path: Path, bundle: dict[str, str]) -> dict[str, Any]:
    """Best-effort detection of Apple signing.

    Combines `codesign -dv` output with bundle identifier heuristics.
    Returns a dict with `apple_signed`, `authority`, `team_id`, `evidence`.
    """
    identifier = bundle.get("identifier", "")
    info: dict[str, Any] = {
        "apple_signed": False,
        "authority": "",
        "team_id": "",
        "evidence": "",
    }
    if identifier.startswith("com.apple."):
        info.update(
            apple_signed=True,
            authority="bundle-identifier-heuristic",
            evidence=f"CFBundleIdentifier={identifier}",
        )
    out = run_codesign(local_path)
    return apply_codesign_evidence(info, out)


def otool_binary(local_path: Path) -> Path | None:
    if local_path.is_file():
        return local_path
    if local_path.is_dir() and local_path.suffix == ".framework":
        stem = local_path.stem
        candidates = [local_path / stem]
        candidates.extend(local_path.glob(f"Versions/*/{stem}"))
        for candidate in candidates:
            if candidate.is_file():
                return candidate
        return None
    if local_path.is_dir():
        from .inventory import read_bundle_metadata
        bundle = read_bundle_metadata(local_path)
        executable = bundle.get("executable", "")
        if executable:
            candidate = local_path / "Contents/MacOS" / executable
            if candidate.is_file():
                return candidate
    return None


def run_otool_dependencies(local_path: Path) -> str:
    binary = otool_binary(local_path)
    if binary is None:
        return ""
    try:
        proc = subprocess.run(
            ["otool", "-L", "--", str(binary)],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""
    return (proc.stdout or "") + (proc.stderr or "")


def parse_dyld_dependencies(otool_output: str) -> dict[str, Any]:
    """Pure parser for `otool -L` output. Stable shape for tests."""
    result: dict[str, Any] = {
        "all_deps": [],
        "private_framework_deps": [],
        "dyld_cache_origin": False,
        "dyld_cache_paths": [],
    }
    if not otool_output:
        return result
    for raw_line in otool_output.splitlines():
        line = raw_line.strip()
        if not line or line.endswith(":"):
            continue
        match = re.match(r"^(\S[\S]*\.(?:dylib|framework/[^\s]+))", line)
        if not match:
            continue
        path = match.group(1)
        result["all_deps"].append(path)
        if "/PrivateFrameworks/" in path:
            result["private_framework_deps"].append(path)
        if path.startswith("/System/") and not Path(path).exists():
            result["dyld_cache_paths"].append(path)
    if result["dyld_cache_paths"]:
        result["dyld_cache_origin"] = True
    result["all_deps"] = result["all_deps"][:200]
    result["private_framework_deps"] = result["private_framework_deps"][:50]
    result["dyld_cache_paths"] = result["dyld_cache_paths"][:30]
    return result


def detect_dyld_dependencies(local_path: Path) -> dict[str, Any]:
    return parse_dyld_dependencies(run_otool_dependencies(local_path))


def build_os_component_facts(
    local_path: Path,
    bundle: dict[str, str],
    kind: str,
    components: list[dict[str, Any]],
) -> dict[str, Any]:
    """Aggregate OS-component facts: signing, dyld dependencies, MachServices."""
    signing = detect_apple_signing(local_path, bundle)
    dyld = detect_dyld_dependencies(local_path)
    mach_services: list[str] = []
    for comp in components:
        for service in comp.get("launchd", {}).get("mach_services", []):
            if service not in mach_services:
                mach_services.append(service)
    return {
        "kind": kind,
        "apple_signed": signing["apple_signed"],
        "authority": signing["authority"],
        "team_id": signing["team_id"],
        "signing_evidence": signing["evidence"],
        "all_dyld_deps": dyld["all_deps"],
        "private_framework_deps": dyld["private_framework_deps"],
        "dyld_cache_origin": dyld["dyld_cache_origin"],
        "dyld_cache_paths": dyld["dyld_cache_paths"],
        "mach_services": mach_services[:50],
    }
