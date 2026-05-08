"""Bundle metadata, component discovery, Electron detection."""

from __future__ import annotations

import json
import plistlib
from pathlib import Path
from typing import Any

from ._util import (
    is_executable,
    is_inside_any_bundle,
    is_privacy_usage_key,
    is_within_root,
    relative_paths,
    sha256_file,
    should_skip_executable,
)


EXECUTABLE_LIMIT = 200

OS_COMPONENT_BUNDLE_SUFFIXES = (
    ".xpc",
    ".systemextension",
    ".networkextension",
    ".appex",
    ".dext",
)

DAEMON_NAME_HINTS = ("daemon", "helper", "service")


class IntakeError(Exception):
    """Raised when target intake cannot safely complete."""


def target_kind(path: Path) -> str:
    if path.is_dir():
        suffix_kinds = {
            ".app": "app-bundle",
            ".framework": "framework",
            ".systemextension": "system-extension",
            ".networkextension": "network-extension",
            ".appex": "appex",
            ".dext": "driverkit-extension",
            ".xpc": "xpc-service",
        }
        if path.suffix in suffix_kinds:
            return suffix_kinds[path.suffix]
    if path.suffix in {".pkg", ".dmg"}:
        return "installer"
    if path.is_file():
        name = path.name.lower()
        if any(hint in name for hint in DAEMON_NAME_HINTS):
            return "daemon"
        if name.endswith("agent"):
            return "agent"
        if len(name) >= 4 and name.endswith("d") and "." not in name:
            return "daemon"
        return "binary"
    return "directory"


def read_bundle_metadata(path: Path) -> dict[str, str]:
    info_plist = path / "Contents/Info.plist"
    if not info_plist.is_file():
        return {}

    try:
        with info_plist.open("rb") as fh:
            data = plistlib.load(fh)
    except (OSError, plistlib.InvalidFileException) as exc:
        raise IntakeError(
            f"could not read bundle Info.plist: {info_plist}: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise IntakeError(
            f"bundle Info.plist root must be a dictionary: {info_plist}"
        )

    return {
        "identifier": str(data.get("CFBundleIdentifier", "")),
        "executable": str(data.get("CFBundleExecutable", "")),
        "short_version": str(data.get("CFBundleShortVersionString", "")),
        "bundle_version": str(data.get("CFBundleVersion", "")),
        "privacy_usage_keys": ",".join(
            sorted(key for key in data if is_privacy_usage_key(key))
        ),
    }


def looks_like_endpoint_security_client(extension_root: Path,
                                        bundle: dict[str, str]) -> bool:
    name = extension_root.name.lower()
    identifier = bundle.get("identifier", "").lower()
    tokens = ("endpointsecurity", "endpoint-security", "endpoint_security",
              "endpoint.security")
    return any(t in name for t in tokens) or any(t in identifier for t in tokens)


def read_launchd_plist(path: Path) -> dict[str, Any]:
    """Read a launchd plist; extract MachServices, program args, watch paths."""
    if not path.is_file():
        return {}
    try:
        with path.open("rb") as fh:
            data = plistlib.load(fh)
    except (OSError, plistlib.InvalidFileException):
        return {}
    if not isinstance(data, dict):
        return {}
    program_arguments = data.get("ProgramArguments")
    mach_services = data.get("MachServices")
    watch_paths = data.get("WatchPaths")
    return {
        "label": str(data.get("Label", "")),
        "program_arguments":
            [str(arg) for arg in program_arguments][:20]
            if isinstance(program_arguments, list) else [],
        "mach_services":
            sorted(str(key) for key in mach_services)[:30]
            if isinstance(mach_services, dict) else [],
        "user_name": str(data.get("UserName", "")),
        "run_at_load": bool(data.get("RunAtLoad", False)),
        "watch_paths":
            [str(p) for p in watch_paths][:10]
            if isinstance(watch_paths, list) else [],
    }


def component(kind: str, path: Path, root: Path) -> dict[str, str]:
    rel = path.relative_to(root) if path != root and root in path.parents else path.name
    data: dict[str, str] = {
        "kind": kind,
        "path": str(rel),
        "name": path.name,
    }
    file_hash = sha256_file(path) if path.is_file() else ""
    if file_hash:
        data["sha256"] = file_hash
    return data


def find_components(root: Path, bundle: dict[str, str]) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    seen: set[Path] = set()

    main_executable = root / "Contents/MacOS" / bundle.get("executable", "")
    if bundle.get("executable") and main_executable.is_file():
        components.append(component("main-executable", main_executable, root))
        seen.add(main_executable.resolve())

    if root.is_dir():
        nested_bundle_kinds = {
            ".xpc": "xpc-service",
            ".systemextension": "system-extension",
            ".networkextension": "network-extension",
            ".appex": "appex",
            ".dext": "driverkit-extension",
        }
        for suffix, kind in nested_bundle_kinds.items():
            for nested in sorted(root.rglob(f"*{suffix}")):
                if not nested.is_dir() or nested == root:
                    continue
                comp = component(kind, nested, root)
                nested_bundle = read_bundle_metadata(nested)
                if nested_bundle:
                    comp["bundle_identifier"] = nested_bundle.get("identifier", "")
                if (kind == "system-extension"
                        and looks_like_endpoint_security_client(nested, nested_bundle)):
                    comp["endpoint_security_client"] = True
                components.append(comp)

    if root.is_dir():
        for item in sorted(root.rglob("*")):
            if len(components) >= EXECUTABLE_LIMIT:
                break
            if not item.is_file():
                continue
            resolved = item.resolve()
            if resolved in seen:
                continue
            if is_inside_any_bundle(item, OS_COMPONENT_BUNDLE_SUFFIXES):
                continue
            rel = item.relative_to(root)
            rel_text = str(rel)
            if "HelperTools" in rel.parts and is_executable(item):
                components.append(component("helper-tool", item, root))
                seen.add(resolved)
            elif (("LaunchDaemons" in rel.parts or "LaunchAgents" in rel.parts)
                  and item.suffix == ".plist"):
                comp = component("launchd-plist", item, root)
                parsed = read_launchd_plist(item)
                if parsed:
                    comp["launchd"] = parsed
                components.append(comp)
                seen.add(resolved)
            elif (("Contents/MacOS" in rel_text or is_executable(item))
                  and not should_skip_executable(item)):
                components.append(component("executable", item, root))
                seen.add(resolved)
    elif root.is_file():
        components.append(component("binary", root, root.parent))

    return components


def detect_electron(root: Path) -> dict[str, Any]:
    if not root.is_dir():
        return {
            "is_electron": False,
            "asar_archives": [],
            "package_json": [],
            "preload_scripts": [],
            "native_modules": [],
            "frameworks": [],
            "package_metadata": {},
        }

    asar_archives = relative_paths(root, root.rglob("*.asar"))
    package_json = relative_paths(root, root.rglob("package.json"))
    preload_scripts = relative_paths(
        root, (path for path in root.rglob("*.js") if "preload" in path.name.lower())
    )
    native_modules = relative_paths(root, root.rglob("*.node"))
    frameworks = relative_paths(
        root, (path for path in root.rglob("*.framework") if "electron" in path.name.lower())
    )
    package_metadata = read_package_metadata(root, package_json[:3])
    text = " ".join([root.name, *asar_archives, *package_json, *frameworks]).lower()
    dependency_names = package_metadata.get("dependency_names", [])
    has_electron_dependency = any(
        "electron" in str(name).lower() for name in dependency_names
    )
    is_electron = bool(asar_archives or frameworks or "electron" in text
                       or has_electron_dependency)

    return {
        "is_electron": is_electron,
        "asar_archives": asar_archives[:20],
        "package_json": package_json[:20],
        "preload_scripts": preload_scripts[:20],
        "native_modules": native_modules[:20],
        "frameworks": frameworks[:20],
        "package_metadata": package_metadata,
    }


def read_package_metadata(root: Path, package_paths: list[str]) -> dict[str, Any]:
    for rel_path in package_paths:
        path = root / rel_path
        if path.is_symlink() or not is_within_root(path, root.resolve()):
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        metadata = {
            key: data[key]
            for key in ("name", "version", "main")
            if isinstance(data.get(key), str)
        }
        dependencies = data.get("dependencies")
        if isinstance(dependencies, dict):
            metadata["dependency_names"] = sorted(str(k) for k in dependencies)[:30]
        return metadata
    return {}
