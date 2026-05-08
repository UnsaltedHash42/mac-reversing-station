#!/usr/bin/env python3
"""Initialize project state from a macOS app bundle, framework, installer, or binary."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit


EXECUTABLE_LIMIT = 200

OS_COMPONENT_BUNDLE_SUFFIXES = (
    ".xpc",
    ".systemextension",
    ".networkextension",
    ".appex",
    ".dext",
)

DAEMON_NAME_HINTS = ("daemon", "helper", "service")


@dataclass(frozen=True)
class IntakeResult:
    target_id: str
    local_path: Path
    target_map_path: Path
    dossier_path: Path
    family_labels: list[str]


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target_path", type=Path, help="App bundle, framework, installer, or binary path")
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path.cwd(),
        help="Project clone root to initialize (default: current directory)",
    )
    parser.add_argument("--pass-id", default="PASS-001", help="Pass ID to create or update")
    parser.add_argument("--target-id", help="Stable target ID for CORPUS.md and artifact names")
    parser.add_argument("--source-root", type=Path, help="Optional source checkout path for source-binary correlation")
    parser.add_argument("--source-ref", help="Optional source commit, tag, or build reference")
    parser.add_argument("--source-url", help="Optional source repository or release URL")
    parser.add_argument("--sast-report", type=Path, help="Optional SAST report path to correlate back to the binary")
    parser.add_argument(
        "--no-copy",
        action="store_true",
        help="Reference the original target path instead of copying it under targets/",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        result = start_target(
            source=args.target_path,
            project_root=args.project_root,
            pass_id=args.pass_id,
            target_id=args.target_id,
            copy_target=not args.no_copy,
            source_metadata=source_metadata_from_args(args),
        )
    except IntakeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print(f"OK - initialized {result.target_id} for {args.pass_id}")
    print(f"local target: {result.local_path}")
    print(f"target map: {result.target_map_path}")
    print(f"dossier: {result.dossier_path}")
    print(f"family labels: {', '.join(result.family_labels)}")
    return 0


class IntakeError(Exception):
    """Raised when target intake cannot safely complete."""


def start_target(
    source: Path,
    project_root: Path,
    pass_id: str,
    target_id: str | None = None,
    copy_target: bool = True,
    source_metadata: dict[str, str] | None = None,
) -> IntakeResult:
    project_root = project_root.resolve()
    source = source.expanduser().resolve()
    if not source.exists():
        raise IntakeError(f"target path does not exist: {source}")

    target_id = target_id or slugify(source.stem if source.suffix == ".app" else source.name)
    if not target_id:
        raise IntakeError(f"could not derive target id from: {source}")

    local_path = copy_or_reference_target(source, project_root, copy_target=copy_target)
    inventory = inventory_target(local_path, source_path=source, source_metadata=source_metadata or {})
    inventory["pass_id"] = pass_id
    inventory["target"]["id"] = target_id

    analysis_dir = project_root / "findings/analysis"
    analysis_dir.mkdir(parents=True, exist_ok=True)
    target_map_path = analysis_dir / f"{pass_id}-{target_id}-target-map.json"
    dossier_path = analysis_dir / f"{pass_id}-{target_id}-dossier.json"
    inventory["target_map_path"] = str(target_map_path.relative_to(project_root))
    inventory["dossier_path"] = str(dossier_path.relative_to(project_root))
    inventory["decision_support"] = build_decision_support(inventory)
    inventory["dossier"] = build_dossier(inventory)
    write_json(target_map_path, inventory)
    write_json(dossier_path, inventory["dossier"])
    update_corpus(project_root / "CORPUS.md", inventory)

    return IntakeResult(
        target_id=target_id,
        local_path=local_path,
        target_map_path=target_map_path,
        dossier_path=dossier_path,
        family_labels=inventory["classification"]["family_labels"],
    )


def copy_or_reference_target(source: Path, project_root: Path, copy_target: bool) -> Path:
    targets_dir = project_root / "targets"
    if not copy_target:
        return source

    try:
        source.relative_to(targets_dir.resolve())
        return source
    except ValueError:
        pass

    targets_dir.mkdir(parents=True, exist_ok=True)
    destination = targets_dir / source.name
    if destination.exists():
        if destination.is_dir():
            shutil.rmtree(destination)
        else:
            destination.unlink()

    if source.is_dir():
        shutil.copytree(source, destination, symlinks=True)
    else:
        shutil.copy2(source, destination)
    return destination.resolve()

def inventory_target(local_path: Path, source_path: Path, source_metadata: dict[str, str]) -> dict[str, Any]:
    bundle = read_bundle_metadata(local_path)
    components = find_components(local_path, bundle)
    electron = detect_electron(local_path)
    kind = target_kind(local_path)
    os_component = build_os_component_facts(local_path, bundle, kind, components)
    surfaces = classify_surfaces(local_path, bundle, components, electron, kind, os_component)
    family_labels = classify_families(local_path, surfaces)

    return {
        "target": {
            "name": local_path.name,
            "kind": kind,
            "source_path": str(source_path),
            "local_path": str(local_path),
        },
        "bundle": bundle,
        "components": components,
        "electron": electron,
        "os_component": os_component,
        "source_correlation": build_source_correlation(source_metadata),
        "classification": {
            "surfaces": surfaces,
            "family_labels": family_labels,
        },
    }


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
        raise IntakeError(f"could not read bundle Info.plist: {info_plist}: {exc}") from exc
    if not isinstance(data, dict):
        raise IntakeError(f"bundle Info.plist root must be a dictionary: {info_plist}")

    return {
        "identifier": str(data.get("CFBundleIdentifier", "")),
        "executable": str(data.get("CFBundleExecutable", "")),
        "short_version": str(data.get("CFBundleShortVersionString", "")),
        "bundle_version": str(data.get("CFBundleVersion", "")),
        "privacy_usage_keys": ",".join(sorted(key for key in data if is_privacy_usage_key(key))),
    }


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
                if kind == "system-extension" and looks_like_endpoint_security_client(nested, nested_bundle):
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
            elif ("LaunchDaemons" in rel.parts or "LaunchAgents" in rel.parts) and item.suffix == ".plist":
                comp = component("launchd-plist", item, root)
                parsed = read_launchd_plist(item)
                if parsed:
                    comp["launchd"] = parsed
                components.append(comp)
                seen.add(resolved)
            elif ("Contents/MacOS" in rel_text or is_executable(item)) and not should_skip_executable(item):
                components.append(component("executable", item, root))
                seen.add(resolved)
    elif root.is_file():
        components.append(component("binary", root, root.parent))

    return components


def component(kind: str, path: Path, root: Path) -> dict[str, str]:
    rel = path.relative_to(root) if path != root and root in path.parents else path.name
    data = {
        "kind": kind,
        "path": str(rel),
        "name": path.name,
    }
    file_hash = sha256_file(path) if path.is_file() else ""
    if file_hash:
        data["sha256"] = file_hash
    return data


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
    preload_scripts = relative_paths(root, (path for path in root.rglob("*.js") if "preload" in path.name.lower()))
    native_modules = relative_paths(root, root.rglob("*.node"))
    frameworks = relative_paths(root, (path for path in root.rglob("*.framework") if "electron" in path.name.lower()))
    package_metadata = read_package_metadata(root, package_json[:3])
    text = " ".join([root.name, *asar_archives, *package_json, *frameworks]).lower()
    dependency_names = package_metadata.get("dependency_names", [])
    has_electron_dependency = any("electron" in str(name).lower() for name in dependency_names)
    is_electron = bool(asar_archives or frameworks or "electron" in text or has_electron_dependency)

    return {
        "is_electron": is_electron,
        "asar_archives": asar_archives[:20],
        "package_json": package_json[:20],
        "preload_scripts": preload_scripts[:20],
        "native_modules": native_modules[:20],
        "frameworks": frameworks[:20],
        "package_metadata": package_metadata,
    }


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
            metadata["dependency_names"] = sorted(str(key) for key in dependencies)[:30]
        return metadata
    return {}


def source_metadata_from_args(args: argparse.Namespace) -> dict[str, str]:
    metadata: dict[str, str] = {}
    if args.source_root:
        metadata["source_root"] = str(args.source_root.expanduser())
    if args.source_ref:
        metadata["source_ref"] = args.source_ref
    if args.source_url:
        metadata["source_url"] = redact_url(args.source_url)
    if args.sast_report:
        metadata["sast_report"] = str(args.sast_report.expanduser().resolve())
    return metadata


def redact_url(value: str) -> str:
    parts = urlsplit(value)
    if not parts.username and not parts.password:
        return value
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    return urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))


def build_source_correlation(metadata: dict[str, str]) -> dict[str, str]:
    if not metadata:
        return {
            "status": "not-provided",
            "confidence": "none",
            "next_action": "Add source metadata only when source is available and useful for binary confirmation.",
        }

    confidence = "unverified"
    status = "provided"
    source_root = metadata.get("source_root", "")
    if source_root:
        confidence = "pending-binary-correlation"
        if not Path(source_root).exists():
            status = "provided-missing-local-path"

    result = dict(metadata)
    result.update(
        {
            "status": status,
            "confidence": confidence,
            "next_action": "Correlate source claims back to shipped binary symbols, strings, or decompiled functions.",
        }
    )
    return result


def build_decision_support(inventory: dict[str, Any]) -> dict[str, Any]:
    surfaces = set(inventory["classification"]["surfaces"])
    recipes: list[str] = ["bundle-dossier"]
    ghidra_scripts: list[str] = []
    coverage_gaps: list[str] = []

    if "xpc-services" in surfaces:
        recipes.append("map-xpc-endpoints")
        ghidra_scripts.append("scan_xpc_client_validation.py")
    if surfaces & {"privileged-helper-tools", "launchd-jobs", "updater"}:
        recipes.append("inspect-privileged-helper-or-updater")
        ghidra_scripts.append("scan_privileged_helper_surface.py")
    if surfaces & {"privacy-permissions", "keychain"}:
        recipes.append("review-tcc-and-persistent-authorization")
        ghidra_scripts.extend(["scan_tcc_prompt_surface.py", "scan_persistent_authorization.py"])
    if "electron-app" in surfaces:
        recipes.append("review-electron-ipc-and-packaging")
        coverage_gaps.append("Electron main/preload IPC requires source or ASAR review before dynamic confirmation.")
    if inventory["source_correlation"]["status"] != "not-provided":
        recipes.append("correlate-source-to-binary")
        coverage_gaps.append("Source metadata is unverified until tied to the shipped binary.")
    if not ghidra_scripts:
        recipes.append("inventory-first-manual-routing")
        coverage_gaps.append("No family-specific Ghidra sweep selected from intake alone.")

    coverage_gaps.append("Codesign, entitlements, notarization, and load-command details require follow-up tooling.")
    return {
        "watch_version": 1,
        "recommended_recipes": dedupe(recipes),
        "recommended_ghidra_scripts": dedupe(ghidra_scripts),
        "coverage_gaps": dedupe(coverage_gaps),
        "next_decision": next_decision(dedupe(recipes), dedupe(ghidra_scripts)),
    }


def build_dossier(inventory: dict[str, Any]) -> dict[str, Any]:
    return {
        "dossier_version": 1,
        "target": inventory["target"],
        "pass_id": inventory["pass_id"],
        "bundle": inventory["bundle"],
        "classification": inventory["classification"],
        "component_summary": summarize_components(inventory["components"]),
        "components": inventory["components"][:75],
        "electron": inventory["electron"],
        "os_component": inventory["os_component"],
        "source_correlation": inventory["source_correlation"],
        "decision_support": inventory["decision_support"],
        "scriptorium": {
            "anchor_id": scriptorium_anchor_id(inventory),
            "target_map_path": inventory["target_map_path"],
            "dossier_path": inventory["dossier_path"],
            "chronicle": "CHRONICLE.md",
        },
    }


def summarize_components(components: list[dict[str, str]]) -> dict[str, Any]:
    by_kind: dict[str, int] = {}
    for item in components:
        by_kind[item["kind"]] = by_kind.get(item["kind"], 0) + 1
    return {
        "total": len(components),
        "by_kind": dict(sorted(by_kind.items())),
    }


def next_decision(recipes: list[str], ghidra_scripts: list[str]) -> str:
    if ghidra_scripts:
        return f"Run first static sweep: {', '.join(ghidra_scripts)}"
    return f"Use recipe routing: {', '.join(recipes)}"


def dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def scriptorium_anchor_id(inventory: dict[str, Any]) -> str:
    return f"{inventory['pass_id']}:{inventory['target']['id']}"


def classify_surfaces(
    root: Path,
    bundle: dict[str, str],
    components: list[dict[str, Any]],
    electron: dict[str, Any],
    kind: str,
    os_component: dict[str, Any],
) -> list[str]:
    surfaces: set[str] = set()
    text = " ".join([root.name, *(component["path"] for component in components)]).lower()

    if any(component["kind"] == "xpc-service" for component in components) or "xpc" in text:
        surfaces.add("xpc-services")
    if any(component["kind"] == "helper-tool" for component in components):
        surfaces.add("privileged-helper-tools")
    if any(component["kind"] == "launchd-plist" for component in components):
        surfaces.add("launchd-jobs")
    if any(component.get("launchd", {}).get("mach_services") for component in components):
        surfaces.add("launchd-machservices")
    if "updater" in text or "sparkle" in text or "update" in text:
        surfaces.add("updater")
    if bundle.get("privacy_usage_keys"):
        surfaces.add("privacy-permissions")
    if "keychain" in text:
        surfaces.add("keychain")
    if "plugin" in text or "extension" in text:
        surfaces.add("plugin-or-extension")
    if electron["is_electron"]:
        surfaces.add("electron-app")
    if electron["asar_archives"]:
        surfaces.add("asar-archive")
    if electron["preload_scripts"]:
        surfaces.add("electron-preload-scripts")
    if electron["native_modules"]:
        surfaces.add("electron-native-modules")

    if any(component["kind"] == "system-extension" for component in components):
        surfaces.add("system-extension")
    if any(component["kind"] == "network-extension" for component in components):
        surfaces.add("network-extension")
    if any(component["kind"] == "appex" for component in components):
        surfaces.add("appex")
    if any(component["kind"] == "driverkit-extension" for component in components):
        surfaces.add("driverkit")
    if any(component.get("endpoint_security_client") for component in components):
        surfaces.add("endpoint-security-client")

    if os_component["apple_signed"]:
        surfaces.add("apple-signed")
    if os_component["private_framework_deps"]:
        surfaces.add("private-framework-dep")
    if os_component["dyld_cache_origin"]:
        surfaces.add("dyld-shared-cache-origin")

    os_component_target_kinds = {
        "framework",
        "system-extension",
        "network-extension",
        "appex",
        "driverkit-extension",
        "xpc-service",
        "daemon",
        "agent",
    }
    os_component_signal_surfaces = {
        "system-extension",
        "network-extension",
        "appex",
        "driverkit",
        "endpoint-security-client",
        "apple-signed",
        "private-framework-dep",
        "dyld-shared-cache-origin",
        "launchd-machservices",
    }
    if kind in os_component_target_kinds or surfaces & os_component_signal_surfaces:
        surfaces.add("os-component")

    return sorted(surfaces)


def classify_families(root: Path, surfaces: list[str]) -> list[str]:
    labels: list[str] = []
    name = root.name.lower()
    surface_set = set(surfaces)

    if surface_set & {"xpc-services", "privileged-helper-tools", "launchd-jobs", "updater"}:
        labels.append("privileged helpers / updaters")
    if re.search(r"(agent|security|edr|mdm|endpoint|filter)", name):
        labels.append("enterprise / security agents")
    if re.search(r"(developer|terminal|build|package|plugin|vm|virtual)", name) or "plugin-or-extension" in surface_set:
        labels.append("developer tools")
    if surface_set & {"privacy-permissions", "keychain"}:
        labels.append("TCC-heavy consumer apps")
    if "os-component" in surface_set:
        labels.append("apple-os-components")

    return labels or ["unknown/mixed"]


def update_corpus(corpus_path: Path, inventory: dict[str, Any]) -> None:
    if not corpus_path.is_file():
        raise IntakeError(f"CORPUS.md not found: {corpus_path}")

    text = corpus_path.read_text(encoding="utf-8")
    pass_row = corpus_pass_row(inventory)
    target_row = target_inventory_row(inventory)
    surface_row = surface_classification_row(inventory)
    family_row = family_routing_row(inventory)
    worklist_row = worklist_row_for(inventory)
    watch_row = watch_row_for(inventory)
    source_row = source_correlation_row(inventory)
    scriptorium_row = scriptorium_anchor_row(inventory)

    text = ensure_table_row(text, "## Corpus Passes", pass_row, row_key=f"| {inventory['pass_id']} |")
    text = ensure_table_row(
        text,
        "## Target Inventory",
        target_row,
        row_key=f"| {inventory['target']['id']} |",
    )
    for row in component_rows(inventory):
        text = ensure_table_row(text, "## Discovered Components", row, row_key=row)
    text = ensure_table_row(
        text,
        "## Surface Classification",
        surface_row,
        row_key=f"| {inventory['target']['id']} | {inventory['pass_id']} |",
    )
    text = ensure_table_row(
        text,
        "## Watch Decision Support",
        watch_row,
        row_key=f"| {inventory['target']['id']} | {inventory['pass_id']} |",
    )
    if source_row:
        text = ensure_table_row(
            text,
            "## Source-Binary Correlation",
            source_row,
            row_key=f"| {inventory['target']['id']} |",
        )
    text = ensure_table_row(
        text,
        "## Family Labels And Routing",
        family_row,
        row_key=f"| {inventory['target']['id']} | {', '.join(inventory['classification']['family_labels'])} |",
    )
    text = ensure_table_row(text, "## Scriptorium Anchors", scriptorium_row, row_key=f"| {scriptorium_anchor_id(inventory)} |")
    text = ensure_table_row(
        text,
        "## Current Hypotheses And Worklist",
        worklist_row,
        row_key=f"| {inventory['pass_id']} | Watch review for {inventory['target']['name']} |",
    )
    corpus_path.write_text(text, encoding="utf-8")


def corpus_pass_row(inventory: dict[str, Any]) -> str:
    labels = ", ".join(inventory["classification"]["family_labels"])
    surfaces = ", ".join(inventory["classification"]["surfaces"]) or "inventory pending"
    return f"| {inventory['pass_id']} | | {labels} | {surfaces} | | intake | `{inventory['pass_id']}` |"


def target_inventory_row(inventory: dict[str, Any]) -> str:
    bundle = inventory["bundle"]
    version = version_string(bundle)
    labels = ", ".join(inventory["classification"]["family_labels"])
    surfaces = ", ".join(inventory["classification"]["surfaces"]) or "none detected yet"
    source = inventory["target"]["source_path"]
    return (
        f"| {inventory['target']['id']} | {inventory['target']['name']} | {version} | "
        f"{source} | {labels} | {surfaces} | target map generated |"
    )


def component_rows(inventory: dict[str, Any]) -> list[str]:
    target_id = inventory["target"]["id"]
    rows = []
    for item in inventory["components"][:50]:
        rows.append(
            f"| {target_id} | {item['name']} | {item['kind']} | `{item['path']}` | intake inventory |"
        )
    return rows


def surface_classification_row(inventory: dict[str, Any]) -> str:
    surfaces = ", ".join(inventory["classification"]["surfaces"]) or "none detected yet"
    return (
        f"| {inventory['target']['id']} | {inventory['pass_id']} | {surfaces} | | "
        f"`{inventory['dossier_path']}` | Watch intake dossier |"
    )


def watch_row_for(inventory: dict[str, Any]) -> str:
    support = inventory["decision_support"]
    recipes = ", ".join(support["recommended_recipes"])
    gaps = "; ".join(support["coverage_gaps"])
    return (
        f"| {inventory['target']['id']} | {inventory['pass_id']} | `{inventory['dossier_path']}` | "
        f"{recipes} | {gaps} | {support['next_decision']} |"
    )


def source_correlation_row(inventory: dict[str, Any]) -> str:
    source = inventory["source_correlation"]
    if source["status"] == "not-provided":
        return ""
    ref = source.get("source_ref") or source.get("source_url") or source.get("source_root") or "provided"
    return (
        f"| {inventory['target']['id']} | {ref} | {source['confidence']} | "
        f"`{inventory['dossier_path']}` | {source['next_action']} |"
    )


def family_routing_row(inventory: dict[str, Any]) -> str:
    family_labels = inventory["classification"]["family_labels"]
    labels = ", ".join(family_labels)
    playbook = next_playbook(family_labels)
    unknown_notes = "needs manual routing" if "unknown/mixed" in family_labels else ""
    return f"| {inventory['target']['id']} | {labels} | initial | {unknown_notes} | {playbook} |"


def worklist_row_for(inventory: dict[str, Any]) -> str:
    support = inventory["decision_support"]
    return (
        f"| {inventory['pass_id']} | Watch review for {inventory['target']['name']} | "
        f"`{inventory['dossier_path']}` | {support['next_decision']} | pending |"
    )


def scriptorium_anchor_row(inventory: dict[str, Any]) -> str:
    return (
        f"| {scriptorium_anchor_id(inventory)} | {inventory['target']['id']} | `{inventory['dossier_path']}` | "
        f"Watch intake decision support | open |"
    )


def next_playbook(labels: list[str]) -> str:
    mapping = {
        "privileged helpers / updaters": "`docs/playbooks/privileged-helpers-updaters.md`",
        "enterprise / security agents": "`docs/playbooks/enterprise-security-agents.md`",
        "developer tools": "`docs/playbooks/developer-tools.md`",
        "TCC-heavy consumer apps": "`docs/playbooks/tcc-heavy-consumer-apps.md`",
        "unknown/mixed": "inventory-first manual routing",
    }
    return ", ".join(mapping[label] for label in labels if label in mapping)


def ensure_table_row(text: str, heading: str, row: str, row_key: str) -> str:
    lines = text.splitlines()
    try:
        heading_line = next(i for i, line in enumerate(lines) if line.strip() == heading)
    except StopIteration as exc:
        raise IntakeError(f"missing {heading} section in CORPUS.md") from exc
    section_end = len(lines)
    for index in range(heading_line + 1, len(lines)):
        if lines[index].startswith("## "):
            section_end = index
            break

    for index in range(heading_line + 1, section_end):
        if lines[index].startswith(row_key):
            lines[index] = row
            return "\n".join(lines) + "\n"

    insert_at = None
    for index in range(heading_line + 1, section_end):
        line = lines[index].strip()
        if line.startswith("|") and set(line.replace("|", "").strip()) <= {"-", ":"}:
            insert_at = index + 1
            break
        if index > heading_line + 8:
            break
    if insert_at is None:
        raise IntakeError(f"could not find table separator under {heading} in CORPUS.md")
    lines.insert(insert_at, row)
    return "\n".join(lines) + "\n"


def version_string(bundle: dict[str, str]) -> str:
    short = bundle.get("short_version", "")
    build = bundle.get("bundle_version", "")
    if short and build:
        return f"{short} ({build})"
    return short or build or "unknown"


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


def looks_like_endpoint_security_client(extension_root: Path, bundle: dict[str, str]) -> bool:
    name = extension_root.name.lower()
    identifier = bundle.get("identifier", "").lower()
    if any(token in name for token in ("endpointsecurity", "endpoint-security", "endpoint_security")):
        return True
    if any(token in identifier for token in ("endpointsecurity", "endpoint-security", "endpoint.security")):
        return True
    return False


def read_launchd_plist(path: Path) -> dict[str, Any]:
    """Read a launchd plist and extract MachServices, program arguments, watch paths."""
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
        "program_arguments": [str(arg) for arg in program_arguments][:20] if isinstance(program_arguments, list) else [],
        "mach_services": sorted(str(key) for key in mach_services)[:30] if isinstance(mach_services, dict) else [],
        "user_name": str(data.get("UserName", "")),
        "run_at_load": bool(data.get("RunAtLoad", False)),
        "watch_paths": [str(p) for p in watch_paths][:10] if isinstance(watch_paths, list) else [],
    }


def run_codesign(local_path: Path) -> str:
    """Run `codesign -dv` and return combined output. Empty string when codesign is unavailable."""
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


def codesign_target(local_path: Path) -> Path | None:
    if local_path.is_file():
        return local_path
    if local_path.is_dir():
        return local_path
    return None


def run_otool_dependencies(local_path: Path) -> str:
    """Run `otool -L` against the most likely main binary. Empty string on failure."""
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
        bundle = read_bundle_metadata(local_path)
        executable = bundle.get("executable", "")
        if executable:
            candidate = local_path / "Contents/MacOS" / executable
            if candidate.is_file():
                return candidate
    return None


def detect_apple_signing(local_path: Path, bundle: dict[str, str]) -> dict[str, Any]:
    """Best-effort detection of Apple signing.

    Combines `codesign -dv` output with bundle identifier heuristics. Returns a dict with
    `apple_signed`, `authority`, `team_id`, `evidence`. False positives are minimized by
    requiring an explicit Apple authority string from codesign or a `com.apple.` identifier.
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
    if authority and ("Software Signing" in authority or "Apple Code Signing Certification Authority" in authority):
        info["apple_signed"] = True
        info["authority"] = authority
        info["evidence"] = f"codesign Authority={authority}"
    elif authority and not info["apple_signed"]:
        info["authority"] = authority
        info["evidence"] = f"codesign Authority={authority}"
    return info


def detect_dyld_dependencies(local_path: Path) -> dict[str, Any]:
    """Detect framework dependencies and dyld shared cache origin via `otool -L`."""
    out = run_otool_dependencies(local_path)
    return parse_dyld_dependencies(out)


def parse_dyld_dependencies(otool_output: str) -> dict[str, Any]:
    """Parse `otool -L` style output. Pure function for testability."""
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


def build_os_component_facts(
    local_path: Path,
    bundle: dict[str, str],
    kind: str,
    components: list[dict[str, Any]],
) -> dict[str, Any]:
    """Aggregate OS-component facts: signing, dyld dependencies, OS build, MachServices."""
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


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
