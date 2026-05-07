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
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


EXECUTABLE_LIMIT = 200


@dataclass(frozen=True)
class IntakeResult:
    target_id: str
    local_path: Path
    target_map_path: Path
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
        )
    except IntakeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print(f"OK - initialized {result.target_id} for {args.pass_id}")
    print(f"local target: {result.local_path}")
    print(f"target map: {result.target_map_path}")
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
) -> IntakeResult:
    project_root = project_root.resolve()
    source = source.expanduser().resolve()
    if not source.exists():
        raise IntakeError(f"target path does not exist: {source}")

    target_id = target_id or slugify(source.stem if source.suffix == ".app" else source.name)
    if not target_id:
        raise IntakeError(f"could not derive target id from: {source}")

    local_path = copy_or_reference_target(source, project_root, copy_target=copy_target)
    inventory = inventory_target(local_path, source_path=source)
    inventory["pass_id"] = pass_id
    inventory["target"]["id"] = target_id

    analysis_dir = project_root / "findings/analysis"
    analysis_dir.mkdir(parents=True, exist_ok=True)
    target_map_path = analysis_dir / f"{pass_id}-{target_id}-target-map.json"
    inventory["target_map_path"] = str(target_map_path.relative_to(project_root))
    write_json(target_map_path, inventory)
    update_corpus(project_root / "CORPUS.md", inventory)

    return IntakeResult(
        target_id=target_id,
        local_path=local_path,
        target_map_path=target_map_path,
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

def inventory_target(local_path: Path, source_path: Path) -> dict[str, Any]:
    bundle = read_bundle_metadata(local_path)
    components = find_components(local_path, bundle)
    surfaces = classify_surfaces(local_path, bundle, components)
    family_labels = classify_families(local_path, surfaces)

    return {
        "target": {
            "name": local_path.name,
            "kind": target_kind(local_path),
            "source_path": str(source_path),
            "local_path": str(local_path),
        },
        "bundle": bundle,
        "components": components,
        "classification": {
            "surfaces": surfaces,
            "family_labels": family_labels,
        },
    }


def target_kind(path: Path) -> str:
    if path.is_dir() and path.suffix == ".app":
        return "app-bundle"
    if path.is_dir() and path.suffix == ".framework":
        return "framework"
    if path.suffix in {".pkg", ".dmg"}:
        return "installer"
    if path.is_file():
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


def find_components(root: Path, bundle: dict[str, str]) -> list[dict[str, str]]:
    components: list[dict[str, str]] = []
    seen: set[Path] = set()

    main_executable = root / "Contents/MacOS" / bundle.get("executable", "")
    if bundle.get("executable") and main_executable.is_file():
        components.append(component("main-executable", main_executable, root))
        seen.add(main_executable.resolve())

    for xpc_dir in (sorted(root.rglob("*.xpc")) if root.is_dir() else []):
        if xpc_dir.is_dir():
            components.append(component("xpc-service", xpc_dir, root))

    if root.is_dir():
        for item in sorted(root.rglob("*")):
            if len(components) >= EXECUTABLE_LIMIT:
                break
            if not item.is_file():
                continue
            resolved = item.resolve()
            if resolved in seen:
                continue
            if is_inside_bundle(item, ".xpc"):
                continue
            rel = item.relative_to(root)
            rel_text = str(rel)
            if "HelperTools" in rel.parts and is_executable(item):
                components.append(component("helper-tool", item, root))
                seen.add(resolved)
            elif ("LaunchDaemons" in rel.parts or "LaunchAgents" in rel.parts) and item.suffix == ".plist":
                components.append(component("launchd-plist", item, root))
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


def classify_surfaces(root: Path, bundle: dict[str, str], components: list[dict[str, str]]) -> list[str]:
    surfaces: set[str] = set()
    text = " ".join([root.name, *(component["path"] for component in components)]).lower()

    if any(component["kind"] == "xpc-service" for component in components) or "xpc" in text:
        surfaces.add("xpc-services")
    if any(component["kind"] == "helper-tool" for component in components):
        surfaces.add("privileged-helper-tools")
    if any(component["kind"] == "launchd-plist" for component in components):
        surfaces.add("launchd-jobs")
    if "updater" in text or "sparkle" in text or "update" in text:
        surfaces.add("updater")
    if bundle.get("privacy_usage_keys"):
        surfaces.add("privacy-permissions")
    if "keychain" in text:
        surfaces.add("keychain")
    if "plugin" in text or "extension" in text:
        surfaces.add("plugin-or-extension")

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

    text = ensure_table_row(text, "## Corpus Passes", pass_row, row_key=f"| {inventory['pass_id']} |")
    text = ensure_table_row(
        text,
        "## Target Inventory",
        target_row,
        row_key=f"| {inventory['target']['id']} |",
    )
    for row in component_rows(inventory):
        text = ensure_table_row(text, "## Discovered Components", row, row_key=row)
    text = ensure_table_row(text, "## Surface Classification", surface_row, row_key=surface_row)
    text = ensure_table_row(
        text,
        "## Family Labels And Routing",
        family_row,
        row_key=f"| {inventory['target']['id']} | {', '.join(inventory['classification']['family_labels'])} |",
    )
    text = ensure_table_row(text, "## Current Hypotheses And Worklist", worklist_row, row_key=worklist_row)
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
        f"`{inventory['target_map_path']}` | intake inventory |"
    )


def family_routing_row(inventory: dict[str, Any]) -> str:
    family_labels = inventory["classification"]["family_labels"]
    labels = ", ".join(family_labels)
    playbook = next_playbook(family_labels)
    unknown_notes = "needs manual routing" if "unknown/mixed" in family_labels else ""
    return f"| {inventory['target']['id']} | {labels} | initial | {unknown_notes} | {playbook} |"


def worklist_row_for(inventory: dict[str, Any]) -> str:
    return (
        f"| {inventory['pass_id']} | Review intake inventory for {inventory['target']['name']} | "
        f"`{inventory['target_map_path']}` | Pick first static sweep from family labels | pending |"
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
    if row_key in text:
        return text

    lines = text.splitlines()
    try:
        heading_line = next(i for i, line in enumerate(lines) if line.strip() == heading)
    except StopIteration as exc:
        raise IntakeError(f"missing {heading} section in CORPUS.md") from exc
    insert_at = None
    for index in range(heading_line + 1, len(lines)):
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
