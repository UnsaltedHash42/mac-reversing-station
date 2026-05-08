"""Inventory + dossier assembly."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .classify import classify_families, classify_surfaces
from .inventory import (
    detect_electron,
    find_components,
    read_bundle_metadata,
    target_kind,
)
from .signing import build_os_component_facts
from .source import build_source_correlation


def inventory_target(local_path: Path,
                     source_path: Path,
                     source_metadata: dict[str, str]) -> dict[str, Any]:
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


def summarize_components(components: list[dict[str, str]]) -> dict[str, Any]:
    by_kind: dict[str, int] = {}
    for item in components:
        by_kind[item["kind"]] = by_kind.get(item["kind"], 0) + 1
    return {
        "total": len(components),
        "by_kind": dict(sorted(by_kind.items())),
    }


def scriptorium_anchor_id(inventory: dict[str, Any]) -> str:
    return f"{inventory['pass_id']}:{inventory['target']['id']}"


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
