"""CORPUS.md row builders + table writer."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ._util import version_string
from .classify import maturity_summary_text, next_playbook
from .dossier import scriptorium_anchor_id
from .inventory import IntakeError
from .source import apple_component_from_url


def os_topology_row_for(inventory: dict[str, Any]) -> str:
    surfaces = set(inventory["classification"]["surfaces"])
    if "os-component" not in surfaces:
        return ""
    target = inventory["target"]
    os_component = inventory.get("os_component", {})
    authority = os_component.get("authority") or "unknown"
    if os_component.get("team_id"):
        authority = f"{authority} ({os_component['team_id']})"
    mach_services = ", ".join(os_component.get("mach_services", [])[:5]) or "none captured"
    private_deps = os_component.get("private_framework_deps", [])
    if private_deps:
        framework_summary = (
            f"{len(private_deps)} private (e.g. {Path(private_deps[0]).name})"
        )
    elif os_component.get("all_dyld_deps"):
        framework_summary = f"{len(os_component['all_dyld_deps'])} total"
    else:
        framework_summary = "n/a (otool not run)"
    maturity = inventory["decision_support"].get("maturity_summary", "")
    os_build = os_component.get("os_build") or "intake-only"
    return (
        f"| {target['id']} | {target['kind']} | {authority} | {os_build} | "
        f"{mach_services} | {framework_summary} | {maturity} |"
    )


def apple_source_map_row(inventory: dict[str, Any]) -> str:
    source = inventory["source_correlation"]
    if source["status"] == "not-provided":
        return ""
    bundle_identifier = inventory.get("bundle", {}).get("identifier", "")
    source_url = source.get("source_url", "") or ""
    is_apple = (bundle_identifier.startswith("com.apple.")
                or "opensource.apple.com" in source_url)
    if not is_apple:
        return ""
    component = bundle_identifier or "unknown"
    if "opensource.apple.com" in source_url:
        component = apple_component_from_url(source_url) or component
    release = source.get("source_ref") or "unknown"
    cache_path = source.get("source_root") or "n/a"
    confidence = source.get("confidence", "unverified")
    notes = source.get("source_url") or "no URL provided"
    return (
        f"| {inventory['target']['id']} | {component} | {release} | "
        f"{cache_path} | {confidence} | {notes} |"
    )


def corpus_pass_row(inventory: dict[str, Any]) -> str:
    labels = ", ".join(inventory["classification"]["family_labels"])
    surfaces = ", ".join(inventory["classification"]["surfaces"]) or "inventory pending"
    return (
        f"| {inventory['pass_id']} | | {labels} | {surfaces} | | intake | "
        f"`{inventory['pass_id']}` |"
    )


def target_inventory_row(inventory: dict[str, Any]) -> str:
    bundle = inventory["bundle"]
    version = version_string(bundle)
    labels = ", ".join(inventory["classification"]["family_labels"])
    surfaces = ", ".join(inventory["classification"]["surfaces"]) or "none detected yet"
    source = inventory["target"]["source_path"]
    return (
        f"| {inventory['target']['id']} | {inventory['target']['name']} | "
        f"{version} | {source} | {labels} | {surfaces} | target map generated |"
    )


def component_rows(inventory: dict[str, Any]) -> list[str]:
    target_id = inventory["target"]["id"]
    rows = []
    for item in inventory["components"][:50]:
        rows.append(
            f"| {target_id} | {item['name']} | {item['kind']} | "
            f"`{item['path']}` | intake inventory |"
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
    maturity = (support.get("maturity_summary")
                or maturity_summary_text(support.get("maturity", {})))
    return (
        f"| {inventory['target']['id']} | {inventory['pass_id']} | "
        f"`{inventory['dossier_path']}` | {recipes} | {maturity} | {gaps} | "
        f"{support['next_decision']} |"
    )


def source_correlation_row(inventory: dict[str, Any]) -> str:
    source = inventory["source_correlation"]
    if source["status"] == "not-provided":
        return ""
    ref = (source.get("source_ref")
           or source.get("source_url")
           or source.get("source_root")
           or "provided")
    return (
        f"| {inventory['target']['id']} | {ref} | {source['confidence']} | "
        f"`{inventory['dossier_path']}` | {source['next_action']} |"
    )


def family_routing_row(inventory: dict[str, Any]) -> str:
    family_labels = inventory["classification"]["family_labels"]
    labels = ", ".join(family_labels)
    playbook = next_playbook(family_labels)
    unknown_notes = "needs manual routing" if "unknown/mixed" in family_labels else ""
    return (
        f"| {inventory['target']['id']} | {labels} | initial | "
        f"{unknown_notes} | {playbook} |"
    )


def worklist_row_for(inventory: dict[str, Any]) -> str:
    support = inventory["decision_support"]
    return (
        f"| {inventory['pass_id']} | Watch review for {inventory['target']['name']} | "
        f"`{inventory['dossier_path']}` | {support['next_decision']} | pending |"
    )


def scriptorium_anchor_row(inventory: dict[str, Any]) -> str:
    return (
        f"| {scriptorium_anchor_id(inventory)} | {inventory['target']['id']} | "
        f"`{inventory['dossier_path']}` | Watch intake decision support | open |"
    )


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
        raise IntakeError(
            f"could not find table separator under {heading} in CORPUS.md"
        )
    lines.insert(insert_at, row)
    return "\n".join(lines) + "\n"


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

    text = ensure_table_row(text, "## Corpus Passes", pass_row,
                            row_key=f"| {inventory['pass_id']} |")
    text = ensure_table_row(
        text, "## Target Inventory", target_row,
        row_key=f"| {inventory['target']['id']} |",
    )
    for row in component_rows(inventory):
        text = ensure_table_row(text, "## Discovered Components", row, row_key=row)
    text = ensure_table_row(
        text, "## Surface Classification", surface_row,
        row_key=f"| {inventory['target']['id']} | {inventory['pass_id']} |",
    )
    text = ensure_table_row(
        text, "## Watch Decision Support", watch_row,
        row_key=f"| {inventory['target']['id']} | {inventory['pass_id']} |",
    )
    if source_row:
        text = ensure_table_row(
            text, "## Source-Binary Correlation", source_row,
            row_key=f"| {inventory['target']['id']} |",
        )
    text = ensure_table_row(
        text, "## Family Labels And Routing", family_row,
        row_key=(f"| {inventory['target']['id']} | "
                 f"{', '.join(inventory['classification']['family_labels'])} |"),
    )
    os_topology_row = os_topology_row_for(inventory)
    if os_topology_row:
        text = ensure_table_row(
            text, "## OS Component Topology", os_topology_row,
            row_key=f"| {inventory['target']['id']} |",
        )
    apple_source_row = apple_source_map_row(inventory)
    if apple_source_row:
        text = ensure_table_row(
            text, "## Apple Source Map", apple_source_row,
            row_key=f"| {inventory['target']['id']} |",
        )
    text = ensure_table_row(
        text, "## Scriptorium Anchors", scriptorium_row,
        row_key=f"| {scriptorium_anchor_id(inventory)} |",
    )
    text = ensure_table_row(
        text, "## Current Hypotheses And Worklist", worklist_row,
        row_key=(f"| {inventory['pass_id']} | "
                 f"Watch review for {inventory['target']['name']} |"),
    )
    corpus_path.write_text(text, encoding="utf-8")
