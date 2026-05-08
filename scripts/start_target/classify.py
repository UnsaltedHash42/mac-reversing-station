"""Surface classification, family routing, decision support."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ._util import dedupe


SURFACE_MATURITY = {
    "xpc-services": "full-recipe",
    "launchd-jobs": "full-recipe",
    "launchd-machservices": "full-recipe",
    "privileged-helper-tools": "full-recipe",
    "private-framework-dep": "full-recipe",
    "apple-signed": "full-recipe",
    "os-component": "full-recipe",
    "updater": "full-recipe",
    "privacy-permissions": "full-recipe",
    "keychain": "full-recipe",
    "plugin-or-extension": "full-recipe",
    "electron-app": "full-recipe",
    "asar-archive": "full-recipe",
    "electron-preload-scripts": "full-recipe",
    "electron-native-modules": "full-recipe",
    "system-extension": "basic-inventory",
    "network-extension": "basic-inventory",
    "endpoint-security-client": "basic-inventory",
    "driverkit": "basic-inventory",
    "appex": "basic-inventory",
    "dyld-shared-cache-origin": "basic-inventory",
}

MATURITY_TIERS = ("full-recipe", "basic-inventory", "manual-route-needed")


def surface_maturity_map(surfaces: list[str]) -> dict[str, str]:
    return {
        surface: SURFACE_MATURITY.get(surface, "manual-route-needed")
        for surface in surfaces
    }


def maturity_summary_text(maturity: dict[str, str]) -> str:
    if not maturity:
        return "no observed surfaces"
    counts: dict[str, list[str]] = {tier: [] for tier in MATURITY_TIERS}
    for surface, tier in sorted(maturity.items()):
        counts.setdefault(tier, []).append(surface)
    parts: list[str] = []
    for tier in MATURITY_TIERS:
        members = counts.get(tier, [])
        if members:
            parts.append(f"{tier}: {', '.join(members)}")
    return "; ".join(parts) or "no observed surfaces"


def maturity_coverage_gaps(maturity: dict[str, str]) -> list[str]:
    gaps: list[str] = []
    basic = sorted(s for s, tier in maturity.items() if tier == "basic-inventory")
    manual = sorted(s for s, tier in maturity.items() if tier == "manual-route-needed")
    if basic:
        gaps.append(
            "Basic-inventory surfaces (operator drives the recipe): "
            + ", ".join(basic) + "."
        )
    if manual:
        gaps.append(
            "Manual-route-needed surfaces (no paired recipe yet): "
            + ", ".join(manual) + "."
        )
    return gaps


def classify_surfaces(
    root: Path,
    bundle: dict[str, str],
    components: list[dict[str, Any]],
    electron: dict[str, Any],
    kind: str,
    os_component: dict[str, Any],
) -> list[str]:
    surfaces: set[str] = set()
    text = " ".join([root.name, *(c["path"] for c in components)]).lower()

    if any(c["kind"] == "xpc-service" for c in components) or "xpc" in text:
        surfaces.add("xpc-services")
    if any(c["kind"] == "helper-tool" for c in components):
        surfaces.add("privileged-helper-tools")
    if any(c["kind"] == "launchd-plist" for c in components):
        surfaces.add("launchd-jobs")
    if any(c.get("launchd", {}).get("mach_services") for c in components):
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

    if any(c["kind"] == "system-extension" for c in components):
        surfaces.add("system-extension")
    if any(c["kind"] == "network-extension" for c in components):
        surfaces.add("network-extension")
    if any(c["kind"] == "appex" for c in components):
        surfaces.add("appex")
    if any(c["kind"] == "driverkit-extension" for c in components):
        surfaces.add("driverkit")
    if any(c.get("endpoint_security_client") for c in components):
        surfaces.add("endpoint-security-client")

    if os_component["apple_signed"]:
        surfaces.add("apple-signed")
    if os_component["private_framework_deps"]:
        surfaces.add("private-framework-dep")
    if os_component["dyld_cache_origin"]:
        surfaces.add("dyld-shared-cache-origin")

    os_component_target_kinds = {
        "framework", "system-extension", "network-extension", "appex",
        "driverkit-extension", "xpc-service", "daemon", "agent",
    }
    os_component_signal_surfaces = {
        "system-extension", "network-extension", "appex", "driverkit",
        "endpoint-security-client", "apple-signed", "private-framework-dep",
        "dyld-shared-cache-origin", "launchd-machservices",
    }
    if kind in os_component_target_kinds or surfaces & os_component_signal_surfaces:
        surfaces.add("os-component")

    return sorted(surfaces)


def classify_families(root: Path, surfaces: list[str]) -> list[str]:
    labels: list[str] = []
    name = root.name.lower()
    surface_set = set(surfaces)

    if surface_set & {"xpc-services", "privileged-helper-tools",
                      "launchd-jobs", "updater"}:
        labels.append("privileged helpers / updaters")
    if re.search(r"(agent|security|edr|mdm|endpoint|filter)", name):
        labels.append("enterprise / security agents")
    if (re.search(r"(developer|terminal|build|package|plugin|vm|virtual)", name)
            or "plugin-or-extension" in surface_set):
        labels.append("developer tools")
    if surface_set & {"privacy-permissions", "keychain"}:
        labels.append("TCC-heavy consumer apps")
    if "os-component" in surface_set:
        labels.append("apple-os-components")

    return labels or ["unknown/mixed"]


def next_decision(recipes: list[str], ghidra_scripts: list[str]) -> str:
    if ghidra_scripts:
        return f"Run first static sweep: {', '.join(ghidra_scripts)}"
    return f"Use recipe routing: {', '.join(recipes)}"


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
        ghidra_scripts.extend(
            ["scan_tcc_prompt_surface.py", "scan_persistent_authorization.py"]
        )
    if "electron-app" in surfaces:
        recipes.append("review-electron-ipc-and-packaging")
        coverage_gaps.append(
            "Electron main/preload IPC requires source or ASAR review "
            "before dynamic confirmation."
        )
    if inventory["source_correlation"]["status"] != "not-provided":
        recipes.append("correlate-source-to-binary")
        coverage_gaps.append(
            "Source metadata is unverified until tied to the shipped binary."
        )
    if not ghidra_scripts:
        recipes.append("inventory-first-manual-routing")
        coverage_gaps.append(
            "No family-specific Ghidra sweep selected from intake alone."
        )

    coverage_gaps.append(
        "Codesign, entitlements, notarization, and load-command details "
        "require follow-up tooling."
    )

    maturity = surface_maturity_map(sorted(surfaces))
    coverage_gaps.extend(maturity_coverage_gaps(maturity))

    return {
        "watch_version": 1,
        "recommended_recipes": dedupe(recipes),
        "recommended_ghidra_scripts": dedupe(ghidra_scripts),
        "coverage_gaps": dedupe(coverage_gaps),
        "maturity": maturity,
        "maturity_summary": maturity_summary_text(maturity),
        "next_decision": next_decision(dedupe(recipes), dedupe(ghidra_scripts)),
    }


def next_playbook(labels: list[str]) -> str:
    mapping = {
        "privileged helpers / updaters":
            "`docs/playbooks/privileged-helpers-updaters.md`",
        "enterprise / security agents":
            "`docs/playbooks/enterprise-security-agents.md`",
        "developer tools": "`docs/playbooks/developer-tools.md`",
        "TCC-heavy consumer apps":
            "`docs/playbooks/tcc-heavy-consumer-apps.md`",
        "unknown/mixed": "inventory-first manual routing",
    }
    return ", ".join(mapping[label] for label in labels if label in mapping)
