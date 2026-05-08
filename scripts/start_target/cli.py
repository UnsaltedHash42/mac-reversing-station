"""CLI entry point. Composes the pipeline: copy/reference -> inventory ->
decision support -> dossier -> corpus update."""

from __future__ import annotations

import argparse
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

from ._util import slugify, write_json
from .classify import build_decision_support
from .corpus import update_corpus
from .dossier import build_dossier, inventory_target
from .inventory import IntakeError
from .source import source_metadata_from_args


@dataclass(frozen=True)
class IntakeResult:
    target_id: str
    local_path: Path
    target_map_path: Path
    dossier_path: Path
    family_labels: list[str]


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Initialize project state from a macOS app bundle, "
                    "framework, installer, or binary."
    )
    parser.add_argument("target_path", type=Path,
                        help="App bundle, framework, installer, or binary path")
    parser.add_argument("--project-root", type=Path, default=Path.cwd(),
                        help="Project clone root to initialize (default: cwd)")
    parser.add_argument("--pass-id", default="PASS-001",
                        help="Pass ID to create or update")
    parser.add_argument("--target-id",
                        help="Stable target ID for CORPUS.md and artifact names")
    parser.add_argument("--source-root", type=Path,
                        help="Optional source checkout path for source-binary correlation")
    parser.add_argument("--source-ref",
                        help="Optional source commit, tag, or build reference")
    parser.add_argument("--source-url",
                        help="Optional source repository or release URL")
    parser.add_argument("--sast-report", type=Path,
                        help="Optional SAST report path to correlate back to the binary")
    parser.add_argument("--no-copy", action="store_true",
                        help="Reference the original target path instead of "
                             "copying it under targets/")
    return parser.parse_args(argv)


def copy_or_reference_target(source: Path, project_root: Path,
                             copy_target: bool) -> Path:
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

    target_id = target_id or slugify(
        source.stem if source.suffix == ".app" else source.name
    )
    if not target_id:
        raise IntakeError(f"could not derive target id from: {source}")

    local_path = copy_or_reference_target(source, project_root, copy_target=copy_target)
    inventory = inventory_target(local_path, source_path=source,
                                 source_metadata=source_metadata or {})
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
