"""Source-correlation metadata helpers."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from ._util import redact_url


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


def build_source_correlation(metadata: dict[str, str]) -> dict[str, str]:
    if not metadata:
        return {
            "status": "not-provided",
            "confidence": "none",
            "next_action": (
                "Add source metadata only when source is available "
                "and useful for binary confirmation."
            ),
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
            "next_action": (
                "Correlate source claims back to shipped binary symbols, "
                "strings, or decompiled functions."
            ),
        }
    )
    return result


def apple_component_from_url(url: str) -> str:
    match = re.search(
        r"opensource\.apple\.com/.*?/([^/]+?)(?:-[^/]+)?(?:/|\.tar\.gz|$)", url
    )
    if match:
        return match.group(1)
    return ""
