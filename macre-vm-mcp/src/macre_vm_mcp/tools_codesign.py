"""codesign / spctl / entitlement tooling."""

from __future__ import annotations

import plistlib
import re
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from ._proc import run


_CODESIGN_KV = re.compile(r"^(?P<key>[A-Za-z][A-Za-z0-9 _-]*)=(?P<value>.*)$")


def _parse_codesign_dv(stderr_text: str) -> dict[str, str]:
    """``codesign -dv`` prints key=value on stderr; parse into a dict."""
    parsed: dict[str, str] = {}
    for line in stderr_text.splitlines():
        line = line.strip()
        if not line:
            continue
        match = _CODESIGN_KV.match(line)
        if match:
            key = match.group("key").strip().replace(" ", "_").lower()
            val = match.group("value").strip()
            parsed.setdefault(key, val)
    return parsed


def register(mcp: FastMCP) -> None:
    @mcp.tool
    def codesign_inspect(binary_path: str) -> dict[str, Any]:
        """Run ``codesign -dvvv --entitlements - --requirements -`` and parse.

        Returns: {parsed: {...}, raw: <full stderr text>, returncode, ...}.
        """
        result = run(
            [
                "/usr/bin/codesign",
                "-dvvv",
                "--entitlements",
                "-",
                "--requirements",
                "-",
                binary_path,
            ]
        )
        parsed = _parse_codesign_dv(result.stderr)
        return {
            **result.to_dict(),
            "parsed": parsed,
        }

    @mcp.tool
    def spctl_assess(path: str, assess_type: str = "execute") -> dict[str, Any]:
        """Run ``spctl --assess --verbose=4 --type <type> <path>``.

        ``assess_type`` is one of execute | install | open (spctl's
        accepted assessment targets).
        """
        return run(
            [
                "/usr/sbin/spctl",
                "--assess",
                "--verbose=4",
                f"--type={assess_type}",
                path,
            ]
        ).to_dict()

    @mcp.tool
    def entitlement_dump(binary_path: str) -> dict[str, Any]:
        """Dump entitlements as a parsed plist dict.

        Uses ``codesign -d --entitlements :-`` which emits the raw plist
        bytes on stdout (no CMS wrapper).
        """
        result = run(
            [
                "/usr/bin/codesign",
                "-d",
                "--entitlements",
                ":-",
                binary_path,
            ]
        )
        entitlements: dict[str, Any] = {}
        parse_error: str | None = None
        if result.stdout:
            try:
                entitlements = plistlib.loads(result.stdout.encode("utf-8", errors="surrogateescape"))
            except (plistlib.InvalidFileException, ValueError, TypeError) as exc:
                parse_error = f"plist parse failed: {exc}"
        return {
            **result.to_dict(),
            "entitlements": entitlements,
            "parse_error": parse_error,
        }
