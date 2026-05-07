"""System-facing tools: ``log stream``, ``launchctl``."""

from __future__ import annotations

from typing import Any

from fastmcp import FastMCP

from ._proc import run


def register(mcp: FastMCP) -> None:
    @mcp.tool
    def log_stream(
        predicate: str,
        style: str = "compact",
        timeout_sec: float = 10.0,
    ) -> dict[str, Any]:
        """Run ``log stream --predicate <expr>`` for a bounded duration.

        Example predicate:
            eventMessage CONTAINS "TCC"
            subsystem == "com.apple.tccd" AND eventMessage CONTAINS "prompt"

        ``style`` is one of default | compact | json | ndjson | syslog.
        """
        return run(
            ["/usr/bin/log", "stream", "--predicate", predicate, "--style", style],
            timeout=timeout_sec,
        ).to_dict()

    @mcp.tool
    def launchctl_list(service_filter: str | None = None) -> dict[str, Any]:
        """Run ``launchctl list``. Optionally pass a substring filter.

        The filter is applied to stdout *after* capture (client-side grep),
        because ``launchctl list`` does not accept a regex.
        """
        result = run(["/bin/launchctl", "list"])
        stdout = result.stdout
        if service_filter:
            stdout = "\n".join(
                line for line in stdout.splitlines() if service_filter in line
            )
        return {
            "returncode": result.returncode,
            "stdout": stdout,
            "stderr": result.stderr,
            "timed_out": result.timed_out,
            "filter_applied": service_filter,
        }

    @mcp.tool
    def launchctl_print(service_target: str) -> dict[str, Any]:
        """Run ``launchctl print <service-target>``.

        ``service-target`` is a domain/service spec — e.g.
        ``system/com.apple.tccd``, ``gui/$(id -u)/com.apple.Finder``.
        """
        return run(["/bin/launchctl", "print", service_target]).to_dict()
