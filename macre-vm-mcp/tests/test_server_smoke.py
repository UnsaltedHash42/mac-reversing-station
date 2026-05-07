"""Smoke tests: server builds, tools register, declared tools list is complete."""

from __future__ import annotations

import asyncio

import pytest

from macre_vm_mcp.server import build_server


EXPECTED_TOOLS = {
    "lldb_run",
    "lldb_break_and_inspect",
    "dtrace_script",
    "dtrace_oneliner",
    "codesign_inspect",
    "spctl_assess",
    "entitlement_dump",
    "log_stream",
    "launchctl_list",
    "launchctl_print",
}


def _extract_tool_names(mcp_server) -> set[str]:
    """Resolve FastMCP 3.x ``list_tools`` (async) -> set of tool names."""
    listing = mcp_server.list_tools()
    if asyncio.iscoroutine(listing):
        listing = asyncio.run(listing)
    names: set[str] = set()
    for tool in listing:
        name = getattr(tool, "name", None) or getattr(tool, "key", None)
        if name:
            names.add(name)
    return names


def test_build_server_returns_instance() -> None:
    mcp = build_server()
    assert mcp is not None


def test_all_expected_tools_registered() -> None:
    mcp = build_server()
    names = _extract_tool_names(mcp)
    missing = EXPECTED_TOOLS - names
    extra = names - EXPECTED_TOOLS
    assert not missing, f"missing tools: {sorted(missing)}"
    assert not extra, f"unexpected tools: {sorted(extra)}"


@pytest.mark.parametrize("tool_name", sorted(EXPECTED_TOOLS))
def test_each_tool_is_present(tool_name: str) -> None:
    mcp = build_server()
    assert tool_name in _extract_tool_names(mcp)
