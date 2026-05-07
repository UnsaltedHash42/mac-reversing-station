"""FastMCP stdio entry point for macre-vm-mcp."""

from __future__ import annotations

from fastmcp import FastMCP

from . import tools_codesign, tools_dtrace, tools_lldb, tools_system


def build_server() -> FastMCP:
    """Build and return a FastMCP server with all tool modules registered.

    Broken out so tests can instantiate a server without invoking stdio.
    """
    mcp = FastMCP(name="macre-vm-mcp")
    tools_codesign.register(mcp)
    tools_dtrace.register(mcp)
    tools_lldb.register(mcp)
    tools_system.register(mcp)
    return mcp


def main() -> None:
    build_server().run()


if __name__ == "__main__":
    main()
