"""MCP (Model Context Protocol) server for HATCHERY — local, stdio, stdlib only (D24)."""

from __future__ import annotations

from engine.mcp.server import (
    LATEST_PROTOCOL_VERSION,
    MCPServer,
    SERVER_NAME,
    SERVER_VERSION,
    SUPPORTED_PROTOCOL_VERSIONS,
    main,
)
from engine.mcp.tools import DEFAULT_RESULTS_ROOT, Tool, ToolError, build_tools

__all__ = [
    "DEFAULT_RESULTS_ROOT",
    "LATEST_PROTOCOL_VERSION",
    "MCPServer",
    "SERVER_NAME",
    "SERVER_VERSION",
    "SUPPORTED_PROTOCOL_VERSIONS",
    "Tool",
    "ToolError",
    "build_tools",
    "main",
]
