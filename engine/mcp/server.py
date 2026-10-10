"""A minimal, dependency-free MCP server over stdio (D24).

HATCHERY is the kind of tool an agent should be able to call. This exposes it as
an MCP server so an LLM agent can `submit_sample`, `get_report`, `get_iocs`,
`triage_run` and `cluster_runs` — the deep dive's "cheap to build (the API
exists), disproportionate value" item.

It is deliberately hand-written over stdlib rather than pulling in an SDK: the
protocol surface a local tool needs is small (``initialize``, ``tools/list``,
``tools/call``, ``ping``), the transport is newline-delimited JSON-RPC 2.0 on
stdio, and every line is verified by a test that drives the server as a real
subprocess. Fewer moving parts is the point.

**Trust model.** stdio only — this is a local process with the operator's
privileges. It must never be exposed on a network socket. Reads are limited to a
run directory's own files; ``triage_run`` cannot be told to use a remote model.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, TextIO

from engine.mcp.tools import DEFAULT_RESULTS_ROOT, Tool, ToolError, build_tools

logger = logging.getLogger(__name__)

JSONRPC_VERSION = "2.0"
SERVER_NAME = "hatchery"
SERVER_VERSION = "0.1.0"
# Newest first. We echo the client's version when we speak it, else we answer
# with our newest so the client can decide whether to continue.
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
LATEST_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[0]

# JSON-RPC error codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


def _error(message_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": JSONRPC_VERSION, "id": message_id, "error": {"code": code, "message": message}}


def _result(message_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": JSONRPC_VERSION, "id": message_id, "result": result}


@dataclass
class MCPServer:
    """The protocol handler. ``handle`` is pure enough to unit-test directly."""

    results_root: Path = DEFAULT_RESULTS_ROOT

    def __post_init__(self) -> None:
        self.tools: dict[str, Tool] = {
            tool.name: tool for tool in build_tools(self.results_root)
        }

    # ------------------------------------------------------------- protocol

    def handle(self, message: Any) -> Optional[dict[str, Any]]:
        """Handle one decoded JSON-RPC message. Returns a response, or ``None``.

        Returns ``None`` for a notification (a message with no ``id``), which by
        the JSON-RPC contract gets no reply.
        """
        if not isinstance(message, dict):
            return _error(None, INVALID_REQUEST, "message must be a JSON object")

        method = message.get("method")
        message_id = message.get("id")
        is_notification = "id" not in message

        if not isinstance(method, str):
            if is_notification:
                return None
            return _error(message_id, INVALID_REQUEST, "missing method")

        handler = getattr(self, f"_mcp_{method.replace('/', '_')}", None)
        if handler is None:
            if is_notification:
                return None
            return _error(message_id, METHOD_NOT_FOUND, f"method not found: {method}")

        try:
            result = handler(message.get("params") or {})
        except ToolError as exc:
            if method == "tools/call":
                # A tool failure is a tool result, not a protocol error.
                return None if is_notification else _result(
                    message_id, {"content": [{"type": "text", "text": str(exc)}], "isError": True}
                )
            if is_notification:
                return None
            return _error(message_id, INVALID_PARAMS, str(exc))
        except Exception as exc:  # noqa: BLE001 - a bad message must not kill the loop
            logger.exception("MCP handler failed for %s", method)
            if is_notification:
                return None
            return _error(message_id, INTERNAL_ERROR, f"{type(exc).__name__}: {exc}")

        if is_notification:
            return None
        return _result(message_id, result)

    # --------------------------------------------------------------- methods

    def _mcp_initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        requested = params.get("protocolVersion")
        version = (
            requested
            if isinstance(requested, str) and requested in SUPPORTED_PROTOCOL_VERSIONS
            else LATEST_PROTOCOL_VERSION
        )
        return {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        }

    def _mcp_notifications_initialized(self, params: dict[str, Any]) -> dict[str, Any]:
        return {}

    def _mcp_ping(self, params: dict[str, Any]) -> dict[str, Any]:
        return {}

    def _mcp_tools_list(self, params: dict[str, Any]) -> dict[str, Any]:
        return {"tools": [tool.descriptor() for tool in self.tools.values()]}

    def _mcp_tools_call(self, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        if not isinstance(name, str) or not name:
            raise ToolError("tools/call requires a tool name")
        tool = self.tools.get(name)
        if tool is None:
            raise ToolError(f"unknown tool: {name}")
        arguments = params.get("arguments")
        if arguments is not None and not isinstance(arguments, dict):
            raise ToolError("tools/call arguments must be an object")
        text = tool.handler(arguments or {})
        return {"content": [{"type": "text", "text": text}], "isError": False}

    # ------------------------------------------------------------- transport

    def read_message(self, line: str) -> Optional[dict[str, Any]]:
        """Parse one transport line into a response, or ``None`` to stay silent."""
        stripped = line.strip()
        if not stripped:
            return None
        try:
            decoded = json.loads(stripped)
        except json.JSONDecodeError as exc:
            return _error(None, PARSE_ERROR, f"invalid JSON: {exc.msg}")
        return self.handle(decoded)

    def serve(self, stdin: TextIO, stdout: TextIO) -> None:
        """Serve newline-delimited JSON-RPC on the given streams until EOF."""
        for line in stdin:
            response = self.read_message(line)
            if response is None:
                continue
            stdout.write(json.dumps(response, default=str) + "\n")
            stdout.flush()


def main(argv: Optional[list[str]] = None) -> int:
    """Run the stdio server. Never writes anything but JSON-RPC to stdout."""
    import sys

    args = list(argv if argv is not None else sys.argv[1:])
    root = DEFAULT_RESULTS_ROOT
    if args and args[0] == "--root" and len(args) > 1:
        root = Path(args[1])
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
    MCPServer(results_root=root).serve(sys.stdin, sys.stdout)
    return 0


__all__ = [
    "LATEST_PROTOCOL_VERSION",
    "MCPServer",
    "SERVER_NAME",
    "SERVER_VERSION",
    "SUPPORTED_PROTOCOL_VERSIONS",
    "main",
]
