"""Entry point for ``python -m engine.mcp`` — the stdio MCP server."""

from __future__ import annotations

import sys

from engine.mcp.server import main

if __name__ == "__main__":
    sys.exit(main())
