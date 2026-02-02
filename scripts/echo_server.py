#!/usr/bin/env python3
"""Minimal echo MCP server for performance measurement.

Provides a single 'echo' tool with near-zero processing time.
Used as a controlled backend to isolate proxy overhead in measurements.

Usage:
    STDIO mode (default):  python scripts/echo_server.py
    HTTP mode:             python scripts/echo_server.py --http --port 8765
"""

from __future__ import annotations

import argparse

from fastmcp import FastMCP

server = FastMCP("echo-server")


@server.tool()
def echo(message: str) -> str:
    """Echo back the input message."""
    return message


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Minimal echo MCP server")
    parser.add_argument(
        "--http",
        action="store_true",
        help="Run as HTTP server instead of STDIO",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="HTTP port (default: 8765)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="HTTP host (default: 127.0.0.1)",
    )
    args = parser.parse_args()

    if args.http:
        server.run(
            transport="streamable-http",
            host=args.host,
            port=args.port,
        )
    else:
        server.run()
