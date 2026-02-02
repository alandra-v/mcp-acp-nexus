#!/usr/bin/env python3
"""Standalone proxy overhead measurement script.

Compares latency of direct backend access vs proxied access using FastMCP Client
with StdioTransport (matching production deployment where Claude Desktop spawns
the proxy as a subprocess over STDIO).

This is a feasibility measurement — proving the proxy doesn't add unacceptable
latency — not performance benchmarking.

Prerequisites (one-time setup):
    1. mcp-acp package installed: pip install -e .
    2. Auth configured:           mcp-acp init (requires OIDC issuer, client_id, audience)
    3. Logged in:                  mcp-acp auth login
    4. Proxy added for STDIO:     mcp-acp proxy add --name echo-stdio \\
                                      --server-name echo-server --connection-type stdio \\
                                      --command .venv/bin/python --args "scripts/echo_server.py"
    5. Allow-all policy: edit the policy.json in the proxy config directory
       (macOS: ~/Library/Application Support/mcp-acp/proxies/<name>/policy.json)
       to add: {"id":"allow-all","effect":"allow","conditions":{"tool_name":"*"}}
    6. (HTTP only) Separate proxy: mcp-acp proxy add --name echo-http \\
                                      --server-name echo-server --connection-type http \\
                                      --url http://127.0.0.1:8765/mcp
       with the same allow-all policy.

    IMPORTANT: Use the virtualenv python for --backend-cmd (e.g. .venv/bin/python)
    since the echo server imports fastmcp.

Usage:
    # STDIO echo backend
    python scripts/measure_overhead.py \\
        --proxy-name echo-stdio \\
        --backend-cmd ".venv/bin/python scripts/echo_server.py" \\
        --output scripts/results/results_stdio.json

    # HTTP echo backend (start server first: .venv/bin/python scripts/echo_server.py --http)
    python scripts/measure_overhead.py \\
        --proxy-name echo-http \\
        --backend-url http://127.0.0.1:8766/mcp \\
        --output scripts/results/results_http.json

    # Filesystem server (STDIO, requires npx)
    python scripts/measure_overhead.py \\
        --proxy-name fs-test \\
        --backend-cmd "npx -y @modelcontextprotocol/server-filesystem /tmp" \\
        --tool read_file --tool-args '{"path": "/tmp"}'
"""

from __future__ import annotations

import argparse
import asyncio
import json
import shlex
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import median, stdev

from fastmcp import Client
from fastmcp.client.transports import StdioTransport

# Derive mcp-acp binary path from the running Python's venv
# so StdioTransport uses the same installation as this script.
_MCP_ACP_CMD = str(Path(sys.executable).parent / "mcp-acp")


@dataclass
class TimingResult:
    """Latency measurements for one operation type."""

    median_ms: float
    stdev_ms: float
    min_ms: float
    max_ms: float
    samples: int
    raw_ms: list[float]


def _compute_timing(values: list[float]) -> TimingResult:
    return TimingResult(
        median_ms=round(median(values), 2),
        stdev_ms=round(stdev(values), 2) if len(values) > 1 else 0.0,
        min_ms=round(min(values), 2),
        max_ms=round(max(values), 2),
        samples=len(values),
        raw_ms=[round(v, 2) for v in values],
    )


async def measure_latency(
    client: Client,
    tool_name: str,
    tool_args: dict,
    n_warmup: int,
    n_runs: int,
    label: str,
    delay: float,
) -> dict[str, TimingResult]:
    """Measure discovery and tool call latency for a connected client.

    Args:
        client: Connected FastMCP Client.
        tool_name: Tool to call for measurement.
        tool_args: Arguments to pass to the tool.
        n_warmup: Number of warmup requests to discard.
        n_runs: Number of measured requests.
        label: Label for progress output.
        delay: Seconds to sleep between requests (avoids DoS rate limiter).

    Returns:
        Dict with 'discovery' and 'tool_call' TimingResult entries.
    """
    # Warmup: discard first N requests (cold caches, lazy imports, policy first-parse)
    # Also validates the tool exists and calls succeed (catches policy misconfiguration)
    print(f"  [{label}] Warming up ({n_warmup} requests)...", end="", flush=True)
    for i in range(n_warmup):
        await client.list_tools()
        result = await client.call_tool(tool_name, tool_args)
        if i == 0 and result.is_error:
            content = result.content[0].text if result.content else "unknown error"
            print(f"\n  ERROR: Tool call failed: {content}", file=sys.stderr)
            print("  Check that the proxy has an allow-all policy.", file=sys.stderr)
            sys.exit(1)
        await asyncio.sleep(delay)
    print(" done.")

    # Measure discovery (tools/list)
    # Delay is BETWEEN requests (outside timing window), not during measurement.
    print(f"  [{label}] Measuring discovery ({n_runs} requests)...", end="", flush=True)
    discovery_times: list[float] = []
    for _ in range(n_runs):
        start = time.perf_counter()
        await client.list_tools()
        discovery_times.append((time.perf_counter() - start) * 1000)
        await asyncio.sleep(delay)
    print(" done.")

    # Measure tool calls
    print(f"  [{label}] Measuring tool calls ({n_runs} requests)...", end="", flush=True)
    tool_call_times: list[float] = []
    errors = 0
    for _ in range(n_runs):
        start = time.perf_counter()
        result = await client.call_tool(tool_name, tool_args)
        tool_call_times.append((time.perf_counter() - start) * 1000)
        if result.is_error:
            errors += 1
        await asyncio.sleep(delay)
    print(" done.")
    if errors:
        print(f"  WARNING: {errors}/{n_runs} tool calls returned errors", file=sys.stderr)

    return {
        "discovery": _compute_timing(discovery_times),
        "tool_call": _compute_timing(tool_call_times),
    }


async def run_stdio_scenario(
    backend_cmd: str,
    proxy_name: str,
    tool_name: str,
    tool_args: dict,
    n_warmup: int,
    n_runs: int,
    delay: float,
) -> dict:
    """Measure overhead for STDIO backend.

    Direct:   Client --STDIO--> Backend (subprocess)
    Proxied:  Client --STDIO--> Proxy (subprocess) --STDIO--> Backend
    """
    parts = shlex.split(backend_cmd)

    print(f"\n{'=' * 60}")
    print(f"STDIO Backend Scenario")
    print(f"{'=' * 60}")
    print(f"Backend command: {backend_cmd}")
    print(f"Proxy: {proxy_name}")
    print(f"Tool: {tool_name}({json.dumps(tool_args)})")
    print(f"Warmup: {n_warmup}, Runs: {n_runs}")

    # --- Direct measurement ---
    print(f"\n--- Direct: Client -> Backend (STDIO) ---")
    direct_transport = StdioTransport(command=parts[0], args=parts[1:])
    async with Client(transport=direct_transport) as client:
        direct = await measure_latency(client, tool_name, tool_args, n_warmup, n_runs, "direct", 0)

    # --- Proxied measurement ---
    print(f"\n--- Proxied: Client -> Proxy -> Backend (STDIO) ---")
    proxy_transport = StdioTransport(command=_MCP_ACP_CMD, args=["start", "--proxy", proxy_name])
    async with Client(transport=proxy_transport) as client:
        proxied = await measure_latency(client, tool_name, tool_args, n_warmup, n_runs, "proxied", delay)

    return {
        "scenario": "stdio",
        "backend_cmd": backend_cmd,
        "proxy_name": proxy_name,
        "tool_name": tool_name,
        "tool_args": tool_args,
        "warmup": n_warmup,
        "runs": n_runs,
        "direct": {k: asdict(v) for k, v in direct.items()},
        "proxied": {k: asdict(v) for k, v in proxied.items()},
    }


async def run_http_scenario(
    backend_url: str,
    proxy_name: str,
    tool_name: str,
    tool_args: dict,
    n_warmup: int,
    n_runs: int,
    delay: float,
) -> dict:
    """Measure overhead for HTTP backend.

    Direct:   Client --HTTP--> Backend (already running)
    Proxied:  Client --STDIO--> Proxy (subprocess) --HTTP--> Backend
    """
    print(f"\n{'=' * 60}")
    print(f"HTTP Backend Scenario")
    print(f"{'=' * 60}")
    print(f"Backend URL: {backend_url}")
    print(f"Proxy: {proxy_name}")
    print(f"Tool: {tool_name}({json.dumps(tool_args)})")
    print(f"Warmup: {n_warmup}, Runs: {n_runs}")

    # --- Direct measurement (HTTP) ---
    # Client auto-infers StreamableHttpTransport from URL string
    print(f"\n--- Direct: Client -> Backend (HTTP) ---")
    async with Client(backend_url) as client:
        direct = await measure_latency(client, tool_name, tool_args, n_warmup, n_runs, "direct", 0)

    # --- Proxied measurement (STDIO to proxy, proxy uses HTTP internally) ---
    print(f"\n--- Proxied: Client -> Proxy (STDIO) -> Backend (HTTP) ---")
    proxy_transport = StdioTransport(command=_MCP_ACP_CMD, args=["start", "--proxy", proxy_name])
    async with Client(transport=proxy_transport) as client:
        proxied = await measure_latency(client, tool_name, tool_args, n_warmup, n_runs, "proxied", delay)

    return {
        "scenario": "http",
        "backend_url": backend_url,
        "proxy_name": proxy_name,
        "tool_name": tool_name,
        "tool_args": tool_args,
        "warmup": n_warmup,
        "runs": n_runs,
        "direct": {k: asdict(v) for k, v in direct.items()},
        "proxied": {k: asdict(v) for k, v in proxied.items()},
    }


def print_scenario_report(result: dict) -> None:
    """Print formatted report for one scenario."""
    scenario = result["scenario"].upper()

    print(f"\n{'=' * 60}")
    print(f"Results: {scenario} Backend")
    print(f"{'=' * 60}")

    for op_type in ("discovery", "tool_call"):
        direct = result["direct"][op_type]
        proxied = result["proxied"][op_type]
        overhead = round(proxied["median_ms"] - direct["median_ms"], 2)
        label = "Discovery (tools/list)" if op_type == "discovery" else "Tool Call (tools/call)"

        print(f"\n  {label}:")
        print(f"    Direct median:  {direct['median_ms']:>8.2f} ms  (stdev: {direct['stdev_ms']:.2f})")
        print(f"    Proxied median: {proxied['median_ms']:>8.2f} ms  (stdev: {proxied['stdev_ms']:.2f})")
        print(f"    Overhead:       {overhead:>8.2f} ms")


def print_summary(results: list[dict]) -> None:
    """Print summary across all scenarios."""
    print(f"\n{'=' * 60}")
    print("Summary")
    print(f"{'=' * 60}")

    for result in results:
        scenario = result["scenario"].upper()
        backend = result.get("backend_cmd") or result.get("backend_url", "unknown")

        tool_direct = result["direct"]["tool_call"]["median_ms"]
        tool_proxied = result["proxied"]["tool_call"]["median_ms"]
        tool_overhead = round(tool_proxied - tool_direct, 2)

        disc_direct = result["direct"]["discovery"]["median_ms"]
        disc_proxied = result["proxied"]["discovery"]["median_ms"]
        disc_overhead = round(disc_proxied - disc_direct, 2)

        print(f"\n  [{scenario}] {backend}")
        print(f"    Tool call overhead:  {tool_overhead:>8.2f} ms  ({tool_direct:.1f} -> {tool_proxied:.1f})")
        print(f"    Discovery overhead:  {disc_overhead:>8.2f} ms  ({disc_direct:.1f} -> {disc_proxied:.1f})")

    print()
    print("  Note: Proxy overhead is a feasibility indicator only.")
    print("  See docs/performance/performance-measurement-plan.md for limitations.")


async def async_main(args: argparse.Namespace) -> None:
    tool_args = json.loads(args.tool_args)
    results: list[dict] = []

    if args.backend_cmd:
        result = await run_stdio_scenario(
            backend_cmd=args.backend_cmd,
            proxy_name=args.proxy_name,
            tool_name=args.tool,
            tool_args=tool_args,
            n_warmup=args.warmup,
            n_runs=args.runs,
            delay=args.delay,
        )
        print_scenario_report(result)
        results.append(result)

    if args.backend_url:
        result = await run_http_scenario(
            backend_url=args.backend_url,
            proxy_name=args.proxy_name,
            tool_name=args.tool,
            tool_args=tool_args,
            n_warmup=args.warmup,
            n_runs=args.runs,
            delay=args.delay,
        )
        print_scenario_report(result)
        results.append(result)

    if not results:
        print("Error: specify --backend-cmd and/or --backend-url", file=sys.stderr)
        sys.exit(1)

    print_summary(results)

    if args.output:
        # Strip raw_ms from output to keep file size reasonable
        for r in results:
            for phase in ("direct", "proxied"):
                for op in ("discovery", "tool_call"):
                    del r[phase][op]["raw_ms"]
        output_path = Path(args.output)
        output_path.write_text(json.dumps(results, indent=2) + "\n")
        print(f"\nResults saved to {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Measure proxy overhead vs direct backend access.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # STDIO echo backend\n"
            "  python scripts/measure_overhead.py \\\n"
            "      --proxy-name echo-stdio \\\n"
            '      --backend-cmd "python scripts/echo_server.py"\n'
            "\n"
            "  # HTTP echo backend (start server first)\n"
            "  python scripts/measure_overhead.py \\\n"
            "      --proxy-name echo-http \\\n"
            "      --backend-url http://127.0.0.1:8765/mcp\n"
        ),
    )
    parser.add_argument(
        "--proxy-name",
        required=True,
        help="Name of the configured mcp-acp proxy",
    )
    parser.add_argument(
        "--backend-cmd",
        type=str,
        default=None,
        help='STDIO backend command (e.g. "python scripts/echo_server.py")',
    )
    parser.add_argument(
        "--backend-url",
        type=str,
        default=None,
        help="HTTP backend URL (e.g. http://127.0.0.1:8765/mcp)",
    )
    parser.add_argument(
        "--tool",
        type=str,
        default="echo",
        help='Tool name to call (default: "echo")',
    )
    parser.add_argument(
        "--tool-args",
        type=str,
        default='{"message": "test"}',
        help='Tool arguments as JSON (default: \'{"message": "test"}\')',
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=10,
        help="Number of warmup requests to discard (default: 10)",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=100,
        help="Number of measured requests (default: 100)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.12,
        help="Seconds between requests for proxied tests to stay under "
        "DoS rate limiter (10 req/s). Default: 0.12. Direct tests use no delay.",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Save results as JSON to this path (e.g. scripts/results/results_stdio.json)",
    )
    args = parser.parse_args()

    if not args.backend_cmd and not args.backend_url:
        parser.error("at least one of --backend-cmd or --backend-url is required")

    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
