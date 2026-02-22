"""CLI entry point for mcp-watchdog.

Usage:
  # Proxy mode — wrap an upstream MCP server:
  mcp-watchdog --verbose -- npx -y @modelcontextprotocol/server-filesystem /tmp

  # Standalone scanner — pipe MCP messages through for testing:
  echo '{"jsonrpc":"2.0","method":"tools/list"}' | mcp-watchdog
"""

import argparse
import asyncio
import sys

from mcp_watchdog.main import run_proxy, run_standalone


def main() -> None:
    parser = argparse.ArgumentParser(
        description="mcp-watchdog: MCP security proxy that detects and blocks attacks",
        epilog=(
            "examples:\n"
            "  mcp-watchdog --verbose -- npx -y @modelcontextprotocol/server-filesystem /tmp\n"
            "  mcp-watchdog -- python -m my_mcp_server\n"
            "  echo '{\"jsonrpc\":\"2.0\"}' | mcp-watchdog          (standalone scanner)\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", action="version", version="mcp-watchdog 0.1.3"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=True,
        help="Enable verbose alert output to stderr (default: on)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        default=False,
        help="Suppress alert output (only proxy traffic)",
    )
    parser.add_argument(
        "upstream",
        nargs=argparse.REMAINDER,
        help="Upstream MCP server command (after --)",
    )
    args = parser.parse_args()

    verbose = not args.quiet

    # Strip leading "--" separator if present
    upstream_cmd = args.upstream
    if upstream_cmd and upstream_cmd[0] == "--":
        upstream_cmd = upstream_cmd[1:]

    if not upstream_cmd:
        # Standalone mode: pass-through scanner
        try:
            asyncio.run(run_standalone(verbose))
        except (KeyboardInterrupt, BrokenPipeError):
            pass
    else:
        try:
            asyncio.run(run_proxy(upstream_cmd, verbose))
        except (KeyboardInterrupt, BrokenPipeError):
            pass

    # Suppress broken pipe errors on exit
    try:
        sys.stdout.flush()
    except BrokenPipeError:
        pass
    try:
        sys.stderr.flush()
    except BrokenPipeError:
        pass


if __name__ == "__main__":
    main()
