"""CLI entry point for mcp-watchdog."""

import argparse

from rich.console import Console

console = Console()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="mcp-watchdog: MCP security proxy (SMAC-L3)"
    )
    parser.add_argument(
        "--version", action="version", version="mcp-watchdog 0.1.0"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=True,
        help="Enable verbose alert output",
    )
    parser.parse_args()

    console.print("[bold cyan]mcp-watchdog[/bold cyan] v0.1.0 - MCP security proxy")
    console.print("SMAC-L3 | Behavioral analysis | Cross-server correlation")
    console.print(
        "Open source by Bountyy Oy - "
        "https://github.com/bountyyfi/mcp-watchdog\n"
    )


if __name__ == "__main__":
    main()
