"""Main proxy loop for mcp-watchdog.

Bidirectional async proxy:
  Claude Desktop -> [stdin] -> watchdog -> process_request() -> upstream
  upstream -> watchdog -> process_response() -> [stdout] -> Claude Desktop
"""

import asyncio
import json
import sys

from rich.console import Console

from mcp_watchdog.proxy import MCPWatchdogProxy
from mcp_watchdog.stdio_transport import create_stdin_reader, read_message, write_message
from mcp_watchdog.upstream import UpstreamConnection

stderr_console = Console(stderr=True)


async def run_proxy(upstream_cmd: list[str], verbose: bool) -> None:
    """Run the full bidirectional proxy with an upstream MCP server."""
    proxy = MCPWatchdogProxy(verbose=verbose)
    upstream = UpstreamConnection(upstream_cmd)

    stderr_console.print(
        "[bold cyan]mcp-watchdog[/bold cyan] v0.1.6 — MCP security proxy",
        highlight=False,
    )
    stderr_console.print(
        f"  upstream: {' '.join(upstream_cmd)}", highlight=False
    )
    stderr_console.print(
        "  SMAC-L3 | behavioral | entropy | flow tracking | rate limiting",
        highlight=False,
    )

    await upstream.start()
    reader = await create_stdin_reader()

    shutdown = asyncio.Event()

    def _signal_handler() -> None:
        shutdown.set()

    # Register graceful-shutdown signal handlers.
    # add_signal_handler is not available on Windows ProactorEventLoop,
    # but KeyboardInterrupt (Ctrl+C) is still caught by the caller.
    if sys.platform != "win32":
        import signal

        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, _signal_handler)

    async def client_to_upstream() -> None:
        """Read from client stdin, inspect, forward to upstream."""
        while not shutdown.is_set():
            raw = await read_message(reader)
            if raw is None:
                shutdown.set()
                return
            if not raw:
                continue
            cleaned, _alerts = await proxy.process_request(raw, server_id="upstream")
            try:
                await upstream.send(cleaned)
            except (BrokenPipeError, ConnectionError):
                shutdown.set()
                return

    async def upstream_to_client() -> None:
        """Read from upstream, inspect, write to client stdout."""
        while not shutdown.is_set():
            raw = await upstream.receive()
            if raw is None:
                shutdown.set()
                return
            if not raw:
                continue
            cleaned, _alerts = await proxy.process_response(raw, server_id="upstream")
            try:
                data = json.loads(cleaned)
                write_message(data)
            except json.JSONDecodeError:
                # Forward non-JSON lines as-is (shouldn't happen in MCP)
                sys.stdout.buffer.write((cleaned + "\n").encode("utf-8"))
                sys.stdout.buffer.flush()
            except BrokenPipeError:
                shutdown.set()
                return

    async def forward_upstream_stderr() -> None:
        """Forward upstream stderr to our stderr for debugging."""
        if not upstream.stderr:
            return
        while not shutdown.is_set():
            try:
                line = await upstream.stderr.readline()
                if not line:
                    return
                text = line.decode("utf-8").rstrip()
                if text:
                    stderr_console.print(
                        f"[dim]  [upstream] {text}[/dim]", highlight=False
                    )
            except (asyncio.CancelledError, ConnectionError):
                return

    tasks = [
        asyncio.create_task(client_to_upstream(), name="client->upstream"),
        asyncio.create_task(upstream_to_client(), name="upstream->client"),
        asyncio.create_task(forward_upstream_stderr(), name="upstream-stderr"),
    ]

    # Wait until any task finishes (EOF, error, or signal)
    _done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

    # Shut down remaining tasks
    shutdown.set()
    for task in pending:
        task.cancel()
    await asyncio.gather(*pending, return_exceptions=True)

    await upstream.close()
    stderr_console.print(
        "[bold cyan]mcp-watchdog[/bold cyan] shutdown complete.", highlight=False
    )


async def run_standalone(verbose: bool) -> None:
    """Standalone mode: pass-through scanner with no upstream.

    Reads JSON-RPC from stdin, runs all security detectors,
    writes cleaned output to stdout. Useful for testing and CI.
    """
    proxy = MCPWatchdogProxy(verbose=verbose)

    stderr_console.print(
        "[bold cyan]mcp-watchdog[/bold cyan] v0.1.6 — standalone scanner",
        highlight=False,
    )
    stderr_console.print(
        "  Reading from stdin, writing cleaned output to stdout.",
        highlight=False,
    )
    stderr_console.print(
        "  Pipe MCP messages through to test detection. Ctrl+C to exit.",
        highlight=False,
    )

    reader = await create_stdin_reader()

    while True:
        raw = await read_message(reader)
        if raw is None:
            break
        if not raw:
            continue

        # Run both request and response scanners
        cleaned, _req_alerts = await proxy.process_request(raw, server_id="stdin")
        cleaned, _resp_alerts = await proxy.process_response(cleaned, server_id="stdin")

        try:
            data = json.loads(cleaned)
            write_message(data)
        except json.JSONDecodeError:
            sys.stdout.buffer.write((cleaned + "\n").encode("utf-8"))
            sys.stdout.buffer.flush()
        except BrokenPipeError:
            break
