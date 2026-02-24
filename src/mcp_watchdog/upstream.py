"""Upstream MCP server subprocess connection.

Launches the real MCP server as a child process and communicates
via newline-delimited JSON over its stdin/stdout pipes.
"""

import asyncio

# 10 MiB – MCP tool responses (e.g. search_files) can easily exceed the
# default 64 KiB asyncio StreamReader limit on a single JSON-RPC line.
_STREAM_LIMIT = 10 * 1024 * 1024


class UpstreamConnection:
    """Manages a subprocess upstream MCP server."""

    def __init__(self, command: list[str]) -> None:
        self._command = command
        self._process: asyncio.subprocess.Process | None = None

    async def start(self) -> None:
        """Launch the upstream process with piped stdin/stdout/stderr."""
        self._process = await asyncio.create_subprocess_exec(
            *self._command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=_STREAM_LIMIT,
        )

    async def send(self, message: str) -> None:
        """Send a newline-delimited JSON message to the upstream stdin."""
        if self._process and self._process.stdin:
            self._process.stdin.write((message + "\n").encode("utf-8"))
            await self._process.stdin.drain()

    async def receive(self) -> str | None:
        """Read one line from upstream stdout. Returns None on EOF."""
        if not self._process or not self._process.stdout:
            return None
        try:
            line = await self._process.stdout.readline()
            if not line:
                return None
            return line.decode("utf-8").strip()
        except (asyncio.CancelledError, ConnectionError, ValueError):
            return None

    @property
    def stderr(self) -> asyncio.StreamReader | None:
        """Access upstream process stderr for log forwarding."""
        return self._process.stderr if self._process else None

    @property
    def returncode(self) -> int | None:
        """Upstream process exit code, or None if still running."""
        return self._process.returncode if self._process else None

    async def close(self) -> None:
        """Shut down the upstream process gracefully."""
        if not self._process:
            return
        # Close stdin to signal EOF to the upstream
        if self._process.stdin:
            try:
                self._process.stdin.close()
            except OSError:
                pass
        # Try graceful termination first
        try:
            self._process.terminate()
            await asyncio.wait_for(self._process.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            try:
                self._process.kill()
                await self._process.wait()
            except ProcessLookupError:
                pass
        except ProcessLookupError:
            pass
