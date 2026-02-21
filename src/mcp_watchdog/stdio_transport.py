"""Async stdio transport for MCP JSON-RPC over stdin/stdout.

MCP uses newline-delimited JSON over stdio. This module provides async
reading from stdin and synchronous writing to stdout (messages are small
enough that sync writes don't block the event loop).
"""

import asyncio
import json
import sys


async def create_stdin_reader() -> asyncio.StreamReader:
    """Create an async reader for stdin (binary mode)."""
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)
    return reader


async def read_message(reader: asyncio.StreamReader) -> str | None:
    """Read one newline-delimited JSON line from stdin.

    Returns None on EOF or cancellation.
    """
    try:
        line = await reader.readline()
        if not line:
            return None
        return line.decode("utf-8").strip()
    except (asyncio.CancelledError, ConnectionError, EOFError):
        return None


def write_message(data: dict) -> None:
    """Write a JSON-RPC message to stdout and flush immediately.

    Raises BrokenPipeError if the downstream reader has disconnected.
    """
    raw = json.dumps(data) + "\n"
    sys.stdout.buffer.write(raw.encode("utf-8"))
    sys.stdout.buffer.flush()
