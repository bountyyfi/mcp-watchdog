"""Async stdio transport for MCP JSON-RPC over stdin/stdout.

MCP uses newline-delimited JSON over stdio. This module provides async
reading from stdin and synchronous writing to stdout (messages are small
enough that sync writes don't block the event loop).

Cross-platform: uses connect_read_pipe on Unix and a background thread
on Windows (where ProactorEventLoop does not support pipe readers).
"""

import asyncio
import json
import sys
import threading

# Buffer hint for asyncio StreamReader.  Most MCP messages fit within this;
# oversized lines are handled gracefully by _read_line() below.
_STREAM_LIMIT = 10 * 1024 * 1024  # 10 MiB


async def _read_line(reader: asyncio.StreamReader) -> bytes:
    """Read a full newline-terminated line regardless of size.

    Uses readuntil() so that lines larger than the StreamReader buffer
    limit are drained in chunks instead of crashing the proxy.
    """
    try:
        return await reader.readuntil(b"\n")
    except asyncio.IncompleteReadError as exc:
        return exc.partial
    except asyncio.LimitOverrunError as exc:
        data = await reader.read(exc.consumed)
        while True:
            try:
                data += await reader.readuntil(b"\n")
                return data
            except asyncio.IncompleteReadError as exc2:
                return data + exc2.partial
            except asyncio.LimitOverrunError as exc2:
                data += await reader.read(exc2.consumed)


async def create_stdin_reader() -> asyncio.StreamReader:
    """Create an async reader for stdin (binary mode).

    On Unix, uses the native asyncio pipe transport.
    On Windows, spawns a daemon thread that feeds data into a
    StreamReader since ProactorEventLoop lacks connect_read_pipe.
    """
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=_STREAM_LIMIT)

    if sys.platform == "win32":
        def _read_stdin_thread() -> None:
            while True:
                try:
                    line = sys.stdin.buffer.readline()
                    if not line:
                        loop.call_soon_threadsafe(reader.feed_eof)
                        return
                    loop.call_soon_threadsafe(reader.feed_data, line)
                except Exception:
                    loop.call_soon_threadsafe(reader.feed_eof)
                    return

        thread = threading.Thread(target=_read_stdin_thread, daemon=True)
        thread.start()
    else:
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)

    return reader


async def read_message(reader: asyncio.StreamReader) -> str | None:
    """Read one newline-delimited JSON line from stdin.

    Returns None on EOF or cancellation.
    """
    try:
        line = await _read_line(reader)
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
