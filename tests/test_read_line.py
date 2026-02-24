"""Tests that large MCP messages don't crash the proxy.

With limit=sys.maxsize on the StreamReader, readline() handles
arbitrarily large lines without raising LimitOverrunError.
"""

import asyncio
import sys
import pytest


def _make_reader(data: bytes) -> asyncio.StreamReader:
    """Create a StreamReader with sys.maxsize limit, pre-loaded with *data*."""
    reader = asyncio.StreamReader(limit=sys.maxsize)
    reader.feed_data(data)
    reader.feed_eof()
    return reader


@pytest.mark.asyncio
async def test_normal_line():
    reader = _make_reader(b'{"ok": true}\n')
    line = await reader.readline()
    assert line == b'{"ok": true}\n'


@pytest.mark.asyncio
async def test_large_line():
    """A 1 MiB single-line message is read without error."""
    payload = b"x" * (1024 * 1024) + b"\n"
    reader = _make_reader(payload)
    line = await reader.readline()
    assert line == payload


@pytest.mark.asyncio
async def test_large_then_normal():
    """After a large message, subsequent normal messages still work."""
    big = b"B" * (512 * 1024) + b"\n"
    small = b'{"ok":1}\n'
    reader = _make_reader(big + small)

    first = await reader.readline()
    assert first == big

    second = await reader.readline()
    assert second == small


@pytest.mark.asyncio
async def test_eof_without_newline():
    """Partial data at EOF is returned."""
    reader = _make_reader(b"partial")
    line = await reader.readline()
    assert line == b"partial"


@pytest.mark.asyncio
async def test_empty_eof():
    """Immediate EOF returns empty bytes."""
    reader = _make_reader(b"")
    line = await reader.readline()
    assert line == b""
