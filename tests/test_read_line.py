"""Tests for _read_line: oversized line handling without crashing."""

import asyncio
import pytest

from mcp_watchdog.upstream import _read_line


def _make_reader(data: bytes, limit: int = 256) -> asyncio.StreamReader:
    """Create a StreamReader pre-loaded with *data* and a small limit."""
    reader = asyncio.StreamReader(limit=limit)
    reader.feed_data(data)
    reader.feed_eof()
    return reader


@pytest.mark.asyncio
async def test_normal_line():
    """Lines within the limit are returned as-is."""
    reader = _make_reader(b'{"ok": true}\n')
    line = await _read_line(reader)
    assert line == b'{"ok": true}\n'


@pytest.mark.asyncio
async def test_oversized_line():
    """Lines exceeding the StreamReader limit are fully read, not dropped."""
    # 1 KiB payload with a 64-byte limit → guaranteed LimitOverrunError
    payload = b"x" * 1024 + b"\n"
    reader = _make_reader(payload, limit=64)
    line = await _read_line(reader)
    assert line == payload


@pytest.mark.asyncio
async def test_oversized_then_normal():
    """After draining an oversized line, the next line is still readable."""
    big = b"B" * 512 + b"\n"
    small = b'{"ok":1}\n'
    reader = _make_reader(big + small, limit=64)

    first = await _read_line(reader)
    assert first == big

    second = await _read_line(reader)
    assert second == small


@pytest.mark.asyncio
async def test_eof_without_newline():
    """Partial data at EOF is returned (not lost or raised)."""
    reader = _make_reader(b"partial")
    line = await _read_line(reader)
    assert line == b"partial"


@pytest.mark.asyncio
async def test_empty_eof():
    """Immediate EOF returns empty bytes."""
    reader = _make_reader(b"")
    line = await _read_line(reader)
    assert line == b""
