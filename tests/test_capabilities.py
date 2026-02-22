"""Tests for initialize capability tracking."""

import pytest
import json
from mcp_watchdog.proxy import MCPWatchdogProxy


@pytest.mark.asyncio
async def test_capabilities_tracked_from_initialize():
    """Server capabilities are recorded from initialize response."""
    proxy = MCPWatchdogProxy(verbose=False)
    msg = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {"listChanged": True},
                "resources": {"subscribe": True},
                "prompts": {"listChanged": True},
            },
            "serverInfo": {"name": "test-server", "version": "1.0.0"},
        },
    })
    proxy.flow.track_request("srv", 1, "{}")
    await proxy.process_response(msg, server_id="srv")
    assert "srv" in proxy._server_capabilities
    caps = proxy._server_capabilities["srv"]
    assert "tools" in caps
    assert "resources" in caps
    assert "prompts" in caps


@pytest.mark.asyncio
async def test_capabilities_not_set_for_non_initialize():
    """Non-initialize responses don't set capabilities."""
    proxy = MCPWatchdogProxy(verbose=False)
    msg = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"tools": [{"name": "test", "description": "A tool"}]},
    })
    proxy.flow.track_request("srv", 1, "{}")
    await proxy.process_response(msg, server_id="srv")
    assert "srv" not in proxy._server_capabilities
