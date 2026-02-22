"""Tests for notification flooding detection across all list_changed types."""

import pytest
import json
from mcp_watchdog.proxy import MCPWatchdogProxy


@pytest.mark.asyncio
async def test_resources_list_changed_flooding():
    """Rapid resources/list_changed notifications trigger alert."""
    proxy = MCPWatchdogProxy(verbose=False)
    for i in range(5):
        msg = json.dumps({
            "jsonrpc": "2.0",
            "method": "notifications/resources/list_changed",
        })
        _, alerts = await proxy.process_response(msg, server_id="srv")
    assert any(a.rule == "NOTIF-INJECT" for a in alerts)


@pytest.mark.asyncio
async def test_prompts_list_changed_flooding():
    """Rapid prompts/list_changed notifications trigger alert."""
    proxy = MCPWatchdogProxy(verbose=False)
    for i in range(5):
        msg = json.dumps({
            "jsonrpc": "2.0",
            "method": "notifications/prompts/list_changed",
        })
        _, alerts = await proxy.process_response(msg, server_id="srv")
    assert any(a.rule == "NOTIF-INJECT" for a in alerts)


@pytest.mark.asyncio
async def test_tools_list_changed_flooding():
    """Rapid tools/list_changed notifications still trigger alert."""
    proxy = MCPWatchdogProxy(verbose=False)
    for i in range(5):
        msg = json.dumps({
            "jsonrpc": "2.0",
            "method": "notifications/tools/list_changed",
        })
        _, alerts = await proxy.process_response(msg, server_id="srv")
    assert any(a.rule == "NOTIF-INJECT" for a in alerts)


@pytest.mark.asyncio
async def test_non_list_changed_notification_no_alert():
    """Non-list_changed notifications don't trigger flooding alert."""
    proxy = MCPWatchdogProxy(verbose=False)
    for i in range(10):
        msg = json.dumps({
            "jsonrpc": "2.0",
            "method": "notifications/progress",
            "params": {"progressToken": "abc", "progress": i, "total": 10},
        })
        _, alerts = await proxy.process_response(msg, server_id="srv")
    assert not any(a.rule == "NOTIF-INJECT" for a in alerts)
