"""Tests for scope enforcer integration in the proxy."""

import pytest
import json
from mcp_watchdog.proxy import MCPWatchdogProxy


@pytest.mark.asyncio
async def test_scope_blocks_ssh_write_in_request():
    """Scope enforcer blocks tool calls writing to .ssh/."""
    proxy = MCPWatchdogProxy(verbose=False)
    proxy.set_scope("srv", ["/tmp/project"])
    msg = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {"path": "/home/user/.ssh/authorized_keys", "content": "ssh-rsa AAAA..."},
        },
    })
    _, alerts = await proxy.process_request(msg, server_id="srv")
    assert any(a.rule == "SCOPE-L4" for a in alerts)


@pytest.mark.asyncio
async def test_scope_allows_in_scope_write():
    """Scope enforcer allows writes within allowed paths."""
    proxy = MCPWatchdogProxy(verbose=False)
    proxy.set_scope("srv", ["/tmp/project"])
    msg = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {"path": "/tmp/project/readme.md", "content": "Hello"},
        },
    })
    _, alerts = await proxy.process_request(msg, server_id="srv")
    assert not any(a.rule == "SCOPE-L4" for a in alerts)


@pytest.mark.asyncio
async def test_scope_blocks_git_config_write():
    """Scope enforcer blocks writes to .git/config."""
    proxy = MCPWatchdogProxy(verbose=False)
    proxy.set_scope("srv", ["/tmp/project"])
    msg = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {"path": "/tmp/project/.git/config", "content": "bad"},
        },
    })
    _, alerts = await proxy.process_request(msg, server_id="srv")
    assert any(a.rule == "SCOPE-L4" for a in alerts)


@pytest.mark.asyncio
async def test_scope_blocks_aws_credentials():
    """Scope enforcer blocks writes to .aws/credentials."""
    proxy = MCPWatchdogProxy(verbose=False)
    proxy.set_scope("srv", ["/home/user"])
    msg = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {"path": "/home/user/.aws/credentials", "content": "key"},
        },
    })
    _, alerts = await proxy.process_request(msg, server_id="srv")
    assert any(a.rule == "SCOPE-L4" for a in alerts)


@pytest.mark.asyncio
async def test_scope_response_path_check():
    """Scope enforcer flags out-of-scope paths in responses."""
    proxy = MCPWatchdogProxy(verbose=False)
    proxy.set_scope("srv", ["/tmp/project"])
    msg = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"path": "/home/user/.ssh/id_rsa"},
    })
    proxy.flow.track_request("srv", 1, "{}")
    _, alerts = await proxy.process_response(msg, server_id="srv")
    assert any(a.rule == "SCOPE-L4" for a in alerts)


@pytest.mark.asyncio
async def test_no_scope_configured_no_alerts():
    """Without scope configured, no SCOPE-L4 alerts fire."""
    proxy = MCPWatchdogProxy(verbose=False)
    msg = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {"path": "/etc/passwd", "content": "bad"},
        },
    })
    _, alerts = await proxy.process_request(msg, server_id="srv")
    assert not any(a.rule == "SCOPE-L4" for a in alerts)
