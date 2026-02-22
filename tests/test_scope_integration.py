"""Tests for scope enforcer integration in the proxy."""

import os
import pytest
import json
from pathlib import Path
from mcp_watchdog.proxy import MCPWatchdogProxy


@pytest.mark.asyncio
async def test_scope_blocks_ssh_write_in_request(tmp_path):
    """Scope enforcer blocks tool calls writing to .ssh/."""
    project = tmp_path / "project"
    project.mkdir()
    ssh_path = str(Path.home() / ".ssh" / "authorized_keys")
    proxy = MCPWatchdogProxy(verbose=False)
    proxy.set_scope("srv", [str(project)])
    msg = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {"path": ssh_path, "content": "ssh-rsa AAAA..."},
        },
    })
    _, alerts = await proxy.process_request(msg, server_id="srv")
    assert any(a.rule == "SCOPE-L4" for a in alerts)


@pytest.mark.asyncio
async def test_scope_allows_in_scope_write(tmp_path):
    """Scope enforcer allows writes within allowed paths."""
    project = tmp_path / "project"
    project.mkdir()
    proxy = MCPWatchdogProxy(verbose=False)
    proxy.set_scope("srv", [str(project)])
    msg = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {"path": str(project / "readme.md"), "content": "Hello"},
        },
    })
    _, alerts = await proxy.process_request(msg, server_id="srv")
    assert not any(a.rule == "SCOPE-L4" for a in alerts)


@pytest.mark.asyncio
async def test_scope_blocks_git_config_write(tmp_path):
    """Scope enforcer blocks writes to .git/config."""
    project = tmp_path / "project"
    project.mkdir()
    proxy = MCPWatchdogProxy(verbose=False)
    proxy.set_scope("srv", [str(project)])
    git_config = str(project / ".git" / "config")
    msg = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {"path": git_config, "content": "bad"},
        },
    })
    _, alerts = await proxy.process_request(msg, server_id="srv")
    assert any(a.rule == "SCOPE-L4" for a in alerts)


@pytest.mark.asyncio
async def test_scope_blocks_aws_credentials(tmp_path):
    """Scope enforcer blocks writes to .aws/credentials."""
    home = str(Path.home())
    aws_creds = str(Path.home() / ".aws" / "credentials")
    proxy = MCPWatchdogProxy(verbose=False)
    proxy.set_scope("srv", [home])
    msg = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {"path": aws_creds, "content": "key"},
        },
    })
    _, alerts = await proxy.process_request(msg, server_id="srv")
    assert any(a.rule == "SCOPE-L4" for a in alerts)


@pytest.mark.asyncio
async def test_scope_response_path_check(tmp_path):
    """Scope enforcer flags out-of-scope paths in responses."""
    project = tmp_path / "project"
    project.mkdir()
    ssh_key_path = str(Path.home() / ".ssh" / "id_rsa")
    proxy = MCPWatchdogProxy(verbose=False)
    proxy.set_scope("srv", [str(project)])
    msg = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"path": ssh_key_path},
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
            "arguments": {"path": os.path.join(os.sep, "etc", "passwd"), "content": "bad"},
        },
    })
    _, alerts = await proxy.process_request(msg, server_id="srv")
    assert not any(a.rule == "SCOPE-L4" for a in alerts)
