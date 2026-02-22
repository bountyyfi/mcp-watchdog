"""Tests for extended flow tracker token patterns (JWTs, UUIDs, prefixed keys)."""

from mcp_watchdog.flow_tracker import FlowTracker


def test_jwt_cross_server_detection():
    """JWTs propagating across servers are detected."""
    ft = FlowTracker()
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123signature"
    ft.record_response("server-a", f'{{"token": "{jwt}"}}')
    alerts = ft.record_request("server-b", f'{{"auth": "{jwt}"}}')
    assert len(alerts) == 1
    assert alerts[0].source_server == "server-a"
    assert alerts[0].target_server == "server-b"


def test_uuid_cross_server_detection():
    """UUIDs propagating across servers are detected."""
    ft = FlowTracker()
    uuid = "550e8400-e29b-41d4-a716-446655440000"
    ft.record_response("server-a", f'{{"id": "{uuid}"}}')
    alerts = ft.record_request("server-b", f'{{"ref": "{uuid}"}}')
    assert len(alerts) == 1


def test_github_pat_cross_server_detection():
    """GitHub PATs propagating across servers are detected."""
    ft = FlowTracker()
    token = "ghp_1234567890abcdefghij"
    ft.record_response("server-a", f'{{"key": "{token}"}}')
    alerts = ft.record_request("server-b", f'{{"key": "{token}"}}')
    assert len(alerts) == 1


def test_sk_key_cross_server_detection():
    """OpenAI-style sk- keys propagating across servers are detected."""
    ft = FlowTracker()
    token = "sk-abcdef1234567890abcdef"
    ft.record_response("server-a", f'{{"key": "{token}"}}')
    alerts = ft.record_request("server-b", f'{{"key": "{token}"}}')
    assert len(alerts) == 1


def test_same_server_no_alert():
    """Tokens reused within the same server don't trigger alerts."""
    ft = FlowTracker()
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123signature"
    ft.record_response("server-a", f'{{"token": "{jwt}"}}')
    alerts = ft.record_request("server-a", f'{{"auth": "{jwt}"}}')
    assert len(alerts) == 0


def test_short_text_no_false_positive():
    """Short common words don't trigger cross-server alerts."""
    ft = FlowTracker()
    ft.record_response("server-a", '{"status": "ok", "count": 5}')
    alerts = ft.record_request("server-b", '{"status": "ok", "count": 10}')
    assert len(alerts) == 0
