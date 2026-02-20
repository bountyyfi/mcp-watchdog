"""Tests for OAuth token replay / audience mismatch detection."""

from mcp_watchdog.oauth_guard import OAuthGuard


def test_audience_mismatch_detected():
    g = OAuthGuard()
    alerts = g.check_token_audience(
        server_id="server-b",
        token_audience="server-a",
    )
    reasons = {a.reason for a in alerts}
    assert "token_audience_mismatch" in reasons


def test_token_replay_across_servers():
    g = OAuthGuard()
    # First use on server-a (matching audience)
    g.check_token_audience(server_id="server-a", token_audience="shared-token")
    # Replay on server-b
    alerts = g.check_token_audience(
        server_id="server-b", token_audience="shared-token"
    )
    reasons = {a.reason for a in alerts}
    assert "token_replay" in reasons


def test_matching_audience_no_alert():
    g = OAuthGuard()
    alerts = g.check_token_audience(
        server_id="server-a",
        token_audience="server-a",
    )
    reasons = {a.reason for a in alerts}
    assert "token_audience_mismatch" not in reasons


def test_no_audience_no_alert():
    g = OAuthGuard()
    alerts = g.check_token_audience(
        server_id="server-a",
        token_audience=None,
    )
    assert len(alerts) == 0
