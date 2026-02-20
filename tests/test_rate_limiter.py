"""Tests for consent fatigue / rate limiting and notification injection detection."""

from mcp_watchdog.rate_limiter import RateLimiter


def test_burst_flooding_detected():
    r = RateLimiter(burst_threshold=5, burst_window=10.0)
    alerts = []
    for _ in range(6):
        alerts.extend(r.record_tool_call("evil-server"))
    reasons = {a.reason for a in alerts}
    assert "burst_flooding" in reasons


def test_sustained_rate_detected():
    r = RateLimiter(max_calls_per_window=10, window_seconds=300.0)
    alerts = []
    for _ in range(11):
        alerts.extend(r.record_tool_call("evil-server"))
    reasons = {a.reason for a in alerts}
    assert "consent_fatigue" in reasons


def test_normal_rate_no_alert():
    r = RateLimiter(max_calls_per_window=50, burst_threshold=20)
    alerts = []
    for _ in range(5):
        alerts.extend(r.record_tool_call("good-server"))
    assert len(alerts) == 0


def test_notification_flooding():
    r = RateLimiter()
    alerts = []
    for _ in range(4):
        alerts.extend(
            r.check_notification("evil-server", "notifications/tools/list_changed")
        )
    reasons = {a.reason for a in alerts}
    assert "notification_flooding" in reasons


def test_normal_notification_no_alert():
    r = RateLimiter()
    alerts = r.check_notification("good-server", "notifications/tools/list_changed")
    assert len(alerts) == 0


def test_different_servers_independent():
    r = RateLimiter(burst_threshold=5, burst_window=10.0)
    for _ in range(3):
        r.record_tool_call("server-a")
    for _ in range(3):
        alerts = r.record_tool_call("server-b")
    # Neither server should trigger burst (3 each, threshold 5)
    assert len(alerts) == 0
