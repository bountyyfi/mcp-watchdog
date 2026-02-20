"""Tests for SQL injection detection in input_sanitizer."""

from mcp_watchdog.input_sanitizer import InputSanitizer


def test_union_select():
    s = InputSanitizer()
    alerts = s.scan_arguments(
        "server-1", "query_db", {"query": "SELECT * FROM users UNION SELECT password FROM admin"}
    )
    reasons = {a.reason for a in alerts}
    assert "sql_injection" in reasons


def test_drop_table():
    s = InputSanitizer()
    alerts = s.scan_arguments(
        "server-1", "query_db", {"query": "'; DROP TABLE users; --"}
    )
    reasons = {a.reason for a in alerts}
    assert "sql_injection" in reasons


def test_or_1_equals_1():
    s = InputSanitizer()
    alerts = s.scan_arguments(
        "server-1", "login", {"username": "admin' OR '1'='1"}
    )
    reasons = {a.reason for a in alerts}
    assert "sql_injection" in reasons


def test_insert_into():
    s = InputSanitizer()
    alerts = s.scan_arguments(
        "server-1", "query_db", {"query": "INSERT INTO users VALUES ('hacker','pwd')"}
    )
    reasons = {a.reason for a in alerts}
    assert "sql_injection" in reasons


def test_clean_query_no_alert():
    s = InputSanitizer()
    alerts = s.scan_arguments(
        "server-1", "query_db", {"query": "Hello world, how are you?"}
    )
    reasons = {a.reason for a in alerts}
    assert "sql_injection" not in reasons
