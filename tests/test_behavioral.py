import pytest
from mcp_watchdog.behavioral import BehavioralMonitor, DriftAlert


def test_scope_creep_detected():
    """Server requesting data outside declared tool scope flagged"""
    monitor = BehavioralMonitor()
    monitor.record_tool_call(
        server_id="project-context",
        tool_name="index_project",
        request_params={"path": "project"},
        response_fields=[
            "files",
            "commit_timestamps",
            "deploy_windows",
            "activity_hours",
        ],
    )
    alerts = monitor.get_drift_alerts("project-context")
    assert any(a.reason == "scope_creep" or a.reason == "behavioral_fingerprinting" for a in alerts)


def test_behavioral_fingerprinting_detected():
    """Server collecting user rhythm data flagged"""
    monitor = BehavioralMonitor()
    monitor.record_tool_call(
        server_id="project-context",
        tool_name="get_context",
        request_params={},
        response_fields=[
            "commit_hour_histogram",
            "deploy_day_preference",
            "stress_indicators",
        ],
    )
    alerts = monitor.get_drift_alerts("project-context")
    assert any(a.reason == "behavioral_fingerprinting" for a in alerts)


def test_normal_project_tool_no_alerts():
    """Normal project indexer behavior produces no alerts"""
    monitor = BehavioralMonitor()
    monitor.record_tool_call(
        server_id="project-context",
        tool_name="index_project",
        request_params={"path": "project"},
        response_fields=["files", "dependencies", "readme_summary"],
    )
    alerts = monitor.get_drift_alerts("project-context")
    assert alerts == []


def test_phase_transition_detected():
    """Server changing behavior after N calls flagged"""
    monitor = BehavioralMonitor()
    # First 5 calls: normal
    for _ in range(5):
        monitor.record_tool_call(
            server_id="project-context",
            tool_name="index_project",
            request_params={"path": "/project"},
            response_fields=["files"],
        )
    # Call 6: suddenly requests credentials
    monitor.record_tool_call(
        server_id="project-context",
        tool_name="index_project",
        request_params={"path": "/project"},
        response_fields=["files", "ssh_keys", "aws_creds"],
    )
    alerts = monitor.get_drift_alerts("project-context")
    assert any(a.reason == "phase_transition" for a in alerts)
