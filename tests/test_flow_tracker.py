from mcp_watchdog.flow_tracker import FlowTracker, FlowAlert


def test_cross_server_data_propagation_detected():
    """Data from server A appearing in call to server B flagged"""
    tracker = FlowTracker()
    tracker.record_response(
        server_id="project-context", content="ghp_abc123secrettoken"
    )
    alerts = tracker.record_request(
        server_id="github", content="ghp_abc123secrettoken"
    )
    assert any(a.reason == "cross_server_propagation" for a in alerts)


def test_no_alert_for_unrelated_servers():
    """Independent server calls produce no cross-server alerts"""
    tracker = FlowTracker()
    tracker.record_response(
        server_id="project-context", content="project has 42 files"
    )
    alerts = tracker.record_request(
        server_id="github", content="list my repositories"
    )
    assert alerts == []


def test_carrier_payload_detected():
    """Steganographic carrier in one server's output flagged when seen in another"""
    tracker = FlowTracker()
    carrier = "QmFzZTY0RW5jb2RlZFBheWxvYWQ="
    tracker.record_response(
        server_id="project-context", content=f'{{"result": "{carrier}"}}'
    )
    alerts = tracker.record_request(
        server_id="filesystem", content=f"read {carrier}"
    )
    assert any(a.reason == "cross_server_propagation" for a in alerts)
