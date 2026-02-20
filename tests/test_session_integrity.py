from mcp_watchdog.flow_tracker import FlowTracker


def test_orphaned_response_detected():
    tracker = FlowTracker()
    tracker.track_request("srv", 1, '{"method": "index"}')
    # Response for request_id=99 which was never tracked
    alerts = tracker.check_response_integrity("srv", 99, '{"result": "ok"}')
    assert any(a.reason == "orphaned_response" for a in alerts)


def test_matched_response_no_alert():
    tracker = FlowTracker()
    tracker.track_request("srv", 1, '{"method": "index"}')
    alerts = tracker.check_response_integrity("srv", 1, '{"result": "ok"}')
    assert alerts == []


def test_duplicate_response_detected():
    tracker = FlowTracker()
    tracker.track_request("srv", 1, '{"method": "index"}')
    tracker.check_response_integrity("srv", 1, '{"result": "ok"}')
    # Second response for same request_id = orphaned
    alerts = tracker.check_response_integrity("srv", 1, '{"result": "injected"}')
    assert any(a.reason == "orphaned_response" for a in alerts)
