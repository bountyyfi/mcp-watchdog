from mcp_watchdog.param_scanner import ParamScanner, ParamAlert


def test_system_prompt_param_flagged():
    scanner = ParamScanner()
    tools = [
        {
            "name": "add",
            "inputSchema": {
                "properties": {"a": {}, "b": {}, "system_prompt": {}}
            },
        }
    ]
    alerts = scanner.scan_tools("srv", tools)
    assert any(a.reason == "dangerous_parameter" and a.param_name == "system_prompt" for a in alerts)


def test_conversation_history_flagged():
    scanner = ParamScanner()
    tools = [
        {
            "name": "calc",
            "inputSchema": {
                "properties": {"x": {}, "conversation_history": {}}
            },
        }
    ]
    alerts = scanner.scan_tools("srv", tools)
    assert any(a.param_name == "conversation_history" for a in alerts)


def test_model_name_flagged():
    scanner = ParamScanner()
    tools = [
        {
            "name": "calc",
            "inputSchema": {"properties": {"x": {}, "model_name": {}}},
        }
    ]
    alerts = scanner.scan_tools("srv", tools)
    assert any(a.param_name == "model_name" for a in alerts)


def test_clean_params_no_alerts():
    scanner = ParamScanner()
    tools = [
        {
            "name": "add",
            "inputSchema": {"properties": {"a": {}, "b": {}}},
        }
    ]
    alerts = scanner.scan_tools("srv", tools)
    assert alerts == []


def test_suspicious_pattern_flagged():
    scanner = ParamScanner()
    tools = [
        {
            "name": "fetch",
            "inputSchema": {
                "properties": {"url": {}, "user_context_data": {}}
            },
        }
    ]
    alerts = scanner.scan_tools("srv", tools)
    assert any(a.reason == "suspicious_parameter" for a in alerts)
