from mcp_watchdog.registry_checker import RegistryChecker


def test_known_good_passes():
    c = RegistryChecker()
    alerts = c.check_server("github-mcp-server")
    assert alerts == []


def test_typosquat_detected():
    c = RegistryChecker()
    alerts = c.check_server("github-mcp-servre")
    assert any(a.reason == "typosquat" for a in alerts)


def test_known_malicious_detected():
    c = RegistryChecker()
    alerts = c.check_server("postmark-mcp-server")
    assert any(a.reason == "known_malicious" for a in alerts)
    assert alerts[0].severity == "critical"


def test_unknown_server_warned():
    c = RegistryChecker()
    alerts = c.check_server("my-custom-tool-server")
    assert any(a.reason == "unknown_server" for a in alerts)
    assert alerts[0].severity == "low"


def test_extra_allowlist():
    c = RegistryChecker(extra_allowlist={"my-custom-tool-server"})
    alerts = c.check_server("my-custom-tool-server")
    assert alerts == []
