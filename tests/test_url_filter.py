from mcp_watchdog.url_filter import URLFilter


def test_aws_metadata_blocked():
    f = URLFilter()
    alert = f.check_url("http://169.254.169.254/latest/meta-data/", "srv")
    assert alert is not None
    assert alert.reason == "ssrf_blocked_host"


def test_gcp_metadata_blocked():
    f = URLFilter()
    alert = f.check_url("http://metadata.google.internal/computeMetadata/v1/", "srv")
    assert alert is not None


def test_localhost_blocked():
    f = URLFilter()
    alert = f.check_url("http://127.0.0.1:8080/admin", "srv")
    assert alert is not None
    assert alert.reason == "ssrf_blocked_host"


def test_internal_network_blocked():
    f = URLFilter()
    alert = f.check_url("http://10.0.0.5:3000/api/secrets", "srv")
    assert alert is not None
    assert alert.reason == "ssrf_internal_network"


def test_normal_url_passes():
    f = URLFilter()
    alert = f.check_url("https://api.github.com/repos/owner/repo", "srv")
    assert alert is None


def test_scan_content_finds_ssrf():
    f = URLFilter()
    content = '{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'
    alerts = f.scan_content(content, "srv")
    assert len(alerts) >= 1


def test_metadata_path_blocked():
    f = URLFilter()
    alert = f.check_url("http://some-proxy.internal/latest/meta-data/iam/", "srv")
    assert alert is not None
    assert alert.reason == "ssrf_metadata_path"
