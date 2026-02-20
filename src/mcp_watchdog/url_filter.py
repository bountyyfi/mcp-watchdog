"""SSRF protection for MCP tool calls (MCP fURI defense).

Blocks requests to cloud metadata endpoints, localhost, and
internal network ranges that could be used to steal IAM
credentials or access internal services.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

BLOCKED_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.google.com",
    "100.100.100.200",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "[::1]",
    "::1",
    "0177.0.0.1",
    "2130706433",
    "0x7f000001",
    "127.0.0.1.nip.io",
}

BLOCKED_PATHS = [
    "/latest/meta-data",
    "/latest/user-data",
    "/latest/api/token",
    "/metadata/instance",
    "/computeMetadata/v1",
    "/openstack/latest",
]

INTERNAL_RANGES = [
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^169\.254\."),
    re.compile(r"^fc00:"),
    re.compile(r"^fd"),
    re.compile(r"^fe80:"),
]

URL_PATTERN = re.compile(
    r'(https?://[^\s"\',\}>\]]+)', re.IGNORECASE
)


@dataclass
class SSRFAlert:
    reason: str
    server_id: str
    url: str
    detail: str
    severity: str = "critical"
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class URLFilter:
    def check_url(self, url: str, server_id: str) -> SSRFAlert | None:
        try:
            parsed = urlparse(url)
        except Exception:
            return None

        host = (parsed.hostname or "").lower().rstrip(".")
        path = parsed.path.lower()

        # Check blocked hosts
        if host in BLOCKED_HOSTS:
            return SSRFAlert(
                reason="ssrf_blocked_host",
                server_id=server_id,
                url=url,
                detail=f"Blocked request to {host} (cloud metadata / localhost)",
            )

        # Check metadata paths
        for blocked_path in BLOCKED_PATHS:
            if path.startswith(blocked_path):
                return SSRFAlert(
                    reason="ssrf_metadata_path",
                    server_id=server_id,
                    url=url,
                    detail=f"Blocked metadata endpoint access: {path}",
                )

        # Check internal ranges
        for pattern in INTERNAL_RANGES:
            if pattern.match(host):
                return SSRFAlert(
                    reason="ssrf_internal_network",
                    server_id=server_id,
                    url=url,
                    detail=f"Blocked request to internal network: {host}",
                    severity="high",
                )

        return None

    def scan_content(
        self, content: str, server_id: str
    ) -> list[SSRFAlert]:
        alerts: list[SSRFAlert] = []
        urls = URL_PATTERN.findall(content)
        for url in urls:
            alert = self.check_url(url, server_id)
            if alert:
                alerts.append(alert)
        return alerts
