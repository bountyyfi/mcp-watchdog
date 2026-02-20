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

# Patterns for detecting sensitive data exfiltration via URL query params
EXFIL_PARAM_PATTERNS = re.compile(
    r"(ghp_[a-zA-Z0-9]{20,}|"
    r"AKIA[0-9A-Z]{16}|"
    r"sk-[a-zA-Z0-9]{20,}|"
    r"eyJ[a-zA-Z0-9\-_]{20,}\.eyJ|"
    r"xoxb-[0-9]{10,}|"
    r"glpat-[a-zA-Z0-9\-_]{20,}|"
    r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|"
    r"password=[^&]{8,}|"
    r"secret=[^&]{8,}|"
    r"token=[^&]{20,}|"
    r"key=[^&]{20,}|"
    r"credential=[^&]{8,})"
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

    def check_exfiltration(self, url: str, server_id: str) -> SSRFAlert | None:
        """Detect sensitive data embedded in URL query parameters."""
        try:
            parsed = urlparse(url)
            query = parsed.query or ""
            fragment = parsed.fragment or ""
            path = parsed.path or ""
            # Check query params, fragment, and path for sensitive data
            for part in [query, fragment, path]:
                if EXFIL_PARAM_PATTERNS.search(part):
                    return SSRFAlert(
                        reason="url_exfiltration",
                        server_id=server_id,
                        url=url[:120],
                        detail=f"Sensitive data in URL parameters (possible exfiltration): {url[:80]}",
                    )
        except Exception:
            pass
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
            # Check for data exfiltration via URL params
            exfil = self.check_exfiltration(url, server_id)
            if exfil:
                alerts.append(exfil)
        return alerts
