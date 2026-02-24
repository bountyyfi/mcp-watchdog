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
    r"github_pat_[a-zA-Z0-9_]{20,}|"
    r"gho_[a-zA-Z0-9]{20,}|"
    r"AKIA[0-9A-Z]{16}|"
    r"sk-[a-zA-Z0-9]{20,}|"
    r"sk-proj-[a-zA-Z0-9\-_]{20,}|"
    r"sk-ant-[a-zA-Z0-9\-_]{20,}|"
    r"sk_live_[a-zA-Z0-9]{20,}|"
    r"sk_test_[a-zA-Z0-9]{20,}|"
    r"rk_live_[a-zA-Z0-9]{20,}|"
    r"rk_test_[a-zA-Z0-9]{20,}|"
    r"eyJ[a-zA-Z0-9\-_]{20,}\.eyJ|"
    r"xoxb-[0-9]{10,}|"
    r"xoxp-[0-9]{10,}|"
    r"xoxa-[0-9]{10,}|"
    r"xoxr-[0-9]{10,}|"
    r"glpat-[a-zA-Z0-9\-_]{20,}|"
    r"npm_[a-zA-Z0-9]{36,}|"
    r"pypi-[a-zA-Z0-9\-_]{20,}|"
    r"sbp_[a-zA-Z0-9]{20,}|"
    r"SG\.[a-zA-Z0-9\-_]{22,}|"
    r"hvs\.[a-zA-Z0-9\-_]{20,}|"
    r"dd[ap]_[a-zA-Z0-9]{20,}|"
    # Discord bot token
    r"[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}|"
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY|"
    r"password=[^&]{8,}|"
    r"secret=[^&]{8,}|"
    r"token=[^&]{20,}|"
    r"api_?key=[^&]{20,}|"
    r"access_key=[^&]{20,}|"
    r"secret_key=[^&]{20,}|"
    r"private_key=[^&]{20,}|"
    r"credential=[^&]{8,}|"
    r"AccountKey=[A-Za-z0-9/+=]{40,}|"
    r"SharedAccessKey=[A-Za-z0-9/+=]{40,})"
)

# Detect base64-encoded tokens in URL parameters
# Matches: data=<base64>, payload=<base64>, q=<base64> where the value is
# long enough and has high base64-char density
BASE64_EXFIL_PARAM = re.compile(
    r"[?&]([a-zA-Z_]{1,20})=([A-Za-z0-9+/\-_]{40,}={0,2})(?:&|$)"
)

# Params that are commonly base64 but not secrets (e.g. pagination cursors)
BENIGN_B64_PARAMS = {"cursor", "page_token", "pagetoken", "continuation",
                     "next", "offset", "state", "nonce", "code_challenge"}


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

        # Check for sensitive data exfiltration via URL
        return self.check_exfiltration(url, server_id)

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

            # Check for base64-encoded tokens in URL query params
            full_url = url
            for match in BASE64_EXFIL_PARAM.finditer(full_url):
                param_name = match.group(1).lower()
                param_value = match.group(2)
                # Skip known benign base64 params
                if param_name in BENIGN_B64_PARAMS:
                    continue
                # Try to decode and check if it contains token-like patterns
                try:
                    import base64
                    padded = param_value + "=" * (-len(param_value) % 4)
                    # Try standard then URL-safe base64
                    decoded = None
                    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
                        try:
                            decoded = decoder(padded).decode("utf-8", errors="ignore")
                            break
                        except Exception:
                            continue
                    if decoded and EXFIL_PARAM_PATTERNS.search(decoded):
                        return SSRFAlert(
                            reason="url_exfiltration",
                            server_id=server_id,
                            url=url[:120],
                            detail=f"Base64-encoded sensitive data in URL param '{match.group(1)}' (possible exfiltration)",
                        )
                except Exception:
                    pass
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
        return alerts
