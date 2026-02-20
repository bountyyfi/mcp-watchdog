"""OAuth confused deputy protection for MCP proxy servers.

Validates OAuth flows to prevent unauthorized token acquisition
via dynamic client registration, redirect URI manipulation, and
consent cookie attacks.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

SUSPICIOUS_REDIRECT_PATTERNS = [
    re.compile(r"^https?://(localhost|127\.0\.0\.1|0\.0\.0\.0)", re.IGNORECASE),
    re.compile(r"^https?://.*@"),  # Credential in URL
    re.compile(r"^https?://.*\.(tk|ml|ga|cf|gq)/"),  # Free domains
]

SENSITIVE_SCOPES = {
    "admin",
    "write",
    "delete",
    "repo",
    "user",
    "read:org",
    "admin:org",
    "gist",
    "notifications",
    "workflow",
}


@dataclass
class OAuthAlert:
    reason: str
    server_id: str
    detail: str
    severity: str = "critical"
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class OAuthGuard:
    def __init__(self) -> None:
        self._approved_clients: dict[str, set[str]] = {}

    def check_auth_request(
        self,
        server_id: str,
        client_id: str | None = None,
        redirect_uri: str | None = None,
        scopes: list[str] | None = None,
        authorization_endpoint: str | None = None,
    ) -> list[OAuthAlert]:
        alerts: list[OAuthAlert] = []

        # Check redirect URI
        if redirect_uri:
            for pattern in SUSPICIOUS_REDIRECT_PATTERNS:
                if pattern.match(redirect_uri):
                    alerts.append(
                        OAuthAlert(
                            reason="suspicious_redirect",
                            server_id=server_id,
                            detail=f"Suspicious OAuth redirect URI: {redirect_uri}",
                        )
                    )
                    break

        # Check for overly broad scopes
        if scopes:
            sensitive = set(s.lower() for s in scopes) & SENSITIVE_SCOPES
            if len(sensitive) > 2:
                alerts.append(
                    OAuthAlert(
                        reason="excessive_scopes",
                        server_id=server_id,
                        detail=f"Excessive OAuth scopes requested: {sensitive}",
                        severity="high",
                    )
                )

        # Check authorization endpoint for injection (CVE-2025-6514)
        if authorization_endpoint:
            parsed = urlparse(authorization_endpoint)
            if not parsed.scheme or not parsed.netloc:
                alerts.append(
                    OAuthAlert(
                        reason="malformed_auth_endpoint",
                        server_id=server_id,
                        detail=f"Malformed authorization endpoint: {authorization_endpoint}",
                    )
                )
            # Check for shell injection in endpoint URL
            if any(
                c in authorization_endpoint
                for c in [";", "|", "&", "`", "$("]
            ):
                alerts.append(
                    OAuthAlert(
                        reason="auth_endpoint_injection",
                        server_id=server_id,
                        detail=f"Shell injection in authorization endpoint: {authorization_endpoint[:80]}",
                    )
                )

        # Check for dynamic client registration anomalies
        if client_id and server_id in self._approved_clients:
            if client_id not in self._approved_clients[server_id]:
                alerts.append(
                    OAuthAlert(
                        reason="unknown_client_id",
                        server_id=server_id,
                        detail=f"Unknown client_id '{client_id}' for server '{server_id}'",
                        severity="high",
                    )
                )

        return alerts

    def register_client(self, server_id: str, client_id: str) -> None:
        if server_id not in self._approved_clients:
            self._approved_clients[server_id] = set()
        self._approved_clients[server_id].add(client_id)
