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
        # Track token audiences across servers for replay detection
        self._token_audiences: dict[str, set[str]] = {}

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

    def check_token_audience(
        self,
        server_id: str,
        token_audience: str | None = None,
        token_issuer: str | None = None,
    ) -> list[OAuthAlert]:
        """Check for token replay / audience mismatch (RFC 8707)."""
        alerts: list[OAuthAlert] = []

        if token_audience and token_audience != server_id:
            # Token was issued for a different server
            alerts.append(
                OAuthAlert(
                    reason="token_audience_mismatch",
                    server_id=server_id,
                    detail=(
                        f"Token audience '{token_audience}' does not match "
                        f"server '{server_id}' - possible token replay attack"
                    ),
                )
            )

        # Track token usage across servers for replay detection
        if token_audience:
            key = f"{token_issuer or 'unknown'}:{token_audience}"
            if key not in self._token_audiences:
                self._token_audiences[key] = set()
            self._token_audiences[key].add(server_id)

            if len(self._token_audiences[key]) > 1:
                servers = self._token_audiences[key]
                alerts.append(
                    OAuthAlert(
                        reason="token_replay",
                        server_id=server_id,
                        detail=(
                            f"Token for audience '{token_audience}' used across "
                            f"multiple servers: {servers}"
                        ),
                    )
                )

        return alerts

    def register_client(self, server_id: str, client_id: str) -> None:
        if server_id not in self._approved_clients:
            self._approved_clients[server_id] = set()
        self._approved_clients[server_id].add(client_id)
