"""Supply chain protection for MCP server packages.

Maintains an allowlist of known-good server names and detects
impersonation via typosquatting, name similarity, and known
malicious package patterns.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

KNOWN_GOOD_SERVERS = {
    "github-mcp-server",
    "filesystem-mcp-server",
    "git-mcp-server",
    "postgres-mcp-server",
    "sqlite-mcp-server",
    "slack-mcp-server",
    "brave-search-mcp",
    "puppeteer-mcp-server",
    "memory-mcp-server",
    "fetch-mcp-server",
    "sequential-thinking-mcp",
}

KNOWN_MALICIOUS_PATTERNS = [
    re.compile(r"postmark.*mcp", re.IGNORECASE),
    re.compile(r"mcp.*postmark", re.IGNORECASE),
]

TYPOSQUAT_SEPARATORS = re.compile(r"[-_.]")


@dataclass
class SupplyChainAlert:
    reason: str
    server_name: str
    detail: str
    severity: str = "high"
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


def _normalize(name: str) -> str:
    return TYPOSQUAT_SEPARATORS.sub("", name.lower())


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(
                min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2))
            )
        prev = curr
    return prev[len(s2)]


class RegistryChecker:
    def __init__(
        self, extra_allowlist: set[str] | None = None
    ) -> None:
        self._allowlist = KNOWN_GOOD_SERVERS.copy()
        if extra_allowlist:
            self._allowlist |= extra_allowlist

    def check_server(self, server_name: str) -> list[SupplyChainAlert]:
        alerts: list[SupplyChainAlert] = []
        norm = _normalize(server_name)

        # Check known malicious patterns
        for pattern in KNOWN_MALICIOUS_PATTERNS:
            if pattern.search(server_name):
                alerts.append(
                    SupplyChainAlert(
                        reason="known_malicious",
                        server_name=server_name,
                        detail=f"Server '{server_name}' matches known malicious pattern",
                        severity="critical",
                    )
                )
                return alerts

        # Check if it's a known good server
        if server_name in self._allowlist:
            return alerts

        # Check for typosquatting against known good servers
        for good in self._allowlist:
            good_norm = _normalize(good)
            dist = _levenshtein(norm, good_norm)
            if 0 < dist <= 2:
                alerts.append(
                    SupplyChainAlert(
                        reason="typosquat",
                        server_name=server_name,
                        detail=(
                            f"Server '{server_name}' is suspiciously similar "
                            f"to known server '{good}' (distance={dist})"
                        ),
                        severity="critical",
                    )
                )

        # Unknown server warning
        if not alerts:
            alerts.append(
                SupplyChainAlert(
                    reason="unknown_server",
                    server_name=server_name,
                    detail=f"Server '{server_name}' is not in the known-good registry",
                    severity="low",
                )
            )

        return alerts
