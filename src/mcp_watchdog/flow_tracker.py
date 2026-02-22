"""Cross-server information flow tracking for Thanatos Layer 3 + session integrity.

Tracks tokens/data from one MCP server's responses and detects when
they appear in requests to a different server, indicating cross-server
data propagation attacks. Also tracks session message sequences to
detect agent session smuggling (A2A injection attacks).
"""

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from collections import defaultdict

# Match long alphanumeric tokens (API keys, PATs), JWTs (dot-separated
# base64 segments), UUIDs, and prefix-keyed secrets (ghp_, sk-, AKIA, etc.)
TOKEN_PATTERN = re.compile(
    r"(?:"
    # JWTs: eyJ...header.eyJ...payload.signature
    r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+"
    r"|"
    # UUIDs: 8-4-4-4-12 hex
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r"|"
    # Prefixed API keys (ghp_, gho_, sk-, xoxb-, glpat-, AKIA, etc.)
    r"(?:ghp_|gho_|github_pat_|sk-|sk-proj-|sk-ant-|xoxb-|xoxp-|glpat-|AKIA)[a-zA-Z0-9\-_]{10,}"
    r"|"
    # General long tokens (20+ alphanumeric/underscore/dash)
    r"\b[a-zA-Z0-9_\-]{20,}\b"
    r")"
)


@dataclass
class FlowAlert:
    reason: str
    source_server: str
    target_server: str
    token_preview: str
    severity: str = "high"
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class SessionAlert:
    reason: str
    server_id: str
    detail: str
    severity: str = "critical"
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class FlowTracker:
    def __init__(self, window_size: int = 100) -> None:
        self._response_tokens: dict[str, set[str]] = defaultdict(set)
        self._window_size = window_size
        # Session integrity: server_id -> list of (request_id, request_hash)
        self._pending_requests: dict[str, dict[int, str]] = defaultdict(dict)
        # Message sequence tracking
        self._sequence: dict[str, int] = defaultdict(int)

    def record_response(self, server_id: str, content: str) -> None:
        tokens = set(TOKEN_PATTERN.findall(content))
        self._response_tokens[server_id].update(tokens)
        # Keep window bounded
        if len(self._response_tokens[server_id]) > self._window_size:
            self._response_tokens[server_id] = set(
                list(self._response_tokens[server_id])[-self._window_size :]
            )

    def record_request(
        self, server_id: str, content: str
    ) -> list[FlowAlert]:
        alerts: list[FlowAlert] = []
        request_tokens = set(TOKEN_PATTERN.findall(content))

        for source_id, response_tokens in self._response_tokens.items():
            if source_id == server_id:
                continue
            overlap = request_tokens & response_tokens
            if overlap:
                sample = next(iter(overlap))
                alerts.append(
                    FlowAlert(
                        reason="cross_server_propagation",
                        source_server=source_id,
                        target_server=server_id,
                        token_preview=f"{sample[:20]}...",
                        severity="high",
                    )
                )

        return alerts

    def track_request(self, server_id: str, request_id: int, content: str) -> None:
        h = hashlib.sha256(content.encode()).hexdigest()[:16]
        self._pending_requests[server_id][request_id] = h
        self._sequence[server_id] += 1

    def check_response_integrity(
        self, server_id: str, request_id: int, content: str
    ) -> list[SessionAlert]:
        alerts: list[SessionAlert] = []
        pending = self._pending_requests.get(server_id, {})

        if request_id not in pending:
            alerts.append(
                SessionAlert(
                    reason="orphaned_response",
                    server_id=server_id,
                    detail=(
                        f"Response for request_id={request_id} has no "
                        f"matching tracked request (possible session smuggling)"
                    ),
                )
            )
        else:
            del pending[request_id]

        return alerts
