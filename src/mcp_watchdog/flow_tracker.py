"""Cross-server information flow tracking for Thanatos Layer 3.

Tracks tokens/data from one MCP server's responses and detects when
they appear in requests to a different server, indicating cross-server
data propagation attacks.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from collections import defaultdict

TOKEN_PATTERN = re.compile(r"\b([a-zA-Z0-9_\-]{20,})\b")


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


class FlowTracker:
    def __init__(self, window_size: int = 100) -> None:
        self._response_tokens: dict[str, set[str]] = defaultdict(set)
        self._window_size = window_size

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
