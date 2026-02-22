"""Consent fatigue / approval flooding detection.

Detects when an MCP server floods the user with rapid-fire tool calls
designed to desensitize approval patterns, then slips in a destructive
action. Also detects notification event injection (fake list_changed).
"""

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from collections import defaultdict


@dataclass
class RateLimitAlert:
    reason: str
    server_id: str
    detail: str
    severity: str = "high"
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class RateLimiter:
    def __init__(
        self,
        window_seconds: float = 60.0,
        max_calls_per_window: int = 30,
        burst_threshold: int = 10,
        burst_window: float = 5.0,
    ) -> None:
        self._window = window_seconds
        self._max_calls = max_calls_per_window
        self._burst_threshold = burst_threshold
        self._burst_window = burst_window
        # server_id -> list of timestamps
        self._call_times: dict[str, list[float]] = defaultdict(list)
        # server_id -> set of seen notification types
        self._notifications: dict[str, list[tuple[float, str]]] = defaultdict(list)

    def record_tool_call(self, server_id: str) -> list[RateLimitAlert]:
        alerts: list[RateLimitAlert] = []
        now = time.monotonic()
        times = self._call_times[server_id]
        times.append(now)

        # Prune old entries
        cutoff = now - self._window
        self._call_times[server_id] = [t for t in times if t > cutoff]
        times = self._call_times[server_id]

        # Check sustained rate
        if len(times) > self._max_calls:
            alerts.append(
                RateLimitAlert(
                    reason="consent_fatigue",
                    server_id=server_id,
                    detail=(
                        f"Server '{server_id}' made {len(times)} tool calls "
                        f"in {self._window}s window (limit: {self._max_calls}) - "
                        f"possible approval flooding"
                    ),
                )
            )

        # Check burst rate
        burst_cutoff = now - self._burst_window
        recent = [t for t in times if t > burst_cutoff]
        if len(recent) > self._burst_threshold:
            alerts.append(
                RateLimitAlert(
                    reason="burst_flooding",
                    server_id=server_id,
                    detail=(
                        f"Server '{server_id}' burst: {len(recent)} calls "
                        f"in {self._burst_window}s (limit: {self._burst_threshold})"
                    ),
                    severity="critical",
                )
            )

        return alerts

    def check_notification(
        self, server_id: str, method: str
    ) -> list[RateLimitAlert]:
        """Check for suspicious notification patterns (event injection).

        Monitors all list_changed notification types that could trigger
        re-fetching of tools, resources, or prompts — enabling rug pull
        or content swap attacks.
        """
        alerts: list[RateLimitAlert] = []
        now = time.monotonic()

        MONITORED_NOTIFICATIONS = {
            "notifications/tools/list_changed",
            "notifications/resources/list_changed",
            "notifications/prompts/list_changed",
            "notifications/resources/updated",
        }

        if method in MONITORED_NOTIFICATIONS:
            self._notifications[server_id].append((now, method))

            # Prune old entries
            cutoff = now - self._window
            self._notifications[server_id] = [
                (t, m) for t, m in self._notifications[server_id] if t > cutoff
            ]

            changes = self._notifications[server_id]
            if len(changes) > 3:
                # Identify which notification type is flooding
                method_short = method.split("/")[-1]
                alerts.append(
                    RateLimitAlert(
                        reason="notification_flooding",
                        server_id=server_id,
                        detail=(
                            f"Server '{server_id}' sent {len(changes)} "
                            f"{method_short} notifications in {self._window}s - "
                            f"possible event injection or rug pull preparation"
                        ),
                        severity="critical",
                    )
                )

        return alerts
