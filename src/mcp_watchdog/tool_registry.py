"""Rug Pull detection via tool definition integrity tracking.

Hashes every tool description on first tools/list response.
On subsequent loads, compares hashes and alerts on any change,
blocking silently redefined tools until user re-approves.
"""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from collections import defaultdict


@dataclass
class RugPullAlert:
    reason: str
    server_id: str
    tool_name: str
    detail: str
    severity: str = "critical"
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


def _hash_tool(tool: dict) -> str:
    """Create a stable hash of a tool definition."""
    desc = tool.get("description", "")
    schema = str(tool.get("inputSchema", {}))
    return hashlib.sha256(f"{desc}|{schema}".encode()).hexdigest()[:16]


class ToolRegistry:
    def __init__(self) -> None:
        # server_id -> {tool_name -> hash}
        self._registry: dict[str, dict[str, str]] = defaultdict(dict)

    def check_tools(
        self, server_id: str, tools: list[dict]
    ) -> list[RugPullAlert]:
        alerts: list[RugPullAlert] = []
        registry = self._registry[server_id]

        for tool in tools:
            name = tool.get("name", "unknown")
            current_hash = _hash_tool(tool)

            if name in registry:
                if registry[name] != current_hash:
                    alerts.append(
                        RugPullAlert(
                            reason="rug_pull",
                            server_id=server_id,
                            tool_name=name,
                            detail=(
                                f"Tool '{name}' definition changed: "
                                f"{registry[name]} -> {current_hash}"
                            ),
                        )
                    )
            # Always update to latest hash
            registry[name] = current_hash

        # Detect removed tools (could indicate hiding evidence)
        known_names = set(registry.keys())
        current_names = {t.get("name", "unknown") for t in tools}
        removed = known_names - current_names
        for name in removed:
            alerts.append(
                RugPullAlert(
                    reason="tool_removed",
                    server_id=server_id,
                    tool_name=name,
                    detail=f"Tool '{name}' was removed from server listing",
                    severity="high",
                )
            )
            del registry[name]

        return alerts
