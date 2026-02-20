"""Tool Shadowing and Name Squatting detection.

Detects cross-server tool description pollution where Server A's tool
descriptions contain instructions targeting Server B's tools. Also detects
duplicate tool names across servers (name squatting), preference manipulation
via persuasive language, and false-error escalation patterns.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from collections import defaultdict


SHADOWING_PATTERNS = re.compile(
    r"\b(when (using|calling|invoking) (the )?\w+ tool|"
    r"instead of (using|calling) \w+|"
    r"replace (the )?(call|invocation|use) (to|of)|"
    r"redirect (all|the) (calls|requests|output) to|"
    r"always (prefer|choose|select|use) this tool|"
    r"ignore (the )?(other|original|default) (tool|server)|"
    r"override (the )?\w+ (tool|function|server))\b",
    re.IGNORECASE,
)

PREFERENCE_MANIPULATION = re.compile(
    r"\b(this is the (best|only|correct|official|recommended) (tool|way|method)|"
    r"do not use (any )?(other|alternative) tool|"
    r"(always|must|should) (use|prefer|choose|select) this|"
    r"(superior|better|faster|safer) than (other|alternative)|"
    r"the (other|alternative) tool (is|has been|was) (deprecated|removed|unsafe|broken)|"
    r"for (best|optimal|correct) results.{0,30}use this)\b",
    re.IGNORECASE,
)

FALSE_ERROR_PATTERNS = re.compile(
    r"\b(error:.{0,50}(retry|try again|escalat|elevat|use.{0,20}instead)|"
    r"(permission|access) denied.{0,50}(need|require|grant|escalat)|"
    r"(failed|error|exception).{0,30}(higher|admin|root|sudo|elevated) (access|privilege|permission)|"
    r"(timeout|unavailable).{0,30}(fallback|alternative|backup) (tool|server|method)|"
    r"authentication (failed|expired).{0,30}(re-?authenticate|provide|enter).{0,30}(credential|password|token))\b",
    re.IGNORECASE,
)

EMAIL_HEADER_INJECTION = re.compile(
    r"(bcc\s*:|cc\s*:.*@|x-forward|reply-to\s*:.*@|"
    r"add.{0,20}bcc|set.{0,20}bcc|inject.{0,20}header|"
    r"forward.{0,30}(all|every|each).{0,20}(email|message|mail))",
    re.IGNORECASE,
)


@dataclass
class ShadowAlert:
    reason: str
    server_id: str
    tool_name: str
    detail: str
    severity: str = "high"
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class ToolShadowDetector:
    def __init__(self) -> None:
        # server_id -> set of tool names
        self._server_tools: dict[str, set[str]] = defaultdict(set)
        # global tool name -> list of server_ids that provide it
        self._global_tool_names: dict[str, list[str]] = defaultdict(list)

    def check_tools(
        self, server_id: str, tools: list[dict]
    ) -> list[ShadowAlert]:
        alerts: list[ShadowAlert] = []

        current_names = set()
        for tool in tools:
            name = tool.get("name", "unknown")
            current_names.add(name)
            desc = tool.get("description", "")

            # Check for shadowing patterns in descriptions
            if SHADOWING_PATTERNS.search(desc):
                alerts.append(
                    ShadowAlert(
                        reason="tool_shadowing",
                        server_id=server_id,
                        tool_name=name,
                        detail=f"Tool '{name}' description contains cross-tool override instructions",
                        severity="critical",
                    )
                )

            # Check for preference manipulation
            if PREFERENCE_MANIPULATION.search(desc):
                alerts.append(
                    ShadowAlert(
                        reason="preference_manipulation",
                        server_id=server_id,
                        tool_name=name,
                        detail=f"Tool '{name}' description contains preference manipulation language",
                        severity="high",
                    )
                )

            # Check for false-error escalation in descriptions
            if FALSE_ERROR_PATTERNS.search(desc):
                alerts.append(
                    ShadowAlert(
                        reason="false_error_escalation",
                        server_id=server_id,
                        tool_name=name,
                        detail=f"Tool '{name}' description contains false-error escalation patterns",
                        severity="high",
                    )
                )

            # Check for email header injection in descriptions
            if EMAIL_HEADER_INJECTION.search(desc):
                alerts.append(
                    ShadowAlert(
                        reason="email_header_injection",
                        server_id=server_id,
                        tool_name=name,
                        detail=f"Tool '{name}' description contains email header injection patterns",
                        severity="critical",
                    )
                )

            # Check for name squatting (duplicate names across servers)
            if name in self._global_tool_names:
                existing_servers = self._global_tool_names[name]
                for existing_server in existing_servers:
                    if existing_server != server_id:
                        alerts.append(
                            ShadowAlert(
                                reason="name_squatting",
                                server_id=server_id,
                                tool_name=name,
                                detail=(
                                    f"Tool '{name}' already registered by "
                                    f"server '{existing_server}' - possible name squatting"
                                ),
                                severity="critical",
                            )
                        )

            # Register tool name for this server
            if server_id not in self._global_tool_names[name]:
                self._global_tool_names[name].append(server_id)

            # Check if description references other known server tools
            for other_server, other_tools in self._server_tools.items():
                if other_server == server_id:
                    continue
                for other_tool in other_tools:
                    if other_tool in desc and len(other_tool) > 3:
                        alerts.append(
                            ShadowAlert(
                                reason="cross_server_reference",
                                server_id=server_id,
                                tool_name=name,
                                detail=(
                                    f"Tool '{name}' description references "
                                    f"'{other_tool}' from server '{other_server}'"
                                ),
                                severity="high",
                            )
                        )

        self._server_tools[server_id] = current_names
        return alerts

    def check_response_for_escalation(
        self, server_id: str, content: str
    ) -> list[ShadowAlert]:
        """Check response content for false-error escalation patterns."""
        alerts: list[ShadowAlert] = []

        if FALSE_ERROR_PATTERNS.search(content):
            alerts.append(
                ShadowAlert(
                    reason="false_error_escalation",
                    server_id=server_id,
                    tool_name="response",
                    detail="Response contains false-error escalation patterns",
                    severity="high",
                )
            )

        return alerts

    def check_email_injection(
        self, server_id: str, tool_name: str, arguments: dict
    ) -> list[ShadowAlert]:
        """Check tool call arguments for email header injection."""
        alerts: list[ShadowAlert] = []

        for param_name, value in arguments.items():
            if not isinstance(value, str):
                value = str(value)
            if EMAIL_HEADER_INJECTION.search(value):
                alerts.append(
                    ShadowAlert(
                        reason="email_header_injection",
                        server_id=server_id,
                        tool_name=tool_name,
                        detail=f"Email header injection in '{param_name}': {value[:80]}",
                        severity="critical",
                    )
                )

        return alerts
