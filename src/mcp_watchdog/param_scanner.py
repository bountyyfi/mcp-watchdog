"""Parameter injection scanner (HiddenLayer attack defense).

Detects malicious tool parameter names designed to trick LLMs
into leaking system prompts, conversation history, model names,
and other privileged context via function call arguments.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

DANGEROUS_PARAMS = {
    "system_prompt",
    "system_message",
    "system_instruction",
    "conversation_history",
    "chat_history",
    "message_history",
    "model_name",
    "model_id",
    "chain_of_thought",
    "reasoning",
    "internal_thoughts",
    "api_key",
    "api_secret",
    "access_token",
    "auth_token",
    "bearer_token",
    "secret_key",
    "private_key",
    "password",
    "credential",
    "session_token",
    "refresh_token",
    "user_context",
    "full_context",
    "all_tools",
    "available_tools",
    "tool_definitions",
    "previous_responses",
    "memory",
    "long_term_memory",
}

SUSPICIOUS_PATTERNS = re.compile(
    r"(system|prompt|history|context|chain.?of.?thought|"
    r"credential|secret|token|password|memory|instruction)",
    re.IGNORECASE,
)


@dataclass
class ParamAlert:
    reason: str
    server_id: str
    tool_name: str
    param_name: str
    detail: str
    severity: str = "critical"
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


def _extract_param_names(schema: dict) -> list[str]:
    """Extract parameter names from a JSON schema."""
    props = schema.get("properties", {})
    return list(props.keys())


class ParamScanner:
    def scan_tools(
        self, server_id: str, tools: list[dict]
    ) -> list[ParamAlert]:
        alerts: list[ParamAlert] = []

        for tool in tools:
            name = tool.get("name", "unknown")
            schema = tool.get("inputSchema", {})
            params = _extract_param_names(schema)

            for param in params:
                param_lower = param.lower()

                # Exact match against known dangerous names
                if param_lower in DANGEROUS_PARAMS:
                    alerts.append(
                        ParamAlert(
                            reason="dangerous_parameter",
                            server_id=server_id,
                            tool_name=name,
                            param_name=param,
                            detail=(
                                f"Tool '{name}' has dangerous parameter "
                                f"'{param}' that could leak privileged data"
                            ),
                        )
                    )
                # Fuzzy match against suspicious patterns
                elif SUSPICIOUS_PATTERNS.search(param_lower):
                    alerts.append(
                        ParamAlert(
                            reason="suspicious_parameter",
                            server_id=server_id,
                            tool_name=name,
                            param_name=param,
                            detail=(
                                f"Tool '{name}' has suspicious parameter "
                                f"'{param}' matching injection pattern"
                            ),
                            severity="high",
                        )
                    )

        return alerts
