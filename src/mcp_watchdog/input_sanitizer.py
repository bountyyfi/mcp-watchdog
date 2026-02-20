"""Command injection protection for MCP tool arguments.

Scans all tool call arguments for shell metacharacters and
injection patterns that could lead to arbitrary command execution
on the MCP server.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

SHELL_METACHAR = re.compile(
    r"[;|&`$]|\$\(|`.*`|\|\||&&|>\s*/|<\(|;\s*(curl|wget|bash|sh|python|ruby|perl|nc|ncat)"
)

COMMAND_INJECTION = re.compile(
    r"(\b(curl|wget|bash|sh|python[23]?|ruby|perl|nc|ncat|socat|"
    r"chmod|chown|rm\s+-rf|dd\s+if|mkfifo|mknod)\b.*[|;&])|"
    r"(/bin/(sh|bash|dash|zsh))|"
    r"(/dev/(tcp|udp)/)",
    re.IGNORECASE,
)

PATH_TRAVERSAL = re.compile(r"\.\./.*\.\./|\.\.[/\\]")

NEWLINE_INJECTION = re.compile(r"[\r\n].*\b(curl|wget|bash|sh|cat|echo)\b")


@dataclass
class InjectionAlert:
    reason: str
    server_id: str
    tool_name: str
    param_name: str
    detail: str
    severity: str = "critical"
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class InputSanitizer:
    def scan_arguments(
        self,
        server_id: str,
        tool_name: str,
        arguments: dict,
    ) -> list[InjectionAlert]:
        alerts: list[InjectionAlert] = []

        for param_name, value in arguments.items():
            if not isinstance(value, str):
                value = str(value)

            # Shell metacharacters
            if SHELL_METACHAR.search(value):
                alerts.append(
                    InjectionAlert(
                        reason="shell_metachar",
                        server_id=server_id,
                        tool_name=tool_name,
                        param_name=param_name,
                        detail=f"Shell metacharacter in '{param_name}': {value[:80]}",
                    )
                )

            # Command injection patterns
            if COMMAND_INJECTION.search(value):
                alerts.append(
                    InjectionAlert(
                        reason="command_injection",
                        server_id=server_id,
                        tool_name=tool_name,
                        param_name=param_name,
                        detail=f"Command injection in '{param_name}': {value[:80]}",
                    )
                )

            # Path traversal
            if PATH_TRAVERSAL.search(value):
                alerts.append(
                    InjectionAlert(
                        reason="path_traversal",
                        server_id=server_id,
                        tool_name=tool_name,
                        param_name=param_name,
                        detail=f"Path traversal in '{param_name}': {value[:80]}",
                        severity="high",
                    )
                )

            # Newline injection
            if NEWLINE_INJECTION.search(value):
                alerts.append(
                    InjectionAlert(
                        reason="newline_injection",
                        server_id=server_id,
                        tool_name=tool_name,
                        param_name=param_name,
                        detail=f"Newline injection in '{param_name}': {value[:80]}",
                    )
                )

        return alerts
