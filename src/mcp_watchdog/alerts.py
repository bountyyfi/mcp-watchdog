"""Alert formatting and output for mcp-watchdog."""

from dataclasses import dataclass, field
from datetime import datetime, timezone

from rich.console import Console
from rich.panel import Panel

console = Console()


@dataclass
class WatchdogAlert:
    severity: str  # critical, high, medium, low
    server_id: str
    rule: str
    detail: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "dim yellow",
}


def print_alert(alert: WatchdogAlert) -> None:
    color = SEVERITY_COLORS.get(alert.severity, "white")
    console.print(
        Panel(
            f"[{color}]{alert.severity.upper()}[/{color}] [{alert.rule}] "
            f"{alert.server_id}\n{alert.detail}",
            title="[bold red]mcp-watchdog ALERT[/bold red]",
            border_style="red",
        )
    )
