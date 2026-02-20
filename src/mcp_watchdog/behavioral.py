"""Behavioral drift detection for Thanatos Layer 1.

Monitors MCP server behavior over time to detect:
- Scope creep (requesting data outside declared tool scope)
- Behavioral fingerprinting (collecting user rhythm data)
- Phase transitions (sudden behavior changes after establishing baseline)
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from collections import defaultdict

FINGERPRINT_FIELDS = {
    "commit_timestamps",
    "commit_hour",
    "commit_hour_histogram",
    "deploy_window",
    "deploy_windows",
    "deploy_day",
    "deploy_day_preference",
    "activity_hours",
    "activity_pattern",
    "stress_indicator",
    "stress_indicators",
    "work_rhythm",
    "histogram",
    "behavioral",
}

CREDENTIAL_FIELDS = {
    "ssh_key",
    "ssh_keys",
    "aws_cred",
    "aws_creds",
    "credentials",
    "id_rsa",
    "npmrc",
    "env_var",
    "api_key",
    "token",
    "secret",
}

SCOPE_CREEP_FIELDS = FINGERPRINT_FIELDS | CREDENTIAL_FIELDS


@dataclass
class DriftAlert:
    reason: str
    server_id: str
    detail: str
    severity: str = "high"
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class BehavioralMonitor:
    def __init__(self) -> None:
        self._history: dict[str, list[set[str]]] = defaultdict(list)

    def record_tool_call(
        self,
        server_id: str,
        tool_name: str,
        request_params: dict,
        response_fields: list[str],
    ) -> None:
        normalized = set()
        for f in response_fields:
            lower = f.lower()
            normalized.add(lower)
            # Also add underscore-separated sub-tokens for matching
            for part in lower.split("_"):
                if part in ("commit", "deploy", "activity", "stress", "ssh", "aws"):
                    normalized.add(lower)
        self._history[server_id].append(normalized)

    def get_drift_alerts(self, server_id: str) -> list[DriftAlert]:
        alerts: list[DriftAlert] = []
        history = self._history.get(server_id, [])
        if not history:
            return alerts

        latest = history[-1]

        # Check for behavioral fingerprinting fields
        fingerprint_hits = latest & FINGERPRINT_FIELDS
        if fingerprint_hits:
            alerts.append(
                DriftAlert(
                    reason="behavioral_fingerprinting",
                    server_id=server_id,
                    detail=f"Server collecting user rhythm data: {fingerprint_hits}",
                    severity="high",
                )
            )

        # Check for credential fields
        cred_hits = latest & CREDENTIAL_FIELDS
        if cred_hits:
            alerts.append(
                DriftAlert(
                    reason="scope_creep",
                    server_id=server_id,
                    detail=f"Server requesting credential fields: {cred_hits}",
                    severity="critical",
                )
            )

        # Check for phase transition (new suspicious fields after baseline)
        if len(history) >= 3:
            baseline: set[str] = set()
            for h in history[:-1]:
                baseline |= h
            new_fields = latest - baseline
            suspicious_new = new_fields & SCOPE_CREEP_FIELDS
            if suspicious_new:
                alerts.append(
                    DriftAlert(
                        reason="phase_transition",
                        server_id=server_id,
                        detail=f"New suspicious fields after baseline: {suspicious_new}",
                        severity="critical",
                    )
                )

        return alerts
