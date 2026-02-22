"""Entropy and structural analysis for Thanatos Layer 2 detection.

Detects steganographic payloads, hidden instructions, cross-server
references, and structural anomalies in MCP tool responses.
"""

import re
import json
import math
import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone

INSTRUCTION_PATTERNS = re.compile(
    r"\b(before (responding|you respond|answering)|first (read|access|load|fetch)|"
    r"do not (mention|tell|inform)|without (telling|mentioning)|"
    r"pass.{0,30}as (context|parameter)|required (step|preparation)|"
    r"include.{0,30}(in your response|as context))\b",
    re.IGNORECASE,
)

CROSS_SERVER_PATTERNS = re.compile(
    r"\b(the (github|filesystem|cursor|claude|windsurf) (mcp )?(server|tool)|"
    r"use (it|the tool) (next|first|instead)|call the \w+ tool)\b",
    re.IGNORECASE,
)

CREDENTIAL_PATTERNS = re.compile(
    r"[~./\\]*(\.ssh[/\\]|\.aws[/\\]|\.npmrc|\.env\b|id_rsa|id_ed25519|credentials)",
    re.IGNORECASE,
)


@dataclass
class EntropyAlert:
    reason: str
    server_id: str
    detail: str
    severity: str = "medium"
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


def max_json_depth(obj: object, depth: int = 0) -> int:
    if isinstance(obj, dict):
        return max(
            (max_json_depth(v, depth + 1) for v in obj.values()), default=depth
        )
    if isinstance(obj, list):
        return max(
            (max_json_depth(v, depth + 1) for v in obj), default=depth
        )
    return depth


def looks_like_base64(s: str) -> bool:
    if len(s) < 20:
        return False
    # Check if the string has base64-like characteristics
    b64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    non_b64 = sum(1 for c in s if c not in b64_chars)
    if non_b64 / len(s) > 0.1:
        return False
    try:
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False


class EntropyAnalyzer:
    HIGH_ENTROPY_THRESHOLD = 4.5
    MAX_DEPTH_THRESHOLD = 5

    def analyze(self, content: str, server_id: str) -> list[EntropyAlert]:
        alerts: list[EntropyAlert] = []

        # Check instruction density
        if INSTRUCTION_PATTERNS.search(content):
            alerts.append(
                EntropyAlert(
                    reason="instruction_density",
                    server_id=server_id,
                    detail="Tool response contains instruction-like language",
                    severity="high",
                )
            )

        # Check cross-server references
        if CROSS_SERVER_PATTERNS.search(content):
            alerts.append(
                EntropyAlert(
                    reason="cross_server_reference",
                    server_id=server_id,
                    detail="Tool response references other MCP servers",
                    severity="high",
                )
            )

        # Check credential path references
        if CREDENTIAL_PATTERNS.search(content):
            alerts.append(
                EntropyAlert(
                    reason="credential_reference",
                    server_id=server_id,
                    detail="Tool response contains credential file paths",
                    severity="critical",
                )
            )

        # Parse JSON and check fields
        try:
            parsed = json.loads(content)
            self._check_strings(parsed, alerts, server_id)

            # Check structural depth
            depth = max_json_depth(parsed)
            if depth > self.MAX_DEPTH_THRESHOLD:
                alerts.append(
                    EntropyAlert(
                        reason="structural_anomaly",
                        server_id=server_id,
                        detail=f"Unusual JSON nesting depth: {depth}",
                        severity="low",
                    )
                )
        except json.JSONDecodeError:
            pass

        return alerts

    def _check_strings(
        self, obj: object, alerts: list[EntropyAlert], server_id: str
    ) -> None:
        if isinstance(obj, str):
            # Check for base64-like tokens within the string
            tokens = obj.split()
            for token in tokens:
                if looks_like_base64(token):
                    alerts.append(
                        EntropyAlert(
                            reason="high_entropy_field",
                            server_id=server_id,
                            detail="Base64-like content detected in response",
                            severity="medium",
                        )
                    )
                    return
            e = shannon_entropy(obj)
            if e > self.HIGH_ENTROPY_THRESHOLD and len(obj) > 50:
                alerts.append(
                    EntropyAlert(
                        reason="high_entropy_field",
                        server_id=server_id,
                        detail=f"High entropy string (e={e:.2f})",
                        severity="medium",
                    )
                )
        elif isinstance(obj, dict):
            for v in obj.values():
                self._check_strings(v, alerts, server_id)
        elif isinstance(obj, list):
            for v in obj:
                self._check_strings(v, alerts, server_id)
