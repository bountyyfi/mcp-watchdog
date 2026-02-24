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


# Regex to find base64-like chunks in larger text (min 16 chars of base64 alphabet)
BASE64_CHUNK_RE = re.compile(
    r"[A-Za-z0-9+/]{16,}={0,2}"
)

# URL-safe base64 variant
BASE64_URL_CHUNK_RE = re.compile(
    r"[A-Za-z0-9\-_]{16,}={0,2}"
)


def looks_like_base64(s: str) -> bool:
    if len(s) < 16:
        return False
    # Check if the string has base64-like characteristics
    b64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_")
    non_b64 = sum(1 for c in s if c not in b64_chars)
    if non_b64 / len(s) > 0.1:
        return False
    # Try standard base64
    try:
        # Pad to multiple of 4
        padded = s + "=" * (-len(s) % 4)
        decoded = base64.b64decode(padded)
        # Verify it's not just ASCII text that happens to be valid base64
        if len(decoded) >= 12:
            return True
        return False
    except Exception:
        pass
    # Try URL-safe base64
    try:
        padded = s + "=" * (-len(s) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        if len(decoded) >= 12:
            return True
    except Exception:
        pass
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
        self, obj: object, alerts: list[EntropyAlert], server_id: str,
        _b64_accumulator: list[str] | None = None,
    ) -> None:
        top_level = _b64_accumulator is None
        if _b64_accumulator is None:
            _b64_accumulator = []

        if isinstance(obj, str):
            # Scan for base64 chunks embedded anywhere in the string
            found_b64 = False
            for pattern in (BASE64_CHUNK_RE, BASE64_URL_CHUNK_RE):
                for match in pattern.finditer(obj):
                    chunk = match.group()
                    if looks_like_base64(chunk):
                        _b64_accumulator.append(chunk)
                        if len(chunk) >= 20:
                            found_b64 = True

            if found_b64:
                alerts.append(
                    EntropyAlert(
                        reason="high_entropy_field",
                        server_id=server_id,
                        detail="Base64-encoded content detected in response",
                        severity="medium",
                    )
                )
                return

            # Also check whitespace-separated tokens for standalone b64
            if not found_b64:
                for token in obj.split():
                    if looks_like_base64(token):
                        _b64_accumulator.append(token)

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
                self._check_strings(v, alerts, server_id, _b64_accumulator)
        elif isinstance(obj, list):
            for v in obj:
                self._check_strings(v, alerts, server_id, _b64_accumulator)

        # At the top level, check if accumulated small b64 segments are suspicious
        if top_level and len(_b64_accumulator) >= 2:
            total_b64_len = sum(len(s) for s in _b64_accumulator)
            if total_b64_len >= 32:
                # Only add if we haven't already flagged a b64 alert
                if not any(a.reason == "high_entropy_field" and "Base64" in a.detail
                           for a in alerts):
                    alerts.append(
                        EntropyAlert(
                            reason="high_entropy_field",
                            server_id=server_id,
                            detail=f"Multiple base64 segments detected ({len(_b64_accumulator)} segments, {total_b64_len} chars total)",
                            severity="medium",
                        )
                    )
