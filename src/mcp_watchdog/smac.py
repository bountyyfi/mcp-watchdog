"""SMAC-L3 preprocessor for MCP tool responses.

Strips hidden instructions, zero-width characters, HTML comments,
markdown reference links, and <IMPORTANT> injection blocks from
MCP server responses before they reach the AI model.
"""

import re
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class SMACViolation:
    rule: str
    server_id: str
    content_hash: str
    content_preview: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


PATTERNS = {
    "SMAC-1-comment": re.compile(r"<!--.*?-->", re.DOTALL),
    "SMAC-1-zwsp": re.compile(
        r"[\u200b\u200c\u200d\ufeff]|"
        r"\\u200[bcdBCD]|\\u[Ff][Ee][Ff][Ff]"
    ),
    "SMAC-1-ansi": re.compile(r"\x1b\[[0-9;]*[a-zA-Z]|\x1b\].*?\x07|\x1b[()][AB012]"),
    "SMAC-1-lre": re.compile(
        r"[\u200e\u200f\u202a-\u202e\u2066-\u2069]|"
        r"\\u200[eEfF]|\\u202[a-eA-E]|\\u206[6-9]"
    ),
    "SMAC-2-reflink": re.compile(
        r"\[//\]:\s*#\s*[\(\"](.*?)[\)\"]"
    ),
    "SMAC-5-important": re.compile(
        r"<IMPORTANT>.*?</IMPORTANT>", re.DOTALL | re.IGNORECASE
    ),
    "SMAC-5-credential-seek": re.compile(
        r"(read|access|load|open|fetch)\s+[~./\\]*(\.ssh|\.aws|\.npmrc|\.env|credentials|id_rsa)",
        re.IGNORECASE,
    ),
    "SMAC-6-token-leak": re.compile(
        r"(ghp_[a-zA-Z0-9]{20,}|"
        r"github_pat_[a-zA-Z0-9_]{20,}|"
        r"gho_[a-zA-Z0-9]{20,}|"
        r"sk-[a-zA-Z0-9]{20,}|"
        r"sk-proj-[a-zA-Z0-9\-_]{20,}|"
        r"sk-ant-[a-zA-Z0-9\-_]{20,}|"
        r"AKIA[0-9A-Z]{16}|"
        r"xoxb-[0-9]{10,}-[a-zA-Z0-9]{20,}|"
        r"xoxp-[0-9]{10,}-[a-zA-Z0-9]{20,}|"
        r"glpat-[a-zA-Z0-9\-_]{20,}|"
        r"eyJ[a-zA-Z0-9\-_]{20,}\.eyJ[a-zA-Z0-9\-_]{20,})"
    ),
}


class SMACPreprocessor:
    def __init__(self, log_path: Optional[Path] = None):
        self.log_path = log_path
        self._logger = None
        if log_path:
            self._logger = logging.getLogger(f"smac-{id(self)}")
            self._logger.setLevel(logging.INFO)
            handler = logging.FileHandler(str(log_path))
            handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
            self._logger.addHandler(handler)

    def process(
        self, content: str, server_id: str
    ) -> tuple[str, list[SMACViolation]]:
        violations: list[SMACViolation] = []
        result = content

        for rule_name, pattern in PATTERNS.items():
            parts = rule_name.split("-")
            rule = f"{parts[0]}-{parts[1]}"

            matches = pattern.findall(result)
            for match in matches:
                match_str = match if isinstance(match, str) else str(match)
                v = SMACViolation(
                    rule=rule,
                    server_id=server_id,
                    content_hash=hashlib.sha256(match_str.encode()).hexdigest()[:12],
                    content_preview=match_str[:80],
                )
                violations.append(v)
                if self._logger:
                    self._logger.info(
                        "%s: stripped from %s hash=%s len=%d",
                        v.rule,
                        server_id,
                        v.content_hash,
                        len(match_str),
                    )

            result = pattern.sub("", result)

        return result, violations
