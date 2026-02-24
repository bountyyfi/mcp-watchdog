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
    # ── SMAC-1: hidden-content stripping ──────────────────────────────
    "SMAC-1-comment": re.compile(r"<!--.*?-->", re.DOTALL),
    "SMAC-1-zwsp": re.compile(
        # Raw unicode
        r"[\u200b\u200c\u200d\ufeff]|"
        # JSON-escaped
        r"\\u200[bcdBCD]|\\u[Ff][Ee][Ff][Ff]|"
        # HTML hex entities
        r"&#[xX]200[bBcCdD];|&#[xX][fF][eE][fF][fF];|"
        # HTML decimal entities
        r"&#820[345];|&#65279;|"
        # URL-encoded UTF-8 bytes (%E2%80%8B = U+200B, etc.)
        r"%[Ee]2%80%8[BbCcDd]|%[Ee][Ff]%[Bb][Bb]%[Bb][Ff]|"
        # Double-encoded HTML entities
        r"&amp;#[xX]200[bBcCdD];|&amp;#820[345];"
    ),
    "SMAC-1-ansi": re.compile(r"\x1b\[[0-9;]*[a-zA-Z]|\x1b\].*?\x07|\x1b[()][AB012]"),
    "SMAC-1-lre": re.compile(
        r"[\u200e\u200f\u202a-\u202e\u2066-\u2069]|"
        r"\\u200[eEfF]|\\u202[a-eA-E]|\\u206[6-9]|"
        r"&#[xX]200[eEfF];|&#[xX]202[a-eA-E];|&#[xX]206[6-9];|"
        r"&#820[67];|&#823[4-8];|&#829[4-7];|"
        # URL-encoded UTF-8 bytes for LRM/RLM
        r"%[Ee]2%80%8[EeFf]|"
        # Double-encoded HTML entities
        r"&amp;#[xX]200[eEfF];"
    ),

    # ── SMAC-2: markdown reference link exfiltration ──────────────────
    "SMAC-2-reflink": re.compile(
        r"\[//\]:\s*#\s*[\(\"](.*?)[\)\"]"
    ),

    # ── SMAC-5: prompt injection / instruction smuggling ──────────────
    # Standard <IMPORTANT> blocks (with optional attributes, unclosed)
    "SMAC-5-important": re.compile(
        r"<IMPORTANT(?:\s[^>]*)?>.*?(?:</IMPORTANT>|$)", re.DOTALL | re.IGNORECASE
    ),
    # Homoglyph variants: Greek Ι (U+0399), Cyrillic А (U+0410), etc.
    "SMAC-5-homoglyph": re.compile(
        r"<[\u0399\u0406\u04CF]MPORTANT[^>]*>.*?(?:</[\u0399\u0406\u04CF]MPORTANT>|$)|"
        r"<IMPORTANT[^>]*>.*?(?:</IMPORTANT>|$)|"
        r"<\u0399MPORTANT[^>]*>.*?(?:</\u0399MPORTANT>|$)",
        re.DOTALL | re.IGNORECASE,
    ),
    # HTML-encoded <IMPORTANT> tags
    "SMAC-5-encoded-tag": re.compile(
        r"&lt;IMPORTANT(?:\s[^&]*)?>.*?(?:&lt;/IMPORTANT&gt;|$)|"
        r"&lt;IMPORTANT&gt;.*?(?:&lt;/IMPORTANT&gt;|$)",
        re.DOTALL | re.IGNORECASE,
    ),
    # [SYSTEM] / [ADMIN] / [ASSISTANT] role injection markers — strips entire line
    "SMAC-5-role-inject": re.compile(
        r"\[(?:SYSTEM|ADMIN|ASSISTANT|USER)\]\s*[:.].*",
        re.IGNORECASE,
    ),
    "SMAC-5-credential-seek": re.compile(
        r"(read|access|load|open|fetch)\s+[~./\\]*(\.ssh|\.aws|\.npmrc|\.env|credentials|id_rsa)",
        re.IGNORECASE,
    ),

    # ── SMAC-6: token/secret leak detection ───────────────────────────
    "SMAC-6-token-leak": re.compile(
        # GitHub
        r"(ghp_[a-zA-Z0-9]{20,}|"
        r"github_pat_[a-zA-Z0-9_]{20,}|"
        r"gho_[a-zA-Z0-9]{20,}|"
        # OpenAI / Anthropic
        r"sk-[a-zA-Z0-9]{20,}|"
        r"sk-proj-[a-zA-Z0-9\-_]{20,}|"
        r"sk-ant-[a-zA-Z0-9\-_]{20,}|"
        # AWS access key ID
        r"AKIA[0-9A-Z]{16}|"
        # AWS secret access key (context-based)
        r"(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key|SecretAccessKey)\s*[=:]\s*\"?[A-Za-z0-9/+=]{40}|"
        # Unlabeled secret keys (generic key-value contexts)
        r"(?:secret|private)[_\s]*(?:key|access[_\s]*key)\s*[=:]\s*\"?[A-Za-z0-9/+=]{30,}\"?|"
        # Stripe
        r"sk_live_[a-zA-Z0-9]{20,}|"
        r"sk_test_[a-zA-Z0-9]{20,}|"
        r"rk_live_[a-zA-Z0-9]{20,}|"
        r"rk_test_[a-zA-Z0-9]{20,}|"
        # Slack (2- and 3-segment)
        r"xoxb-[0-9]{10,}(?:-[0-9]+)?-[a-zA-Z0-9]{20,}|"
        r"xoxp-[0-9]{10,}(?:-[0-9]+)?-[a-zA-Z0-9]{20,}|"
        r"xoxa-[0-9]{10,}(?:-[0-9]+)?-[a-zA-Z0-9]{20,}|"
        r"xoxr-[0-9]{10,}(?:-[0-9]+)?-[a-zA-Z0-9]{20,}|"
        # Discord bot token
        r"[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}|"
        # GitLab
        r"glpat-[a-zA-Z0-9\-_]{20,}|"
        # npm
        r"npm_[a-zA-Z0-9]{36,}|"
        # PyPI
        r"pypi-[a-zA-Z0-9\-_]{20,}|"
        # Supabase
        r"sbp_[a-zA-Z0-9]{20,}|"
        # Sendgrid
        r"SG\.[a-zA-Z0-9\-_]{22,}\.[a-zA-Z0-9\-_]{22,}|"
        # Twilio
        r"SK[a-f0-9]{32}|"
        # Vault
        r"hvs\.[a-zA-Z0-9\-_]{20,}|"
        r"s\.[a-zA-Z0-9]{24,}|"
        # Datadog
        r"dd[ap]_[a-zA-Z0-9]{20,}|"
        # Heroku (labeled env var or with heroku context)
        r"(?:HEROKU_API_KEY|HEROKU_OAUTH_TOKEN|HEROKU_API_TOKEN)\s*[=:]\s*\"?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\"?|"
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?=.*heroku)|"
        # GCP service account key (private_key_id field)
        r"\"private_key_id\"\s*:\s*\"[a-f0-9]{40}\"|"
        # Azure connection string
        r"(?:AccountKey|SharedAccessKey)=[A-Za-z0-9/+=]{40,}|"
        # PEM private keys
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----|"
        # JWT
        r"eyJ[a-zA-Z0-9\-_]{20,}\.eyJ[a-zA-Z0-9\-_]{20,})"
    ),
}


_SPLIT_TAG_RE = re.compile(
    r"<\s*(/?)\s*I\s*M\s*P\s*O\s*R\s*T\s*A\s*N\s*T",
    re.IGNORECASE,
)
# Collapse spaces around underscores in known token prefixes
_TOKEN_PREFIX_SPACE_RE = re.compile(
    r"\b(sk|rk|npm|pypi|sbp|ghp|gho|hvs|SG|dd[ap]|glpat|github_pat|xox[bpar])"
    r"\s*_\s*",
)
# Collapse spaces between Stripe sub-prefix: sk_<space>live_<space>
_STRIPE_SPACE_RE = re.compile(r"(sk_|rk_)\s*(live|test)\s*_\s*")


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

    @staticmethod
    def _pre_normalize(text: str) -> str:
        """Normalize evasion techniques before pattern matching."""
        # Collapse split <IMPORTANT> tags: <IMPOR\nTANT> → <IMPORTANT
        text = _SPLIT_TAG_RE.sub(lambda m: f"<{m.group(1)}IMPORTANT", text)
        # Collapse spaces in token prefixes: "sk_ live_ " → "sk_live_"
        text = _TOKEN_PREFIX_SPACE_RE.sub(r"\1_", text)
        text = _STRIPE_SPACE_RE.sub(r"\1\2_", text)
        return text

    def process(
        self, content: str, server_id: str
    ) -> tuple[str, list[SMACViolation]]:
        violations: list[SMACViolation] = []
        result = self._pre_normalize(content)

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
