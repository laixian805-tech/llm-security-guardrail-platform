from __future__ import annotations

import hashlib
import re
from typing import Any

_SECRET_PAIR_RE = re.compile(
    r"(?i)\b(api[_-]?key|apikey|access[_-]?token|auth[_-]?token|token|password|passwd|secret|credential)s?\b"
    r"(\s*[\"']?\s*[:=]\s*)([\"']?)[^\s\"']{4,}\3"
)
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{8,}=*")
_AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_SECRET_KEY_NAME_RE = re.compile(
    r"(?i)(api[_-]?key|apikey|access[_-]?token|auth[_-]?token|token|password|passwd|secret|credential)"
)

REDACTED = "***REDACTED***"


def redact_text(text: str) -> str:
    """Mask obvious secret material before storage or upload."""
    if not text:
        return text
    redacted = _SECRET_PAIR_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)
    redacted = _BEARER_RE.sub(REDACTED, redacted)
    redacted = _AWS_KEY_RE.sub(REDACTED, redacted)
    redacted = _PRIVATE_KEY_RE.sub(REDACTED, redacted)
    return redacted


def redact_value(value: Any) -> Any:
    """Recursively redact strings inside dicts, lists and tuples."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            if _SECRET_KEY_NAME_RE.search(str(key)):
                redacted[key] = REDACTED if isinstance(item, (str, int, float)) else redact_value(item)
            else:
                redacted[key] = redact_value(item)
        return redacted
    if isinstance(value, (list, tuple)):
        return [redact_value(item) for item in value]
    return value


def hash_value(value: str) -> str:
    """Stable SHA-256 digest used instead of raw argument payloads."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
