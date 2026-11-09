"""ThreatBook shadow IOC enrichment. This module never changes enforcement."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import TIVerdict

PROVIDER = "threatbook"
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")
_URL_RE = re.compile(r"(?i)\bhttps?://[^\s\]\[()<>\"']+")
_IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")


def _api_key() -> str:
    key = os.environ.get("THREATBOOK_API_KEY", "").strip()
    if key:
        return key
    # Read only this explicitly gitignored local secrets file. Never log its contents.
    path = Path(os.environ.get("AGENTSEC_LOCAL_ENV", Path(__file__).resolve().parents[3]
                               / ".agentsec.local.env"))
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            raw = line.strip()
            if raw and not raw.startswith("#") and "=" in raw:
                name, value = raw.split("=", 1)
                if name.strip() == "THREATBOOK_API_KEY":
                    return value.strip().strip("\"'")
    except OSError:
        pass
    return ""


def normalize_ioc(value: str, ioc_type: str = "") -> tuple[str, str] | None:
    raw = value.strip().rstrip(".")
    if not raw or len(raw) > 253:
        return None
    kind = ioc_type.lower()
    if kind in {"sha256", "hash", "file"} or _SHA256_RE.fullmatch(raw):
        if not _SHA256_RE.fullmatch(raw):
            return None
        return raw.lower(), "sha256"
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        address = None
    if address is not None:
        # Threat intel only receives globally routable indicators.
        if not address.is_global:
            return None
        return address.compressed, "ip"
    if kind == "ip":
        return None
    if not _DOMAIN_RE.fullmatch(raw):
        return None
    domain = raw.encode("idna").decode("ascii").lower()
    if domain == "localhost" or domain.endswith((".localhost", ".local", ".internal", ".test")):
        return None
    return domain, "domain"


def extract_iocs(text: str) -> list[tuple[str, str]]:
    """Extract only normalized public indicators from scanner evidence."""
    found: set[tuple[str, str]] = set()
    for match in _URL_RE.finditer(text):
        url = match.group(0).rstrip(".,;:!?}")
        try:
            host = urllib.parse.urlsplit(url).hostname or ""
        except ValueError:
            continue
        normalized = normalize_ioc(host)
        if normalized:
            found.add(normalized)
    for match in _IP_RE.finditer(text):
        normalized = normalize_ioc(match.group(0), "ip")
        if normalized:
            found.add(normalized)
    for match in re.finditer(r"(?i)(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", text):
        normalized = normalize_ioc(match.group(0), "sha256")
        if normalized:
            found.add(normalized)
    return sorted(found)


def _confidence(value: Any) -> float:
    if isinstance(value, (int, float)):
        return max(0.0, min(1.0, float(value) / (100 if value > 1 else 1)))
    return {"high": 0.9, "medium": 0.65, "low": 0.35}.get(str(value).lower(), 0.0)


def parse_threatbook_payload(ioc: str, ioc_type: str, payload: dict[str, Any]) -> TIVerdict:
    if payload.get("response_code") != 0:
        return TIVerdict(provider=PROVIDER, verdict="unknown", confidence=0.0)
    data = payload.get("data") or {}
    record: dict[str, Any] = {}
    if ioc_type == "ip" and isinstance(data, dict):
        record = data.get(ioc, {}) if isinstance(data.get(ioc), dict) else {}
    elif ioc_type == "domain" and isinstance(data, dict):
        record = data.get(ioc, {}) if isinstance(data.get(ioc), dict) else {}
    elif ioc_type == "sha256" and isinstance(data, dict):
        record = data.get("summary", {}) if isinstance(data.get("summary"), dict) else {}
    else:
        return TIVerdict(provider=PROVIDER, verdict="unknown", confidence=0.0)
    malicious = record.get("is_malicious")
    if malicious is True or str(malicious).lower() in {"true", "1", "yes"}:
        verdict = "malicious"
    else:
        severity = str(record.get("severity", record.get("threat_level", ""))).lower()
        score = _confidence(record.get("threat_score", record.get("confidence_level", 0)))
        if severity in {"critical", "high", "malicious"}:
            verdict = "malicious"
        elif severity in {"medium", "suspicious"} or score >= 0.6:
            verdict = "suspicious"
        elif severity in {"info", "low", "clean"} or malicious is False:
            verdict = "clean"
        else:
            verdict = "unknown"
    return TIVerdict(provider=PROVIDER, verdict=verdict,
                     confidence=_confidence(record.get("confidence_level",
                                                       record.get("threat_score", 0))))


class ThreatBookClient:
    def __init__(self, *, api_key: str | None = None, timeout: float = 2.0,
                 domain_enabled: bool | None = None) -> None:
        self.api_key = api_key if api_key is not None else _api_key()
        self.timeout = timeout
        configured = os.environ.get("THREATBOOK_DOMAIN_ENABLED", "").strip().lower()
        self.domain_enabled = (configured in {"1", "true", "yes", "enabled"}
                              if domain_enabled is None else domain_enabled)

    def lookup(self, ioc: str, ioc_type: str) -> TIVerdict:
        if not self.api_key:
            return TIVerdict(provider=PROVIDER, verdict="unknown", confidence=0.0)
        endpoint, parameter = {
            "ip": ("/v3/scene/ip_reputation", "resource"),
            "sha256": ("/v3/file/report", "resource"),
            "domain": ("/v3/domain/query", "resource"),
        }.get(ioc_type, ("", ""))
        if ioc_type == "domain" and not self.domain_enabled:
            return TIVerdict(provider=PROVIDER, verdict="unknown", confidence=0.0)
        if not endpoint:
            # Domain endpoint is not enabled for this account; do not probe it.
            return TIVerdict(provider=PROVIDER, verdict="unknown", confidence=0.0)
        query = urllib.parse.urlencode({"apikey": self.api_key, parameter: ioc})
        request = urllib.request.Request(
            f"https://api.threatbook.cn{endpoint}?{query}",
            headers={"Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, OSError,
                TimeoutError, ValueError, json.JSONDecodeError):
            return TIVerdict(provider=PROVIDER, verdict="unknown", confidence=0.0)
        return parse_threatbook_payload(ioc, ioc_type, payload)


def utc_budget_day() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")
