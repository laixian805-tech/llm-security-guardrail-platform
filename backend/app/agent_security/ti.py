"""Budgeted ThreatBook shadow lookups for public indicators and asset hashes."""

from __future__ import annotations

from typing import Any

from .models import TIVerdict
from .store import AgentSecStore
from .threat_intel import PROVIDER, ThreatBookClient, normalize_ioc, utc_budget_day


def check_ioc(
    store: AgentSecStore,
    value: str,
    *,
    ioc_type: str = "",
    mode: str = "shadow",
    soft_daily_budget: int = 250,
    hard_daily_limit: int = 300,
    cache_days: int = 7,
    timeout_seconds: float = 2.0,
    client: ThreatBookClient | None = None,
) -> dict[str, Any]:
    """Return TI evidence without changing local policy or scanner verdicts."""
    if mode != "shadow":
        normalized = normalize_ioc(value, ioc_type)
        ioc = normalized[0] if normalized else ""
        kind = normalized[1] if normalized else ioc_type or "unknown"
        reason = "ThreatBook lookups are shadow-only in this workflow"
        if ioc:
            store.record_ioc_query(ioc=ioc, ioc_type=kind, provider=PROVIDER,
                                   verdict="unknown", confidence=0, cached=False,
                                   reason=reason)
        return {"ioc": ioc,
                "ioc_type": kind,
                "verdict": "unknown", "provider": PROVIDER,
                "confidence": 0.0, "cached": False,
                "reason": reason}
    normalized = normalize_ioc(value, ioc_type)
    if normalized is None:
        return {"ioc": "", "ioc_type": ioc_type or "unknown",
                "verdict": "unknown", "provider": PROVIDER,
                "confidence": 0.0, "cached": False,
                "reason": "indicator is private, malformed, or unsupported"}
    ioc, kind = normalized
    cached_row = store.get_cached_ioc(ioc)
    if cached_row:
        verdict = TIVerdict(provider=cached_row["provider"],
                            verdict=cached_row["verdict"],
                            confidence=float(cached_row["confidence"] or 0),
                            cached=True)
        reason = "seven-day IOC cache"
        store.record_ioc_query(ioc=ioc, ioc_type=kind, provider=verdict.provider,
                               verdict=verdict.verdict, confidence=verdict.confidence,
                               cached=True, reason=reason)
        return {"ioc": ioc, "ioc_type": kind, **verdict.model_dump(), "reason": reason}

    lookup_client = client or ThreatBookClient(timeout=timeout_seconds)
    if kind == "domain" and not lookup_client.domain_enabled:
        reason = "domain reputation endpoint is not enabled for this account"
        store.record_ioc_query(ioc=ioc, ioc_type=kind, provider=PROVIDER,
                               verdict="unknown", confidence=0, cached=False,
                               reason=reason)
        return {"ioc": ioc, "ioc_type": kind, "verdict": "unknown",
                "provider": PROVIDER, "confidence": 0.0, "cached": False,
                "reason": reason}

    day = utc_budget_day()
    budget_key = f"ti_budget:{day}"
    used = int(store.get_state(budget_key, "0") or 0)
    if used >= soft_daily_budget:
        store.set_state(f"ti_soft_limit_exceeded:{day}", "1")
    if not store.reserve_daily_budget(budget_key, limit=hard_daily_limit):
        verdict = TIVerdict(provider=PROVIDER, verdict="unknown", confidence=0.0)
        reason = "daily hard budget reached"
        store.record_ioc_query(ioc=ioc, ioc_type=kind, provider=PROVIDER,
                               verdict=verdict.verdict, confidence=verdict.confidence,
                               cached=False, reason=reason)
        return {"ioc": ioc, "ioc_type": kind, **verdict.model_dump(), "reason": reason}

    verdict = lookup_client.lookup(ioc, kind)
    if verdict.verdict != "unknown":
        store.put_cached_ioc(ioc, kind, verdict.verdict, verdict.confidence,
                             ttl_days=cache_days, provider=PROVIDER)
    verdict = verdict.model_copy(update={"cached": False})
    reason = ("live shadow lookup" if verdict.verdict != "unknown"
              else "provider returned unknown or lookup failed")
    store.record_ioc_query(ioc=ioc, ioc_type=kind, provider=verdict.provider,
                           verdict=verdict.verdict, confidence=verdict.confidence,
                           cached=False, reason=reason)
    return {"ioc": ioc, "ioc_type": kind, **verdict.model_dump(), "reason": reason}
