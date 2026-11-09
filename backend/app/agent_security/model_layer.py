"""Model-layer events: turn guardrail decisions and eval runs into audit events.

The runtime side (hook / monitor / scanner) already writes SecurityEvent rows
for tool calls, file access and process execution. The model layer used to
live in a separate storage world (reports/*/results.json) with no reference
from the events table. These builders close that gap: a /chat guardrail
decision and a GuardBench run become first-class events in the same store,
keyed by the same session_id, so one session timeline can show both layers.
"""

from __future__ import annotations

import socket
import uuid
from typing import Any

from app.agent_security.models import (
    EventSource,
    EventType,
    SecurityAction,
    SecurityEvent,
    Severity,
    utc_now_iso,
)

_GUARD_ACTION_TO_SECURITY_ACTION = {
    "block": SecurityAction.BLOCK,
    "audit": SecurityAction.AUDIT,
    "allow": SecurityAction.ALLOW,
}

_ACTION_RANK = {
    SecurityAction.ALLOW: 0,
    SecurityAction.AUDIT: 1,
    SecurityAction.ASK: 2,
    SecurityAction.ALERT: 3,
    SecurityAction.BLOCK: 4,
}

_SEVERITY_BY_ACTION = {
    SecurityAction.BLOCK: Severity.HIGH,
    SecurityAction.ASK: Severity.MEDIUM,
    SecurityAction.AUDIT: Severity.MEDIUM,
    SecurityAction.ALERT: Severity.HIGH,
    SecurityAction.ALLOW: Severity.INFO,
}

_EVAL_METRIC_KEYS = (
    "guard_bypass_rate",
    "behavioral_asr",
    "partial_behavioral_asr",
    "false_positive_rate",
    "false_refusal_rate",
    "hard_negative_fpr",
)


def default_host() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return ""


def _summarize_guard_result(result: dict[str, Any]) -> dict[str, Any]:
    metadata = result.get("metadata") or {}
    summary: dict[str, Any] = {
        "stage": str(result.get("stage") or ""),
        "rule_name": str(result.get("rule_name") or ""),
        "action": str(result.get("action") or ""),
        "triggered": bool(result.get("triggered")),
        "confidence": float(result.get("confidence") or 0.0),
        "reason": str(result.get("reason") or ""),
    }
    engine = metadata.get("guard_engine")
    if engine:
        summary["guard_engine"] = str(engine)
    return summary


def guardrail_decision_event(
    *,
    session_id: str,
    guard_results: list[dict[str, Any]],
    host: str | None = None,
    agent_name: str = "",
    event_id: str | None = None,
) -> SecurityEvent | None:
    """Build one guardrail decision event from a guarded chat turn.

    Returns None when every layer allowed the request: the events table must
    record guardrail decisions, not every chat turn, otherwise a 300-case
    eval floods the store with pass rows.
    """
    decisions = [
        result for result in guard_results
        if _GUARD_ACTION_TO_SECURITY_ACTION.get(str(result.get("action") or ""),
                                                SecurityAction.AUDIT) != SecurityAction.ALLOW
    ]
    if not decisions:
        return None

    actions = [
        _GUARD_ACTION_TO_SECURITY_ACTION.get(str(result.get("action") or ""),
                                             SecurityAction.AUDIT)
        for result in decisions
    ]
    action = max(actions, key=lambda item: _ACTION_RANK[item])
    rule_ids: list[str] = []
    for result in decisions:
        rule_name = str(result.get("rule_name") or "")
        if rule_name and rule_name not in rule_ids:
            rule_ids.append(rule_name)

    evidence = {
        "layers": [_summarize_guard_result(result) for result in decisions],
        "guard_engines": sorted({
            str((result.get("metadata") or {}).get("guard_engine"))
            for result in decisions
            if (result.get("metadata") or {}).get("guard_engine")
        }),
    }
    return SecurityEvent(
        event_id=event_id or f"evt-grd-{uuid.uuid4().hex}",
        ts=utc_now_iso(),
        source=EventSource.GUARDRAIL,
        event_type=EventType.GUARDRAIL_DECISION,
        host=host if host is not None else default_host(),
        session_id=session_id,
        agent_name=agent_name,
        action=action,
        rule_ids=rule_ids,
        severity=_SEVERITY_BY_ACTION[action],
        evidence=evidence,
    )


def eval_run_event(
    *,
    run_id: str,
    split: str,
    model: str,
    judge: dict[str, Any] | None = None,
    matrix: list[dict[str, Any]] | None = None,
    warnings: list[str] | None = None,
    host: str | None = None,
    event_id: str | None = None,
) -> SecurityEvent:
    """Build one eval-run event summarizing a GuardBench v2 run.

    Evidence keeps per-run metrics (bypass / behavioral ASR / FPR) but never
    the raw samples; the full artifacts stay in the report directory.
    """
    runs = []
    for entry in matrix or []:
        metrics = entry.get("metrics") or {}
        runs.append({
            "run_name": str(entry.get("run_name") or ""),
            "guard_mode": str(entry.get("guard_mode") or ""),
            "guard_engine": entry.get("guard_engine"),
            "cases": int(entry.get("cases") or 0),
            "metrics": {key: metrics[key] for key in _EVAL_METRIC_KEYS if key in metrics},
        })
    asr_values = [
        float(run["metrics"].get("behavioral_asr") or 0.0) for run in runs
    ]
    worst_asr = max(asr_values) if asr_values else 0.0
    if worst_asr >= 0.5:
        severity = Severity.HIGH
    elif worst_asr > 0.0:
        severity = Severity.MEDIUM
    else:
        severity = Severity.INFO

    return SecurityEvent(
        event_id=event_id or f"evt-eval-{uuid.uuid4().hex}",
        ts=utc_now_iso(),
        source=EventSource.EVAL,
        event_type=EventType.EVAL_RUN,
        host=host if host is not None else default_host(),
        action=SecurityAction.AUDIT,
        severity=severity,
        evidence={
            "run_id": run_id,
            "split": str(split),
            "model": str(model),
            "judge": dict(judge or {}),
            "runs": runs,
            "warnings": list(warnings or []),
        },
    )
