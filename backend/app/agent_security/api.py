"""Platform-side HTTP API for the agent security gateway.

Mounted in ``app.api.main`` under ``/api/agent-security``; serves the four
frontend pages (asset ledger, session list, behavior timeline, policy
management) plus the edge upload/decision endpoints. This module is the only
part of ``agent_security`` that imports platform code, and it does so lazily
inside functions so the edge bundle never pulls in ``app.*``.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from typing import Any

from fastapi import APIRouter, Body, HTTPException, Query, Request

from .models import (
    AssetCarrier,
    AssetInventoryBatch,
    AssetAssessmentReview,
    AssetKind,
    AssetRecord,
    AssetState,
    Decision,
    DeviceEnrollmentRequest,
    DeviceEnrollmentResponse,
    EventBatch,
    EventIngestResponse,
    EventSource,
    EventType,
    PolicyRule,
    SecurityAction,
    SecurityEvent,
    Severity,
    TIVerdict,
    utc_now_iso,
)
from .assessment import provenance_for_path
from .admission import evaluate_asset
from .asset_identity import derive_ids, infer_product, legacy_provenance, state_for_carrier
from .asset_identity import classify_carrier
from .ti import check_ioc
from .threat_intel import PROVIDER, extract_iocs, normalize_ioc, utc_budget_day
from .adapters import capability_matrix, get_adapter
from .policy import CallerContext, GuardPolicies, decide, default_policies
from .rules import CATEGORY_LABELS, RULES, RUNTIME_RULES
from .scanner import Registry, scan_path
from .store import AgentSecStore


def _header_value(request: Request, name: str) -> str | None:
    """Case/hyphen-insensitive header lookup.

    HTTP header names are case-insensitive, but some ASGI clients normalize
    ``X-AgentSec-Key`` to ``x-agentsec-key`` (dropping a hyphen), so a plain
    ``Header`` parameter can miss the edge upload key.
    """
    target = name.replace("-", "").lower()
    for key, value in request.headers.items():
        if key.replace("-", "").lower() == target:
            return value
    return None


def _rule_catalog() -> list[dict[str, Any]]:
    return [
        {
            "rule_id": rule.rule_id,
            "name": rule.name,
            "category": rule.category,
            "category_label": CATEGORY_LABELS.get(rule.category, rule.category),
            "layer": rule.layer,
            "kind": rule.kind,
            "severity": rule.severity.value,
            "action": rule.action.value,
            "message": rule.message,
            "targets": list(rule.targets),
        }
        for rule in (*RULES, *RUNTIME_RULES)
    ]


def _default_policy_rows() -> list[PolicyRule]:
    """Seed the platform policy table from the shared default guard policies.

    Edge devices read the same semantics from ``policies.json``; the platform
    keeps them in SQLite so the policy page can display and edit them.
    """
    policies = default_policies()
    now = utc_now_iso()
    rows: list[PolicyRule] = []

    def add(policy_id: str, name: str, kind: str, pattern: str,
            severity: Severity, action: SecurityAction, note: str = "") -> None:
        rows.append(PolicyRule(policy_id=policy_id, name=name, kind=kind,
                               pattern=pattern, severity=severity, action=action,
                               enabled=True, updated_at=now, note=note))

    for index, pattern in enumerate(policies.block_paths, start=1):
        add(f"P-PATH-B{index:02d}", f"阻止访问 {pattern}", "path", pattern,
            Severity.HIGH, SecurityAction.BLOCK, "block_paths")
    for index, pattern in enumerate(policies.ask_paths, start=1):
        add(f"P-PATH-A{index:02d}", f"访问审批 {pattern}", "path", pattern,
            Severity.MEDIUM, SecurityAction.ASK, "ask_paths")
    for index, pattern in enumerate(policies.block_commands, start=1):
        add(f"P-CMD-B{index:02d}", f"阻止命令 {pattern[:40]}", "command", pattern,
            Severity.HIGH, SecurityAction.BLOCK, "block_commands")
    for index, pattern in enumerate(policies.ask_commands, start=1):
        add(f"P-CMD-A{index:02d}", f"命令审批 {pattern[:40]}", "command", pattern,
            Severity.MEDIUM, SecurityAction.ASK, "ask_commands")
    for index, tool in enumerate(policies.approved_network_tools, start=1):
        add(f"P-NET-A{index:02d}", f"批准网络工具 {tool}", "network", tool,
            Severity.MEDIUM, SecurityAction.ALLOW, "approved_network_tools")
    for index, host in enumerate(policies.prod_hosts, start=1):
        add(f"P-HOST-P{index:02d}", f"生产主机 {host}", "host", host,
            Severity.CRITICAL, SecurityAction.ASK, "prod_hosts")
    for index, server in enumerate(policies.approved_mcp_servers, start=1):
        add(f"P-MCP-A{index:02d}", f"批准 MCP Server {server}", "mcp", server,
            Severity.HIGH, SecurityAction.ALLOW, "approved_mcp_servers")
    return rows


def create_agent_security_router(store: AgentSecStore, *, upload_key: str = "",
                                 enroll_key: str = "", ti_mode: str = "off",
                                 ti_daily_budget: int = 250,
                                 ti_hard_daily_limit: int = 300,
                                 ti_cache_days: int = 7,
                                 ti_timeout_seconds: float = 2.0) -> APIRouter:
    """Build the ``/api/agent-security`` router bound to one store instance."""
    router = APIRouter(prefix="/api/agent-security", tags=["agent-security"])

    def ensure_default_policies() -> None:
        if not store.list_policies():
            for row in _default_policy_rows():
                store.upsert_policy(row)

    def save_policy(policy_id: str, policy: PolicyRule) -> PolicyRule:
        record = policy.model_copy(update={"policy_id": policy_id,
                                           "updated_at": utc_now_iso()})
        store.upsert_policy(record)
        store.insert_event(SecurityEvent(
            event_id=f"evt-pol-{policy_id}-{record.updated_at}",
            ts=record.updated_at,
            source=EventSource.PLATFORM,
            event_type=EventType.CONFIG_CHANGE,
            action=record.action,
            severity=record.severity,
            target_path=record.pattern,
            evidence={"policy_id": policy_id, "kind": record.kind,
                      "name": record.name, "pattern": record.pattern,
                      "enabled": record.enabled, "note": record.note},
        ))
        return record

    def require_admin(request: Request) -> None:
        if not enroll_key:
            raise HTTPException(status_code=503, detail="device enrollment is disabled")
        supplied = _header_value(request, "X-AgentSec-Admin-Key") or ""
        if not secrets.compare_digest(supplied, enroll_key):
            raise HTTPException(status_code=401, detail="invalid admin key")

    def authenticated_device(request: Request):
        token = _header_value(request, "X-AgentSec-Device-Key") or ""
        if not token:
            raise HTTPException(status_code=401, detail="device key required")
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        device = store.authenticate_device(token_hash)
        if device is None:
            raise HTTPException(status_code=401, detail="invalid device key")
        return device

    def enrich_ti_shadow(event: SecurityEvent) -> SecurityEvent:
        if ti_mode != "shadow" or event.event_type != EventType.NET_CONNECT:
            return event
        indicator = normalize_ioc(event.dst_domain)
        if indicator is None:
            return event
        ioc, ioc_type = indicator
        shadow = check_ioc(
            store, ioc, ioc_type=ioc_type, mode=ti_mode,
            soft_daily_budget=ti_daily_budget,
            hard_daily_limit=ti_hard_daily_limit,
            cache_days=ti_cache_days, timeout_seconds=ti_timeout_seconds,
        )
        verdict = TIVerdict(provider=shadow["provider"], verdict=shadow["verdict"],
                            confidence=shadow["confidence"], cached=shadow["cached"])
        evidence = dict(event.evidence)
        evidence["ti_shadow"] = {"ioc_type": ioc_type, "verdict": verdict.verdict,
                                 "confidence": verdict.confidence,
                                 "cached": verdict.cached}
        return event.model_copy(update={"ti_verdict": verdict.verdict,
                                        "ti_provider": verdict.provider,
                                        "ti_confidence": verdict.confidence,
                                        "evidence": evidence})

    def refresh_event_ti(event: SecurityEvent) -> dict[str, Any]:
        if ti_mode != "shadow":
            raise HTTPException(status_code=409, detail="ThreatBook is not in shadow mode")
        if event.event_type != EventType.NET_CONNECT:
            raise HTTPException(status_code=400, detail="only network IOC events can be refreshed")
        result = check_ioc(
            store, event.dst_domain, mode=ti_mode,
            soft_daily_budget=ti_daily_budget,
            hard_daily_limit=ti_hard_daily_limit,
            cache_days=ti_cache_days,
            timeout_seconds=ti_timeout_seconds,
        )
        if not result["ioc"]:
            raise HTTPException(status_code=400, detail=result["reason"])
        store.update_event_ti(event.event_id, verdict=result["verdict"],
                              provider=result["provider"],
                              confidence=result["confidence"],
                              ioc_type=result["ioc_type"], cached=result["cached"])
        return {"event_id": event.event_id, **result, "mode": ti_mode}

    @router.post("/devices/enroll", response_model=DeviceEnrollmentResponse)
    def enroll_device(payload: DeviceEnrollmentRequest, request: Request) -> DeviceEnrollmentResponse:
        """Create or rotate one endpoint token; the raw token is returned once."""
        require_admin(request)
        token = secrets.token_urlsafe(32)
        record = store.enroll_device(
            device_id=payload.device_id,
            hostname=payload.hostname,
            owner=payload.owner,
            host_role=payload.host_role,
            platform=payload.platform,
            token_sha256=hashlib.sha256(token.encode("utf-8")).hexdigest(),
        )
        store.insert_event(SecurityEvent(
            event_id=f"evt-device-enroll-{payload.device_id}-{record.created_at}",
            ts=record.created_at,
            source=EventSource.PLATFORM,
            event_type=EventType.CONFIG_CHANGE,
            host=record.hostname,
            host_role=record.host_role,
            action=SecurityAction.AUDIT,
            severity=Severity.INFO,
            evidence={"operation": "device_enroll", "device_id": record.device_id,
                      "owner": record.owner, "platform": record.platform},
        ))
        return DeviceEnrollmentResponse(device_id=record.device_id,
                                        device_token=token,
                                        created_at=record.created_at)

    @router.get("/devices")
    def get_devices(request: Request) -> dict[str, Any]:
        require_admin(request)
        return {"devices": [device.model_dump(mode="json")
                             for device in store.list_devices()]}

    @router.get("/devices/health")
    def get_devices_health() -> dict[str, Any]:
        rows = store.device_health_rows()
        return {"devices": rows, "checked_at": utc_now_iso(),
                "targets": {"poll_seconds": 5, "heartbeat_seconds": 60,
                            "online_seconds": 120, "offline_seconds": 300}}

    @router.post("/ti/refresh")
    def refresh_ti(request: Request,
                   payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        require_admin(request)
        event_id = str(payload.get("event_id", ""))
        event = store.get_event(event_id) if event_id else None
        if event is None:
            raise HTTPException(status_code=404, detail="network event not found")
        return refresh_event_ti(event)

    @router.post("/ti/lookup")
    def lookup_ti(request: Request, payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        require_admin(request)
        value = str(payload.get("ioc", ""))
        ioc_type = str(payload.get("ioc_type", ""))
        result = check_ioc(
            store, value, ioc_type=ioc_type, mode=ti_mode,
            soft_daily_budget=ti_daily_budget,
            hard_daily_limit=ti_hard_daily_limit,
            cache_days=ti_cache_days,
            timeout_seconds=ti_timeout_seconds,
        )
        if not result["ioc"]:
            raise HTTPException(status_code=400, detail=result["reason"])
        return {**result, "mode": ti_mode}

    @router.get("/ti/queries")
    def get_ti_queries(request: Request,
                       ioc_type: str | None = None,
                       limit: int = Query(default=100, le=500)) -> dict[str, Any]:
        require_admin(request)
        return {"queries": store.list_ioc_queries(ioc_type=ioc_type, limit=limit)}

    @router.post("/devices/{device_id}/revoke")
    def revoke_device(device_id: str, request: Request) -> dict[str, Any]:
        require_admin(request)
        record = store.revoke_device(device_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"device not found: {device_id}")
        store.insert_event(SecurityEvent(
            event_id=f"evt-device-revoke-{device_id}-{record.revoked_at}",
            ts=record.revoked_at,
            source=EventSource.PLATFORM,
            event_type=EventType.CONFIG_CHANGE,
            host=record.hostname,
            host_role=record.host_role,
            action=SecurityAction.BLOCK,
            severity=Severity.HIGH,
            evidence={"operation": "device_token_revoked", "device_id": device_id},
        ))
        return {"device_id": device_id, "revoked_at": record.revoked_at,
                "state": "revoked"}

    @router.post("/assets/inventory")
    def ingest_asset_inventory(batch: AssetInventoryBatch,
                               request: Request) -> dict[str, Any]:
        """Accept metadata-only endpoint inventory under its enrolled identity."""
        device = authenticated_device(request)
        if not batch.assets and not batch.scans:
            raise HTTPException(status_code=400, detail="assets or scans must not be empty")
        if len(batch.assets) > 1000:
            raise HTTPException(status_code=413, detail="too many assets")
        normalized: list[AssetRecord] = []
        for asset in batch.assets:
            carrier = classify_carrier(asset.path)
            state = state_for_carrier(carrier)
            if asset.kind == AssetKind.AGENT and carrier == AssetCarrier.UNKNOWN:
                carrier = AssetCarrier.USER_INSTALLED
                state = AssetState.INSTALLED
            product = infer_product(asset.path, asset.product)
            logical_id, instance_id = derive_ids(
                product=product, kind=asset.kind, name=asset.name,
                host=device.hostname, carrier=carrier, path=asset.path,
            )
            normalized.append(asset.model_copy(update={
                "host": device.hostname,
                "owner": device.owner,
                "source": "managed-inventory",
                "provenance": (provenance_for_path(asset.path)
                               if carrier != AssetCarrier.UNKNOWN else asset.provenance),
                "product": product,
                "logical_id": logical_id,
                "instance_id": instance_id,
                "content_hash": asset.content_hash or asset.sha256,
                "carrier": carrier,
                "state": state,
                "scope": "project" if carrier == AssetCarrier.PROJECT_LOCAL else "host",
                "risk_score": 0.0,
                "ranking_score": 0.0,
                "risk_breakdown": [],
            }))
        for asset in normalized:
            store.upsert_asset(asset)
        sanitized_scans = 0
        for report in batch.scans:
            carrier = classify_carrier(report.target_path)
            state = state_for_carrier(carrier)
            product = infer_product(report.target_path, report.product)
            logical_id, instance_id = derive_ids(
                product=product, kind=report.target_kind, name=report.target_name,
                host=device.hostname, carrier=carrier, path=report.target_path,
            )
            safe_report = report.model_copy(update={
                "host": device.hostname,
                "findings": [finding.model_copy(update={"evidence": ""})
                             for finding in report.findings],
                "ti_iocs": [],
                "product": product,
                "logical_id": logical_id,
                "instance_id": instance_id,
                "content_hash": report.content_hash or report.sha256,
                "carrier": carrier,
                "state": state,
                "scope": "project" if carrier == AssetCarrier.PROJECT_LOCAL else "host",
                "inventory_only": state not in {
                    AssetState.INSTALLED, AssetState.ENABLED, AssetState.ACTIVE,
                } or carrier == AssetCarrier.SYNTHETIC,
            })
            store.upsert_asset(AssetRecord(
                asset_id=instance_id,
                kind=safe_report.target_kind,
                name=safe_report.target_name,
                path=safe_report.target_path,
                sha256=safe_report.sha256,
                host=device.hostname,
                owner=device.owner,
                source="managed-inventory",
                registered=safe_report.registered,
                provenance=legacy_provenance(carrier),
                product=product,
                logical_id=logical_id,
                instance_id=instance_id,
                content_hash=safe_report.content_hash,
                carrier=carrier,
                state=state,
                scope=safe_report.scope,
            ))
            store.record_scan(safe_report)
            sanitized_scans += 1
        return {"accepted": len(normalized) + sanitized_scans,
                "assets_accepted": len(normalized), "scans_accepted": sanitized_scans,
                "device_id": device.device_id, "hostname": device.hostname}

    @router.get("/stats")
    def get_stats() -> dict[str, Any]:
        stats = store.stats()
        day = utc_budget_day()
        ti_used = int(store.get_state(f"ti_budget:{day}", "0") or 0)
        stats["rules_total"] = len(RULES) + len(RUNTIME_RULES)
        stats["runtime_rules"] = len(RUNTIME_RULES)
        stats["pending_uploads"] = len(store.pending_events(limit=1000))
        stats["pending_approvals"] = sum(
            1 for event in store.list_events(limit=1000)
            if event.action.value == SecurityAction.ASK.value
        )
        stats["threat_intel"] = {
            "mode": ti_mode,
            "provider": PROVIDER if ti_mode != "off" else "",
            "lookups_today": ti_used,
            "soft_budget": ti_daily_budget,
            "hard_budget": ti_hard_daily_limit,
            "soft_budget_exceeded": bool(store.get_state(
                f"ti_soft_limit_exceeded:{day}", "0") == "1"),
            "cache_days": ti_cache_days,
        }
        return stats

    @router.get("/rules")
    def get_rules() -> dict[str, Any]:
        return {
            "rules": _rule_catalog(),
            "categories": CATEGORY_LABELS,
            "runtime_rule_ids": [rule.rule_id for rule in RUNTIME_RULES],
        }

    @router.get("/assets")
    def get_assets(kind: str | None = None,
                   host: str | None = None,
                   state: str | None = None,
                   carrier: str | None = None,
                   logical_id: str | None = None,
                   include_inventory: bool = False) -> dict[str, Any]:
        assets = store.list_assets(kind=kind, host=host, state=state,
                                   carrier=carrier, logical_id=logical_id)
        if not include_inventory:
            assets = [asset for asset in assets
                      if asset.state in {AssetState.INSTALLED, AssetState.ENABLED,
                                          AssetState.ACTIVE}]
        return {"assets": [asset.model_dump(mode="json") for asset in assets]}

    @router.get("/assets/summary")
    def get_asset_summary(kind: str | None = None,
                          host: str | None = None) -> dict[str, Any]:
        return store.asset_summary(kind=kind, host=host)

    @router.post("/admission/check")
    def check_asset_admission(request: Request,
                              payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        require_admin(request)
        asset_key = str(payload.get("instance_id") or payload.get("asset_id")
                        or payload.get("logical_id") or "")
        stored_asset = store.get_asset(asset_key) if asset_key else None
        evidence = (stored_asset.model_dump(mode="json")
                    if stored_asset is not None else payload)
        decision = evaluate_asset(evidence, registry=Registry.load())
        decision_id = f"adm-{uuid.uuid4().hex}"
        now = utc_now_iso()
        logical_id = str(evidence.get("logical_id", ""))
        release_id = str(evidence.get("release_id", ""))
        instance_id = str(evidence.get("instance_id", evidence.get("asset_id", "")))
        store.record_admission_decision(
            decision_id=decision_id, logical_id=logical_id, release_id=release_id,
            instance_id=instance_id, content_hash=str(evidence.get("content_hash", evidence.get("sha256", ""))),
            requested_state=str(payload.get("requested_state", "enabled")),
            action=decision.action, policy_version="registry-v1",
            checks=decision.as_dict()["checks"], reason=decision.reason,
            created_at=now,
        )
        store.insert_event(SecurityEvent(
            event_id=f"evt-admission-{decision_id}",
            ts=now,
            source=EventSource.PLATFORM,
            event_type=EventType.CONFIG_CHANGE,
            host=str(payload.get("host", "")),
            target_kind=str(payload.get("kind", "")),
            target_path=str(payload.get("path", "")),
            action=SecurityAction.ALLOW if decision.allowed else SecurityAction.BLOCK,
            severity=Severity.INFO if decision.allowed else Severity.HIGH,
            evidence={"operation": "asset_admission_check",
                      "logical_id": str(payload.get("logical_id", "")),
                      "instance_id": str(payload.get("instance_id", "")),
                      "allowed": decision.allowed,
                      "reason": decision.reason,
                      "checks": [item["name"] for item in decision.as_dict()["checks"]]},
        ))
        result = decision.as_dict()
        result["decision_id"] = decision_id
        result["policy_version"] = "registry-v1"
        result["created_at"] = now
        return result

    @router.put("/assets/{asset_id}/assessment")
    def review_asset_assessment(asset_id: str, payload: AssetAssessmentReview,
                                request: Request) -> dict[str, Any]:
        require_admin(request)
        asset = store.record_asset_review(asset_id, assessment=payload.risk_assessment,
                                          reviewer=payload.reviewer, reason=payload.reason)
        if asset is None:
            raise HTTPException(status_code=404, detail="asset not found")
        store.insert_event(SecurityEvent(
            event_id=f"evt-assessment-{asset_id}-{utc_now_iso()}",
            ts=utc_now_iso(),
            source=EventSource.PLATFORM,
            event_type=EventType.CONFIG_CHANGE,
            host=asset.host,
            action=SecurityAction.AUDIT,
            severity=Severity.HIGH if payload.risk_assessment.value == "confirmed_malicious"
                     else Severity.INFO,
            evidence={"operation": "asset_assessment_review", "asset_id": asset_id,
                      "risk_assessment": payload.risk_assessment.value,
                      "reviewer": payload.reviewer, "reason": payload.reason},
        ))
        return {"asset": asset.model_dump(mode="json"),
                "reviewer": payload.reviewer, "reason": payload.reason}

    @router.post("/assets/{asset_id}/ti/refresh")
    def refresh_asset_ti(asset_id: str, request: Request) -> dict[str, Any]:
        require_admin(request)
        asset = store.get_asset(asset_id)
        if asset is None:
            raise HTTPException(status_code=404, detail="asset not found")
        if asset.kind.value != "deps" or len(asset.sha256) != 64:
            raise HTTPException(status_code=400,
                                detail="only dependency/package SHA-256 indicators are eligible")
        result = check_ioc(
            store, asset.sha256, ioc_type="sha256", mode=ti_mode,
            soft_daily_budget=ti_daily_budget,
            hard_daily_limit=ti_hard_daily_limit,
            cache_days=ti_cache_days,
            timeout_seconds=ti_timeout_seconds,
        )
        updated = store.set_asset_ti(asset_id, provider=result["provider"],
                                     verdict=result["verdict"],
                                     confidence=result["confidence"])
        return {"asset": updated.model_dump(mode="json") if updated else {}, **result,
                "mode": ti_mode}

    @router.post("/assets/scan")
    def post_assets_scan(payload: dict[str, Any]) -> list[dict[str, Any]]:
        path = str(payload.get("path", "")).strip()
        host = str(payload.get("host", ""))
        if not path:
            raise HTTPException(status_code=400, detail="path is required")
        reports = scan_path(path, host=host, registry=Registry.load())
        if not reports:
            raise HTTPException(status_code=404,
                                detail=f"no scannable target found at {path}")
        for index, report in enumerate(reports):
            ioc_results: list[dict[str, Any]] = []
            indicators = sorted({indicator for finding in report.findings
                                 for indicator in extract_iocs(finding.evidence)})
            if ti_mode == "shadow":
                for ioc, ioc_type in indicators:
                    ioc_results.append(check_ioc(
                        store, ioc, ioc_type=ioc_type, mode=ti_mode,
                        soft_daily_budget=ti_daily_budget,
                        hard_daily_limit=ti_hard_daily_limit,
                        cache_days=ti_cache_days,
                        timeout_seconds=ti_timeout_seconds,
                    ))
            else:
                ioc_results = [
                    {"ioc": ioc, "ioc_type": ioc_type, "verdict": "unknown",
                     "provider": PROVIDER, "confidence": 0.0, "cached": False,
                     "reason": "ThreatBook enrichment is disabled"}
                    for ioc, ioc_type in indicators
                ]
            report = report.model_copy(update={"ti_iocs": ioc_results})
            reports[index] = report
            store.record_scan(report)
        return [report.model_dump(mode="json") for report in reports]

    @router.get("/scans")
    def get_scans(host: str | None = None,
                  limit: int = Query(default=100, le=500)) -> dict[str, Any]:
        return {"scans": store.list_scans(host=host, limit=limit)}

    @router.get("/sessions")
    def get_sessions(host: str | None = None,
                     limit: int = Query(default=100, le=500)) -> dict[str, Any]:
        return {"sessions": store.list_sessions(host=host, limit=limit)}

    @router.get("/sessions/{session_id}")
    def get_session(session_id: str) -> dict[str, Any]:
        detail = store.session_detail(session_id)
        known = any(item["session_id"] == session_id
                    for item in store.list_sessions(limit=500))
        if not known and not detail.get("timeline"):
            raise HTTPException(status_code=404, detail=f"session not found: {session_id}")
        return detail

    @router.get("/events")
    def get_events(
        host: str | None = None,
        severity: str | None = None,
        rule_id: str | None = None,
        source: str | None = None,
        event_type: str | None = None,
        session_id: str | None = None,
        action: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = Query(default=200, le=1000),
    ) -> dict[str, Any]:
        events = store.list_events(
            host=host, severity=severity, rule_id=rule_id, source=source,
            event_type=event_type, session_id=session_id, since=since,
            until=until, limit=limit,
        )
        if action:
            events = [event for event in events if event.action.value == action]
        return {"events": [event.model_dump(mode="json") for event in events]}

    @router.post("/events", response_model=EventIngestResponse)
    def post_events(batch: EventBatch, request: Request) -> EventIngestResponse:
        """Edge batch upload (retrofit plan 6).

        Duplicates are reported in ``rejected`` and stored once; malformed
        items never fail the whole batch.
        """
        device_token = _header_value(request, "X-AgentSec-Device-Key")
        if device_token:
            device = authenticated_device(request)
            events = [event.model_copy(update={
                "host": device.hostname,
                "host_role": device.host_role,
                "session_id": (f"{device.device_id}:{event.session_id}"
                               if event.session_id else ""),
            }) for event in batch.events]
            store.touch_device(device.device_id)
        else:
            shared_key = _header_value(request, "X-AgentSec-Key") or ""
            if upload_key and not secrets.compare_digest(shared_key, upload_key):
                raise HTTPException(status_code=401, detail="invalid upload key")
            if not upload_key and enroll_key:
                raise HTTPException(status_code=401,
                                    detail="enrolled device key required")
            events = batch.events
        events = [enrich_ti_shadow(event) for event in events]
        duplicates = store.existing_event_ids([e.event_id for e in events])
        accepted = store.insert_events(events)
        rejected = [
            {"event_id": event.event_id, "reason": "duplicate"}
            for event in events if event.event_id in duplicates
        ]
        return EventIngestResponse(accepted=accepted, rejected=rejected)

    @router.get("/policies")
    def get_policies(kind: str | None = None) -> dict[str, Any]:
        ensure_default_policies()
        policies = store.list_policies(kind=kind)
        return {"policies": [policy.model_dump(mode="json") for policy in policies]}

    @router.put("/policies/{policy_id}", response_model=PolicyRule)
    def put_policy_by_id(policy_id: str, policy: PolicyRule) -> PolicyRule:
        """Path id wins over the body id so edits cannot rename a policy."""
        return save_policy(policy_id, policy)

    @router.put("/policies", response_model=PolicyRule)
    def put_policy(policy: PolicyRule) -> PolicyRule:
        return save_policy(policy.policy_id, policy)

    @router.get("/approvals")
    def get_approvals(limit: int = Query(default=50, le=200)) -> dict[str, Any]:
        """Pending ask-decisions plus the policy-change audit trail."""
        pending = [event.model_dump(mode="json")
                   for event in store.list_events(limit=limit)
                   if event.action.value == SecurityAction.ASK.value]
        history = [event.model_dump(mode="json")
                   for event in store.list_events(event_type="config_change",
                                                  limit=limit)]
        return {"pending": pending, "history": history}

    @router.post("/approvals", response_model=SecurityEvent)
    def post_approval(payload: dict[str, Any] = Body(...)) -> SecurityEvent:
        """Record an approval decision for a pending ask event."""
        event_id = str(payload.get("event_id", ""))
        decision = str(payload.get("decision", "")).lower()
        note = str(payload.get("note", ""))
        if decision not in {"approve", "reject"}:
            raise HTTPException(status_code=400, detail="decision must be approve or reject")
        if not event_id:
            raise HTTPException(status_code=400, detail="event_id is required")
        matches = [event for event in store.list_events(limit=1000)
                   if event.event_id == event_id]
        if not matches:
            raise HTTPException(status_code=404, detail=f"event not found: {event_id}")
        target = matches[0]
        record = SecurityEvent(
            event_id=f"evt-apr-{event_id}-{decision}",
            ts=utc_now_iso(),
            source=EventSource.PLATFORM,
            event_type=EventType.CONFIG_CHANGE,
            host=target.host,
            host_role=target.host_role,
            session_id=target.session_id,
            agent_name=target.agent_name,
            tool_name=target.tool_name,
            target_path=target.target_path,
            action=SecurityAction.ALLOW if decision == "approve" else SecurityAction.BLOCK,
            rule_ids=target.rule_ids,
            severity=target.severity,
            evidence={"approval_of": event_id, "decision": decision, "note": note},
        )
        store.insert_event(record)
        return record

    @router.get("/guard/capabilities")
    def get_guard_capabilities() -> list[dict[str, Any]]:
        """Per-product capability matrix: events, matchers, trust, governance."""
        return capability_matrix()

    @router.post("/hooks/decision", response_model=Decision)
    def hooks_decision(payload: dict[str, Any]) -> Decision:
        """Synchronous guard decision for edge hooks when offline policies apply.

        Always returns the product-neutral Decision; each product's adapter
        owns the translation into its own hook protocol.
        """
        tool_name = str(payload.get("tool_name", ""))
        tool_input = payload.get("tool_input") or {}
        if not isinstance(tool_input, dict):
            tool_input = {}
        agent_name = str(payload.get("agent_name", ""))
        agent_key = str(payload.get("agent", ""))
        if agent_key:
            try:
                agent_name = agent_name or get_adapter(agent_key).agent_name
            except ValueError:
                pass
        ctx = CallerContext(
            host=str(payload.get("host", "")),
            host_role=str(payload.get("host_role", "")),
            user=str(payload.get("user", "")),
            session_id=str(payload.get("session_id", "")),
            agent_name=agent_name,
            tool_server=str(payload.get("tool_server", "")),
            cwd=str(payload.get("cwd", "")),
        )
        policies_payload = payload.get("policies")
        policies = (GuardPolicies.from_dict(policies_payload)
                    if isinstance(policies_payload, dict) else default_policies())
        return decide(tool_name, tool_input, ctx, policies)

    return router
