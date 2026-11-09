from __future__ import annotations

import pytest

from app.agent_security.models import (
    AssetKind,
    AssetRecord,
    EventSource,
    EventType,
    PolicyRule,
    RiskAssessment,
    ScanFinding,
    ScanReport,
    ScanVerdict,
    SecurityAction,
    SecurityEvent,
    Severity,
)
from app.agent_security.store import AgentSecStore


def make_event(event_id: str, **overrides) -> SecurityEvent:
    payload = {
        "event_id": event_id,
        "ts": "2026-11-06T10:00:00+08:00",
        "source": EventSource.HOOK,
        "event_type": EventType.TOOL_CALL,
        "host": "d2-dev",
        "host_role": "dev",
        "session_id": "sess-1",
        "tool_name": "Bash",
        "action": SecurityAction.BLOCK,
        "rule_ids": ["S08"],
        "severity": Severity.CRITICAL,
    }
    payload.update(overrides)
    return SecurityEvent(**payload)


@pytest.fixture()
def store(tmp_path) -> AgentSecStore:
    return AgentSecStore(tmp_path / "agentsec.db")


def test_insert_event_dedupes_by_event_id(store: AgentSecStore) -> None:
    assert store.insert_event(make_event("evt-1")) is True
    assert store.insert_event(make_event("evt-1")) is False
    assert len(store.list_events()) == 1


def test_insert_events_returns_accepted_count(store: AgentSecStore) -> None:
    accepted = store.insert_events([make_event("evt-1"), make_event("evt-1"), make_event("evt-2")])
    assert accepted == 2


def test_list_events_filters(store: AgentSecStore) -> None:
    store.insert_events([
        make_event("evt-1"),
        make_event("evt-2", severity=Severity.LOW, host="d1-win", rule_ids=[]),
        make_event("evt-3", ts="2026-11-07T10:00:00+08:00", severity=Severity.HIGH,
                   host="d3-cloud", rule_ids=[]),
    ])
    assert len(store.list_events(host="d2-dev")) == 1
    assert len(store.list_events(severity="critical")) == 1
    assert len(store.list_events(rule_id="S08")) == 1
    assert len(store.list_events(since="2026-11-06T12:00:00+08:00")) == 1
    assert len(store.list_events(until="2026-11-06T12:00:00+08:00")) == 2


def test_pending_and_mark_uploaded(store: AgentSecStore) -> None:
    store.insert_events([make_event("evt-1"), make_event("evt-2")])
    assert len(store.pending_events()) == 2
    store.mark_uploaded(["evt-1"])
    pending = store.pending_events()
    assert [event.event_id for event in pending] == ["evt-2"]


def test_session_upsert_and_detail(store: AgentSecStore) -> None:
    store.upsert_session("sess-1", host="d2-dev", agent_name="claude-code", user="u")
    store.upsert_session("sess-1", cwd="/home/u/proj")
    store.insert_event(make_event("evt-1"))
    detail = store.session_detail("sess-1")
    assert detail["session"]["cwd"] == "/home/u/proj"
    assert len(detail["timeline"]) == 1
    sessions = store.list_sessions()
    assert sessions[0]["event_count"] == 1
    assert sessions[0]["max_severity"] == "critical"


def test_upsert_asset_updates_without_duplicating(store: AgentSecStore) -> None:
    asset = AssetRecord(asset_id="a-1", kind=AssetKind.SKILL, name="s", sha256="x",
                        host="d2-dev", owner="agentsec-lab")
    store.upsert_asset(asset)
    store.upsert_asset(asset.model_copy(update={"sha256": "y"}))
    assets = store.list_assets(kind="skill")
    assert len(assets) == 1
    assert assets[0].sha256 == "y"
    assert assets[0].owner == "agentsec-lab"
    assert assets[0].first_seen == assets[0].last_seen or assets[0].first_seen <= assets[0].last_seen


def test_asset_lifecycle_dimensions_are_independent(store: AgentSecStore) -> None:
    asset = AssetRecord(asset_id="lifecycle", kind=AssetKind.SKILL, name="lifecycle",
                        path="/root/.codex/skills/lifecycle", sha256="a" * 64)
    store.upsert_asset(asset)
    current = store.list_assets()[0]
    assert current.installation_state.value == "installed"
    assert current.activation_state.value == "disabled"
    assert current.runtime_state.value == "idle"
    store.mark_asset_used(current.asset_id)
    active = store.list_assets()[0]
    assert active.installation_state.value == "installed"
    assert active.activation_state.value == "enabled"
    assert active.runtime_state.value == "active"


def test_existing_assets_table_migrates_owner_column(tmp_path) -> None:
    import sqlite3

    db_path = tmp_path / "legacy.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "CREATE TABLE assets (asset_id TEXT PRIMARY KEY, kind TEXT, name TEXT,"
            " version TEXT, path TEXT, sha256 TEXT, host TEXT, source TEXT,"
            " registered INTEGER, first_seen TEXT, last_seen TEXT)"
        )

    store = AgentSecStore(db_path)
    store.upsert_asset(AssetRecord(
        asset_id="asset-new", kind=AssetKind.AGENT, name="Codex CLI",
        host="agentsec-test-01", owner="agentsec-lab",
    ))
    row = store.list_assets(kind="agent", host="agentsec-test-01")[0]
    assert row.owner == "agentsec-lab"


def test_store_limits_database_and_directory_permissions(tmp_path) -> None:
    store = AgentSecStore(tmp_path / "private" / "agentsec.db")
    store.insert_event(make_event("evt-private"))
    if __import__("os").name != "nt":
        assert store.db_path.parent.stat().st_mode & 0o777 == 0o700
        assert store.db_path.stat().st_mode & 0o777 == 0o600


def test_record_scan_writes_scan_asset_and_event(store: AgentSecStore) -> None:
    report = ScanReport(
        scan_id="scan-1", ts="2026-11-06T10:00:00+08:00", host="d2-dev",
        target_kind=AssetKind.SKILL, target_name="evil-skill",
        target_path="/home/lab/.claude/skills/evil-skill",
        sha256="a" * 64,
        findings=[ScanFinding(rule_id="S05", name="remote_script_exec",
                              severity=Severity.CRITICAL, action=SecurityAction.BLOCK)],
        verdict=ScanVerdict.BLOCK,
    )
    store.record_scan(report)
    scans = store.list_scans()
    assert len(scans) == 1
    assert scans[0]["verdict"] == "block"
    events = store.list_events(event_type="scan_finding")
    assert len(events) == 1
    assert events[0].rule_ids == ["S05"]
    # stable asset id across repeated scans of the same content
    store.record_scan(report)
    assets = store.list_assets(kind="skill")
    assert len(assets) == 1


def test_repeated_scans_update_current_asset_but_keep_scan_history(
    store: AgentSecStore,
) -> None:
    first = ScanReport(
        scan_id="scan-mcp-old", ts="2026-11-08T10:00:00+00:00", host="test-host",
        target_kind=AssetKind.MCP, target_name=".mcp.json",
        target_path="/home/lab/.mcp.json", sha256="1" * 64,
        verdict=ScanVerdict.CLEAN,
    )
    changed = first.model_copy(update={
        "scan_id": "scan-mcp-new", "ts": "2026-11-08T11:00:00+00:00",
        "sha256": "2" * 64, "verdict": ScanVerdict.BLOCK,
    })

    store.record_scan(first)
    before = store.list_assets(kind="mcp", host="test-host")
    store.upsert_asset(before[0].model_copy(update={
        "owner": "agentsec-lab", "source": "managed-inventory",
    }))
    store.record_scan(changed)

    assets = store.list_assets(kind="mcp", host="test-host")
    scans = store.list_scans(host="test-host")
    assert len(assets) == 1
    assert assets[0].sha256 == "2" * 64
    assert assets[0].owner == "agentsec-lab"
    assert assets[0].source == "managed-inventory"
    assert {scan["scan_id"] for scan in scans} == {"scan-mcp-old", "scan-mcp-new"}


def test_analyst_review_survives_subsequent_scan(store: AgentSecStore) -> None:
    report = ScanReport(
        scan_id="scan-reviewed", ts="2026-11-08T10:00:00+00:00", host="test-host",
        target_kind=AssetKind.SKILL, target_name="skill", target_path="/home/lab/skill",
        sha256="f" * 64, verdict=ScanVerdict.ALERT,
        findings=[ScanFinding(rule_id="S08", name="path_mention", severity=Severity.CRITICAL,
                              action=SecurityAction.BLOCK)],
    )
    store.record_scan(report)
    asset = store.list_assets(kind="skill", host="test-host")[0]
    reviewed = store.record_asset_review(
        asset.asset_id, assessment=RiskAssessment.FALSE_POSITIVE,
        reviewer="analyst", reason="Skill describes a policy path; no runtime read observed",
    )
    assert reviewed is not None
    report2 = report.model_copy(update={"scan_id": "scan-reviewed-again"})
    store.record_scan(report2)
    current = store.list_assets(kind="skill", host="test-host")[0]
    assert current.risk_assessment.value == "false_positive"
    assert current.assessment_reviewer == "analyst"
    assert "no runtime read" in current.assessment_reason


def test_policy_roundtrip(store: AgentSecStore) -> None:
    policy = PolicyRule(policy_id="p-1", name="block ssh", kind="path",
                        pattern="~/.ssh", severity=Severity.CRITICAL,
                        action=SecurityAction.BLOCK)
    store.upsert_policy(policy)
    store.upsert_policy(policy.model_copy(update={"enabled": False}))
    policies = store.list_policies(kind="path")
    assert len(policies) == 1
    assert policies[0].enabled is False


def test_ioc_cache_respects_ttl(store: AgentSecStore) -> None:
    store.put_cached_ioc("evil.example.com", "domain", "malicious", 0.98)
    cached = store.get_cached_ioc("evil.example.com")
    assert cached is not None
    assert cached["verdict"] == "malicious"
    expired = store.get_cached_ioc("evil.example.com", now="2030-01-01T00:00:00+00:00")
    assert expired is None
    assert store.get_cached_ioc("never-seen.example.com") is None


def test_stats_aggregates(store: AgentSecStore) -> None:
    store.insert_events([
        make_event("evt-1"),
        make_event("evt-2", rule_ids=["S08", "S11"], severity=Severity.LOW),
    ])
    stats = store.stats()
    assert stats["events_total"] == 2
    assert stats["by_severity"]["critical"] == 1
    assert stats["by_severity"]["low"] == 1
    assert stats["by_rule"]["S08"] == 2
