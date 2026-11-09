from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.main import create_app

FIXTURES = Path(__file__).parent / "fixtures" / "agentsec"


def _event(event_id: str, *, session_id: str = "s-1", severity: str = "high",
           rule_ids: list[str] | None = None, event_type: str = "process_exec",
           host: str = "d2-dev", action: str = "alert") -> dict:
    return {
        "event_id": event_id,
        "ts": "2026-11-06T09:00:00+00:00",
        "source": "monitor",
        "event_type": event_type,
        "host": host,
        "host_role": "dev",
        "session_id": session_id,
        "agent_name": "claude",
        "agent_pid": 501,
        "tool_name": "psql",
        "target_path": "/usr/bin/psql",
        "action": action,
        "rule_ids": rule_ids or ["S26"],
        "severity": severity,
        "evidence": {"cmdline": "psql -h db.internal"},
    }


@pytest.fixture()
def client(tmp_path, monkeypatch) -> TestClient:
    monkeypatch.setenv("LLMSEC_AGENTSEC_DB_PATH", str(tmp_path / "agentsec.db"))
    monkeypatch.setenv("AGENTSEC_HOME", str(tmp_path / "agentsec-home"))
    monkeypatch.setenv("LLMSEC_AGENTSEC_UPLOAD_KEY", "")
    return TestClient(create_app())


def test_ingest_events_dedupes_and_reports_duplicates(client: TestClient) -> None:
    response = client.post("/api/agent-security/events",
                           json={"events": [_event("evt-1"), _event("evt-2")]})
    assert response.status_code == 200
    assert response.json()["accepted"] == 2
    again = client.post("/api/agent-security/events",
                        json={"events": [_event("evt-1"), _event("evt-3")]})
    payload = again.json()
    assert payload["accepted"] == 1  # evt-3 only; evt-1 is a duplicate
    assert [row["event_id"] for row in payload["rejected"]] == ["evt-1"]
    events = client.get("/api/agent-security/events",
                        params={"limit": 100}).json()["events"]
    assert sorted(e["event_id"] for e in events) == ["evt-1", "evt-2", "evt-3"]


def test_ingest_registers_session_from_tool_events(client: TestClient) -> None:
    client.post("/api/agent-security/events",
                json={"events": [_event("evt-4", session_id="s-auto")]})
    sessions = client.get("/api/agent-security/sessions").json()["sessions"]
    assert any(s["session_id"] == "s-auto" and s["event_count"] >= 1
               for s in sessions)


def test_ingest_rejects_bad_upload_key(client: TestClient, tmp_path,
                                       monkeypatch) -> None:
    monkeypatch.setenv("LLMSEC_AGENTSEC_UPLOAD_KEY", "secret-key")
    guarded = TestClient(create_app())
    assert guarded.post("/api/agent-security/events",
                        json={"events": [_event("evt-9")]}).status_code == 401
    ok = guarded.post("/api/agent-security/events", json={"events": [_event("evt-9")]},
                      headers={"X-AgentSec-Key": "secret-key"})
    assert ok.status_code == 200
    assert ok.json()["accepted"] == 1


def test_events_query_filters(client: TestClient) -> None:
    client.post("/api/agent-security/events", json={"events": [
        _event("evt-a", severity="critical", rule_ids=["S08"], session_id="s-a"),
        _event("evt-b", severity="low", rule_ids=["S24"], session_id="s-b",
               event_type="file_access", action="audit"),
    ]})
    by_severity = client.get("/api/agent-security/events",
                             params={"severity": "critical"}).json()["events"]
    assert [e["event_id"] for e in by_severity] == ["evt-a"]
    by_rule = client.get("/api/agent-security/events",
                         params={"rule_id": "S24"}).json()["events"]
    assert [e["event_id"] for e in by_rule] == ["evt-b"]
    by_type = client.get("/api/agent-security/events",
                         params={"event_type": "file_access"}).json()["events"]
    assert [e["event_id"] for e in by_type] == ["evt-b"]
    by_action = client.get("/api/agent-security/events",
                           params={"action": "audit"}).json()["events"]
    assert [e["event_id"] for e in by_action] == ["evt-b"]


def test_sessions_list_and_detail(client: TestClient) -> None:
    client.post("/api/agent-security/events", json={"events": [
        _event("evt-c", session_id="s-c"), _event("evt-d", session_id="s-c"),
    ]})
    sessions = client.get("/api/agent-security/sessions").json()["sessions"]
    listed = [s for s in sessions if s["session_id"] == "s-c"]
    assert listed and listed[0]["event_count"] == 2
    assert listed[0]["max_severity"] == "high"
    detail = client.get("/api/agent-security/sessions/s-c").json()
    assert len(detail["timeline"]) == 2
    assert client.get("/api/agent-security/sessions/nope").status_code == 404


def test_assets_scan_and_ledger(client: TestClient) -> None:
    response = client.post("/api/agent-security/assets/scan",
                           json={"path": str(FIXTURES / "evil-skill"),
                                 "host": "d2-dev"})
    assert response.status_code == 200
    reports = response.json()
    assert reports and reports[0]["verdict"] in {"alert", "block"}
    assets = client.get("/api/agent-security/assets",
                        params={"kind": "skill"}).json()["assets"]
    assert any(a["name"] == "evil-skill" for a in assets)
    scans = client.get("/api/agent-security/scans").json()["scans"]
    assert any(s["target_name"] == "evil-skill" for s in scans)
    assert client.post("/api/agent-security/assets/scan",
                       json={"path": "/nonexistent/path"}).status_code == 404
    assert client.post("/api/agent-security/assets/scan",
                       json={"host": "d2"}).status_code == 400


def test_enrolled_device_uploads_host_bound_asset_inventory(
    client: TestClient, monkeypatch
) -> None:
    monkeypatch.setenv("LLMSEC_AGENTSEC_ENROLL_KEY", "test-admin-key")
    client = TestClient(create_app())
    enrollment = client.post("/api/agent-security/devices/enroll", headers={
        "X-AgentSec-Admin-Key": "test-admin-key",
    }, json={
        "device_id": "lab-test-01",
        "hostname": "agentsec-test-01",
        "owner": "agentsec-lab",
        "host_role": "test",
        "platform": "ubuntu-22.04",
    })
    assert enrollment.status_code == 200
    token = enrollment.json()["device_token"]
    assert len(token) >= 32

    listed = client.get("/api/agent-security/devices", headers={
        "X-AgentSec-Admin-Key": "test-admin-key",
    }).json()["devices"]
    assert len(listed) == 1
    assert listed == [{
        "device_id": "lab-test-01",
        "hostname": "agentsec-test-01",
        "owner": "agentsec-lab",
        "host_role": "test",
        "platform": "ubuntu-22.04",
        "created_at": listed[0]["created_at"],
        "last_seen": "",
        "revoked_at": "",
    }]
    assert token not in json.dumps(listed)
    assert "token_sha256" not in json.dumps(listed)

    response = client.post("/api/agent-security/assets/inventory", headers={
        "X-AgentSec-Device-Key": token,
    }, json={"assets": [{
        "asset_id": "agent-test-01-codex",
        "kind": "agent",
        "name": "Codex CLI",
        "version": "0.test",
        "path": "/home/agentsec-lab/.local/bin/codex",
        "sha256": "a" * 64,
        "host": "spoofed-client-host",
        "source": "client-controlled",
        "registered": False,
    }], "scans": [{
        "scan_id": "scan-test-evil-skill",
        "ts": "2026-11-06T10:00:00+00:00",
        "host": "spoofed-client-host",
        "target_kind": "skill",
        "target_name": "evil-skill",
        "target_path": "/home/agentsec-lab/.claude/skills/evil-skill",
        "sha256": "b" * 64,
        "findings": [{
            "rule_id": "S01", "name": "hidden_instruction", "severity": "high",
            "action": "alert", "file": "SKILL.md", "line": 2,
            "evidence": "FAKE-SECRET-MUST-NOT-UPLOAD",
        }],
        "verdict": "alert", "registered": False, "drift": False,
    }]})
    assert response.status_code == 200
    assert response.json() == {
        "accepted": 2,
        "assets_accepted": 1,
        "scans_accepted": 1,
        "device_id": "lab-test-01",
        "hostname": "agentsec-test-01",
    }
    assets = client.get("/api/agent-security/assets").json()["assets"]
    agent = next(asset for asset in assets if asset["kind"] == "agent")
    skill = next(asset for asset in assets if asset["kind"] == "skill")
    assert agent["host"] == "agentsec-test-01"
    assert agent["owner"] == "agentsec-lab"
    assert agent["source"] == "managed-inventory"
    assert agent["sha256"] == "a" * 64
    assert skill["host"] == "agentsec-test-01"
    assert skill["source"] == "managed-inventory"
    scans = client.get("/api/agent-security/scans",
                       params={"host": "agentsec-test-01"}).json()["scans"]
    assert scans and scans[0]["target_name"] == "evil-skill"
    scan_events = client.get("/api/agent-security/events",
                             params={"event_type": "scan_finding"}).json()["events"]
    assert scan_events
    assert "FAKE-SECRET-MUST-NOT-UPLOAD" not in json.dumps(scan_events)


def test_asset_inventory_rejects_unknown_device_and_unconfigured_enrollment(
    client: TestClient, monkeypatch
) -> None:
    bad = client.post("/api/agent-security/assets/inventory",
                      headers={"X-AgentSec-Device-Key": "wrong"},
                      json={"assets": []})
    assert bad.status_code == 401
    monkeypatch.setenv("LLMSEC_AGENTSEC_ENROLL_KEY", "")
    disabled = TestClient(create_app()).post(
        "/api/agent-security/devices/enroll",
        headers={"X-AgentSec-Admin-Key": "test-admin-key"},
        json={"device_id": "another", "hostname": "host-2"},
    )
    assert disabled.status_code == 503


def test_enabled_device_enrollment_requires_device_auth_for_event_upload(
    client: TestClient, monkeypatch
) -> None:
    monkeypatch.setenv("LLMSEC_AGENTSEC_ENROLL_KEY", "test-admin-key")
    guarded = TestClient(create_app())
    response = guarded.post("/api/agent-security/events",
                            json={"events": [_event("evt-anon")]})
    assert response.status_code == 401
    assert response.json()["detail"] == "enrolled device key required"


def test_device_event_session_namespace_and_threatbook_shadow(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("LLMSEC_AGENTSEC_DB_PATH", str(tmp_path / "ti.db"))
    monkeypatch.setenv("LLMSEC_AGENTSEC_ENROLL_KEY", "ti-admin")
    monkeypatch.setenv("LLMSEC_AGENTSEC_TI_MODE", "shadow")
    from app.agent_security.models import TIVerdict
    monkeypatch.setattr(
        "app.agent_security.threat_intel.ThreatBookClient.lookup",
        lambda self, ioc, kind: TIVerdict(verdict="clean", confidence=0.8),
    )
    client = TestClient(create_app())
    enrolled = client.post("/api/agent-security/devices/enroll", headers={
        "X-AgentSec-Admin-Key": "ti-admin",
    }, json={"device_id": "ti-device", "hostname": "ti-host", "owner": "lab"})
    token = enrolled.json()["device_token"]
    event = _event("evt-same-local-session", session_id="same", event_type="net_connect",
                   severity="critical", rule_ids=["R005"], action="alert")
    event["dst_domain"] = "8.8.8.8"
    response = client.post("/api/agent-security/events", headers={
        "X-AgentSec-Device-Key": token,
    }, json={"events": [event]})
    assert response.status_code == 200
    stored = client.get("/api/agent-security/events", params={"host": "ti-host"}).json()["events"]
    runtime_event = next(row for row in stored if row["event_id"] == "evt-same-local-session")
    assert runtime_event["session_id"] == "ti-device:same"
    assert runtime_event["host"] == "ti-host"
    assert runtime_event["ti_verdict"] == "clean"
    assert runtime_event["evidence"]["ti_shadow"]["ioc_type"] == "ip"
    assert runtime_event["severity"] == "critical" and runtime_event["action"] == "alert"
    assert runtime_event["ti_provider"] == "threatbook"
    assert runtime_event["ti_confidence"] == 0.8


def test_device_health_and_token_revocation(client: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("LLMSEC_AGENTSEC_ENROLL_KEY", "admin-key")
    admin = {"X-AgentSec-Admin-Key": "admin-key"}
    client = TestClient(create_app())
    enrollment = client.post("/api/agent-security/devices/enroll", headers=admin, json={
        "device_id": "health-device", "hostname": "health-host", "owner": "lab",
    })
    token = enrollment.json()["device_token"]
    event = _event("evt-health", session_id="session-1", event_type="heartbeat",
                   severity="info", action="audit", rule_ids=[])
    from datetime import datetime, timezone
    event["ts"] = datetime.now(timezone.utc).isoformat()
    event["evidence"] = {"pending_events": 3, "oldest_pending_age_seconds": 44,
                         "upload_fail_count": 0, "audit_lost": 0}
    uploaded = client.post("/api/agent-security/events", headers={
        "X-AgentSec-Device-Key": token,
    }, json={"events": [event]})
    assert uploaded.status_code == 200
    health = client.get("/api/agent-security/devices/health").json()["devices"]
    assert health[0]["state"] == "online"
    assert health[0]["pending_events"] == 3

    revoked = client.post("/api/agent-security/devices/health-device/revoke",
                          headers=admin)
    assert revoked.status_code == 200
    assert revoked.json()["state"] == "revoked"
    after = client.post("/api/agent-security/events", headers={
        "X-AgentSec-Device-Key": token,
    }, json={"events": [_event("evt-after-revoke")]})
    assert after.status_code == 401


def test_asset_review_is_audited_and_does_not_use_static_scan_as_verdict(
    client: TestClient, monkeypatch
) -> None:
    monkeypatch.setenv("LLMSEC_AGENTSEC_ENROLL_KEY", "review-admin")
    review_client = TestClient(create_app())
    created = review_client.post("/api/agent-security/assets/inventory", headers={
        "X-AgentSec-Device-Key": "not-enrolled",
    }, json={"assets": [{
        "asset_id": "review-asset", "kind": "skill", "name": "unknown",
        "path": "/tmp/unknown", "host": "spoof", "source": "spoof",
    }]})
    assert created.status_code == 401

    enrollment = review_client.post("/api/agent-security/devices/enroll", headers={
        "X-AgentSec-Admin-Key": "review-admin",
    }, json={"device_id": "review-device", "hostname": "review-host", "owner": "lab"})
    token = enrollment.json()["device_token"]
    ingest = review_client.post("/api/agent-security/assets/inventory", headers={
        "X-AgentSec-Device-Key": token,
    }, json={"assets": [{
        "asset_id": "review-asset", "kind": "skill", "name": "unknown",
        "path": "/tmp/unknown", "sha256": "a" * 64,
    }]})
    assert ingest.status_code == 200

    accepted = review_client.put(
        "/api/agent-security/assets/review-asset/assessment",
        headers={"X-AgentSec-Admin-Key": "review-admin"},
        json={"risk_assessment": "false_positive", "reviewer": "analyst",
              "reason": "test fixture"},
    )
    assert accepted.status_code == 200
    assert accepted.json()["asset"]["risk_assessment"] == "false_positive"
    events = review_client.get("/api/agent-security/events",
                               params={"event_type": "config_change"}).json()["events"]
    assert any(event["evidence"].get("operation") == "asset_assessment_review"
               for event in events)


def test_admission_check_and_threat_intel_query_audit(client: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("LLMSEC_AGENTSEC_ENROLL_KEY", "admin-key")
    monkeypatch.setenv("LLMSEC_AGENTSEC_TI_MODE", "shadow")
    monkeypatch.delenv("THREATBOOK_DOMAIN_ENABLED", raising=False)
    guarded = TestClient(create_app())
    admin = {"X-AgentSec-Admin-Key": "admin-key"}

    admission = guarded.post("/api/agent-security/admission/check", headers=admin,
                             json={
                                 "kind": "skill", "name": "risky",
                                 "path": "/root/.codex/skills/risky/SKILL.md",
                                 "sha256": "a" * 64,
                                 "carrier": "user_installed", "state": "installed",
                                 "risk_assessment": "high_risk_candidate",
                             })
    assert admission.status_code == 200
    assert admission.json()["action"] == "block"

    lookup = guarded.post("/api/agent-security/ti/lookup", headers=admin,
                          json={"ioc": "example.com", "ioc_type": "domain"})
    assert lookup.status_code == 200
    assert lookup.json()["verdict"] == "unknown"
    assert "not enabled" in lookup.json()["reason"]
    history = guarded.get("/api/agent-security/ti/queries", headers=admin).json()["queries"]
    assert history[0]["ioc"] == "example.com"
    assert history[0]["ioc_type"] == "domain"
    assert history[0]["verdict"] == "unknown"


def test_threatbook_shadow_budget_cache_and_admin_refresh(monkeypatch, tmp_path) -> None:
    from app.agent_security.models import TIVerdict

    monkeypatch.setenv("LLMSEC_AGENTSEC_DB_PATH", str(tmp_path / "ti-budget.db"))
    monkeypatch.setenv("LLMSEC_AGENTSEC_ENROLL_KEY", "ti-admin")
    monkeypatch.setenv("LLMSEC_AGENTSEC_TI_MODE", "shadow")
    monkeypatch.setenv("LLMSEC_AGENTSEC_TI_DAILY_BUDGET", "1")
    monkeypatch.setenv("LLMSEC_AGENTSEC_TI_HARD_DAILY_LIMIT", "2")
    calls = []

    def fake_lookup(self, ioc, kind):
        calls.append((ioc, kind))
        return TIVerdict(verdict="suspicious", confidence=0.65)

    monkeypatch.setattr("app.agent_security.threat_intel.ThreatBookClient.lookup", fake_lookup)
    client = TestClient(create_app())
    enrollment = client.post("/api/agent-security/devices/enroll", headers={
        "X-AgentSec-Admin-Key": "ti-admin",
    }, json={"device_id": "ti-device", "hostname": "ti-host"})
    token = enrollment.json()["device_token"]

    events = []
    for index, ip in enumerate(("83.2.103.14", "1.1.1.1", "9.9.9.9")):
        row = _event(f"evt-ti-{index}", session_id=f"s-{index}",
                     event_type="net_connect", severity="info", action="audit",
                     rule_ids=[])
        row["dst_domain"] = ip
        events.append(row)
    uploaded = client.post("/api/agent-security/events", headers={
        "X-AgentSec-Device-Key": token,
    }, json={"events": events})
    assert uploaded.status_code == 200
    assert len(calls) == 2  # soft threshold warns; hard budget blocks the third
    stored = client.get("/api/agent-security/events", params={"host": "ti-host"}).json()["events"]
    by_rule = {event["event_id"]: event for event in stored}
    assert by_rule["evt-ti-0"]["ti_verdict"] == "suspicious"
    assert by_rule["evt-ti-1"]["ti_verdict"] == "suspicious"
    assert by_rule["evt-ti-2"]["ti_verdict"] == "unknown"
    refreshed = client.post("/api/agent-security/ti/refresh", headers={
        "X-AgentSec-Admin-Key": "ti-admin",
    }, json={"event_id": "evt-ti-0"})
    assert refreshed.status_code == 200
    assert refreshed.json()["cached"] is True
    assert len(calls) == 2
    stats = client.get("/api/agent-security/stats").json()["threat_intel"]
    assert stats["mode"] == "shadow"
    assert stats["lookups_today"] == 2
    assert stats["soft_budget_exceeded"] is True


def test_policies_seeded_put_and_audit(client: TestClient) -> None:
    seeded = client.get("/api/agent-security/policies").json()["policies"]
    assert seeded  # defaults are seeded on first read
    put = client.put("/api/agent-security/policies/P-CMD-B01", json={
        "policy_id": "ignored-path-wins",
        "name": "阻止命令 rm -rf",
        "kind": "command",
        "pattern": r"rm\s+-[a-z]*[rf][a-z]*\s+(/|~|\*|\$home)",
        "severity": "high",
        "action": "block",
        "enabled": True,
        "note": "poc",
    })
    assert put.status_code == 200
    body = put.json()
    assert body["policy_id"] == "P-CMD-B01"  # path id wins over body
    assert body["updated_at"]
    audit = client.get("/api/agent-security/events",
                       params={"event_type": "config_change"}).json()["events"]
    assert audit and audit[0]["evidence"]["policy_id"] == "P-CMD-B01"


def test_hooks_decision_blocks_sensitive_path(client: TestClient) -> None:
    blocked = client.post("/api/agent-security/hooks/decision", json={
        "tool_name": "Write",
        "tool_input": {"file_path": "/home/u/.ssh/id_rsa"},
        "host": "d2-dev",
    })
    assert blocked.status_code == 200
    assert blocked.json()["action"] == "block"
    allowed = client.post("/api/agent-security/hooks/decision", json={
        "tool_name": "Read",
        "tool_input": {"file_path": "/home/u/main.py"},
        "host": "d2-dev",
    })
    assert allowed.json()["action"] == "allow"


def test_approvals_flow(client: TestClient) -> None:
    client.post("/api/agent-security/events", json={"events": [
        _event("evt-ask", action="ask", severity="medium"),
    ]})
    approvals = client.get("/api/agent-security/approvals").json()
    assert any(e["event_id"] == "evt-ask" for e in approvals["pending"])
    approved = client.post("/api/agent-security/approvals", json={
        "event_id": "evt-ask", "decision": "approve", "note": "poc ok",
    })
    assert approved.status_code == 200
    assert approved.json()["action"] == "allow"
    assert approved.json()["evidence"]["approval_of"] == "evt-ask"
    assert client.post("/api/agent-security/approvals",
                       json={"event_id": "evt-ask", "decision": "maybe"}
                       ).status_code == 400
    assert client.post("/api/agent-security/approvals",
                       json={"event_id": "evt-missing",
                             "decision": "approve"}).status_code == 404


def test_stats_and_rules_catalog(client: TestClient) -> None:
    client.post("/api/agent-security/events",
                json={"events": [_event("evt-e"),
                                 _event("evt-ask", action="ask", severity="medium")]})
    stats = client.get("/api/agent-security/stats").json()
    assert stats["events_total"] == 2
    assert stats["by_severity"]["high"] == 1
    assert stats["by_severity"]["medium"] == 1
    assert stats["by_rule"]["S26"] == 2
    assert stats["pending_approvals"] == 1
    assert stats["rules_total"] == 33  # 28 static + 5 runtime
    assert stats["runtime_rules"] == 5
    rules = client.get("/api/agent-security/rules").json()
    assert len(rules["rules"]) == 33
    assert set(rules["runtime_rule_ids"]) == {"R001", "R002", "R003", "R004", "R005"}
    assert rules["categories"]["A"] == "指令投毒与隐藏指令"
