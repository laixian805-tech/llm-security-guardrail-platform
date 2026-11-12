"""策略版本回滚：retired 版本可以被退回，但必须说明原因。

为什么单独一条路径而不是放开 ``activate``：``activate`` 的语义是"启用新版本"，
让它接受 retired 会让"废弃"失去意义。回滚是运维退路，必须
(a) 允许 retired → active，(b) 带上原因，(c) 在迁移记录里与普通激活区分。
"""
from __future__ import annotations

import pytest

from services.ingestion_service import IngestError
from storage.repositories import Storage
from test_console_auth import api, admin_token, call


def _rules(threshold: float) -> list[dict]:
    return [
        {"rule_id": "block-strict", "action": "block", "reason": f"intrinsic >= {threshold}",
         "intrinsic_risk_min": threshold},
        {"rule_id": "allow-clean", "action": "allow", "reason": "no risk", "peak_at_most": 0},
    ]


def _create(api, token, version: str, threshold: float):
    return call(api.base, "POST", "/api/v1/policies/versions",
                token=token, body={"policy_version": version, "rules": _rules(threshold)})


def _activate(api, token, version: str):
    return call(api.base, "POST", f"/api/v1/policies/versions/{version}/activate",
                token=token, body={})


def _rollback(api, token, version: str, reason=None):
    body = {} if reason is None else {"reason": reason}
    return call(api.base, "POST", f"/api/v1/policies/versions/{version}/rollback",
                token=token, body=body)


def _active(api, token):
    response = call(api.base, "GET", "/api/v1/policies/active", token=token)
    assert response.status_code == 200
    return (response.json().get("active") or {}).get("policy_version")


def test_rollback_reactivates_a_retired_version(api, admin_token):
    """误激活激进版本后，能退回旧版本并恢复原决策。"""
    assert _create(api, admin_token, "policy-roll-a", 60).status_code == 200
    assert _activate(api, admin_token, "policy-roll-a").status_code == 200
    assert _active(api, admin_token) == "policy-roll-a"

    response = _rollback(api, admin_token, "policy-v1", "激进阈值导致误拦，退回")
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "active"
    assert _active(api, admin_token) == "policy-v1"


def test_rollback_requires_a_reason(api, admin_token):
    _create(api, admin_token, "policy-roll-b", 60)
    _activate(api, admin_token, "policy-roll-b")
    response = _rollback(api, admin_token, "policy-v1")
    assert response.status_code == 400
    assert "rollback_reason_required" in response.text


def test_rollback_rejects_blank_reason(api, admin_token):
    _create(api, admin_token, "policy-roll-c", 60)
    _activate(api, admin_token, "policy-roll-c")
    assert _rollback(api, admin_token, "policy-v1", "   ").status_code == 400


def test_rollback_unknown_version_is_404(api, admin_token):
    response = _rollback(api, admin_token, "policy-does-not-exist", "退回")
    assert response.status_code == 404


def test_rollback_to_current_active_is_idempotent(api, admin_token):
    """已经是活跃版本时直接返回，不重复写迁移记录。"""
    before = _active(api, admin_token)
    response = _rollback(api, admin_token, before, "无变化")
    assert response.status_code == 200
    assert response.json()["status"] == "active"
    assert _active(api, admin_token) == before


def test_activate_still_refuses_retired(api, admin_token):
    """回滚专用路径不应污染 activate 的语义。"""
    _create(api, admin_token, "policy-roll-d", 60)
    _activate(api, admin_token, "policy-roll-d")
    _rollback(api, admin_token, "policy-v1", "退回")
    response = _activate(api, admin_token, "policy-roll-d")
    assert response.status_code == 409


def test_rollback_leaves_consistent_state(tmp_path):
    """直接测服务：retired_at 必须清空，且只有一个 active。"""
    from domain import PolicyStatus
    from services.policy_service import PolicyService
    from storage.governance_repositories import GovernanceRepository

    storage = Storage(tmp_path / "policy.db")
    service = PolicyService(storage, GovernanceRepository(storage))
    service.create({"policy_version": "v-new", "rules": _rules(60)}, "tester")
    service.activate("v-new", "tester")
    service.rollback("policy-v1", "tester", "退回默认")

    with storage.connection() as conn:
        rows = {row[0]: row[1:] for row in conn.execute(
            "SELECT policy_version, status, retired_at FROM policy_versions")}
        transitions = conn.execute(
            "SELECT from_state, to_state, action, detail FROM governance_transitions"
            " WHERE entity_id='policy-v1' ORDER BY seq DESC").fetchall()

    assert rows["policy-v1"][0] == PolicyStatus.ACTIVE.value
    assert rows["policy-v1"][1] is None, "active 版本不能保留 retired_at"
    assert [r for r in rows.values() if r[0] == "active"].__len__() == 1
    latest = transitions[0]
    assert latest[2] == "rollback"
    assert "退回默认" in (latest[3] or ""), "回滚原因必须写进迁移记录"


def test_rollback_requires_reason_at_service_layer(tmp_path):
    from services.policy_service import PolicyService
    from storage.governance_repositories import GovernanceRepository

    storage = Storage(tmp_path / "policy2.db")
    service = PolicyService(storage, GovernanceRepository(storage))
    with pytest.raises(IngestError) as exc:
        service.rollback("policy-v1", "tester", None)
    assert exc.value.code == "rollback_reason_required"
