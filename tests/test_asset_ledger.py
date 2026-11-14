"""资产台账：登记幂等、三态按证据推导、追踪视图串联整条链路。

重点不在 happy path，而在"状态只能来自平台真正持有的证据"：
- installation_state 由准入事务推导，安装器没落过盘就不能是 installed；
- activation_state 由准入事务派生，客户端声明一律拒绝（登记接口不接受该字段）；
- 追踪视图里 finding 是分析员显式关联，policy_decision/admission 按标识
  字符串匹配，响应里的 section_links 把关联方式写清楚。
"""
from datetime import datetime, timezone

import pytest

from services.asset_service import derive_installation_state, derive_runtime_state
from services.managed_installer import tree_hash
from test_console_auth import api, admin_token, call, login
from test_console_auth import ADMIN_PASSWORD, VIEWER_PASSWORD
from domain import ConsoleRole
from domain.enums import AdmissionState

CONTENT_HASH = "a" * 64


def _register(api, token, **overrides):
    body = {"asset_type": "skill", "canonical_name": "demo-skill",
            "product": "claude-code"}
    body.update(overrides)
    response = call(api.base, "POST", "/api/v1/assets", token=token, body=body)
    assert response.status_code == 200, response.text
    return response.json()


def _instance(api, token, asset_id, *, host_id="host_lab", scope="claude-code",
              install_path=None):
    body = {"asset_id": asset_id, "host_id": host_id, "product_scope": scope}
    if install_path:
        body["install_path"] = install_path
    response = call(api.base, "POST", "/api/v1/asset-instances", token=token,
                    body=body)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["instance"]["instance_id"]
    return result


def _make_package(api, name, body="print('ok')\n"):
    package = api.managed / "inbound" / name
    (package / "src").mkdir(parents=True, exist_ok=True)
    (package / "src" / "main.py").write_text(body, encoding="utf-8")
    (package / "README.md").write_text(name, encoding="utf-8")
    return tree_hash(package)


def _run(api, token, run_id, findings=(), status="succeeded"):
    from adapters.detectors import NormalizedFinding, RawOutput
    from domain import Severity
    repo = api.module.scan_service.runs
    run_id = repo.create_run(detector_id="skillspector", detector_version="2.12.0",
                             target_ref="skills/demo", mode="static", timeout_seconds=30,
                             idempotency_key=run_id)
    if status == "succeeded":
        repo.record_success(run_id=run_id,
                            raw=RawOutput(report={"findings": []},
                                          media_type="application/json",
                                          sha256=CONTENT_HASH, byte_length=16),
                            findings=[NormalizedFinding(
                                rule_id=rule, title=f"title {rule}",
                                severity=Severity.HIGH, message="m",
                                fingerprint=fingerprint, detector_id="skillspector",
                                detector_version="2.12.0")
                                for rule, fingerprint in findings])
    else:
        repo.record_failure(run_id=run_id, status=status, error="boom")
    return run_id


class TestRegistration:
    def test_asset_instance_and_release_round_trip(self, api, admin_token):
        asset = _register(api, admin_token, publisher="acme", namespace="skills",
                          provenance="marketplace")["asset"]
        assert asset["asset_type"] == "skill" and asset["provenance"] == "marketplace"

        registered = _instance(api, admin_token, asset["asset_id"],
                           install_path="~/.claude/skills/demo")
        instance = registered["instance"]
        assert instance["installation_state"] == "unknown"
        assert instance["activation_state"] == "unknown"
        assert instance["runtime_state"] == "unknown"

        release = call(api.base, "POST", "/api/v1/asset-releases", token=admin_token,
                       body={"asset_id": asset["asset_id"], "version": "1.0.0",
                             "content_hash": CONTENT_HASH}).json()["release"]
        assert release["version"] == "1.0.0" and release["signature_verified"] is False

        listing = call(api.base, "GET", "/api/v1/assets", token=admin_token).json()
        assert [item["asset"]["asset_id"] for item in listing["items"]] == [asset["asset_id"]]
        row = listing["items"][0]
        assert row["instances"][0]["instance_id"] == instance["instance_id"]
        # 关联方式必须写进响应，否则界面会把字符串匹配读成采集器证明。
        assert "字符串匹配" in listing["links"]["admission"]

    def test_duplicate_registration_returns_the_same_row(self, api, admin_token):
        first = _register(api, admin_token)
        again = call(api.base, "POST", "/api/v1/assets", token=admin_token,
                     body={"asset_type": "skill", "canonical_name": "demo-skill",
                           "product": "claude-code"})
        assert again.json()["duplicate"] is True
        assert again.json()["asset"]["asset_id"] == first["asset"]["asset_id"]

        # 同一名称换产品是不同逻辑资产。
        other = _register(api, admin_token, product="codex")
        assert other["duplicate"] is False
        assert other["asset"]["asset_id"] != first["asset"]["asset_id"]

        instance = _instance(api, admin_token, first["asset"]["asset_id"])["instance"]
        repeat = _instance(api, admin_token, first["asset"]["asset_id"])
        assert repeat["instance"]["instance_id"] == instance["instance_id"]
        assert repeat["duplicate"] is True
        # 重复登记不分裂出第二个副本。
        listing = {item["asset"]["asset_id"]: item for item in
                   call(api.base, "GET", "/api/v1/assets", token=admin_token).json()["items"]}
        assert len(listing[first["asset"]["asset_id"]]["instances"]) == 1

    def test_registration_input_is_validated(self, api, admin_token):
        asset = _register(api, admin_token)["asset"]
        assert call(api.base, "POST", "/api/v1/assets", token=admin_token,
                    body={"asset_type": "nonsense", "canonical_name": "x"}).status_code == 400
        assert call(api.base, "POST", "/api/v1/assets", token=admin_token,
                    body={"asset_type": "skill"}).status_code == 400
        assert call(api.base, "POST", "/api/v1/assets", token=admin_token,
                    body={"asset_type": "skill", "canonical_name": "x",
                          "surprise": "field"}).status_code == 400
        assert call(api.base, "POST", "/api/v1/asset-instances", token=admin_token,
                    body={"asset_id": "asset_missing", "host_id": "h",
                          "product_scope": "claude-code"}).status_code == 404
        assert call(api.base, "POST", "/api/v1/asset-releases", token=admin_token,
                    body={"asset_id": asset["asset_id"], "version": "1",
                          "content_hash": "not-a-hash"}).status_code == 400
        assert call(api.base, "POST", "/api/v1/asset-releases", token=admin_token,
                    body={"asset_id": asset["asset_id"], "version": "1",
                          "content_hash": CONTENT_HASH,
                          "signature_verified": "yes"}).status_code == 400
        assert call(api.base, "POST", "/api/v1/asset-releases", token=admin_token,
                    body={"asset_id": asset["asset_id"], "version": "1",
                          "content_hash": CONTENT_HASH,
                          "published_at": "not-a-date"}).status_code == 400

    def test_secret_shaped_input_is_rejected(self, api, admin_token):
        response = call(api.base, "POST", "/api/v1/assets", token=admin_token,
                        body={"asset_type": "skill", "canonical_name": "demo",
                              "provenance": "sk-ant-" + "a" * 30})
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "suspected_secret_parameter"


class TestDerivedStates:
    def test_installation_state_follows_installer_evidence(self, api, admin_token):
        asset = _register(api, admin_token)["asset"]
        instance = _instance(api, admin_token, asset["asset_id"])["instance"]
        content_hash = _make_package(api, "skill-demo")

        admission = call(api.base, "POST", "/api/v1/admissions/check", token=admin_token,
                         body={"asset_instance_id": instance["instance_id"],
                               "content_hash": content_hash,
                               "transaction_id": "txn_demo"}).json()
        url = "/api/v1/admissions/" + admission["admission_id"]

        def state():
            listing = call(api.base, "GET", "/api/v1/assets", token=admin_token).json()
            return listing["items"][0]["instances"][0]["installation_state"]

        # 只开了检查单：安装器什么都没做，不能是 installed。
        assert state() == "unknown"
        call(api.base, "POST", url + "/approve", token=admin_token, body={})
        call(api.base, "POST", url + "/stage", token=admin_token,
             body={"source_path": "skill-demo"}).raise_for_status()
        assert state() == "unknown", "staged 只是暂存，未提交不算已安装"
        call(api.base, "POST", url + "/commit", token=admin_token, body={}).raise_for_status()
        assert state() == "installed"
        call(api.base, "POST", url + "/verify", token=admin_token, body={}).raise_for_status()
        assert state() == "installed"

        # 回滚首次安装：安装器移除落盘内容，记 absent。
        call(api.base, "POST", url + "/rollback", token=admin_token, body={}).raise_for_status()
        assert state() == "absent"
        assert not (api.managed / "installed" / instance["instance_id"]).exists()

    def test_failed_admission_does_not_claim_a_state(self, api, admin_token):
        asset = _register(api, admin_token)["asset"]
        instance = _instance(api, admin_token, asset["asset_id"])["instance"]
        content_hash = _make_package(api, "skill-drift")
        admission = call(api.base, "POST", "/api/v1/admissions/check", token=admin_token,
                         body={"asset_instance_id": instance["instance_id"],
                               "content_hash": content_hash,
                               "transaction_id": "txn_drift"}).json()
        url = "/api/v1/admissions/" + admission["admission_id"]
        call(api.base, "POST", url + "/approve", token=admin_token, body={}).raise_for_status()
        _make_package(api, "skill-drift", body="print('tampered')\n")
        failed = call(api.base, "POST", url + "/stage", token=admin_token,
                      body={"source_path": "skill-drift"}).json()
        assert failed["state"] == "failed" and "content_drift" in failed["failure_reason"]

        listing = call(api.base, "GET", "/api/v1/assets", token=admin_token).json()
        view = listing["items"][0]["instances"][0]
        # 磁盘内容与审批声明不符：不重新 verify 前说不清上面有什么。
        assert view["installation_state"] == "unknown"
        assert view["activation_state"] == "unknown"

    def test_runtime_state_follows_executions_only(self, api, admin_token):
        from test_v1_ingest import execution, setup_device

        asset = _register(api, admin_token)["asset"]
        instance = _instance(api, admin_token, asset["asset_id"])["instance"]
        assert call(api.base, "GET", "/api/v1/assets", token=admin_token).json()[
            "items"][0]["instances"][0]["runtime_state"] == "unknown"

        device = setup_device(api, admin_token)
        body = dict(execution("exec_live"), asset_instance_id=instance["instance_id"])
        call(api.base, "POST", "/api/v1/executions", token=device["token"],
             body=body).raise_for_status()
        assert call(api.base, "GET", "/api/v1/assets", token=admin_token).json()[
            "items"][0]["instances"][0]["runtime_state"] == "running"

        # 收尾后不再运行；产品是否加载该包仍无证据。
        call(api.base, "POST", "/api/v1/executions", token=device["token"],
             body=dict(body, outcome="completed",
                       ended_at=datetime.now(timezone.utc).isoformat())).raise_for_status()
        view = call(api.base, "GET", "/api/v1/assets", token=admin_token).json()[
            "items"][0]["instances"][0]
        assert view["runtime_state"] == "stopped"
        assert view["activation_state"] == "unknown"

    def test_activation_state_cannot_be_declared(self, api, admin_token):
        asset = _register(api, admin_token)["asset"]
        response = call(api.base, "POST", "/api/v1/asset-instances", token=admin_token,
                        body={"asset_id": asset["asset_id"], "host_id": "h",
                              "product_scope": "claude-code",
                              "activation_state": "enabled"})
        assert response.status_code == 400
        # 登记接口不接受 activation_state；没有准入记录时派生值为 unknown，
        # 按 enabled 过滤自然为空。
        assert call(api.base, "GET", "/api/v1/assets?activation_state=enabled",
                    token=admin_token).json()["items"] == []

    @pytest.mark.parametrize("states,expected", [
        ([], "unknown"),
        ([("check", None), ("approved", None)], "unknown"),
        ([("committed", "first_install")], "installed"),
        ([("verified", "first_install")], "installed"),
        ([("reconciled", "first_install")], "installed"),
        ([("rolled_back", "first_install")], "absent"),
        ([("rolled_back", "snap_1")], "installed"),
        ([("failed", "snap_1")], "unknown"),
        # 新版本已提交，旧回滚记录不再代表当前磁盘状态。
        ([("committed", "snap_1"), ("rolled_back", "snap_1")], "installed"),
    ])
    def test_installation_state_rules(self, states, expected):
        rows = [{"state": state, "rollback_ref": ref} for state, ref in states]
        assert derive_installation_state(rows) == expected

    def test_runtime_state_rules(self):
        assert derive_runtime_state([]) == "unknown"
        assert derive_runtime_state([{"outcome": "completed"}]) == "stopped"
        assert derive_runtime_state([{"outcome": "running"}]) == "running"
        assert derive_runtime_state([{"outcome": "running"}, {"outcome": "completed"}]) == "running"


class TestTrace:
    def test_trace_collects_finding_admission_incident_and_decision(self, api, admin_token):
        from test_v1_ingest import execution, setup_device

        asset = _register(api, admin_token)["asset"]
        instance = _instance(api, admin_token, asset["asset_id"])["instance"]
        device = setup_device(api, admin_token)
        call(api.base, "POST", "/api/v1/executions", token=device["token"],
             body=dict(execution("exec_trace"),
                       asset_instance_id=instance["instance_id"])).raise_for_status()

        run_id = _run(api, admin_token, "run-skill",
                      findings=[("SKILL-OVERRIDE", "f" * 64)])
        with api.module.storage.connection() as conn:
            finding_id = conn.execute(
                "SELECT finding_id FROM detector_run_findings WHERE detector_run_id = ?",
                (run_id,)).fetchone()[0]

        linked = call(api.base, "POST", "/api/v1/executions/exec_trace/findings",
                      token=admin_token, body={"finding_id": finding_id,
                                               "note": "同一次会话里调用过该技能"})
        assert linked.status_code == 200, linked.text
        assert linked.json()["linked"] is True
        # 重复关联幂等，且始终标注为分析员关联而非自动归因。
        again = call(api.base, "POST", "/api/v1/executions/exec_trace/findings",
                     token=admin_token, body={"finding_id": finding_id})
        assert again.json()["linked"] is False
        assert again.json()["association"] == "analyst_linked"

        content_hash = _make_package(api, "skill-trace")
        call(api.base, "POST", "/api/v1/admissions/check", token=admin_token,
             body={"asset_instance_id": instance["instance_id"],
                   "content_hash": content_hash,
                   "transaction_id": "txn_trace"}).raise_for_status()

        incident = call(api.base, "POST", "/api/v1/incidents", token=admin_token,
                        body={"title": "可疑技能", "severity": "high"}).json()
        call(api.base, "POST", f"/api/v1/incidents/{incident['incident_id']}/evidence",
             token=admin_token,
             body={"evidence_kind": "finding", "evidence_id": finding_id}).raise_for_status()
        call(api.base, "POST", f"/api/v1/incidents/{incident['incident_id']}/evidence",
             token=admin_token,
             body={"evidence_kind": "execution",
                   "evidence_id": "exec_trace"}).raise_for_status()

        risk = call(api.base, "POST", "/api/v1/risk-assessments", token=admin_token,
                    body={"finding_ids": [finding_id],
                          "exposure": {"privileged": True}}).json()
        decision = call(api.base, "POST", "/api/v1/policies/evaluate", token=admin_token,
                        body={"assessment_id": risk["assessment_id"],
                              "subject_kind": "asset_instance",
                              "subject_id": instance["instance_id"]}).json()
        assert decision["action"] in {"allow", "audit", "confirm", "block"}

        trace = call(api.base, "GET", f"/api/v1/assets/{asset['asset_id']}",
                     token=admin_token).json()
        assert trace["asset"]["canonical_name"] == "demo-skill"
        assert [r["version"] for r in trace["releases"]] == []
        assert trace["instances"][0]["instance_id"] == instance["instance_id"]
        assert [a["transaction_id"] for a in trace["admissions"]] == ["txn_trace"]
        assert [e["execution_id"] for e in trace["executions"]] == ["exec_trace"]
        assert [f["finding_id"] for f in trace["findings"]] == [finding_id]
        assert trace["findings"][0]["linked_by"].startswith("user_")
        assert trace["findings"][0]["link_note"] == "同一次会话里调用过该技能"
        assert [d["decision_id"] for d in trace["policy_decisions"]] == [decision["decision_id"]]
        assert [i["incident_id"] for i in trace["incidents"]] == [incident["incident_id"]]
        assert "finding" in trace["incidents"][0]["evidence"]

    def test_trace_of_unknown_asset_is_404(self, api, admin_token):
        assert call(api.base, "GET", "/api/v1/assets/asset_missing",
                    token=admin_token).status_code == 404

    def test_timeline_shows_linked_finding_admission_and_decision(self, api, admin_token):
        from test_v1_ingest import execution, setup_device

        asset = _register(api, admin_token)["asset"]
        instance = _instance(api, admin_token, asset["asset_id"])["instance"]
        device = setup_device(api, admin_token)
        call(api.base, "POST", "/api/v1/executions", token=device["token"],
             body=dict(execution("exec_tl"),
                       asset_instance_id=instance["instance_id"])).raise_for_status()
        call(api.base, "POST", "/api/v1/executions/exec_tl/intents", token=device["token"],
             body={"intent_id": "intent_tl", "tool_name": "Bash", "tool_call_id": "call_tl",
                   "hook_event_type": "pre_tool_use",
                   "occurred_at": execution("exec_tl")["started_at"]}).raise_for_status()
        run_id = _run(api, admin_token, "run-tl", findings=[("R1", "e" * 64)])
        with api.module.storage.connection() as conn:
            finding_id = conn.execute(
                "SELECT finding_id FROM detector_run_findings WHERE detector_run_id = ?",
                (run_id,)).fetchone()[0]
        call(api.base, "POST", "/api/v1/executions/exec_tl/findings", token=admin_token,
             body={"finding_id": finding_id}).raise_for_status()
        risk = call(api.base, "POST", "/api/v1/risk-assessments", token=admin_token,
                    body={"finding_ids": [finding_id]}).json()
        call(api.base, "POST", "/api/v1/policies/evaluate", token=admin_token,
             body={"assessment_id": risk["assessment_id"],
                   "subject_kind": "execution", "subject_id": "exec_tl"}).raise_for_status()
        content_hash = _make_package(api, "skill-tl")
        call(api.base, "POST", "/api/v1/admissions/check", token=admin_token,
             body={"asset_instance_id": instance["instance_id"],
                   "content_hash": content_hash,
                   "transaction_id": "txn_tl"}).raise_for_status()

        result = call(api.base, "GET", "/api/v1/executions/exec_tl/timeline",
                      token=admin_token).json()
        kinds = {entry["kind"] for entry in result["entries"]}
        assert {"intent", "finding", "policy_decision", "admission"} <= kinds
        finding = next(e for e in result["entries"] if e["kind"] == "finding")
        assert finding["data"]["linked_by"].startswith("user_")
        admission = next(e for e in result["entries"] if e["kind"] == "admission")
        assert admission["data"]["transaction_id"] == "txn_tl"
        assert admission["data"]["state"] == "check"
        assert result["sections_pending"] == []

    def test_link_requires_existing_execution_and_finding(self, api, admin_token):
        from test_v1_ingest import execution, setup_device

        device = setup_device(api, admin_token)
        call(api.base, "POST", "/api/v1/executions", token=device["token"],
             body=execution("exec_link")).raise_for_status()
        assert call(api.base, "POST", "/api/v1/executions/exec_link/findings",
                    token=admin_token, body={"finding_id": "find_missing"}).status_code == 404
        assert call(api.base, "POST", "/api/v1/executions/exec_missing/findings",
                    token=admin_token, body={"finding_id": "find_missing"}).status_code == 404
        assert call(api.base, "POST", "/api/v1/executions/exec_link/findings",
                    token=admin_token, body={"finding_id": "find_missing",
                                             "note": "x"}).status_code == 404


class TestPermissions:
    def test_viewer_reads_ledger_but_cannot_register(self, api, admin_token):
        actor = api.module.auth_service.authenticate(admin_token)[0]
        api.module.auth_service.create_user(actor=actor, username="viewer",
                                            password=VIEWER_PASSWORD,
                                            role=ConsoleRole.VIEWER)
        token = login(api.base, "viewer", VIEWER_PASSWORD)

        asset = _register(api, admin_token)["asset"]
        assert call(api.base, "GET", "/api/v1/assets", token=token).status_code == 200
        assert call(api.base, "GET", f"/api/v1/assets/{asset['asset_id']}",
                    token=token).status_code == 200
        assert call(api.base, "POST", "/api/v1/assets", token=token,
                    body={"asset_type": "skill", "canonical_name": "x"}).status_code == 403
        assert call(api.base, "POST", "/api/v1/asset-instances", token=token,
                    body={"asset_id": asset["asset_id"], "host_id": "h",
                          "product_scope": "claude-code"}).status_code == 403
        assert call(api.base, "POST", "/api/v1/asset-releases", token=token,
                    body={"asset_id": asset["asset_id"], "version": "1",
                          "content_hash": CONTENT_HASH}).status_code == 403

    def test_device_token_cannot_touch_the_ledger(self, api, admin_token):
        from test_v1_ingest import setup_device

        device = setup_device(api, admin_token)
        assert call(api.base, "GET", "/api/v1/assets",
                    token=device["token"]).status_code == 401
        assert call(api.base, "POST", "/api/v1/assets", token=device["token"],
                    body={"asset_type": "skill",
                          "canonical_name": "x"}).status_code == 401


class TestMigration:
    def test_v8_tables_exist_and_version_is_recorded(self, api):
        import sqlite3

        conn = sqlite3.connect(api.db_path)
        names = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"assets", "asset_instances", "asset_releases",
                "execution_findings"} <= names
        # 版本号跟常量对齐：写死字面量会让每次升版都要改这条断言。
        from storage.schema import SCHEMA_VERSION
        assert conn.execute(
            "SELECT value FROM schema_meta WHERE key='schema_version'"
        ).fetchone()[0] == str(SCHEMA_VERSION)
        columns = {row[1] for row in conn.execute("PRAGMA table_info(asset_instances)")}
        assert {"installation_state", "activation_state", "runtime_state"}.isdisjoint(columns), \
            "三态是按证据现算的派生值，不落库"
        conn.close()


# 测试专用 Ed25519 签名工具（控制面生产代码绝不持有或生成私钥）。
def _test_ed25519_keypair(seed: bytes):
    import hashlib
    from services.ed25519 import _B, _L, _P, _point_mul

    def encode_point(pt):
        z_inv = pow(pt[2], -1, _P)
        x = (pt[0] * z_inv) % _P
        y = (pt[1] * z_inv) % _P
        encoded = bytearray(y.to_bytes(32, "little"))
        encoded[31] |= (x & 1) << 7
        return bytes(encoded)

    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    pub = encode_point(_point_mul(a, _B))
    prefix = h[32:]

    def sign(msg: bytes) -> bytes:
        r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % _L
        r_bytes = encode_point(_point_mul(r, _B))
        k = int.from_bytes(hashlib.sha512(r_bytes + pub + msg).digest(), "little") % _L
        s = (r + k * a) % _L
        return r_bytes + s.to_bytes(32, "little")

    return pub.hex(), sign


class TestEd25519ReleaseVerification:
    def test_rfc8032_vectors_and_server_signing_round_trip(self, api, admin_token):
        from services.ed25519 import verify_ed25519

        pk_vec = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        sig_vec = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        assert verify_ed25519(pk_vec, b"", sig_vec)
        assert not verify_ed25519(pk_vec, b"tampered", sig_vec)

        pub_hex, sign = _test_ed25519_keypair(b"\x07" * 32)
        pub_resp = call(api.base, "POST", "/api/v1/publishers", token=admin_token,
                        body={"name": "acme-signer", "public_key": pub_hex})
        assert pub_resp.status_code == 200, pub_resp.text
        publisher = pub_resp.json()["publisher"]
        assert publisher["algorithm"] == "ed25519"
        assert publisher["status"] == "active"

        # 重复登记同一发布方同名同公钥幂等，换公钥则 409 冲突。
        dup = call(api.base, "POST", "/api/v1/publishers", token=admin_token,
                   body={"name": "acme-signer", "public_key": pub_hex})
        assert dup.status_code == 200 and dup.json()["duplicate"] is True
        other_pub_hex, _ = _test_ed25519_keypair(b"\x08" * 32)
        conflict = call(api.base, "POST", "/api/v1/publishers", token=admin_token,
                        body={"name": "acme-signer", "public_key": other_pub_hex})
        assert conflict.status_code == 409

        from services.asset_service import release_signing_payload
        # 拒绝小阶点公钥或 R 点。
        assert not verify_ed25519(bytes([1]) + b"\x00" * 31, b"msg", sig_vec)
        assert not verify_ed25519(pk_vec, b"msg", bytes([1]) + b"\x00" * 31 + b"\x00" * 32)

        asset = _register(api, admin_token, publisher="acme-signer")["asset"]
        other_asset = _register(api, admin_token, canonical_name="other-pkg", publisher="acme-signer")["asset"]
        sig_hex = sign(release_signing_payload(asset["asset_id"], "1.0.0", CONTENT_HASH)).hex()

        # 绝不信任客户端自报 signature_verified。
        forged_flag = call(api.base, "POST", "/api/v1/asset-releases", token=admin_token,
                           body={"asset_id": asset["asset_id"], "version": "1.0.0",
                                 "content_hash": CONTENT_HASH, "signature_verified": True})
        assert forged_flag.status_code == 400
        assert forged_flag.json()["error"]["code"] == "client_signature_verified_forbidden"

        # 篡改 content_hash 或签名必须被拒。
        bad_hash = "b" * 64
        tampered = call(api.base, "POST", "/api/v1/asset-releases", token=admin_token,
                        body={"asset_id": asset["asset_id"], "version": "1.0.0",
                              "content_hash": bad_hash,
                              "publisher_id": publisher["publisher_id"],
                              "signature": sig_hex})
        assert tampered.status_code == 400
        assert tampered.json()["error"]["code"] == "signature_verification_failed"

        # 跨版本或跨资产重放相同 content_hash 签名必须失败。
        cross_version = call(api.base, "POST", "/api/v1/asset-releases", token=admin_token,
                             body={"asset_id": asset["asset_id"], "version": "2.0.0",
                                   "content_hash": CONTENT_HASH,
                                   "publisher_id": publisher["publisher_id"],
                                   "signature": sig_hex})
        assert cross_version.status_code == 400
        assert cross_version.json()["error"]["code"] == "signature_verification_failed"
        cross_asset = call(api.base, "POST", "/api/v1/asset-releases", token=admin_token,
                           body={"asset_id": other_asset["asset_id"], "version": "1.0.0",
                                 "content_hash": CONTENT_HASH,
                                 "publisher_id": publisher["publisher_id"],
                                 "signature": sig_hex})
        assert cross_asset.status_code == 400
        assert cross_asset.json()["error"]["code"] == "signature_verification_failed"

        # 合法 Ed25519 签名：服务端算得 signature_verified=True 与 verified_at。
        verified = call(api.base, "POST", "/api/v1/asset-releases", token=admin_token,
                        body={"asset_id": asset["asset_id"], "version": "1.0.0",
                              "content_hash": CONTENT_HASH,
                              "publisher_id": publisher["publisher_id"],
                              "signature": sig_hex})
        assert verified.status_code == 200, verified.text
        rel = verified.json()["release"]
        assert rel["signature_verified"] is True
        assert rel["publisher_id"] == publisher["publisher_id"]
        assert rel["verified_at"] is not None

        # 吊销发布方后不得再验签通过。
        revoked = call(api.base, "POST", f"/api/v1/publishers/{publisher['publisher_id']}/revoke",
                       token=admin_token)
        assert revoked.status_code == 200
        assert revoked.json()["publisher"]["status"] == "revoked"
        after_revoke = call(api.base, "POST", "/api/v1/asset-releases", token=admin_token,
                            body={"asset_id": asset["asset_id"], "version": "1.0.1",
                                  "content_hash": CONTENT_HASH,
                                  "publisher_id": publisher["publisher_id"],
                                  "signature": sig_hex})
        assert after_revoke.status_code == 400
        assert after_revoke.json()["error"]["code"] == "publisher_revoked"

    def test_v11_migration_clears_unverified_legacy_boolean_claims(self, tmp_path):
        import sqlite3
        from storage.repositories import Storage
        from storage.schema import SCHEMA_VERSION

        db = tmp_path / "legacy_v10.db"
        Storage(db)
        conn = sqlite3.connect(db)
        conn.execute(
            "INSERT INTO assets VALUES ('a1','skill','demo','claude-code',NULL,NULL,NULL,'2026-11-01T00:00:00+00:00','2026-11-01T00:00:00+00:00')"
        )
        conn.execute(
            "INSERT INTO asset_releases (release_id, asset_id, version, content_hash, source_uri, signature_verified, published_at)"
            " VALUES ('r1','a1','1.0.0',?,'https://example.com',1,NULL)",
            (CONTENT_HASH,),
        )
        conn.commit()
        conn.close()

        # 重新运行迁移应清除无签名作证的客户端自报标记。
        Storage(db)
        conn = sqlite3.connect(db)
        row = conn.execute(
            "SELECT signature_verified, verified_at FROM asset_releases WHERE release_id='r1'"
        ).fetchone()
        assert row == (0, None)
        assert conn.execute(
            "SELECT value FROM schema_meta WHERE key='schema_version'"
        ).fetchone()[0] == str(SCHEMA_VERSION)
        conn.close()
