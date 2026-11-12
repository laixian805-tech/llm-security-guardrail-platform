"""数据外发链：能抓、且不乱抓。

这套东西的价值不在"抓得到恶意"，而在"不把正常外发当成攻击"。最能杀人信心的
误报是：开发者读私钥、然后 git push 到 github —— 每天几百次，报一次这个功能就废了。
所以下面一半用例是负样本。
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from adapters.products.capabilities import PRODUCT_VERSIONS  # noqa: E402
from services.dataflow_service import DataFlowService, _is_external  # noqa: E402
from storage.repositories import Storage  # noqa: E402

BASE = datetime(2026, 11, 12, 12, 0, 0, tzinfo=timezone.utc)


def at(seconds: float) -> str:
    return (BASE + timedelta(seconds=seconds)).isoformat()


def build(storage: Storage, *, execution_id: str, intents: list[tuple[str, list[str]]],
          nets: list[tuple[str, int]]) -> None:
    with storage.connection() as conn:
        conn.execute(
            "INSERT INTO device_identities (device_id,label,credential_hash,status,enrolled_at,host_id)"
            " VALUES (?,?,?,?,?,?)",
            ("dev_df", "df", "0" * 64, "active", at(0), "host-a"))
        conn.execute(
            "INSERT INTO executions (execution_id,host_id,device_id,product,product_version,"
            "session_id,started_at,outcome,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (execution_id, "host-a", "dev_df", "qwen-code", PRODUCT_VERSIONS["qwen-code"], "s-" + execution_id,
             at(0), "completed", at(0), at(0)))
        for index, (tool, hints) in enumerate(intents):
            conn.execute(
                "INSERT INTO intents (intent_id,execution_id,tool_call_id,tool_name,hook_event_type,"
                "decision,params_summary,params_sha256,redaction_applied,occurred_at,created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (f"{execution_id}-i{index}", execution_id, f"call{index}", tool, "pre_tool_use",
                 "allow", json.dumps({"parameter_names": ["command"], "values_omitted": True,
                                      "resource_hints": hints}), "0" * 64, 1,
                 at(index * 2), at(index * 2)))
        for index, (host, port) in enumerate(nets):
            conn.execute(
                "INSERT INTO runtime_events (event_id,host_id,collector_id,device_id,execution_id,"
                "event_type,occurred_at,received_at,pid,ppid,executable,resource_host,resource_port,"
                "action,result,sequence,evidence_refs) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (f"{execution_id}-n{index}", "host-a", "audit-v1", "dev_df", execution_id,
                 "network_connect", at(10 + index), at(10 + index), 9000, 1, "/usr/bin/curl",
                 host, port, "connect", "success", index, "[]"))
        conn.commit()


@pytest.fixture()
def service(tmp_path):
    storage = Storage(tmp_path / "df.db")
    return DataFlowService(storage), storage


def test_sensitive_read_with_external_connect_is_a_flow(service):
    svc, storage = service
    build(storage, execution_id="exec_x", intents=[("read_file", ["~/.ssh/id_rsa"])],
          nets=[("45.33.32.156", 4444)])
    flows = svc.trace("exec_x")["flows"]
    assert len(flows) == 1
    assert flows[0]["source"]["path"] == "~/.ssh/id_rsa"
    assert flows[0]["sink"]["host"] == "45.33.32.156"
    assert flows[0]["confidence"] == "low", "无中转时应为低置信度"


def test_staging_write_raises_confidence(service):
    """读了敏感文件又写出新文件，可疑度高于直连，但不能到 high（路径级证明不了内容）。"""
    svc, storage = service
    build(storage, execution_id="exec_stage",
          intents=[("read_file", ["~/.ssh/id_rsa"]), ("write_file", ["/tmp/out.b64"])],
          nets=[("45.33.32.156", 4444)])
    flow = svc.trace("exec_stage")["flows"][0]
    assert flow["confidence"] == "medium"
    assert [hop["role"] for hop in flow["hops"]] == ["staging"]


def test_sensitive_read_without_egress_is_not_a_flow(service):
    svc, storage = service
    build(storage, execution_id="exec_local", intents=[("read_file", ["~/.ssh/id_rsa"])], nets=[])
    assert svc.trace("exec_local")["flows"] == []


def test_ssh_key_then_github_push_is_not_flagged(service):
    """关键负样本：读私钥 + git push 到 github 是日常操作，不能报。"""
    svc, storage = service
    build(storage, execution_id="exec_push",
          intents=[("read_file", ["~/.ssh/id_ed25519"]), ("run_shell_command", [])],
          nets=[("github.com", 22)])
    assert svc.trace("exec_push")["flows"] == []


def test_internal_target_is_not_egress(service):
    svc, storage = service
    build(storage, execution_id="exec_intra", intents=[("read_file", ["~/.kube/config"])],
          nets=[("10.0.0.5", 6443)])
    assert svc.trace("exec_intra")["flows"] == []


@pytest.mark.parametrize("host,external", [
    ("8.8.8.8", True),
    ("github.com", False),
    ("api.internal", False),
    ("127.0.0.1", False),
    ("localhost", False),
    ("10.1.2.3", False),
    ("192.168.1.1", False),
    ("203.0.113.9", False),   # 文档保留段：不可路由，不该当外发终点
    ("evil.example.net", True),
])
def test_external_judgement(host, external):
    assert _is_external(host) is external


def test_unknown_execution_is_404(service):
    from services.ingestion_service import IngestError
    svc, _ = service
    with pytest.raises(IngestError) as exc:
        svc.trace("exec_missing")
    assert exc.value.status == 404
