#!/usr/bin/env python3
"""P1 扩展规模归因评测集（>= 50 事件）：多跳 2-3 跳进程树、并发多调用、PID 复用与良性背景噪声。"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from adapters.products.capabilities import PRODUCT_VERSIONS  # noqa: E402
from services.attribution_service import AttributionService  # noqa: E402
from storage.repositories import Storage  # noqa: E402

BASE = datetime(2026, 11, 14, 2, 0, 0, tzinfo=timezone.utc)


def _at(sec: float) -> str:
    return (BASE + timedelta(seconds=sec)).isoformat()


def _intent(intent_id: str, *, ex_id: str = "exec_scale", call_id: str,
            start: float, end: float | None, decision: str = "allow",
            hints: list[str] | None = None) -> dict:
    return {
        "intent_id": intent_id,
        "execution_id": ex_id,
        "tool_call_id": call_id,
        "tool_name": "bash",
        "hook_event_type": "pre_tool_use",
        "decision": decision,
        "decision_reason": "eval",
        "params_summary": json.dumps({"parameter_names": ["command"], "values_omitted": True,
                                      **({"resource_hints": hints} if hints else {})}, ensure_ascii=False),
        "params_sha256": "0" * 64,
        "redaction_applied": 1,
        "occurred_at": _at(start),
        "ended_at": _at(end) if end is not None else None,
        "product_result": None,
        "created_at": _at(start),
    }


def _ev(event_id: str, *, ex_id: str | None = "exec_scale", kind: str, when: float,
        pid: int | None = None, ppid: int | None = None,
        intent_ref: str | None = None, path: str | None = None,
        host: str | None = None, port: int | None = None) -> dict:
    return {
        "event_id": event_id,
        "host_id": "host_scale",
        "collector_id": "audit-scale",
        "device_id": "dev_scale",
        "execution_id": ex_id,
        "intent_ref": intent_ref,
        "event_type": kind,
        "occurred_at": _at(when),
        "received_at": _at(when),
        "pid": pid,
        "ppid": ppid,
        "executable": "/usr/bin/bash",
        "resource_host": host,
        "resource_port": port,
        "resource_path": path,
        "action": kind,
        "result": "success",
        "sequence": None,
        "evidence_refs": "[]",
    }


def build_dataset() -> tuple[list[dict], list[dict], dict[str, set[str] | None], dict[str, str]]:
    intents: list[dict] = []
    events: list[dict] = []
    truth: dict[str, set[str] | None] = {}
    categories: dict[str, str] = {}

    # 1. 4 组 2-3 跳多级派生进程链 (4 * 4 = 16 个事件)
    for grp in range(1, 5):
        t0 = grp * 50.0
        iid = f"i_mhop_{grp}"
        p_anchor = 10000 + grp * 100
        p_h1 = p_anchor + 1
        p_h2 = p_anchor + 2
        p_h3 = p_anchor + 3
        intents.append(_intent(iid, call_id=f"c_mhop_{grp}", start=t0, end=t0 + 10.0))
        events.append(_ev(f"a_mhop_{grp}", kind="hook_anchor", when=t0, pid=p_anchor, intent_ref=iid))
        events.extend([
            _ev(f"ev_mhop_{grp}_1", ex_id=None, kind="process_start", when=t0 + 1.0, pid=p_h1, ppid=p_anchor),
            _ev(f"ev_mhop_{grp}_2", ex_id=None, kind="process_start", when=t0 + 2.0, pid=p_h2, ppid=p_h1),
            _ev(f"ev_mhop_{grp}_3", ex_id=None, kind="file_access", when=t0 + 3.0, pid=p_h3, ppid=p_h2, path="/home/u/.ssh/id_rsa"),
            _ev(f"ev_mhop_{grp}_4", ex_id=None, kind="network_connect", when=t0 + 4.0, pid=p_h3, ppid=p_h2, host="198.51.100.10", port=443),
        ])
        for idx in range(1, 5):
            eid = f"ev_mhop_{grp}_{idx}"
            truth[eid] = {iid}
            categories[eid] = "multi_hop_tree"

    # 2. 3 组双 Agent/双工具并发隔离场景（独立 pid 锚点同窗重叠，3 * 4 = 12 个事件）
    for grp in range(1, 4):
        t0 = 300.0 + grp * 50.0
        ia, ib = f"i_conc_a_{grp}", f"i_conc_b_{grp}"
        pa, pb = 20000 + grp * 100, 20000 + grp * 100 + 50
        intents.append(_intent(ia, call_id=f"c_conc_a_{grp}", start=t0, end=t0 + 10.0))
        intents.append(_intent(ib, call_id=f"c_conc_b_{grp}", start=t0 + 0.5, end=t0 + 10.5))
        events.append(_ev(f"a_conc_a_{grp}", kind="hook_anchor", when=t0, pid=pa, intent_ref=ia))
        events.append(_ev(f"a_conc_b_{grp}", kind="hook_anchor", when=t0 + 0.5, pid=pb, intent_ref=ib))
        events.extend([
            _ev(f"ev_conc_{grp}_a1", ex_id=None, kind="process_start", when=t0 + 2.0, pid=pa + 1, ppid=pa),
            _ev(f"ev_conc_{grp}_a2", ex_id=None, kind="file_access", when=t0 + 3.0, pid=pa + 1, ppid=pa, path="/tmp/build.log"),
            _ev(f"ev_conc_{grp}_b1", ex_id=None, kind="process_start", when=t0 + 2.2, pid=pb + 1, ppid=pb),
            _ev(f"ev_conc_{grp}_b2", ex_id=None, kind="network_connect", when=t0 + 3.5, pid=pb + 2, ppid=pb + 1, host="api.github.com", port=443),
        ])
        truth[f"ev_conc_{grp}_a1"] = {ia}
        truth[f"ev_conc_{grp}_a2"] = {ia}
        truth[f"ev_conc_{grp}_b1"] = {ib}
        truth[f"ev_conc_{grp}_b2"] = {ib}
        for suf in ("a1", "a2", "b1", "b2"):
            categories[f"ev_conc_{grp}_{suf}"] = "concurrent_isolated"

    # 3. 2 组同锚点冲突场景 (2 * 2 = 4 个事件，truth 为冲突集合，机制必须保留冲突不 selected)
    for grp in range(1, 3):
        t0 = 500.0 + grp * 40.0
        ia, ib = f"i_amb_a_{grp}", f"i_amb_b_{grp}"
        p_anc = 30000 + grp * 10
        intents.append(_intent(ia, call_id=f"c_amb_a_{grp}", start=t0, end=t0 + 8.0))
        intents.append(_intent(ib, call_id=f"c_amb_b_{grp}", start=t0 + 1.0, end=t0 + 9.0))
        events.append(_ev(f"a_amb_a_{grp}", kind="hook_anchor", when=t0, pid=p_anc, intent_ref=ia))
        events.append(_ev(f"a_amb_b_{grp}", kind="hook_anchor", when=t0 + 1.0, pid=p_anc, intent_ref=ib))
        events.extend([
            _ev(f"ev_amb_{grp}_1", ex_id=None, kind="process_start", when=t0 + 3.0, pid=p_anc + 1, ppid=p_anc),
            _ev(f"ev_amb_{grp}_2", ex_id=None, kind="file_access", when=t0 + 4.0, pid=p_anc + 2, ppid=p_anc + 1, path="/tmp/shared.txt"),
        ])
        for idx in (1, 2):
            eid = f"ev_amb_{grp}_{idx}"
            truth[eid] = {ia, ib}
            categories[eid] = "conflict_preserved"

    # 4. 4 组拒绝调用阻断后的背景负样本（deny 且无 ended_at + 外部背景噪声 = 8 个事件不应误归）
    for grp in range(1, 5):
        t0 = 700.0 + grp * 40.0
        iid = f"i_deny_{grp}"
        p_anc = 40000 + grp * 10
        intents.append(_intent(iid, call_id=f"c_deny_{grp}", start=t0, end=None, decision="deny", hints=["~/proj/foo.py"]))
        events.append(_ev(f"a_deny_{grp}", kind="hook_anchor", when=t0, pid=p_anc, intent_ref=iid))
        events.extend([
            _ev(f"ev_deny_{grp}_1", ex_id=None, kind="network_connect", when=t0 + 2.0, pid=p_anc + 1, ppid=p_anc, host="10.0.0.5", port=443),
            _ev(f"ev_deny_{grp}_2", ex_id=None, kind="file_access", when=t0 + 0.5, pid=49999, ppid=1, path="~/proj/foo.py"),
        ])
        truth[f"ev_deny_{grp}_1"] = None
        truth[f"ev_deny_{grp}_2"] = None
        categories[f"ev_deny_{grp}_1"] = "denied_no_sweep_neg"
        categories[f"ev_deny_{grp}_2"] = "denied_no_sweep_neg"

    # 5. 背景无关进程 / PID 复用 / 窗外滞后 / 未知宿主机连接共 14 个负样本
    t_bg = 950.0
    intents.append(_intent("i_bg", call_id="c_bg", start=t_bg, end=t_bg + 5.0))
    events.append(_ev("a_bg", kind="hook_anchor", when=t_bg, pid=50000, intent_ref="i_bg"))
    for k in range(1, 7):
        eid = f"ev_bg_orphan_{k}"
        events.append(_ev(eid, ex_id=None, kind="file_access", when=t_bg + 1.0 + k * 0.2, pid=51000 + k, ppid=1, path=f"/var/cache/pkg_{k}"))
        truth[eid] = None
        categories[eid] = "orphan_noise"
    for k in range(1, 5):
        eid = f"ev_bg_late_{k}"
        events.append(_ev(eid, ex_id=None, kind="file_access", when=t_bg + 40.0 + k, pid=52000 + k, ppid=50000, path="/tmp/late.txt"))
        truth[eid] = None
        categories[eid] = "out_of_window_neg"
    for k in range(1, 5):
        eid = f"ev_bg_reuse_{k}"
        events.append(_ev(eid, ex_id=None, kind="process_start", when=t_bg - 50.0 + k, pid=50000, ppid=1))
        truth[eid] = None
        categories[eid] = "pid_reuse_neg"

    # 总计 16 + 12 + 4 + 8 + 14 = 54 个待归因事件！
    return intents, events, truth, categories


def main(json_out: Path | None = None) -> int:
    intents, events, truth, categories = build_dataset()
    with TemporaryDirectory() as td:
        db = Path(td) / "scale.db"
        storage = Storage(db)
        with storage.connection() as conn:
            conn.execute(
                "INSERT INTO device_identities (device_id,label,credential_hash,status,enrolled_at,host_id) VALUES (?,?,?,?,?,?)",
                ("dev_scale", "scale-eval", "0" * 64, "active", _at(0), "host_scale"),
            )
            conn.execute(
                "INSERT INTO executions (execution_id,host_id,device_id,product,product_version,session_id,started_at,outcome,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                ("exec_scale", "host_scale", "dev_scale", "qwen-code", PRODUCT_VERSIONS["qwen-code"], "s-scale", _at(0), "completed", _at(0), _at(0)),
            )
            for item in intents:
                conn.execute(f"INSERT INTO intents ({','.join(item)}) VALUES ({','.join('?'*len(item))})", list(item.values()))
            for item in events:
                conn.execute(f"INSERT INTO runtime_events ({','.join(item)}) VALUES ({','.join('?'*len(item))})", list(item.values()))
            conn.commit()

        AttributionService(storage).correlate("exec_scale")
        with storage.connection() as conn:
            anchors = {r[0] for r in conn.execute("SELECT event_id FROM runtime_events WHERE event_type='hook_anchor'")}
            edges = [dict(r) for r in conn.execute("SELECT intent_id,event_id,method,score,selected FROM event_attributions").fetchall()]
    edges = [e for e in edges if e["event_id"] not in anchors]

    selected = [e for e in edges if e["selected"]]
    correct_sel = [e for e in selected if truth.get(e["event_id"]) and e["intent_id"] in truth[e["event_id"]]]
    unambiguous_truth = {eid for eid, exp in truth.items() if exp and len(exp) == 1}
    negative_truth = {eid for eid, exp in truth.items() if exp is None}
    neg_fp = [e for e in selected if e["event_id"] in negative_truth]
    conflict_truth = {eid for eid, exp in truth.items() if exp and len(exp) > 1}
    conflict_kept = sum(
        1 for eid in conflict_truth
        if {e["intent_id"] for e in edges if e["event_id"] == eid} == truth[eid]
        and not any(e["selected"] for e in edges if e["event_id"] == eid)
    )

    report = {
        "benchmark": "attribution-scale-v1",
        "events_evaluated": len(truth),
        "positive_unambiguous": len(unambiguous_truth),
        "conflict_events": len(conflict_truth),
        "negative_events": len(negative_truth),
        "selected_edges": len(selected),
        "correct_selected_edges": len(correct_sel),
        "precision": round(len(correct_sel) / len(selected), 4) if selected else None,
        "recall_unambiguous": round(len({e["event_id"] for e in correct_sel if e["event_id"] in unambiguous_truth}) / len(unambiguous_truth), 4),
        "negative_fpr": round(len({e["event_id"] for e in neg_fp}) / len(negative_truth), 4),
        "conflict_preserved_rate": round(conflict_kept / len(conflict_truth), 4),
        "by_category": {
            cat: {
                "events": sum(1 for eid, c in categories.items() if c == cat),
                "selected": sum(1 for e in selected if categories.get(e["event_id"]) == cat),
                "correct_selected": sum(1 for e in correct_sel if categories.get(e["event_id"]) == cat),
            }
            for cat in sorted(set(categories.values()))
        },
    }
    out = json_out if json_out is not None else (ROOT / "docs" / "acceptance" / "attribution-scale-eval.json")
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["precision"] == 1.0 and report["recall_unambiguous"] == 1.0 and report["negative_fpr"] == 0.0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
