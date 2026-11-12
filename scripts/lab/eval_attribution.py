#!/usr/bin/env python3
"""行为归因的标注集与 Precision/Recall 实验。

为什么用受控标注集而不是直接统计生产库：
生产库里的 runtime_events 只有 0.09% 带 ``intent_ref``，绝大多数事件
（network_connect、process_start）到底"该不该"归给某个 Intent，没有真值。
在没有真值的数据上算 P/R 是自欺——只能数出"归因了多少"，算不出"归对没有"。

所以这里构造标注集：每个场景都有确定真值（该归给谁 / 不该归给谁），
覆盖归因器的三种方法与它们的失效边界。指标口径：

- Precision = 判为归因（selected）且真值正确的边 / 全部 selected 边
- Recall    = 判为归因且正确的边 / 全部"应归因"的事件
- 另给一档 any（含 weak 候选）：说明弱关联带来的召回增益与精度代价

合成集的结论不能直接外推到生产，必须与"真实流量人工抽查"配合看。
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from adapters.products.capabilities import PRODUCT_VERSIONS  # noqa: E402
from services.attribution_service import AttributionService  # noqa: E402
from storage.repositories import Storage  # noqa: E402

BASE = datetime(2026, 11, 12, 10, 0, 0, tzinfo=timezone.utc)


def iso(moment: datetime) -> str:
    return moment.isoformat()


def at(seconds: float) -> str:
    return iso(BASE + timedelta(seconds=seconds))


def intent(intent_id: str, *, call_id: str, start: float, end: float | None,
           resource_hint: str | None = None) -> dict:
    return {
        "intent_id": intent_id,
        "execution_id": "exec_attr_eval",
        "tool_call_id": call_id,
        "tool_name": "run_shell_command",
        "hook_event_type": "pre_tool_use",
        "decision": "allow",
        "decision_reason": "ASGP endpoint rule",
        "params_summary": json.dumps(
            {"parameter_names": ["command"], "values_omitted": True,
             **({"resource_hint": resource_hint} if resource_hint else {})},
            ensure_ascii=False),
        "params_sha256": "0" * 64,
        "redaction_applied": 1,
        "occurred_at": at(start),
        "ended_at": at(end) if end is not None else None,
        "product_result": None,
        "created_at": at(start),
    }


def event(event_id: str, *, kind: str, when: float, pid: int | None = None,
          ppid: int | None = None, intent_ref: str | None = None,
          resource_path: str | None = None, action: str = "observed") -> dict:
    return {
        "event_id": event_id,
        "host_id": "test-agentsec-01",
        "collector_id": "audit-v1",
        "device_id": "dev_attr_eval",
        "execution_id": "exec_attr_eval",
        "intent_ref": intent_ref,
        "event_type": kind,
        "occurred_at": at(when),
        "received_at": at(when),
        "pid": pid,
        "ppid": ppid,
        "executable": "/usr/bin/bash",
        "resource_host": None,
        "resource_port": None,
        "resource_path": resource_path,
        "action": action,
        "result": "success",
        "sequence": None,
        "evidence_refs": "[]",
    }


def anchor(event_id: str, *, pid: int, intent_ref: str, when: float) -> dict:
    return event(event_id, kind="hook_anchor", when=when, pid=pid, intent_ref=intent_ref)


# --- 场景定义 -----------------------------------------------------------
# 每组：intents + events + 真值（event_id -> 期望的 intent_id，None 表示不该归因）
SCENARIOS: list[dict] = [
    {
        "name": "exact_hook_id",
        "why": "事件直接带 intent_ref，应精确命中",
        "intents": [intent("i_exact", call_id="call_exact", start=0, end=3)],
        "events": [
            anchor("e_exact_a1", pid=1001, intent_ref="i_exact", when=0),
            event("e_exact_1", kind="file_access", when=1, pid=1001, intent_ref="i_exact",
                  resource_path="/home/u/.ssh/id_rsa"),
            event("e_exact_2", kind="file_access", when=2, pid=1001, intent_ref="i_exact",
                  resource_path="/tmp/out.txt"),
        ],
        "truth": {"e_exact_1": "i_exact", "e_exact_2": "i_exact"},
    },
    {
        "name": "process_tree_in_window",
        "why": "子进程无 intent_ref，但父链指向 anchor 且在调用窗口内",
        "intents": [intent("i_tree", call_id="call_tree", start=10, end=16)],
        "events": [
            anchor("e_tree_a1", pid=2001, intent_ref="i_tree", when=10),
            event("e_tree_1", kind="process_start", when=11, pid=2002, ppid=2001),
            event("e_tree_2", kind="network_connect", when=12, pid=2002, ppid=2001,
                  resource_path="203.0.113.9:4444"),
            event("e_tree_3", kind="file_access", when=15, pid=2003, ppid=2002,
                  resource_path="/etc/passwd"),
        ],
        "truth": {"e_tree_1": "i_tree", "e_tree_2": "i_tree", "e_tree_3": "i_tree"},
    },
    {
        "name": "process_tree_out_of_window",
        "why": "同一条进程链，但事件发生在调用结束之后——不能倒推因果",
        "intents": [intent("i_late", call_id="call_late", start=20, end=22)],
        "events": [
            anchor("e_late_a1", pid=3001, intent_ref="i_late", when=20),
            event("e_late_1", kind="network_connect", when=90, pid=3002, ppid=3001,
                  resource_path="198.51.100.7:443"),
        ],
        "truth": {"e_late_1": None},
    },
    {
        "name": "orphan_process",
        "why": "无 anchor 的陌生进程，任何归因都是猜",
        "intents": [intent("i_orphan", call_id="call_orphan", start=30, end=33)],
        "events": [
            anchor("e_orphan_a1", pid=4001, intent_ref="i_orphan", when=30),
            event("e_orphan_1", kind="network_connect", when=31, pid=4099, ppid=1,
                  resource_path="192.0.2.55:8080"),
        ],
        "truth": {"e_orphan_1": None},
    },
    {
        "name": "pid_reuse_before_anchor",
        "why": "事件时间早于 anchor，即使 PID 相同也不是这次调用",
        "intents": [intent("i_reuse", call_id="call_reuse", start=40, end=43)],
        "events": [
            anchor("e_reuse_a1", pid=5001, intent_ref="i_reuse", when=40),
            event("e_reuse_1", kind="file_access", when=5, pid=5001,
                  resource_path="/var/log/old.log"),
        ],
        "truth": {"e_reuse_1": None},
    },
    {
        "name": "weak_resource_hint",
        "why": "无进程关联，但资源与调用参数一致且在 2s 内——弱候选",
        "intents": [intent("i_weak", call_id="call_weak", start=50, end=53,
                           resource_hint="/tmp/weak.txt")],
        "events": [
            anchor("e_weak_a1", pid=6001, intent_ref="i_weak", when=50),
            event("e_weak_1", kind="file_access", when=51, pid=6999, ppid=1,
                  resource_path="/tmp/weak.txt"),
        ],
        "truth": {"e_weak_1": "i_weak"},
    },
    {
        "name": "weak_resource_out_of_time",
        "why": "资源相同但超出时间窗，弱关联也不能连",
        "intents": [intent("i_weak2", call_id="call_weak2", start=60, end=63,
                           resource_hint="/tmp/weak2.txt")],
        "events": [
            anchor("e_weak2_a1", pid=7001, intent_ref="i_weak2", when=60),
            event("e_weak2_1", kind="file_access", when=80, pid=7999, ppid=1,
                  resource_path="/tmp/weak2.txt"),
        ],
        "truth": {"e_weak2_1": None},
    },
    {
        "name": "conflict_two_intents_same_anchor",
        "why": "两个调用窗重叠且共用 anchor，应保留冲突而不是二选一",
        "intents": [
            intent("i_conf_a", call_id="call_conf_a", start=70, end=76),
            intent("i_conf_b", call_id="call_conf_b", start=72, end=78),
        ],
        "events": [
            anchor("e_conf_aa", pid=8001, intent_ref="i_conf_a", when=70),
            anchor("e_conf_ab", pid=8001, intent_ref="i_conf_b", when=72),
            event("e_conf_1", kind="process_start", when=74, pid=8002, ppid=8001),
        ],
        "truth": {"e_conf_1": {"i_conf_a", "i_conf_b"}},
    },
]


def seed(db_path: Path) -> None:
    """按场景写入临时库；每轮新建，避免上一轮残留影响。"""
    if db_path.exists():
        db_path.unlink()
    storage = Storage(db_path)
    with storage.connection() as conn:
        # executions.device_id 有指向 device_identities 的外键，先建设备再建执行。
        conn.execute(
            "INSERT INTO device_identities (device_id,label,credential_hash,status,enrolled_at,host_id)"
            " VALUES (?,?,?,?,?,?)",
            ("dev_attr_eval", "attr-eval", "0" * 64, "active", at(0), "test-agentsec-01"))
        conn.execute(
            "INSERT INTO executions (execution_id,host_id,device_id,product,product_version,"
            "session_id,started_at,outcome,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            ("exec_attr_eval", "test-agentsec-01", "dev_attr_eval", "qwen-code", PRODUCT_VERSIONS["qwen-code"],
             "s-attr-eval", at(0), "completed", at(0), at(0)))
        for scene in SCENARIOS:
            for item in scene["intents"]:
                cols = ",".join(item)
                marks = ",".join("?" * len(item))
                conn.execute(f"INSERT INTO intents ({cols}) VALUES ({marks})", list(item.values()))
            for item in scene["events"]:
                cols = ",".join(item)
                marks = ",".join("?" * len(item))
                conn.execute(f"INSERT INTO runtime_events ({cols}) VALUES ({marks})", list(item.values()))
        conn.commit()


def evaluate(db_path: Path) -> dict:
    storage = Storage(db_path)
    AttributionService(storage).correlate("exec_attr_eval")
    with storage.connection() as conn:
        # hook_anchor 是"哪条调用对应哪个 pid"的绑定元数据，不是被归因对象。
        # 把它算进评估会让 hook_id 方法凭空多出一堆"错误边"，指标失真。
        anchors = {row[0] for row in conn.execute(
            "SELECT event_id FROM runtime_events WHERE event_type='hook_anchor'")}
        edges = [dict(row) for row in conn.execute(
            "SELECT intent_id,event_id,method,score,selected FROM event_attributions"
            " WHERE host_id='test-agentsec-01'").fetchall()]
    edges = [e for e in edges if e["event_id"] not in anchors]

    truth: dict[str, set[str] | None] = {}
    for scene in SCENARIOS:
        for event_id, expected in scene["truth"].items():
            truth[event_id] = ({expected} if isinstance(expected, str) else expected)

    def correct(edge: dict) -> bool:
        expected = truth.get(edge["event_id"])
        return bool(expected) and edge["intent_id"] in expected

    selected = [e for e in edges if e["selected"]]
    any_edge = edges
    should = [eid for eid, exp in truth.items() if exp]

    def ratios(rows):
        hit = [e for e in rows if correct(e)]
        # 同一事件可能有多条边（冲突），按事件去重统计召回。
        hit_events = {e["event_id"] for e in hit}
        return {
            "edges": len(rows),
            "correct_edges": len(hit),
            "precision": round(len(hit) / len(rows), 4) if rows else None,
            "recall": round(len(hit_events) / len(should), 4) if should else None,
            "covered_events": len(hit_events),
            "should_attribute": len(should),
        }

    by_method: dict[str, dict] = {}
    for method in sorted({e["method"] for e in edges}):
        subset = [e for e in edges if e["method"] == method]
        hit = [e for e in subset if correct(e)]
        by_method[method] = {
            "edges": len(subset),
            "correct": len(hit),
            "precision": round(len(hit) / len(subset), 4) if subset else None,
        }

    missed = [eid for eid in should
              if not any(e["event_id"] == eid and e["selected"] for e in edges)]
    false_alarms = [{"event_id": e["event_id"], "intent_id": e["intent_id"],
                     "method": e["method"], "score": e["score"]}
                    for e in any_edge if not correct(e)]
    return {
        "scenarios": len(SCENARIOS),
        "events_total": len(truth),
        "should_attribute": len(should),
        "selected": ratios(selected),
        "any_edge": ratios(any_edge),
        "by_method": by_method,
        "missed_events": missed,
        "incorrect_edges": false_alarms,
        "unattributed_events": sorted(eid for eid in truth if not any(
            e["event_id"] == eid for e in edges)),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="/tmp/attribution-eval.db")
    parser.add_argument("--json-out", default="")
    args = parser.parse_args()
    db = Path(args.db)
    seed(db)
    result = evaluate(db)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(result, ensure_ascii=False, indent=2),
                                       encoding="utf-8")
        print(f"written {args.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
