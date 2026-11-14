"""数据外发链重建：在单次执行内找「读敏感文件 → 中转 → 外连」这条路径。

**这是路径级启发式，不是内容追踪。** 它证明的是"同一会话里先读了敏感文件、
后有到外部地址的连接"，不证明"这些字节被发出去了"。要做内容级需要端侧拦读写
内容，量级完全不同，这里明确不做——宁可把边界写清楚，也不给一个看起来更强的
错误结论。

为什么值得做：现有归因只回答"这个事件属于哪次调用"，回答不了"这次会话有没有
把东西送出去"。后者才是 Agent 安全真正要回答的问题。
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath

from services.evidence_rules import (
    SENSITIVE_MARKERS,
    TRUSTED_HOSTS,
    TRUSTED_SUFFIXES,
    is_external_host,
    is_sensitive_path,
    normalize_hint_path,
)
from services.ingestion_service import IngestError

VERSION = "dataflow-v1"

# 这些工具是"往外发东西"的典型形态，用来给链路提高置信度。
EXFIL_COMMANDS = ("curl", "wget", "nc", "ncat", "scp", "sftp", "rsync", "httpie", "http ", "socat")

# 写类工具：路径级追踪无法知道内容流向哪个新文件，但"读了敏感文件之后又写出
# 新文件、随后外连"这一形态明显比"只读+外连"更可疑，用它来区分中/低置信度。
WRITE_TOOLS = ("write", "edit", "create", "save", "append", "modify", "compress", "zip", "tar")


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


_is_sensitive = is_sensitive_path
_is_external = is_external_host


def _basename(path: str) -> str:
    return PurePosixPath(str(path)).name


def _evidence(kind: str, uri: str) -> dict:
    return {"kind": kind, "uri": uri}


class DataFlowService:
    """按会话重建数据外发候选链；同一会话可产出多条。"""

    def __init__(self, storage) -> None:
        self.storage = storage

    def trace(self, execution_id: str) -> dict:
        with self.storage.connection() as conn:
            execution = conn.execute(
                "SELECT * FROM executions WHERE execution_id=?", (execution_id,)).fetchone()
            if not execution:
                raise IngestError("unknown_execution", 404)
            intents = [dict(row) for row in conn.execute(
                "SELECT intent_id,execution_id,tool_name,decision,occurred_at,ended_at,params_summary"
                " FROM intents WHERE execution_id=? ORDER BY occurred_at", (execution_id,))]
            intent_ids = [i["intent_id"] for i in intents]
            attributed_files: dict[str, list[dict]] = {}
            attributed_nets: list[dict] = []
            if intent_ids:
                marks = ",".join("?" * len(intent_ids))
                for row in conn.execute(
                    "SELECT a.intent_id,e.event_id,e.event_type,e.occurred_at,"
                    "e.resource_host,e.resource_port,e.resource_path,e.pid"
                    " FROM event_attributions a JOIN runtime_events e"
                    " ON e.host_id=a.host_id AND e.collector_id=a.collector_id AND e.event_id=a.event_id"
                    f" WHERE a.selected=1 AND a.intent_id IN ({marks})"
                    " AND e.event_type IN ('network_connect','file_access')"
                    " ORDER BY e.occurred_at",
                    intent_ids,
                ):
                    item = dict(row)
                    if item["event_type"] == "file_access":
                        attributed_files.setdefault(item["intent_id"], []).append(item)
                    else:
                        attributed_nets.append(item)

            events = [dict(row) for row in conn.execute(
                "SELECT event_id,event_type,occurred_at,resource_host,resource_port,resource_path,pid"
                " FROM runtime_events WHERE execution_id=? AND event_type IN"
                " ('network_connect','file_access') ORDER BY occurred_at", (execution_id,))]
            # 真实采集里审计事件几乎都不带 execution_id；优先采用已 selected=1 归因的外连事件，
            # 无归因外连时再退回"同主机 + 时间窗"，并如实标注 sink_basis。
            sink_basis = "execution_id"
            if not events:
                if any(_is_external(ev.get("resource_host")) for ev in attributed_nets):
                    events = attributed_nets
                    sink_basis = "attribution"
                else:
                    started = str(execution["started_at"])
                    # 事件带毫秒、intent 时间不带，统一按时间戳计算并留 90 秒缓冲。
                    last = max((datetime.fromisoformat(str(i["occurred_at"])) for i in intents),
                               default=datetime.fromisoformat(started))
                    if execution["ended_at"]:
                        end_dt = datetime.fromisoformat(str(execution["ended_at"]))
                    else:
                        end_dt = last + timedelta(seconds=90)
                    ended = end_dt.isoformat()
                    events = [dict(row) for row in conn.execute(
                        "SELECT event_id,event_type,occurred_at,resource_host,resource_port,resource_path,pid"
                        " FROM runtime_events WHERE host_id=? AND device_id=? AND occurred_at>=?"
                        " AND occurred_at<=? AND event_type IN ('network_connect','file_access')"
                        " ORDER BY occurred_at",
                        (execution["host_id"], execution["device_id"], started, ended))]
                    sink_basis = "time_window"
            anchors = [dict(row) for row in conn.execute(
                "SELECT intent_id,occurred_at FROM intents WHERE execution_id=?", (execution_id,))]
        _ = anchors  # 保留查询以便后续做时间对齐扩展

        flows: list[dict] = []
        for index, intent in enumerate(intents):
            if intent.get("decision") == "deny" and not intent.get("ended_at"):
                continue
            sources: dict[str, tuple[str, str, str | None]] = {}
            for hint in self._hints(intent):
                if _is_sensitive(hint):
                    key = normalize_hint_path(hint) or hint
                    sources.setdefault(key, (hint, str(intent["occurred_at"]), None))
            for ev in attributed_files.get(intent["intent_id"], []):
                path = ev.get("resource_path")
                if _is_sensitive(path):
                    key = normalize_hint_path(path) or str(path)
                    sources.setdefault(key, (str(path), str(ev["occurred_at"]), ev["event_id"]))
            for source_path, source_time, source_event_id in sources.values():
                flow = self._build(
                    intent, source_path, intents[index + 1:], events, sink_basis,
                    source_time=source_time, source_event_id=source_event_id,
                )
                if flow:
                    flows.append(flow)
        return {"execution_id": execution_id, "version": VERSION,
                "sink_basis": sink_basis, "flows": flows, "note": self._note()}

    # --- 内部 ----------------------------------------------------------

    @staticmethod
    def _hints(intent: dict) -> list[str]:
        try:
            summary = json.loads(intent.get("params_summary") or "{}")
        except (ValueError, TypeError):
            return []
        if not isinstance(summary, dict):
            return []
        hints = summary.get("resource_hints")
        if not hints and summary.get("resource_hint"):
            hints = [summary["resource_hint"]]
        return [str(hint) for hint in (hints or [])]

    def _build(self, source_intent: dict, source_path: str,
               later_intents: list[dict], events: list[dict], sink_basis: str,
               *, source_time: str | None = None, source_event_id: str | None = None) -> dict | None:
        """从一次敏感读取出发，找中转跳与外部 sink。没有 sink 就不产链。"""
        source_time = source_time or str(source_intent["occurred_at"])
        name = _basename(source_path)

        hops = []
        for intent in later_intents:
            if str(intent["occurred_at"]) < source_time:
                continue
            hints = self._hints(intent)
            tool = str(intent.get("tool_name") or "")
            # 强中转：后续调用碰了同一个文件（同路径或同文件名）。
            same_file = bool(name) and any(
                hint == source_path or _basename(hint) == name for hint in hints)
            # 弱中转（staging）：读了敏感文件之后又写出新文件，内容可能被搬走。
            staging = (not same_file) and any(token in tool.lower() for token in WRITE_TOOLS) and bool(hints)
            if same_file or staging:
                hops.append({
                    "intent_id": intent["intent_id"],
                    "tool_name": intent["tool_name"],
                    "role": "same_file" if same_file else "staging",
                    "occurred_at": intent["occurred_at"],
                    "paths": hints[:4],
                    "evidence_refs": [_evidence("intent", intent["intent_id"])],
                })

        sinks = []
        for event in events:
            if event["event_type"] != "network_connect":
                continue
            if str(event["occurred_at"]) < source_time:
                continue
            if not _is_external(event.get("resource_host")):
                continue
            sinks.append(event)

        if not sinks:
            # 读了私钥但没有外部连接：不是外发链。宁可漏报也不误报。
            return None

        # 置信度：有中转跳、或读取动作本身是外发类命令，才升到 medium。
        tool = str(source_intent.get("tool_name") or "")
        command_like = any(token in tool for token in EXFIL_COMMANDS)
        confidence = "medium" if (hops or command_like) else "low"
        if sink_basis == "time_window" and confidence == "medium":
            # sink 只是"同一时间窗内这台机器的某个连接"，可能不属于本次执行，
            # 那么强结论就站不住——降一级，而不是继续按 medium 报。
            confidence = "low"

        sink = sinks[0]
        evidence = [_evidence("intent", source_intent["intent_id"]),
                    _evidence("file_access", source_path)]
        if source_event_id:
            evidence.append(_evidence("runtime_event", source_event_id))
        evidence.extend(item["evidence_refs"][0] for item in hops)
        evidence.append(_evidence("network_connect", sink["event_id"]))

        return {
            "flow_id": "flow_" + uuid.uuid4().hex,
            "execution_id": source_intent.get("execution_id"),
            "source": {"intent_id": source_intent["intent_id"], "path": source_path,
                       "tool_name": source_intent["tool_name"],
                       "occurred_at": source_intent["occurred_at"]},
            "hops": hops,
            "sink": {"host": sink.get("resource_host"), "port": sink.get("resource_port"),
                     "event_id": sink["event_id"], "occurred_at": sink["occurred_at"]},
            "sink_count": len(sinks),
            "sink_basis": sink_basis,
            "confidence": confidence,
            "evidence_refs": evidence,
            "detected_at": now(),
        }

    @staticmethod
    def _note() -> str:
        return ("路径级启发式：同一会话内先读敏感文件、后连外部地址；"
                "不证明内容被发送。内网与已知可信域名不计入外发。")
