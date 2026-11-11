"""Execution/Intent/RuntimeEvent 仓储。

写入语义与 P0 的 DetectorRun 一脉相承：标识由端点生成并在重试中保持
稳定，服务端以唯一约束去重，重复上报返回 duplicate=True 且不产生第二行。

Execution 是"创建 + 收尾两用"：SessionStart 建行，SessionEnd 补
ended_at/outcome。状态只进不退——终态行不再接受任何改写，重放的
SessionStart 不会把 completed 改回 running。

Intent 按 (execution_id, tool_call_id) 合并：PreToolUse 创建并可能带
决策，PostToolUse 只补 ended_at/product_result。创建事件与决策不被执行
后观测改写，否则"执行前拦截过"会被"执行后看到过"抹掉。
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Any, Iterable

from domain import ExecutionOutcome, RuntimeEvent
from storage.repositories import Storage, now_iso

TERMINAL_OUTCOME_VALUES = frozenset({
    ExecutionOutcome.COMPLETED.value,
    ExecutionOutcome.ABORTED.value,
    ExecutionOutcome.FAILED.value,
})

NOT_APPLICABLE = "not_applicable"
PRE_TOOL_USE = "pre_tool_use"


class ExecutionConflict(Exception):
    """上报的标识已被其它设备或主机占用（抢注）。"""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


class ExecutionRepository:
    def __init__(self, storage: Storage) -> None:
        self._storage = storage

    def get(self, execution_id: str) -> dict[str, Any] | None:
        with self._storage.connection() as conn:
            row = conn.execute(
                "SELECT * FROM executions WHERE execution_id = ?", (execution_id,)
            ).fetchone()
        return dict(row) if row else None

    def list(self, *, host_id: str | None = None, product: str | None = None,
             limit: int = 50) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if host_id:
            clauses.append("host_id = ?")
            params.append(host_id)
        if product:
            clauses.append("product = ?")
            params.append(product)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        with self._storage.connection() as conn:
            rows = conn.execute(
                f"SELECT * FROM executions{where} ORDER BY started_at DESC LIMIT ?", params
            ).fetchall()
        return [dict(row) for row in rows]

    def upsert(self, *, execution_id: str, host_id: str, device_id: str, product: str,
               product_version: str, session_id: str, asset_instance_id: str | None,
               started_at: datetime, ended_at: datetime | None,
               outcome: ExecutionOutcome) -> dict[str, Any]:
        """创建或收尾一条 Execution。

        返回 {"execution_id", "duplicate"}：duplicate=True 表示本次上报
        没有改变任何状态（重放，或同一会话已被另一条 execution_id 占位）。
        返回值里的 execution_id 是库中的权威标识——端点重装丢失 outbox
        后用新 ID 上报同一会话时，拿到的是原行标识。
        """
        now = now_iso()
        started_at_text = started_at.isoformat()
        ended_at_text = ended_at.isoformat() if ended_at else None
        with self._storage._lock, self._storage.connection() as conn:
            conn.execute("BEGIN")
            try:
                row = conn.execute(
                    "SELECT * FROM executions WHERE execution_id = ?", (execution_id,)
                ).fetchone()
                if row is None:
                    try:
                        conn.execute(
                            "INSERT INTO executions (execution_id, host_id, device_id,"
                            " product, product_version, session_id, asset_instance_id,"
                            " started_at, ended_at, outcome, intent_count, created_at,"
                            " updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,0,?,?)",
                            (execution_id, host_id, device_id, product, product_version,
                             session_id, asset_instance_id, started_at_text, ended_at_text,
                             outcome.value, now, now),
                        )
                    except sqlite3.IntegrityError:
                        # UNIQUE(host_id, product, session_id)：同一会话已有
                        # 另一条 execution_id（端点重装后重新上报）。认领原行，
                        # 不分裂出第二条。
                        row = conn.execute(
                            "SELECT * FROM executions WHERE host_id = ? AND product = ?"
                            " AND session_id = ?",
                            (host_id, product, session_id),
                        ).fetchone()
                        if row is None:
                            raise
                    else:
                        conn.execute("COMMIT")
                        return {"execution_id": execution_id, "duplicate": False}

                if row["device_id"] != device_id or row["host_id"] != host_id:
                    raise ExecutionConflict("该执行标识已属于其它设备或主机。")

                # 状态只进不退：终态行不再接受改写。
                if row["outcome"] in TERMINAL_OUTCOME_VALUES:
                    conn.execute("COMMIT")
                    return {"execution_id": row["execution_id"], "duplicate": True}

                if (row["outcome"] == outcome.value
                        and (row["ended_at"] or None) == ended_at_text):
                    conn.execute("COMMIT")
                    return {"execution_id": row["execution_id"], "duplicate": True}

                conn.execute(
                    "UPDATE executions SET ended_at = COALESCE(?, ended_at), outcome = ?,"
                    " updated_at = ? WHERE execution_id = ?",
                    (ended_at_text, outcome.value, now, row["execution_id"]),
                )
                conn.execute("COMMIT")
                return {"execution_id": row["execution_id"], "duplicate": False}
            except Exception:
                conn.execute("ROLLBACK")
                raise


class IntentRepository:
    def __init__(self, storage: Storage) -> None:
        self._storage = storage

    def list_for_execution(self, execution_id: str) -> list[dict[str, Any]]:
        with self._storage.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM intents WHERE execution_id = ? ORDER BY occurred_at, intent_id",
                (execution_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def record(self, *, intent_id: str, execution_id: str, parent_intent_id: str | None,
               tool_call_id: str | None, tool_name: str, hook_event_type: str,
               decision: str, decision_reason: str | None, params_summary: str,
               params_sha256: str | None, redaction_applied: bool,
               occurred_at: datetime, ended_at: datetime | None,
               product_result: str | None) -> dict[str, Any]:
        """登记一次观测。

        同一 (execution_id, tool_call_id) 的后续事件合并进原行：补
        ended_at/product_result，决策取首个非 not_applicable 值（执行前
        观测优先），occurred_at 取最早。产品不提供 tool_call_id 时每次
        观测各自成条，按 intent_id 幂等。

        返回 {"intent_id", "duplicate"}。
        """
        now = now_iso()
        occurred_at_text = occurred_at.isoformat()
        ended_at_text = ended_at.isoformat() if ended_at else None
        with self._storage._lock, self._storage.connection() as conn:
            conn.execute("BEGIN")
            try:
                existing = None
                if tool_call_id is not None:
                    existing = conn.execute(
                        "SELECT * FROM intents WHERE execution_id = ? AND tool_call_id = ?",
                        (execution_id, tool_call_id),
                    ).fetchone()

                if existing is not None:
                    before = (existing["ended_at"], existing["product_result"],
                              existing["decision"], existing["decision_reason"],
                              existing["occurred_at"], existing["params_summary"],
                              existing["params_sha256"])
                    conn.execute(
                        "UPDATE intents SET"
                        # 结果只补空，不覆盖：首次观测到的 ended_at/结果留档，
                        # 后续观测（含重放）不得改写。
                        " ended_at = COALESCE(ended_at, ?),"
                        " product_result = COALESCE(product_result, ?),"
                        # 执行前观测到的决策优先；not_applicable 不覆盖已有决策。
                        " decision = CASE WHEN decision = ? AND ? != ? THEN ? ELSE decision END,"
                        " decision_reason = COALESCE(decision_reason, ?),"
                        " occurred_at = MIN(occurred_at, ?),"
                        " params_summary = CASE WHEN params_summary = '' THEN ?"
                        " ELSE params_summary END,"
                        " params_sha256 = COALESCE(params_sha256, ?),"
                        " redaction_applied = MAX(redaction_applied, ?),"
                        # 一旦被执行前事件观测过，创建事件就固定为 pre_tool_use：
                        # 决策与创建事件必须同源，不能出现"事后事件带决策"的行。
                        " hook_event_type = CASE WHEN ? = ? THEN ? ELSE hook_event_type END"
                        " WHERE intent_id = ?",
                        (ended_at_text, product_result,
                         NOT_APPLICABLE, decision, NOT_APPLICABLE, decision,
                         decision_reason, occurred_at_text,
                         params_summary, params_sha256,
                         1 if redaction_applied else 0,
                         hook_event_type, PRE_TOOL_USE, PRE_TOOL_USE,
                         existing["intent_id"]),
                    )
                    after_row = conn.execute(
                        "SELECT * FROM intents WHERE intent_id = ?", (existing["intent_id"],)
                    ).fetchone()
                    after = (after_row["ended_at"], after_row["product_result"],
                             after_row["decision"], after_row["decision_reason"],
                             after_row["occurred_at"], after_row["params_summary"],
                             after_row["params_sha256"])
                    conn.execute("COMMIT")
                    return {"intent_id": existing["intent_id"], "duplicate": before == after}

                cursor = conn.execute(
                    "INSERT INTO intents (intent_id, execution_id, parent_intent_id,"
                    " tool_call_id, tool_name, hook_event_type, decision, decision_reason,"
                    " params_summary, params_sha256, redaction_applied, occurred_at,"
                    " ended_at, product_result, created_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
                    " ON CONFLICT(intent_id) DO NOTHING",
                    (intent_id, execution_id, parent_intent_id, tool_call_id, tool_name,
                     hook_event_type, decision, decision_reason, params_summary,
                     params_sha256, 1 if redaction_applied else 0, occurred_at_text,
                     ended_at_text, product_result, now),
                )
                if cursor.rowcount == 0:
                    # intent_id 重放：同一事件重复上报。
                    replayed = conn.execute(
                        "SELECT intent_id FROM intents WHERE intent_id = ?", (intent_id,)
                    ).fetchone()
                    conn.execute("COMMIT")
                    return {"intent_id": replayed["intent_id"], "duplicate": True}
                conn.execute(
                    "UPDATE executions SET intent_count = intent_count + 1,"
                    " updated_at = ? WHERE execution_id = ?",
                    (now, execution_id),
                )
                conn.execute("COMMIT")
                return {"intent_id": intent_id, "duplicate": False}
            except Exception:
                conn.execute("ROLLBACK")
                raise


class RuntimeEventRepository:
    def __init__(self, storage: Storage) -> None:
        self._storage = storage

    def record_many(self, events: Iterable[RuntimeEvent]) -> dict[str, int]:
        """批量写入，整批一个事务。

        单条按 (host_id, collector_id, event_id) 去重：重放只计
        duplicates，不拖垮整批。execution_id 外键不存在的事件让整批失败
        （IntegrityError），由调用方转成 unknown_execution。
        """
        inserted = 0
        duplicates = 0
        with self._storage._lock, self._storage.connection() as conn:
            conn.execute("BEGIN")
            try:
                for event in events:
                    process = event.process
                    resource = event.resource
                    cursor = conn.execute(
                        "INSERT INTO runtime_events (event_id, host_id, collector_id,"
                        " device_id, execution_id, intent_ref, event_type, occurred_at,"
                        " received_at, pid, ppid, executable, resource_host, resource_port,"
                        " resource_path, action, result, sequence, evidence_refs)"
                        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
                        " ON CONFLICT(host_id, collector_id, event_id) DO NOTHING",
                        (event.event_id, event.host_id, event.collector_id, event.device_id,
                         event.execution_id, event.intent_ref, event.event_type,
                         event.occurred_at.isoformat(), event.received_at.isoformat(),
                         process.pid if process else None,
                         process.ppid if process else None,
                         process.executable if process else None,
                         resource.host if resource else None,
                         resource.port if resource else None,
                         resource.path if resource else None,
                         event.action, event.result, event.sequence,
                         _dump_evidence(event.evidence_refs)),
                    )
                    if cursor.rowcount:
                        inserted += 1
                    else:
                        duplicates += 1
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        return {"inserted": inserted, "duplicates": duplicates}

    def list_for_execution(self, execution_id: str) -> list[dict[str, Any]]:
        with self._storage.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM runtime_events WHERE execution_id = ?"
                " ORDER BY occurred_at, event_id",
                (execution_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_for_host(self, host_id: str, *, since: str | None = None,
                      limit: int = 200) -> list[dict[str, Any]]:
        clauses = ["host_id = ?"]
        params: list[Any] = [host_id]
        if since:
            clauses.append("occurred_at >= ?")
            params.append(since)
        params.append(limit)
        with self._storage.connection() as conn:
            rows = conn.execute(
                f"SELECT * FROM runtime_events WHERE {' AND '.join(clauses)}"
                " ORDER BY occurred_at DESC LIMIT ?",
                params,
            ).fetchall()
        return [dict(row) for row in rows]

    def delete_before(self, cutoff: str) -> int:
        with self._storage._lock, self._storage.connection() as conn:
            cursor = conn.execute(
                "DELETE FROM runtime_events WHERE received_at < ?", (cutoff,)
            )
            return cursor.rowcount


def _dump_evidence(refs: list) -> str:
    import json

    return json.dumps([ref.model_dump() for ref in refs], ensure_ascii=False)
