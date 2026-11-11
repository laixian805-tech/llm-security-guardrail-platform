"""Execution/Intent/RuntimeEvent 仓储测试。

锁定的写入语义：标识由端点生成并在重试中保持稳定，服务端以唯一约束去重；
Execution 创建与收尾两用且状态只进不退；Intent 按 (execution_id,
tool_call_id) 合并，执行前观测优先于执行后观测。
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from domain import ExecutionOutcome, HookEventType, IntentDecision, RetentionKind, RuntimeEvent
from storage.execution_repositories import (
    ExecutionConflict,
    ExecutionRepository,
    IntentRepository,
    RuntimeEventRepository,
)
from storage.repositories import RetentionRepository, Storage

NOW = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)
LATER = NOW + timedelta(seconds=30)


def enroll_device(storage: Storage, device_id: str) -> None:
    import hashlib

    with storage.connection() as conn:
        conn.execute(
            "INSERT INTO device_identities (device_id, label, credential_hash, status,"
            " enrolled_at) VALUES (?,?,?,?,?)",
            (device_id, "工作站", hashlib.sha256(device_id.encode()).hexdigest(),
             "active", NOW.isoformat()),
        )


@pytest.fixture
def seeded(tmp_path):
    """一台已登记设备 + 一条 running 的 Execution。"""
    storage = Storage(tmp_path / "asgp.db")
    enroll_device(storage, "dev_1")
    enroll_device(storage, "dev_2")
    executions = ExecutionRepository(storage)
    executions.upsert(
        execution_id="exec_1", host_id="host_1", device_id="dev_1",
        product="claude-code", product_version="2.0.0", session_id="sess_1",
        asset_instance_id=None, started_at=NOW, ended_at=None,
        outcome=ExecutionOutcome.RUNNING,
    )
    return storage, executions, IntentRepository(storage), RuntimeEventRepository(storage)


def upsert(repo: ExecutionRepository, *, execution_id: str, host_id: str = "host_1",
           device_id: str = "dev_1", session_id: str = "sess_1",
           outcome: ExecutionOutcome = ExecutionOutcome.RUNNING,
           ended_at: datetime | None = None,
           started_at: datetime = NOW) -> dict:
    return repo.upsert(
        execution_id=execution_id, host_id=host_id, device_id=device_id,
        product="claude-code", product_version="2.0.0", session_id=session_id,
        asset_instance_id=None, started_at=started_at, ended_at=ended_at,
        outcome=outcome,
    )


def record(intents: IntentRepository, *, intent_id: str, execution_id: str = "exec_1",
           tool_call_id: str | None = "toolu_01", tool_name: str = "Bash",
           hook_event_type: HookEventType = HookEventType.PRE_TOOL_USE,
           decision: IntentDecision = IntentDecision.NOT_APPLICABLE,
           decision_reason: str | None = None,
           occurred_at: datetime = NOW, ended_at: datetime | None = None,
           product_result: str | None = None) -> dict:
    return intents.record(
        intent_id=intent_id, execution_id=execution_id, parent_intent_id=None,
        tool_call_id=tool_call_id, tool_name=tool_name, hook_event_type=hook_event_type,
        decision=decision, decision_reason=decision_reason, params_summary='{"cmd":"ls"}',
        params_sha256="a" * 64, redaction_applied=False, occurred_at=occurred_at,
        ended_at=ended_at, product_result=product_result,
    )


def runtime_event(event_id: str, *, execution_id: str | None = "exec_1",
                  collector_id: str = "linux-audit-v1", occurred_at: datetime = NOW,
                  received_at: datetime = NOW) -> RuntimeEvent:
    return RuntimeEvent(
        event_id=event_id, host_id="host_1", collector_id=collector_id,
        device_id="dev_1", execution_id=execution_id, event_type="process_exec",
        occurred_at=occurred_at, received_at=received_at,
    )


class TestExecutionRepository:
    def test_session_start_creates_row(self, seeded):
        _, executions, _, _ = seeded
        row = executions.get("exec_1")
        assert row["outcome"] == "running"
        assert row["ended_at"] is None
        assert row["intent_count"] == 0

    def test_replay_returns_duplicate_without_second_row(self, seeded):
        _, executions, _, _ = seeded
        assert upsert(executions, execution_id="exec_1")["duplicate"] is True
        assert len(executions.list()) == 1

    def test_session_end_advances_to_terminal(self, seeded):
        _, executions, _, _ = seeded
        result = upsert(executions, execution_id="exec_1",
                        outcome=ExecutionOutcome.COMPLETED, ended_at=LATER)
        assert result["duplicate"] is False
        row = executions.get("exec_1")
        assert row["outcome"] == "completed"
        assert row["ended_at"] == LATER.isoformat()

    def test_terminal_row_is_frozen(self, seeded):
        # 状态只进不退：重放的 SessionStart 不得把 completed 改回 running。
        _, executions, _, _ = seeded
        upsert(executions, execution_id="exec_1",
               outcome=ExecutionOutcome.COMPLETED, ended_at=LATER)
        assert upsert(executions, execution_id="exec_1")["duplicate"] is True
        row = executions.get("exec_1")
        assert row["outcome"] == "completed"
        assert row["ended_at"] == LATER.isoformat()

    def test_replay_does_not_drop_recorded_ended_at(self, seeded):
        _, executions, _, _ = seeded
        upsert(executions, execution_id="exec_1",
               outcome=ExecutionOutcome.FAILED, ended_at=LATER)
        upsert(executions, execution_id="exec_1")
        row = executions.get("exec_1")
        assert row["outcome"] == "failed"
        assert row["ended_at"] == LATER.isoformat()

    def test_same_session_with_new_id_adopts_original_row(self, seeded):
        # 端点重装丢失 outbox 后用新 execution_id 上报同一会话：认领原行，
        # 不分裂出第二条，返回库中的权威标识。
        _, executions, _, _ = seeded
        adopted = upsert(executions, execution_id="exec_2")
        assert adopted["execution_id"] == "exec_1"
        assert len(executions.list()) == 1
        # 认领后仍可继续收尾。
        closed = upsert(executions, execution_id="exec_2",
                        outcome=ExecutionOutcome.COMPLETED, ended_at=LATER)
        assert closed == {"execution_id": "exec_1", "duplicate": False}
        assert executions.get("exec_1")["outcome"] == "completed"

    def test_foreign_device_cannot_squat_execution_id(self, seeded):
        _, executions, _, _ = seeded
        with pytest.raises(ExecutionConflict):
            upsert(executions, execution_id="exec_1", device_id="dev_2", session_id="sess_2")
        assert executions.get("exec_1")["device_id"] == "dev_1"

    def test_unknown_device_is_rejected_by_foreign_key(self, seeded):
        # 用新会话隔离：否则 INSERT 撞 FK 后会去认领 sess_1 的原行，
        # 报出来的是 ExecutionConflict 而不是外键错误。
        _, executions, _, _ = seeded
        with pytest.raises(sqlite3.IntegrityError):
            upsert(executions, execution_id="exec_9", device_id="dev_missing",
                   session_id="sess_9")


class TestIntentRepository:
    def test_post_tool_use_merges_into_pre_tool_use_row(self, seeded):
        _, _, intents, _ = seeded
        record(intents, intent_id="intent_pre", decision=IntentDecision.DENY,
               decision_reason="策略禁止")
        record(intents, intent_id="intent_post",
               hook_event_type=HookEventType.POST_TOOL_USE,
               occurred_at=LATER, ended_at=LATER, product_result="exit 0")
        rows = intents.list_for_execution("exec_1")
        assert len(rows) == 1
        row = rows[0]
        assert row["intent_id"] == "intent_pre"
        assert row["decision"] == "deny"
        assert row["decision_reason"] == "策略禁止"
        assert row["hook_event_type"] == "pre_tool_use"
        assert row["ended_at"] == LATER.isoformat()
        assert row["product_result"] == "exit 0"

    def test_post_observation_does_not_erase_pre_decision(self, seeded):
        # 执行后观测不得把"拦住了"改成"看到了"。
        _, _, intents, _ = seeded
        record(intents, intent_id="intent_pre", decision=IntentDecision.DENY,
               decision_reason="策略禁止")
        record(intents, intent_id="intent_post",
               hook_event_type=HookEventType.POST_TOOL_USE,
               occurred_at=LATER)
        row = intents.list_for_execution("exec_1")[0]
        assert row["decision"] == "deny"
        assert row["decision_reason"] == "策略禁止"

    def test_first_observed_result_is_kept(self, seeded):
        _, _, intents, _ = seeded
        record(intents, intent_id="intent_pre", product_result="第一次结果")
        record(intents, intent_id="intent_post",
               hook_event_type=HookEventType.POST_TOOL_USE,
               occurred_at=LATER, product_result="重放结果")
        assert intents.list_for_execution("exec_1")[0]["product_result"] == "第一次结果"

    def test_occurred_at_takes_earliest(self, seeded):
        _, _, intents, _ = seeded
        record(intents, intent_id="intent_pre", occurred_at=LATER)
        record(intents, intent_id="intent_post",
               hook_event_type=HookEventType.POST_TOOL_USE, occurred_at=NOW)
        assert intents.list_for_execution("exec_1")[0]["occurred_at"] == NOW.isoformat()

    def test_without_tool_call_id_each_observation_is_its_own_row(self, seeded):
        # 产品不提供调用 ID 时唯一约束不触发，按 intent_id 幂等。
        _, _, intents, _ = seeded
        record(intents, intent_id="intent_a", tool_call_id=None)
        record(intents, intent_id="intent_b", tool_call_id=None,
               hook_event_type=HookEventType.POST_TOOL_USE)
        assert len(intents.list_for_execution("exec_1")) == 2
        assert record(intents, intent_id="intent_a", tool_call_id=None)["duplicate"] is True
        assert len(intents.list_for_execution("exec_1")) == 2

    def test_intent_replay_is_duplicate(self, seeded):
        _, _, intents, _ = seeded
        record(intents, intent_id="intent_pre")
        assert record(intents, intent_id="intent_pre")["duplicate"] is True

    def test_intent_count_follows_distinct_tool_calls(self, seeded):
        _, executions, intents, _ = seeded
        record(intents, intent_id="intent_pre")
        record(intents, intent_id="intent_post",
               hook_event_type=HookEventType.POST_TOOL_USE, occurred_at=LATER)
        record(intents, intent_id="intent_c", tool_call_id="toolu_02")
        assert executions.get("exec_1")["intent_count"] == 2


class TestRuntimeEventRepository:
    def test_batch_reports_inserted_and_duplicates(self, seeded):
        *_, events = seeded
        assert events.record_many(
            [runtime_event("e1"), runtime_event("e2")]
        ) == {"inserted": 2, "duplicates": 0}
        assert events.record_many(
            [runtime_event("e1"), runtime_event("e3")]
        ) == {"inserted": 1, "duplicates": 1}
        assert len(events.list_for_execution("exec_1")) == 3

    def test_same_event_id_from_another_collector_is_distinct(self, seeded):
        # 同一主机可有多个采集器，去重键是三元组而不是 event_id。
        *_, events = seeded
        events.record_many([runtime_event("e1")])
        assert events.record_many(
            [runtime_event("e1", collector_id="ebpf-v1")]
        ) == {"inserted": 1, "duplicates": 0}

    def test_unknown_execution_fails_whole_batch(self, seeded):
        *_, events = seeded
        with pytest.raises(sqlite3.IntegrityError):
            events.record_many([runtime_event("e1", execution_id="exec_missing")])
        assert events.list_for_execution("exec_1") == []

    def test_unattributed_event_is_kept(self, seeded):
        *_, events = seeded
        events.record_many([runtime_event("e1", execution_id=None)])
        assert len(events.list_for_host("host_1")) == 1


class TestRetention:
    def test_execution_retention_removes_children(self, seeded):
        storage, executions, intents, events = seeded
        upsert(executions, execution_id="exec_old", session_id="sess_old",
               started_at=NOW - timedelta(days=2))
        record(intents, intent_id="i_old", execution_id="exec_old")
        record(intents, intent_id="i_new", execution_id="exec_1")
        events.record_many([runtime_event("e_old", execution_id="exec_old",
                                          occurred_at=NOW - timedelta(days=2))])
        events.record_many([runtime_event("e_new")])

        retention = RetentionRepository(storage)
        retention.ensure_defaults()
        retention.set_rule(data_kind=RetentionKind.EXECUTIONS, retention_days=1, enabled=True)
        counts = retention.prune(now=NOW)
        assert counts["executions"] == 1
        assert executions.get("exec_old") is None
        assert executions.get("exec_1") is not None
        assert [r["intent_id"] for r in intents.list_for_execution("exec_1")] == ["i_new"]
        assert [e["event_id"] for e in events.list_for_execution("exec_1")] == ["e_new"]

    def test_runtime_event_retention_prunes_unattributed_events(self, seeded):
        storage, _, _, events = seeded
        events.record_many([
            runtime_event("e_old", execution_id=None,
                          occurred_at=NOW - timedelta(days=2),
                          received_at=NOW - timedelta(days=2)),
            runtime_event("e_new", execution_id=None),
        ])
        retention = RetentionRepository(storage)
        retention.ensure_defaults()
        retention.set_rule(data_kind=RetentionKind.RUNTIME_EVENTS, retention_days=1,
                           enabled=True)
        retention.prune(now=NOW)
        assert [e["event_id"] for e in events.list_for_host("host_1")] == ["e_new"]

    def test_defaults_cover_runtime_kinds(self, seeded):
        storage = seeded[0]
        retention = RetentionRepository(storage)
        retention.ensure_defaults()
        rules = {row["data_kind"]: row["retention_days"] for row in retention.rules()}
        assert rules["executions"] == 90
        assert rules["runtime_events"] == 30

    def test_disabled_rule_prunes_nothing(self, seeded):
        storage, executions, _, _ = seeded
        upsert(executions, execution_id="exec_old", session_id="sess_old",
               started_at=NOW - timedelta(days=400))
        retention = RetentionRepository(storage)
        retention.ensure_defaults()
        retention.set_rule(data_kind=RetentionKind.EXECUTIONS, retention_days=1, enabled=False)
        assert retention.prune(now=NOW)["executions"] == 0
        assert executions.get("exec_old") is not None


def test_replayed_pre_tool_decision_keeps_first_evidence(seeded):
    _, _, intents, _ = seeded
    record(intents, intent_id='first', decision=IntentDecision.DENY, decision_reason='first refusal')
    record(intents, intent_id='second', decision=IntentDecision.ALLOW, decision_reason='later replay')
    row=intents.list_for_execution('exec_1')[0]
    assert row['decision']=='deny'
    assert row['decision_reason']=='first refusal'
