"""Execution 与 Intent 契约。

Execution 是一次 Agent 任务/会话的边界，不是进程：同一会话里的多次工具
调用共享一个 Execution，每次调用各自成为一条 Intent。Intent 是观测到的
操作请求，不从自然语言 prompt 推断；参数只存端侧脱敏后的摘要与哈希，
tool_input 原文、prompt 正文和环境变量不得进入契约。

决策边界：只有执行前事件（PreToolUse）才允许携带 allow/ask/deny；其余
事件的 decision 必须是 not_applicable。这不是展示问题—— observe 模式下
的观测事件一旦带上决策语义，报告就会把"看到了"呈现成"拦住了"。
"""

from __future__ import annotations

from datetime import datetime

from pydantic import Field, model_validator

from domain.asset import StrictModel
from domain.enums import (
    PRE_EXECUTION_HOOK_EVENTS,
    ExecutionOutcome,
    HookEventType,
    IntentDecision,
)

# 参数摘要长度上限。端侧脱敏后仍是任意结构，超出即截断，完整内容以
# params_sha256 标识。
MAX_PARAMS_SUMMARY = 8192
MAX_PRODUCT_RESULT = 1024

TERMINAL_OUTCOMES = frozenset({
    ExecutionOutcome.COMPLETED,
    ExecutionOutcome.ABORTED,
    ExecutionOutcome.FAILED,
})


class Execution(StrictModel):
    """一次 Agent 任务/会话的执行边界。"""

    execution_id: str = Field(min_length=1)
    host_id: str = Field(min_length=1)
    device_id: str = Field(min_length=1)
    product: str = Field(min_length=1)
    product_version: str = Field(min_length=1)
    session_id: str = Field(min_length=1)
    # P1 没有资产注册表：该字段只存端点上报的引用，不代表资产已纳管。
    asset_instance_id: str | None = None
    started_at: datetime
    ended_at: datetime | None = None
    outcome: ExecutionOutcome = ExecutionOutcome.RUNNING
    intent_count: int = Field(default=0, ge=0)
    created_at: datetime
    updated_at: datetime

    @model_validator(mode="after")
    def _check_outcome_boundary(self) -> Execution:
        if self.outcome is ExecutionOutcome.RUNNING and self.ended_at is not None:
            raise ValueError("running 状态的 Execution 不得记录 ended_at")
        if self.outcome in TERMINAL_OUTCOMES and self.ended_at is None:
            raise ValueError("终态 Execution 必须记录 ended_at")
        if self.ended_at is not None and self.ended_at < self.started_at:
            raise ValueError("ended_at 不得早于 started_at")
        return self

    @property
    def is_terminal(self) -> bool:
        return self.outcome in TERMINAL_OUTCOMES


class Intent(StrictModel):
    """一次观测到的工具调用。

    hook_event_type 记录创建这条 Intent 的事件；同一 tool_call_id 的后续
    事件（如 PostToolUse）只补结果，不改写事件类型与决策，避免"执行后
    观测"覆盖"执行前决策"的记录。
    """

    intent_id: str = Field(min_length=1)
    execution_id: str = Field(min_length=1)
    # P1 恒为 NULL，为 P2 子 Agent 调用链预留。
    parent_intent_id: str | None = None
    tool_call_id: str | None = None
    tool_name: str = Field(min_length=1)
    hook_event_type: HookEventType
    decision: IntentDecision = IntentDecision.NOT_APPLICABLE
    decision_reason: str | None = None
    # 端侧脱敏后的参数摘要；原文不进契约。
    params_summary: str = Field(default="", max_length=MAX_PARAMS_SUMMARY)
    params_sha256: str | None = None
    redaction_applied: bool = False
    occurred_at: datetime
    ended_at: datetime | None = None
    # 产品侧结果的脱敏短摘要，不是完整输出。
    product_result: str | None = Field(default=None, max_length=MAX_PRODUCT_RESULT)
    created_at: datetime

    @model_validator(mode="after")
    def _check_decision_boundary(self) -> Intent:
        pre_execution = self.hook_event_type in PRE_EXECUTION_HOOK_EVENTS
        if not pre_execution and self.decision is not IntentDecision.NOT_APPLICABLE:
            raise ValueError(
                f"{self.hook_event_type.value} 不是执行前事件，不得携带决策；"
                "只有 PreToolUse 可以记录 allow/ask/deny"
            )
        if self.decision is IntentDecision.NOT_APPLICABLE and self.decision_reason:
            raise ValueError("没有决策时不得记录 decision_reason")
        if self.params_sha256 is not None:
            digest = self.params_sha256
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError("params_sha256 必须是 64 位小写十六进制")
        if self.ended_at is not None and self.ended_at < self.occurred_at:
            raise ValueError("ended_at 不得早于 occurred_at")
        return self
