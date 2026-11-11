"""时间线只陈述已观测内容；未实现的归因和策略明确列出。"""
from datetime import datetime
from typing import Any, Literal
from pydantic import Field
from domain.asset import StrictModel


class TimelineEntry(StrictModel):
    kind: Literal["intent", "runtime_event"]
    id: str
    occurred_at: datetime
    data: dict[str, Any]


class TimelineResponse(StrictModel):
    execution_id: str
    product: str
    product_version: str
    host_id: str
    capability_verification: str
    sections_supported: list[str] = Field(default_factory=lambda: ["intent", "runtime_event"])
    sections_pending: list[str] = Field(default_factory=lambda: ["attribution", "finding", "policy_decision"])
    attribution_supported: Literal[False] = False
    attribution_note: str = "intent_ref 是采集器提示，尚无 P2 因果归因结论。"
    entries: list[TimelineEntry]
    next_cursor: str | None = None
