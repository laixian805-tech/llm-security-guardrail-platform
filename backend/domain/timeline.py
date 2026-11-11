"""时间线只陈述已观测内容；未实现的归因和策略明确列出。"""
from datetime import datetime
from typing import Any, Literal
from pydantic import Field
from domain.asset import StrictModel
from domain.attribution import EventAttribution


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
    sections_supported: list[str] = Field(default_factory=lambda: ["intent", "runtime_event", "attribution"])
    sections_pending: list[str] = Field(default_factory=lambda: ["finding", "policy_decision"])
    attribution_supported: Literal[True] = True
    attribution_note: str = "归因边是可冲突的证据候选，selected 不等于已证明因果；未归因事件仍保留在主机视图。"
    attributions: list[EventAttribution] = Field(default_factory=list)
    entries: list[TimelineEntry]
    next_cursor: str | None = None
