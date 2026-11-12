"""时间线只陈述已观测内容；未实现的归因和策略明确列出。"""
from datetime import datetime
from typing import Any, Literal
from pydantic import Field
from domain.asset import StrictModel
from domain.attribution import EventAttribution


class TimelineEntry(StrictModel):
    kind: Literal["intent", "runtime_event", "finding", "policy_decision", "admission"]
    id: str
    occurred_at: datetime
    data: dict[str, Any]


class TimelineResponse(StrictModel):
    execution_id: str
    product: str
    product_version: str
    host_id: str
    capability_verification: str
    sections_supported: list[str] = Field(default_factory=lambda: [
        "intent", "runtime_event", "attribution", "finding", "policy_decision", "admission"])
    sections_pending: list[str] = Field(default_factory=list)
    attribution_supported: Literal[True] = True
    attribution_note: str = "归因边是可冲突的证据候选，selected 不等于已证明因果；未归因事件仍保留在主机视图。"
    # 每个分段是怎么被关联进来的。finding 是分析员显式登记的，不是采集器
    # 证明的因果；policy_decision 和 admission 按标识字符串匹配。写进响应，
    # 界面按原样展示，避免把关联读成证明。
    section_links: dict[str, str] = Field(default_factory=lambda: {
        "intent": "产品 Hook 执行前/后观测，按 occurred_at 排序",
        "runtime_event": "采集器观测，按 occurred_at 排序",
        "attribution": "候选归因边，可冲突、可多条",
        "finding": "分析员显式关联（execution_findings），不是自动归因",
        "policy_decision": "按 subject_id 匹配本次执行、资产实例、关联发现项或准入标识",
        "admission": "按 admissions.asset_instance_id 匹配本次执行引用的实例，且限定事务活跃区间与本次执行时间窗有交集；"
                     "同一实例历史上更早的准入不会挂到这条执行上",
    })
    attributions: list[EventAttribution] = Field(default_factory=list)
    entries: list[TimelineEntry]
    next_cursor: str | None = None
