"""RuntimeEvent 与 Intent 的候选归因。

归因是证据关系，不是事实改写：同一事件可以有多个候选，弱候选不能
覆盖强候选；没有足够证据时保留为空。
"""
from __future__ import annotations

from datetime import datetime

from pydantic import Field, model_validator

from domain.asset import StrictModel
from domain.enums import AttributionMethod, Confidence
from domain.evidence import EvidenceRef


class EventAttribution(StrictModel):
    attribution_id: str = Field(min_length=1)
    intent_id: str = Field(min_length=1)
    event_id: str = Field(min_length=1)
    host_id: str = Field(min_length=1)
    collector_id: str = Field(min_length=1)
    method: AttributionMethod
    confidence: Confidence
    score: float = Field(ge=0, le=1)
    selected: bool = False
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    rule_version: str = Field(min_length=1)
    created_at: datetime

    @model_validator(mode="after")
    def _selected_requires_strong_evidence(self) -> EventAttribution:
        if self.selected and self.score < 0.8:
            raise ValueError("弱归因候选不得标记为 selected")
        if self.method is AttributionMethod.HOOK_ID and self.score < 0.95:
            raise ValueError("Hook ID 精确归因必须有高置信分")
        return self
