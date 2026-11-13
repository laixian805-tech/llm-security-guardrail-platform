"""指令来源谱系 × 预期/真实 OS 副作用差分契约。"""

from __future__ import annotations

from pydantic import Field

from domain.asset import StrictModel
from domain.enums import AttributionMethod, Confidence, EffectDiffVerdict, SourceKind


class EffectDiffItem(StrictModel):
    """单条模型调用与其归因 OS 副作用的差分条目。"""

    intent_id: str = Field(min_length=1)
    tool_name: str = Field(min_length=1)
    source_kind: SourceKind = SourceKind.UNKNOWN
    source_ref: str | None = None
    trust_tier: str = Field(min_length=1)
    expected_scope: str = Field(min_length=1)
    event_id: str | None = None
    event_type: str | None = None
    observed_target: str | None = None
    attribution_method: AttributionMethod | None = None
    attribution_confidence: Confidence | None = None
    verdict: EffectDiffVerdict
    reason: str = Field(min_length=1)


class ExecutionEffectDiff(StrictModel):
    """一次执行的来源谱系与 OS 副作用差分结果。"""

    execution_id: str = Field(min_length=1)
    rule_version: str = Field(min_length=1)
    intent_count: int = Field(ge=0)
    attributed_event_count: int = Field(ge=0)
    unattributed_event_count: int = Field(ge=0)
    undeclared_count: int = Field(ge=0)
    within_expected_count: int = Field(ge=0)
    by_source_kind: dict[str, int] = Field(default_factory=dict)
    items: list[EffectDiffItem] = Field(default_factory=list)
